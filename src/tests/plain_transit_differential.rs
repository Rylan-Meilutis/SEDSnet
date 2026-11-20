//! Plain transit (`Router::try_plain_transit`, `Router::send_plain_to_side`)
//! must be invisible: two identical relays receive the same randomized frame
//! sequence and the same routing and policy changes, one with the plain
//! transit paths and one sending everything down the general paths. Every
//! frame each relay hands to each side, and its runtime statistics, must be
//! identical.

use crate::config::{DataEndpoint, DataType, register_data_type_with_description};
use crate::packet::Packet;
use crate::router::{
    EndpointHandler, Router, RouterConfig, RouterSideOptions, plain_transit_test_switch,
};
use crate::{MessageClass, MessageDataType, MessageElement, ReliableMode};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const REMOTE: &str = "PLAIN_DIFF_REMOTE";
const OTHER: &str = "PLAIN_DIFF_OTHER";
const LOCAL: &str = "PLAIN_DIFF_LOCAL";

fn endpoint(name: &str) -> DataEndpoint {
    crate::tests::ensure_common_test_schema();
    DataEndpoint::try_named(name).unwrap_or_else(|| {
        crate::config::register_endpoint_with_description(name, "differential endpoint", false)
            .unwrap()
    })
}

fn data_type(name: &str, endpoints: &[&str], mode: ReliableMode) -> DataType {
    let endpoints: Vec<DataEndpoint> = endpoints.iter().map(|name| endpoint(name)).collect();
    DataType::try_named(name).unwrap_or_else(|| {
        register_data_type_with_description(
            name,
            "differential type",
            MessageElement::Static(2, MessageDataType::Float32, MessageClass::Data),
            &endpoints,
            mode,
            20,
        )
        .unwrap()
    })
}

type Wire = Arc<Mutex<Vec<(usize, Vec<u8>)>>>;

struct Relay {
    router: Router,
    wire: Wire,
    delivered: Arc<AtomicUsize>,
    sides: Vec<usize>,
    plain: bool,
}

impl Relay {
    fn new(now: &Arc<AtomicU64>, plain: bool) -> Self {
        let clock = now.clone();
        let delivered = Arc::new(AtomicUsize::new(0));
        let hits = delivered.clone();
        let router = Router::new_with_clock(
            RouterConfig::new([EndpointHandler::new_packet_handler(endpoint(LOCAL), move |_| {
                hits.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })])
            .with_sender("PLAIN_DIFF_RELAY"),
            Box::new(move || clock.load(Ordering::Relaxed)),
        );
        let mut relay = Self { router, wire: Wire::default(), delivered, sides: Vec::new(), plain };
        relay.add_side("in", 128);
        relay.add_side("out", 1024);
        relay
    }

    fn add_side(&mut self, name: &str, max_frame_bytes: usize) {
        let index = self.sides.len();
        let wire = self.wire.clone();
        let opts = RouterSideOptions {
            reliable_enabled: false,
            header_template_enabled: true,
            max_frame_bytes,
            max_side_transport_templates: 8,
            ..RouterSideOptions::default()
        };
        let id = self.with(|router| {
            router.add_side_packed_with_options(
                name,
                move |bytes: &[u8]| {
                    wire.lock().unwrap().push((index, bytes.to_vec()));
                    Ok(())
                },
                opts,
            )
        });
        self.sides.push(id);
    }

    /// Run `f` with plain transit enabled or disabled for this relay.
    fn with<R>(&self, f: impl FnOnce(&Router) -> R) -> R {
        plain_transit_test_switch::set_disabled(!self.plain);
        let result = f(&self.router);
        plain_transit_test_switch::set_disabled(false);
        result
    }
}

/// Small deterministic generator (xorshift64*).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[test]
fn plain_transit_matches_the_general_path_over_random_traffic_and_policy() {
    let plain_type = data_type("PLAIN_DIFF_BULK", &[REMOTE], ReliableMode::None);
    let wide_type = data_type("PLAIN_DIFF_WIDE", &[REMOTE, OTHER], ReliableMode::None);
    let reliable_type = data_type("PLAIN_DIFF_RELIABLE", &[REMOTE], ReliableMode::Unordered);
    let local_type = data_type("PLAIN_DIFF_LOCAL_BULK", &[LOCAL], ReliableMode::None);
    let types = [
        (plain_type, &[REMOTE][..]),
        (wide_type, &[REMOTE, OTHER][..]),
        (reliable_type, &[REMOTE][..]),
        (local_type, &[LOCAL][..]),
    ];

    for seed in [0x5EED_0001u64, 0x5EED_0002, 0x5EED_0003] {
        let now = Arc::new(AtomicU64::new(1_700_000_000_000));
        // The source encodes every frame once; both relays get the same bytes.
        let source_clock = now.clone();
        let source = Router::new_with_clock(
            RouterConfig::new([]).with_sender("PLAIN_DIFF_SOURCE"),
            Box::new(move || source_clock.load(Ordering::Relaxed)),
        );
        let source_wire: Wire = Wire::default();
        let sink = source_wire.clone();
        source.add_side_packed_with_options(
            "bus",
            move |bytes: &[u8]| {
                sink.lock().unwrap().push((0, bytes.to_vec()));
                Ok(())
            },
            RouterSideOptions {
                reliable_enabled: false,
                header_template_enabled: true,
                max_frame_bytes: 128,
                max_side_transport_templates: 8,
                ..RouterSideOptions::default()
            },
        );
        let mut relays = [Relay::new(&now, true), Relay::new(&now, false)];
        let taken_before = plain_transit_test_switch::taken();
        let mut rng = Rng(seed);
        let mut last_frames: Vec<Vec<u8>> = Vec::new();

        for step in 0..600 {
            match rng.below(16) {
                // Mostly traffic, some of it repeated (duplicates).
                0..=9 => {
                    let frames = if rng.below(6) == 0 && !last_frames.is_empty() {
                        last_frames.clone()
                    } else {
                        let (ty, endpoints) = types[rng.below(types.len() as u64) as usize];
                        let endpoints: Vec<DataEndpoint> =
                            endpoints.iter().map(|name| endpoint(name)).collect();
                        let v = rng.below(1000) as f32;
                        let packet = Packet::from_f32_slice(
                            ty,
                            &[v, v + 0.5],
                            &endpoints,
                            now.load(Ordering::Relaxed),
                        )
                        .unwrap();
                        source.tx(packet).unwrap();
                        let frames: Vec<Vec<u8>> = core::mem::take(&mut *source_wire.lock().unwrap())
                            .into_iter()
                            .map(|(_, bytes)| bytes)
                            .collect();
                        last_frames = frames.clone();
                        frames
                    };
                    for relay in &relays {
                        for frame in &frames {
                            let result =
                                relay.with(|router| router.rx_packed_queue_from_side(frame, relay.sides[0]));
                            let _ = result;
                        }
                    }
                }
                10..=11 => {
                    let advance = [1, 7, 40, 600][rng.below(4) as usize];
                    now.fetch_add(advance, Ordering::Relaxed);
                }
                12 => {
                    let side = rng.below(relays[0].sides.len() as u64) as usize;
                    let enabled = rng.below(4) != 0;
                    for relay in &relays {
                        let _ = relay.with(|router| router.set_side_egress_enabled(relay.sides[side], enabled));
                    }
                }
                13 => {
                    let enabled = rng.below(4) != 0;
                    for relay in &relays {
                        let _ = relay.with(|router| router.set_side_ingress_enabled(relay.sides[0], enabled));
                    }
                }
                14 => {
                    let dst = rng.below(relays[0].sides.len() as u64) as usize;
                    let enabled = rng.below(2) == 0;
                    for relay in &relays {
                        let _ = relay.with(|router| {
                            router.set_route(Some(relay.sides[0]), relay.sides[dst], enabled)
                        });
                    }
                }
                _ => {
                    // A third link makes untargeted traffic ambiguous until a
                    // policy narrows it again.
                    if relays[0].sides.len() < 3 {
                        for relay in &mut relays {
                            relay.add_side("aux", 128);
                        }
                    } else {
                        let enabled = rng.below(2) == 0;
                        for relay in &relays {
                            let _ = relay.with(|router| {
                                router.set_route(Some(relay.sides[0]), relay.sides[2], enabled)
                            });
                        }
                    }
                }
            }
            if rng.below(3) == 0 {
                for relay in &relays {
                    let _ = relay.with(|router| router.drain_queues_with_timeout(0));
                }
            }
            let [plain, general] = &relays;
            assert_eq!(
                *plain.wire.lock().unwrap(),
                *general.wire.lock().unwrap(),
                "seed {seed:#x}, step {step}: side output differs"
            );
            assert_eq!(
                plain.delivered.load(Ordering::Relaxed),
                general.delivered.load(Ordering::Relaxed),
                "seed {seed:#x}, step {step}: local delivery differs"
            );
        }
        for relay in &relays {
            relay.with(|router| router.drain_queues_with_timeout(0)).unwrap();
        }
        let [plain, general] = &relays;
        assert_eq!(*plain.wire.lock().unwrap(), *general.wire.lock().unwrap());
        let taken = plain_transit_test_switch::taken();
        let forwarded = plain.wire.lock().unwrap().len();
        assert!(
            forwarded > 20 && taken[0] - taken_before[0] > 20 && taken[1] - taken_before[1] > 20,
            "seed {seed:#x}: too little plain transit to compare ({forwarded} frames, {taken:?})"
        );
        assert_eq!(
            plain.with(|router| router.export_runtime_stats()),
            general.with(|router| router.export_runtime_stats()),
            "seed {seed:#x}: runtime statistics differ"
        );
    }
}
