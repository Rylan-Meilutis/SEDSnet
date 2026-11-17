#![cfg(all(feature = "std", feature = "timesync"))]
//! Regression for the 2026-11-16 field fault, written against the public API
//! that SEDSnet 5.0.0 already had, so the same file shows the failure there:
//!
//! - a station corrects a clock 3 h 49 min off: 5.0.0 slewed it at 5%
//!   (76 h) and followers behind a relay fell seconds behind;
//! - after a 4 h step back, the managed FLIGHT_STATE refused every write made
//!   after the step (stamped "older"), and a late copy of the pre-step Launch
//!   re-applied over a newer state.
use sedsnet::config::{DataEndpoint, DataType};
use sedsnet::packet::Packet;
use sedsnet::router::{NetworkVariablePermissions, Router, RouterConfig, RouterSideId};
use sedsnet::timesync::{PartialNetworkTime, TimeSyncConfig, TimeSyncRole};
use sedsnet::{MessageClass, MessageDataType, MessageElement, ReliableMode};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const UTC: u64 = 1_793_000_000_000;
const HOUR: u64 = 3_600_000;
const FIELD_OFFSET: u64 = 3 * HOUR + 49 * 60_000;
type Wire = Arc<Mutex<Vec<Vec<u8>>>>;

struct Link {
    a: usize,
    b: usize,
    side_a: RouterSideId,
    side_b: RouterSideId,
    a_out: Wire,
    b_out: Wire,
    delay_ms: u64,
    /// Frames lost per 1000.
    loss_permille: u64,
}

struct Net {
    now: Arc<AtomicU64>,
    nodes: Vec<Router>,
    links: Vec<Link>,
    flight: Vec<(u64, usize, bool, Vec<u8>)>,
    rng: u64,
}

impl Net {
    /// GS --Wi-Fi-- GATEWAY --CAN-- ACTUATOR; GS --radio (25% loss)-- RF --CAN-- FC.
    fn field() -> Self {
        let now = Arc::new(AtomicU64::new(60_000));
        let source = TimeSyncConfig { role: TimeSyncRole::Source, priority: 50, ..Default::default() };
        let nodes = [("GS", source), ("GATEWAY", Default::default()), ("ACTUATOR", Default::default()), ("RF", Default::default()), ("FC", Default::default())]
            .into_iter()
            .map(|(name, cfg)| {
                let read = now.clone();
                Router::new_with_clock(
                    RouterConfig::default().with_sender(name).with_timesync(cfg),
                    Box::new(move || read.load(Ordering::SeqCst)),
                )
            })
            .collect();
        let mut net = Self { now, nodes, links: Vec::new(), flight: Vec::new(), rng: 0x5eed };
        net.link(0, 1, 3, 0);
        net.link(1, 2, 1, 0);
        net.link(0, 3, 25, 250);
        net.link(3, 4, 1, 0);
        net
    }

    fn link(&mut self, a: usize, b: usize, delay_ms: u64, loss_permille: u64) {
        let side = |net: &Self, node: usize, out: &Wire| {
            let tx = out.clone();
            let side = net.nodes[node].add_side_packed(format!("to{}", if node == a { b } else { a }), move |bytes: &[u8]| {
                tx.lock().unwrap().push(bytes.to_vec());
                Ok(())
            });
            net.nodes[node].set_side_timesync_min_delay(side, (delay_ms.saturating_sub(1) * 1_000_000) as u32);
            side
        };
        let (a_out, b_out): (Wire, Wire) = (Arc::default(), Arc::default());
        let side_a = side(self, a, &a_out);
        let side_b = side(self, b, &b_out);
        self.links.push(Link { a, b, side_a, side_b, a_out, b_out, delay_ms, loss_permille });
    }

    fn mono(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }

    fn tick(&mut self) {
        for node in &self.nodes {
            let _ = node.periodic(0);
        }
        for _ in 0..3 {
            let now = self.mono();
            for i in 0..self.links.len() {
                for toward_b in [true, false] {
                    let l = &self.links[i];
                    let out = if toward_b { &l.a_out } else { &l.b_out };
                    for bytes in std::mem::take(&mut *out.lock().unwrap()) {
                        self.rng ^= self.rng << 13;
                        self.rng ^= self.rng >> 7;
                        self.rng ^= self.rng << 17;
                        if self.rng % 1000 < l.loss_permille {
                            continue;
                        }
                        self.flight.push((now + l.delay_ms, i, toward_b, bytes));
                    }
                }
            }
            let mut due = Vec::new();
            self.flight.retain(|f| {
                if f.0 <= now {
                    due.push(f.clone());
                    false
                } else {
                    true
                }
            });
            for (_, i, toward_b, bytes) in due {
                let l = &self.links[i];
                let (to, side) = if toward_b { (l.b, l.side_b) } else { (l.a, l.side_a) };
                let _ = self.nodes[to].rx_packed_from_side(&bytes, side);
            }
            for node in &self.nodes {
                let _ = node.drain_queues_with_timeout(0);
            }
        }
        self.now.fetch_add(1, Ordering::SeqCst);
    }

    fn run(&mut self, ms: u64) {
        for _ in 0..ms {
            self.tick();
        }
    }

    fn worst_offset_ms(&self) -> u64 {
        let gs = self.nodes[0].network_time_ms().unwrap();
        self.nodes[1..]
            .iter()
            .map(|n| n.network_time_ms().map_or(u64::MAX, |t| t.abs_diff(gs)))
            .max()
            .unwrap()
    }

    /// Runs until every board is within `ms` of the station; elapsed ms.
    fn converge(&mut self, ms: u64, limit_ms: u64) -> u64 {
        let start = self.mono();
        while self.mono() - start <= limit_ms {
            if self.worst_offset_ms() <= ms {
                return self.mono() - start;
            }
            self.tick();
        }
        panic!("boards still {} ms from the station after {limit_ms} ms", self.worst_offset_ms());
    }

    /// A correction reaches every board: within the radio's one-way delay at
    /// once (a coarse step), within 2 ms once exchanges complete.
    fn follows_station(&mut self, label: &str) {
        let coarse = self.converge(50, 2_000);
        let fine = self.converge(2, 15_000);
        println!("{label}: every board within 50 ms after {coarse} ms, within 2 ms after {} ms", coarse + fine);
    }

    fn station_sets(&self, unix_ms: u64) {
        self.nodes[0].try_set_local_network_time(PartialNetworkTime::from_unix_ms(unix_ms)).unwrap();
    }

    /// The station application's explicit step (GroundStation26 steps
    /// corrections above 1 s itself while the flight state allows it).
    fn station_steps(&self, unix_ms: u64) {
        assert!(self.nodes[0].step_local_network_time_ns((unix_ms * 1_000_000) as i64));
    }

    fn station_time(&self) -> u64 {
        self.nodes[0].network_time_ms().unwrap()
    }
}

fn stale_station_net() -> Net {
    let mut net = Net::field();
    net.station_sets(UTC + net.mono() - FIELD_OFFSET);
    net.converge(5, 30_000);
    net.run(20_000);
    net
}

/// An operator time set (the SDK decides: step) and an explicit step back.
#[test]
fn station_corrections_of_hours_reach_every_board_in_seconds() {
    let mut net = stale_station_net();
    net.station_sets(UTC + net.mono());
    net.follows_station("+3 h 49 min");
    net.run(20_000);
    assert!(net.worst_offset_ms() <= 5);
    // The station application steps itself (explicit step).
    net.station_steps(net.station_time() - 4 * HOUR);
    net.follows_station("-4 h");
    net.run(20_000);
    assert!(net.worst_offset_ms() <= 5);
}

fn flight_state() -> (DataType, DataEndpoint) {
    let ep = sedsnet::config::register_endpoint("TS_STEP_RADIO", false).unwrap();
    let ty = sedsnet::config::register_data_type(
        "TS_STEP_FLIGHT_STATE",
        MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        0,
    )
    .unwrap();
    (ty, ep)
}

fn cached(router: &Router, ty: DataType) -> Option<u8> {
    router.cached_managed_variable(ty).map(|p| p.payload()[0])
}

#[test]
fn flight_state_written_after_a_step_back_supersedes_and_pre_step_copies_never_reapply() {
    const IDLE: u8 = 1;
    const LAUNCH: u8 = 3;
    let (ty, ep) = flight_state();
    let mut net = stale_station_net();
    net.nodes[0].enable_network_variable(ty, NetworkVariablePermissions::READ_WRITE).unwrap();
    for node in &net.nodes[1..] {
        node.enable_network_variable(ty, NetworkVariablePermissions::READ_ONLY).unwrap();
    }
    net.run(5_000);
    let write = |net: &Net, value: u8| {
        let pkt = Packet::new(ty, &[ep], "GS", net.station_time(), Arc::<[u8]>::from([value])).unwrap();
        net.nodes[0].set_network_variable(pkt).unwrap();
    };
    write(&net, LAUNCH);
    net.run(1_000);
    assert_eq!(cached(&net.nodes[4], ty), Some(LAUNCH));
    // What the station sent (as a board received it), for the late copy below.
    let launch = net.nodes[4].cached_managed_variable(ty).unwrap();

    net.station_steps(net.station_time() - 4 * HOUR);
    net.converge(50, 10_000);
    write(&net, IDLE);
    net.run(1_000);
    assert_eq!(cached(&net.nodes[0], ty), Some(IDLE), "the station refused its own write");
    for (i, node) in net.nodes.iter().enumerate().skip(1) {
        assert_eq!(cached(node, ty), Some(IDLE), "board {i} refused the post-step write");
    }

    // A late copy of the pre-step Launch (new nonce: receipt dedupe is not
    // what must stop it) reaches the flight computer.
    let nonce = launch.nonce() ^ 0x5a5a;
    let late = launch.with_nonce(nonce);
    let bytes = sedsnet::wire_format::pack_packet(&late);
    let side = net.links[3].side_b;
    net.nodes[4].rx_packed_from_side(&bytes, side).unwrap();
    net.nodes[4].drain_queues_with_timeout(0).unwrap();
    assert_eq!(cached(&net.nodes[4], ty), Some(IDLE), "a pre-step Launch re-applied");
}

