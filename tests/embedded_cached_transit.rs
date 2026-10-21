#![cfg(all(not(feature = "std"), feature = "discovery"))]
use sedsnet::config::{
    DataEndpoint, DataType, register_data_type_with_description, register_endpoint_with_description,
};
use sedsnet::discovery::{TopologyBoardNode, build_discovery_announce, build_discovery_topology};
use sedsnet::packet::Packet;
use sedsnet::relay::{Relay, RelaySideOptions};
use sedsnet::router::{Router, RouterConfig, RouterSideOptions};
use sedsnet::{MessageClass, MessageDataType, MessageElement, ReliableMode, TelemetryError};
use std::sync::{
    Arc,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};
// This harness is single threaded. The real board supplies recursive RTOS locks.
#[unsafe(no_mangle)]
pub extern "C" fn telemetry_lock() {}
#[unsafe(no_mangle)]
pub extern "C" fn telemetry_unlock() {}
extern "C" fn only_cached(additional: usize, largest: usize, work: u32) -> bool {
    work == sedsnet::memory_admission::WORK_CACHED_TRANSIT && additional <= 1280 && largest <= 256
}
enum Bridge {
    Router(Box<Router>, usize, usize),
    Relay(Box<Relay>, usize, usize),
}
impl Bridge {
    fn receive(&self, bytes: &[u8]) -> sedsnet::TelemetryResult<()> {
        match self {
            Self::Router(r, i, _) => r.rx_packed_queue_from_side(bytes, *i),
            Self::Relay(r, i, _) => r.rx_packed_from_side(*i, bytes),
        }
    }
    fn learn_output(&self, p: Packet) {
        match self {
            Self::Router(r, _, o) => r.rx_from_side(&p, *o).unwrap(),
            Self::Relay(r, _, o) => r.rx_from_side(*o, p).unwrap(),
        }
    }
    fn learn_input(&self, p: Packet) {
        match self {
            Self::Router(r, i, _) => r.rx_from_side(&p, *i).unwrap(),
            Self::Relay(r, i, _) => r.rx_from_side(*i, p).unwrap(),
        }
    }
    fn drain(&self) -> sedsnet::TelemetryResult<()> {
        match self {
            Self::Router(r, _, _) => r.drain_queues_with_timeout(0),
            Self::Relay(r, _, _) => r.drain_queues_with_timeout(0),
        }
    }
}
fn packet(ty: DataType, ep: DataEndpoint, sender: &str, timestamp: u64) -> Packet {
    Packet::new(
        ty,
        &[ep],
        sender,
        timestamp,
        Arc::<[u8]>::from((timestamp as f32).to_le_bytes()),
    )
    .unwrap()
}
fn exercise(use_relay: bool) {
    sedsnet::memory_admission::set_probe(None);
    #[cfg(feature = "compact-packet-store")]
    let store = {
        let store = sedsnet::packet_store::PacketStore::new(2048, 16, 512).unwrap();
        sedsnet::packet_store::set_default_store(Some(store.clone()));
        store
    };
    let suffix = if use_relay { "RELAY" } else { "ROUTER" };
    let ep =
        register_endpoint_with_description(&format!("CACHE_SINK_{suffix}"), "", false).unwrap();
    let types: [DataType; 3] = std::array::from_fn(|i| {
        register_data_type_with_description(
            &format!("CACHE_{suffix}_{i}"),
            "",
            MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
            &[ep],
            ReliableMode::None,
            0,
        )
        .unwrap()
    });
    let sent = Arc::new(AtomicUsize::new(0));
    let output = sent.clone();
    let clock = Arc::new(AtomicU64::new(0));
    let tick = clock.clone();
    let bridge = if use_relay {
        let r = Relay::new(Box::new(move || tick.load(Ordering::Relaxed)));
        let mut opts = RelaySideOptions::default().with_small_packet_transport(64);
        opts.max_side_transport_templates = 1;
        let input = r.add_side_packed_with_options("can", |_| Ok(()), opts.clone());
        let out = r.add_side_packed_with_options(
            "uart",
            move |_| {
                output.fetch_add(1, Ordering::Relaxed);
                Ok(())
            },
            opts,
        );
        Bridge::Relay(Box::new(r), input, out)
    } else {
        let r = Router::new_with_clock(
            RouterConfig::default(),
            Box::new(move || tick.load(Ordering::Relaxed)),
        );
        r.set_sender("GATEWAY");
        let mut opts = RouterSideOptions::default().with_small_packet_transport(64);
        opts.max_side_transport_templates = 1;
        let input = r.add_side_packed_with_options("can", |_| Ok(()), opts.clone());
        let out = r.add_side_packed_with_options(
            "uart",
            move |_| {
                output.fetch_add(1, Ordering::Relaxed);
                Ok(())
            },
            opts,
        );
        Bridge::Router(Box::new(r), input, out)
    };
    bridge.learn_output(
        build_discovery_topology(
            "GS",
            0,
            &[TopologyBoardNode {
                sender_id: "GS".into(),
                reachable_endpoints: vec![ep],
                reachable_timesync_sources: vec![],
                connections: vec![],
            }],
        )
        .unwrap(),
    );
    bridge.drain().unwrap();
    bridge
        .receive(&sedsnet::wire_format::pack_packet(&packet(
            types[0], ep, "DAQ", 0,
        )))
        .unwrap();
    bridge.drain().unwrap();
    bridge.learn_input(build_discovery_announce("DAQ", 0, &[]).unwrap());
    bridge.drain().unwrap();
    bridge
        .receive(&sedsnet::wire_format::pack_packet(&packet(
            types[1], ep, "DAQ", 0,
        )))
        .unwrap();
    bridge.drain().unwrap();
    let before = sent.load(Ordering::Relaxed);
    sedsnet::memory_admission::set_probe_v2(Some(only_cached));
    for timestamp in 1..=32 {
        bridge
            .receive(&sedsnet::wire_format::pack_packet(&packet(
                types[0], ep, "DAQ", timestamp,
            )))
            .unwrap();
        #[cfg(feature = "compact-packet-store")]
        assert!(
            store.stats().live_handles > 0,
            "compact test must exercise an active packet arena"
        );
        bridge.drain().unwrap();
    }
    assert_eq!(
        sent.load(Ordering::Relaxed) - before,
        32,
        "{suffix}: evicted optional dictionary must not stop warm data"
    );
    let cold = sedsnet::wire_format::pack_packet(&packet(types[2], ep, "DAQ", 99));
    assert!(matches!(
        bridge.receive(&cold),
        Err(TelemetryError::Io("memory pressure"))
    ));
    let unknown = sedsnet::wire_format::pack_packet(&packet(types[0], ep, "UNKNOWN", 99));
    assert!(matches!(
        bridge.receive(&unknown),
        Err(TelemetryError::Io("memory pressure"))
    ));
    let mut invalid = sedsnet::wire_format::pack_packet(&packet(types[0], ep, "DAQ", 99)).to_vec();
    let last = invalid.len() - 1;
    invalid[last] ^= 1;
    assert!(bridge.receive(&invalid).is_err());
    bridge
        .receive(&sedsnet::wire_format::pack_packet(&packet(
            types[0], ep, "DAQ", 100,
        )))
        .unwrap();
    clock.store(200000, Ordering::Relaxed);
    assert!(matches!(
        bridge.drain(),
        Err(TelemetryError::Io("memory pressure"))
    ));
    sedsnet::memory_admission::set_probe(None);
    drop(bridge);
    #[cfg(feature = "compact-packet-store")]
    {
        assert_eq!(store.stats().live_handles, 0);
        sedsnet::packet_store::set_default_store(None);
    }
}
#[test]
fn no_std_router_and_relay_survive_dictionary_eviction_under_pressure() {
    exercise(false);
    exercise(true);
}
