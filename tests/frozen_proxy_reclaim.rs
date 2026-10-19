#![cfg(all(feature = "std", feature = "discovery"))]
use sedsnet::{
    MessageClass, MessageDataType, MessageElement, ReliableMode,
    config::{self, DataEndpoint, DataType},
    packet::Packet,
    relay::{Relay, RelayConfig},
    router::{Router, RouterConfig},
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
static LOCK: Mutex<()> = Mutex::new(());
static CHECKS: AtomicUsize = AtomicUsize::new(0);
extern "C" fn pressure_until_two_payloads_are_reclaimed(_: usize, _: usize, _: u32) -> bool {
    CHECKS.fetch_add(1, Ordering::Relaxed) >= 2
}
struct Reset;
impl Drop for Reset {
    fn drop(&mut self) {
        sedsnet::memory_admission::set_probe_v2(None);
        #[cfg(feature = "compact-packet-store")]
        sedsnet::packet_store::set_default_store(None);
    }
}
fn fixture(suffix: &str) -> (DataEndpoint, DataType, DataType, Vec<u8>) {
    let ep =
        config::register_endpoint_id(DataEndpoint(266702084), "FLIGHT_CONTROLLER", false).unwrap();
    config::register_data_type_id(
        DataType(169036741),
        "FLIGHT_BUZZER",
        MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::Ordered,
        16,
    )
    .unwrap();
    let bulk = config::register_data_type(
        &format!("PROXY_BULK_{suffix}"),
        MessageElement::Static(64, MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        0,
    )
    .unwrap();
    let control = config::register_data_type(
        &format!("PROXY_PRESERVE_{suffix}"),
        MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        201,
    )
    .unwrap();
    // Actual GS -> RF frame from bay-1792362672924079710. RF is a proxy,
    // not the buzzer owner. Schema priority is only16, but the frozen owner
    // contract and fixed one-byte shape qualify as bounded protected work.
    let hex =
        "ce01c597cd5001ea94888995341897d78ea20d849a967f0c0742010164422c5af1d8d68584000074c6aeba";
    let wire = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect::<Vec<_>>();
    let decoded = sedsnet::wire_format::unpack_packet(&wire).unwrap();
    assert_eq!(decoded.data_type(), DataType(169036741));
    assert_eq!(
        sedsnet::wire_format::peek_envelope(&wire)
            .unwrap()
            .target_senders
            .as_ref(),
        [9644134183172063844]
    );
    (ep, bulk, control, wire)
}
fn packet(ty: DataType, ep: DataEndpoint, t: u64, n: usize) -> Packet {
    Packet::new(ty, &[ep], "DAQ", t, Arc::<[u8]>::from(vec![1; n])).unwrap()
}
fn router_proxy_reclaim(arena: bool) {
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _reset = Reset;
    configure_store(arena);
    let (ep, bulk, control, wire) = fixture("ROUTER");
    let router = Router::new(RouterConfig::new([]).with_sender("RF"));
    let side = router.add_side_packed("radio", |_| Ok(()));
    router.clear_queues();
    for t in 1..=2 {
        router.tx_queue(packet(bulk, ep, t, 64)).unwrap();
    }
    router.tx_queue(packet(control, ep, 3, 1)).unwrap();
    assert_eq!(router.export_runtime_stats().queues.tx_len, 3);
    CHECKS.store(0, Ordering::Relaxed);
    sedsnet::memory_admission::set_probe_v2(Some(pressure_until_two_payloads_are_reclaimed));
    let result = router.rx_packed_queue_from_side(&wire, side);
    sedsnet::memory_admission::set_probe_v2(None);
    result.expect(
        "a proxy must reclaim bulk for a bounded frozen command even without owning its variable",
    );
    assert!(CHECKS.load(Ordering::Relaxed) >= 3);
    let queues = router.export_runtime_stats().queues;
    assert_eq!(queues.tx_len, 1, "previous protected control survives");
    assert_eq!(queues.rx_len, 1, "new frozen control remains queued");
    router.clear_queues();
    router.tx_queue(packet(bulk, ep, 4, 64)).unwrap();
    let mut corrupt = wire;
    *corrupt.last_mut().unwrap() ^= 1;
    CHECKS.store(0, Ordering::Relaxed);
    sedsnet::memory_admission::set_probe_v2(Some(pressure_until_two_payloads_are_reclaimed));
    assert!(router.rx_packed_queue_from_side(&corrupt, side).is_err());
    sedsnet::memory_admission::set_probe_v2(None);
    assert_eq!(
        router.export_runtime_stats().queues.tx_len,
        1,
        "bad CRC cannot evict payloads"
    );
}
fn relay_proxy_reclaim(arena: bool) {
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _reset = Reset;
    configure_store(arena);
    let (ep, bulk, control, wire) = fixture("RELAY");
    let relay = Relay::new_with_config(RelayConfig::default().with_sender("RF"), Box::new(|| 0));
    let side = relay.add_side_packed("radio", |_| Ok(()));
    relay.clear_queues();
    for t in 1..=2 {
        relay.rx_from_side(side, packet(bulk, ep, t, 64)).unwrap();
    }
    relay.rx_from_side(side, packet(control, ep, 3, 1)).unwrap();
    assert_eq!(relay.export_runtime_stats().queues.rx_len, 3);
    CHECKS.store(0, Ordering::Relaxed);
    sedsnet::memory_admission::set_probe_v2(Some(pressure_until_two_payloads_are_reclaimed));
    let result = relay.rx_packed_from_side(side, &wire);
    sedsnet::memory_admission::set_probe_v2(None);
    result
        .expect("relay-only nodes must give frozen control the same pressure priority as routers");
    assert!(CHECKS.load(Ordering::Relaxed) >= 3);
    assert_eq!(
        relay.export_runtime_stats().queues.rx_len,
        2,
        "only old protected and new frozen controls survive"
    );
    relay.clear_queues();
    relay.rx_from_side(side, packet(bulk, ep, 4, 64)).unwrap();
    let mut corrupt = wire;
    *corrupt.last_mut().unwrap() ^= 1;
    CHECKS.store(0, Ordering::Relaxed);
    sedsnet::memory_admission::set_probe_v2(Some(pressure_until_two_payloads_are_reclaimed));
    assert!(relay.rx_packed_from_side(side, &corrupt).is_err());
    sedsnet::memory_admission::set_probe_v2(None);
    assert_eq!(
        relay.export_runtime_stats().queues.rx_len,
        1,
        "bad CRC cannot evict payloads"
    );
}

fn configure_store(arena: bool) {
    #[cfg(feature = "compact-packet-store")]
    sedsnet::packet_store::set_default_store(
        arena.then(|| sedsnet::packet_store::PacketStore::new(8192, 32, 512).unwrap()),
    );
    #[cfg(not(feature = "compact-packet-store"))]
    assert!(!arena);
}
#[test]
fn router_proxy_admits_captured_frozen_control_by_reclaiming_only_bulk() {
    router_proxy_reclaim(false);
}
#[test]
fn relay_proxy_admits_captured_frozen_control_by_reclaiming_only_bulk() {
    relay_proxy_reclaim(false);
}
#[cfg(feature = "compact-packet-store")]
#[test]
fn router_arena_proxy_reclaims_payloads_for_captured_control() {
    router_proxy_reclaim(true);
}
#[cfg(feature = "compact-packet-store")]
#[test]
fn relay_arena_proxy_reclaims_payloads_for_captured_control() {
    relay_proxy_reclaim(true);
}

static DISPATCH_ADMISSIONS: AtomicUsize = AtomicUsize::new(0);
extern "C" fn refuse_third_control_admission_once(additional: usize, _: usize, _: u32) -> bool {
    additional != 2177 || DISPATCH_ADMISSIONS.fetch_add(1, Ordering::SeqCst) != 2
}
#[test]
fn proxy_pressure_retry_within_replay_window_is_forwarded() {
    use sedsnet::discovery::{TopologyBoardNode, build_discovery_topology};
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _reset = Reset;
    let (ep, _, _, wire) = fixture("DISPATCH_RETRY");
    let clock = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let now = clock.clone();
    let router = Router::new_with_clock(
        RouterConfig::new([]).with_sender("RF"),
        Box::new(move || now.load(Ordering::SeqCst)),
    );
    let radio = router.add_side_packed("radio", |_| Ok(()));
    let forwards = Arc::new(AtomicUsize::new(0));
    let received = forwards.clone();
    let can = router.add_side_packed("can", move |bytes| {
        if sedsnet::wire_format::peek_envelope(bytes)?.ty == DataType(169036741) {
            received.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    });
    router
        .rx_from_side(
            &build_discovery_topology(
                "FC",
                0,
                &[TopologyBoardNode {
                    sender_id: "FC".into(),
                    reachable_endpoints: vec![ep],
                    reachable_timesync_sources: vec![],
                    connections: vec!["RF".into()],
                }],
            )
            .unwrap(),
            can,
        )
        .unwrap();
    router.clear_queues();
    DISPATCH_ADMISSIONS.store(0, Ordering::SeqCst);
    sedsnet::memory_admission::set_probe_v2(Some(refuse_third_control_admission_once));
    let first = router.rx_packed_from_side(&wire, radio);
    sedsnet::memory_admission::set_probe_v2(None);
    assert!(
        matches!(first, Err(sedsnet::TelemetryError::Io("memory pressure"))),
        "{first:?}; admissions={}",
        DISPATCH_ADMISSIONS.load(Ordering::SeqCst)
    );
    assert_eq!(forwards.load(Ordering::SeqCst), 0);
    // Actual failed runs retry at about230ms; pressure refusal must still
    // permit forwarding within the normal replay window once headroom returns.
    clock.store(230, Ordering::SeqCst);
    router.rx_packed_from_side(&wire, radio).unwrap();
    assert_eq!(
        forwards.load(Ordering::SeqCst),
        1,
        "an unprocessed proxy command was treated as a completed duplicate"
    );
}
