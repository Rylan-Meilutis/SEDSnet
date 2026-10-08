#![cfg(all(feature = "std", feature = "discovery"))]
use sedsnet::config::{register_data_type_with_description, register_endpoint_with_description};
use sedsnet::packet::Packet;
use sedsnet::router::{EndpointHandler, Router, RouterConfig};
use sedsnet::{MessageClass, MessageDataType, MessageElement, ReliableMode, TelemetryError};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
struct CountingAllocator;
std::thread_local! {
    static ALLOCATION_COUNT: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;
unsafe impl std::alloc::GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        let _ = ALLOCATION_COUNT.try_with(|count| {
            if let Some(n) = count.get() {
                count.set(Some(n + 1));
            }
        });
        unsafe { std::alloc::System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        unsafe { std::alloc::System.dealloc(ptr, layout) }
    }
}

static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
static ALLOW: AtomicBool = AtomicBool::new(true);
extern "C" fn probe(_additional: usize, _largest: usize) -> bool {
    ALLOW.load(Ordering::Relaxed)
}
struct Reset;
impl Drop for Reset {
    fn drop(&mut self) {
        sedsnet::memory_admission::set_probe(None);
        ALLOW.store(true, Ordering::Relaxed);
        #[cfg(feature = "compact-packet-store")]
        sedsnet::packet_store::set_default_store(None);
    }
}

#[test]
fn pressure_rejects_new_ingress_while_retained_work_dispatches_and_recovers() {
    let _lock = TEST_LOCK.lock().unwrap();
    let ep = register_endpoint_with_description("PRESSURE_LOCAL", "", false).unwrap();
    let ty = register_data_type_with_description(
        "PRESSURE_VALUE",
        "",
        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        0,
    )
    .unwrap();
    let delivered = Arc::new(AtomicUsize::new(0));
    let output = delivered.clone();
    let handler = EndpointHandler::new_packet_handler(ep, move |_| {
        output.fetch_add(1, Ordering::Relaxed);
        Ok(())
    });
    let router = Router::new_with_clock(RouterConfig::new(vec![handler]), Box::new(|| 0));
    for i in 1..=3 {
        router
            .tx_queue(Packet::from_f32_slice(ty, &[i as f32], &[ep], i).unwrap())
            .unwrap();
    }
    router.add_side_packed("pressure-test", |_| Ok(()));
    let incoming = Packet::from_f32_slice(ty, &[4.0], &[ep], 4).unwrap();
    let wire = sedsnet::wire_format::pack_packet(&incoming);
    let before = sedsnet::memory_admission::rejected_operations();
    let _reset = Reset;
    ALLOW.store(false, Ordering::Relaxed);
    sedsnet::memory_admission::set_probe(Some(probe));
    assert!(matches!(
        router.rx_packed(&wire),
        Err(TelemetryError::Io("memory pressure"))
    ));
    assert_eq!(sedsnet::memory_admission::rejected_operations(), before + 1);
    assert!(matches!(
        router.announce_discovery(),
        Err(TelemetryError::Io("memory pressure"))
    ));
    router.dispatch_tx_queue_with_timeout(0).unwrap();
    assert_eq!(
        delivered.load(Ordering::Relaxed),
        3,
        "pressure prevented retained queue dispatch"
    );
    router
        .tx_queue(Packet::from_f32_slice(ty, &[5.0], &[ep], 5).unwrap())
        .unwrap();
    // Normal maintenance must also defer refused snapshots and release work.
    router.process_all_queues().unwrap();
    assert_eq!(delivered.load(Ordering::Relaxed), 4);
    ALLOW.store(true, Ordering::Relaxed);
    router.rx_packed(&wire).unwrap();
    assert_eq!(
        delivered.load(Ordering::Relaxed),
        5,
        "rejected packet was incorrectly deduplicated"
    );
}

#[test]
fn relay_drains_backpressured_frames_even_when_discovery_admission_is_refused() {
    use sedsnet::relay::Relay;
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    ALLOW.store(true, Ordering::Relaxed);
    let ep = register_endpoint_with_description("RELAY_PRESSURE_SINK", "", false).unwrap();
    let ty = register_data_type_with_description(
        "RELAY_PRESSURE_FRAME",
        "",
        MessageElement::Dynamic(MessageDataType::Binary, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        10,
    )
    .unwrap();
    let blocked = Arc::new(AtomicBool::new(true));
    let delivered = Arc::new(AtomicUsize::new(0));
    let relay = Relay::new(Box::new(|| 0));
    let ingress = relay.add_side_packed("upstream", |_| Ok(()));
    let blocked_out = blocked.clone();
    let output = delivered.clone();
    relay.add_side_packed("downstream", move |bytes| {
        if blocked_out.load(Ordering::Relaxed) {
            return Err(TelemetryError::Io("link full"));
        }
        if sedsnet::wire_format::peek_envelope(bytes).is_ok_and(|e| e.ty == ty) {
            output.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    });
    let first = Packet::new(ty, &[ep], "PRESSURE", 1, Arc::from([3; 512])).unwrap();
    let first = sedsnet::wire_format::pack_packet(&first);
    relay.rx_packed_from_side(ingress, &first).unwrap();
    let service = relay.process_all_queues_with_timeout(0);
    assert!(service.is_ok() || matches!(service, Err(TelemetryError::Io(_))));
    assert_eq!(delivered.load(Ordering::Relaxed), 0);
    ALLOW.store(false, Ordering::Relaxed);
    sedsnet::memory_admission::set_probe(Some(probe));
    let retry = Packet::new(ty, &[ep], "PRESSURE", 2, Arc::from([4; 512])).unwrap();
    let retry = sedsnet::wire_format::pack_packet(&retry);
    assert!(matches!(
        relay.rx_packed_from_side(ingress, &retry),
        Err(TelemetryError::Io("memory pressure"))
    ));
    assert!(matches!(
        relay.announce_discovery(),
        Err(TelemetryError::Io("memory pressure"))
    ));
    blocked.store(false, Ordering::Relaxed);
    relay.process_all_queues_with_timeout(0).unwrap();
    assert_eq!(
        delivered.load(Ordering::Relaxed),
        1,
        "relay stranded retained traffic while memory-pressure maintenance failed"
    );
    ALLOW.store(true, Ordering::Relaxed);
    relay.rx_packed_from_side(ingress, &retry).unwrap();
    relay.process_all_queues_with_timeout(0).unwrap();
    assert_eq!(
        delivered.load(Ordering::Relaxed),
        2,
        "refused ingress was incorrectly deduplicated or did not recover"
    );
}

#[cfg(feature = "compact-packet-store")]
#[test]
fn full_arena_keeps_owned_heap_work_and_dispatch_recovers() {
    use sedsnet::packet_store::{PacketStore, set_default_store};
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    let ep = register_endpoint_with_description("ARENA_PRESSURE_SINK", "", false).unwrap();
    let ty = register_data_type_with_description(
        "ARENA_PRESSURE_FRAME",
        "",
        MessageElement::Dynamic(MessageDataType::Binary, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        10,
    )
    .unwrap();
    let store = PacketStore::new(8192, 32, 512).unwrap();
    set_default_store(Some(store.clone()));
    let output = Arc::new(AtomicUsize::new(0));
    let hits = output.clone();
    let router = Router::new_with_clock(RouterConfig::default(), Box::new(|| 0));
    router.add_side_packed("wire", move |bytes| {
        if sedsnet::wire_format::peek_envelope(bytes).is_ok_and(|e| e.ty == ty) {
            hits.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    });
    for timestamp in 1..=3 {
        let packet = Packet::new(ty, &[ep], "PRESSURE", timestamp, Arc::from([9; 600])).unwrap();
        router
            .tx_packed_queue(sedsnet::wire_format::pack_packet(&packet))
            .unwrap();
    }
    let blocker = store.store(&vec![0; store.stats().largest_gap]).unwrap();
    assert_eq!(store.stats().largest_gap, 0);
    let retry = Packet::new(ty, &[ep], "PRESSURE", 4, Arc::from([8; 600])).unwrap();
    let retry = sedsnet::wire_format::pack_packet(&retry);
    // Explicit arena insertion remains strict. Optional queue parking must
    // retain the already-owned heap bytes instead of rejecting valid work.
    assert!(matches!(
        store.store(&[1]),
        Err(TelemetryError::Io("memory pressure"))
    ));
    router.tx_packed_queue(retry).unwrap();
    router.announce_discovery().unwrap();
    router.process_all_queues_with_timeout(0).unwrap();
    assert_eq!(
        output.load(Ordering::Relaxed),
        4,
        "full arena stopped dispatch of retained or heap-backed frames"
    );
    drop(blocker);
    let next = Packet::new(ty, &[ep], "PRESSURE", 5, Arc::from([6; 600])).unwrap();
    router
        .tx_packed_queue(sedsnet::wire_format::pack_packet(&next))
        .unwrap();
    router.process_all_queues_with_timeout(0).unwrap();
    assert_eq!(output.load(Ordering::Relaxed), 5);
    drop(router);
    assert_eq!(store.stats().live_bytes, 0);
}

#[test]
fn live_return_route_survives_refused_ingress_but_invalid_or_wrong_side_does_not() {
    use sedsnet::discovery::{DISCOVERY_ROUTE_TTL_MS, TopologyBoardNode, build_discovery_topology};
    use sedsnet::relay::Relay;
    use std::sync::atomic::AtomicU64;
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    let ep = register_endpoint_with_description("LIVE_RETURN", "", false).unwrap();
    let ty = register_data_type_with_description(
        "LIVE_RETURN_VALUE",
        "",
        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        0,
    )
    .unwrap();
    let clock = Arc::new(AtomicU64::new(0));
    let tick = clock.clone();
    let router = Router::new_with_clock(
        RouterConfig::default(),
        Box::new(move || tick.load(Ordering::Relaxed)),
    );
    let tick = clock.clone();
    let relay = Relay::new(Box::new(move || tick.load(Ordering::Relaxed)));
    let side = router.add_side_packed("uart", |_| Ok(()));
    let other = router.add_side_packed("other", |_| Ok(()));
    let relay_side = relay.add_side_packed("uart", |_| Ok(()));
    let relay_other = relay.add_side_packed("other", |_| Ok(()));
    let discovery = build_discovery_topology(
        "LIVE_GS",
        0,
        &[TopologyBoardNode {
            sender_id: "LIVE_GS".into(),
            reachable_endpoints: vec![ep],
            reachable_timesync_sources: vec![],
            connections: vec![],
        }],
    )
    .unwrap();
    router.rx_from_side(&discovery, side).unwrap();
    relay.rx_from_side(relay_side, discovery).unwrap();
    relay.process_all_queues().unwrap();
    assert!(!router.export_topology().routes.is_empty());
    assert!(!relay.export_topology().routes.is_empty());
    let packet = Packet::new(ty, &[ep], "LIVE_GS", 1, Arc::from(1f32.to_le_bytes())).unwrap();
    let wire = sedsnet::wire_format::pack_packet(&packet);
    let foreign = Packet::new(ty, &[ep], "UNKNOWN_GS", 1, Arc::from(1f32.to_le_bytes())).unwrap();
    let foreign = sedsnet::wire_format::pack_packet(&foreign);
    let mut corrupt = wire.to_vec();
    let end = corrupt.len() - 1;
    corrupt[end] ^= 1;
    ALLOW.store(false, Ordering::Relaxed);
    sedsnet::memory_admission::set_probe(Some(probe));
    for now in [10_000, 20_000, 30_000, 40_000, 50_000, 60_000] {
        clock.store(now, Ordering::Relaxed);
        ALLOCATION_COUNT.with(|count| count.set(Some(0)));
        let router_result = router.rx_packed_queue_from_side(&wire, side);
        let relay_result = relay.rx_packed_from_side(relay_side, &wire);
        let allocations = ALLOCATION_COUNT.with(|count| count.replace(None).unwrap());
        assert!(router_result.is_err());
        assert!(relay_result.is_err());
        assert_eq!(allocations, 0, "pressure liveness refresh allocated");
        router.poll_discovery().ok();
        relay.poll_discovery().ok();
        assert!(
            !router.export_topology().routes.is_empty(),
            "live router return route expired"
        );
        assert!(
            !relay.export_topology().routes.is_empty(),
            "live relay return route expired"
        );
    }
    // Neither a bad CRC, a different ingress nor an unknown source keeps this peer alive.
    clock.store(60_000 + DISCOVERY_ROUTE_TTL_MS + 1, Ordering::Relaxed);
    for bytes in [&corrupt[..], foreign.as_ref()] {
        router.rx_packed_queue_from_side(bytes, side).ok();
        relay.rx_packed_from_side(relay_side, bytes).ok();
    }
    router.rx_packed_queue_from_side(&wire, other).ok();
    relay.rx_packed_from_side(relay_other, &wire).ok();
    router.poll_discovery().ok();
    relay.poll_discovery().ok();
    assert!(router.export_topology().routes.is_empty());
    assert!(relay.export_topology().routes.is_empty());
}
