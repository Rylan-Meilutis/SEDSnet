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
    static REFUSE_CONTIGUOUS: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static CONTIGUOUS_REFUSALS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
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
        // Simulate a fragmented pool: small objects still fit, but a larger
        // contiguous queue ring does not. Return NULL instead of panicking.
        let refused = REFUSE_CONTIGUOUS
            .try_with(|limit| limit.get().is_some_and(|bytes| layout.size() >= bytes))
            .unwrap_or(false);
        if refused {
            let _ = CONTIGUOUS_REFUSALS.try_with(|n| n.set(n.get() + 1));
            return core::ptr::null_mut();
        }
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

#[cfg(not(feature = "compact-packet-store"))]
#[test]
fn fragmented_queue_growth_returns_null_without_crashing_or_stopping_dispatch() {
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    let ep = register_endpoint_with_description("FRAGMENTED_QUEUE_LOCAL", "", false).unwrap();
    let ty = register_data_type_with_description(
        "FRAGMENTED_QUEUE_VALUE",
        "",
        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        0,
    )
    .unwrap();
    let latest = Arc::new(AtomicUsize::new(0));
    let output = latest.clone();
    let handler = EndpointHandler::new_packet_handler(ep, move |packet| {
        output.store(packet.timestamp() as usize, Ordering::Relaxed);
        Ok(())
    });
    let memory = sedsnet::config::RuntimeMemoryConfig::new(65536, 16, 1024, 1.25).unwrap();
    let router = Router::new_with_clock(
        RouterConfig::new(vec![handler])
            .with_memory_config(memory)
            .unwrap(),
        Box::new(|| 0),
    );
    struct AllocationReset;
    impl Drop for AllocationReset {
        fn drop(&mut self) {
            REFUSE_CONTIGUOUS.with(|v| v.set(None));
        }
    }
    let _allocation_reset = AllocationReset;
    CONTIGUOUS_REFUSALS.with(|v| v.set(0));
    REFUSE_CONTIGUOUS.with(|v| v.set(Some(2048)));
    for timestamp in 1..=64 {
        router
            .tx_queue(Packet::from_f32_slice(ty, &[1.0], &[ep], timestamp).unwrap())
            .unwrap();
    }
    REFUSE_CONTIGUOUS.with(|v| v.set(None));
    assert!(
        CONTIGUOUS_REFUSALS.with(|v| v.get()) > 0,
        "test did not exercise the fragmented queue-ring allocation"
    );
    router.dispatch_tx_queue_with_timeout(0).unwrap();
    assert_eq!(latest.load(Ordering::Relaxed), 64);
    for timestamp in 65..=128 {
        router
            .tx_queue(Packet::from_f32_slice(ty, &[1.0], &[ep], timestamp).unwrap())
            .unwrap();
    }
    router.dispatch_tx_queue_with_timeout(0).unwrap();
    assert_eq!(latest.load(Ordering::Relaxed), 128);
}

#[test]
fn idle_dispatch_with_learned_routes_does_not_allocate_destination_maps() {
    use sedsnet::discovery::{TopologyBoardNode, build_discovery_topology};
    let _lock = TEST_LOCK.lock().unwrap();
    let router = Router::new_with_clock(RouterConfig::default(), Box::new(|| 0));
    let side = router.add_side_packed("learned-network", |_| Ok(()));
    let topology = build_discovery_topology(
        "PEER",
        0,
        &[TopologyBoardNode {
            sender_id: "DESTINATION".into(),
            reachable_endpoints: vec![sedsnet::config::DataEndpoint::Discovery],
            reachable_timesync_sources: vec![],
            connections: vec!["PEER".into()],
        }],
    )
    .unwrap();
    router.rx_from_side(&topology, side).unwrap();
    router.drain_queues_with_timeout(0).unwrap();
    ALLOCATION_COUNT.with(|count| count.set(Some(0)));
    for _ in 0..100 {
        router.drain_queues_with_timeout(1).unwrap();
    }
    let allocations = ALLOCATION_COUNT.with(|count| count.replace(None).unwrap());
    assert_eq!(
        allocations, 0,
        "idle queue service allocated topology scratch"
    );
}

#[test]
fn small_wire_packets_do_not_allocate_temporary_contract_buffers() {
    let _lock = TEST_LOCK.lock().unwrap();
    let ep = register_endpoint_with_description("SMALL_WIRE_ALLOCATION", "", false).unwrap();
    let ty = register_data_type_with_description(
        "SMALL_WIRE_VALUE",
        "",
        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        0,
    )
    .unwrap();
    let plain = Packet::from_f32_slice(ty, &[1.0], &[ep], 1).unwrap();
    let reliable_ty = register_data_type_with_description(
        "SMALL_WIRE_RELIABLE_VALUE",
        "",
        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
        &[ep],
        ReliableMode::Ordered,
        0,
    )
    .unwrap();
    let reliable = Packet::from_f32_slice(reliable_ty, &[2.0], &[ep], 127).unwrap();
    // Captured GroundStation receipt with a frozen shape and two targets.
    let ack = sedsnet::wire_format::unpack_packet(&[
        0x0c, 0x01, 0x01, 0x08, 0xef, 0x01, 0x95, 0x95, 0x02, 0xcd, 0x8d, 0xbb, 0x3b, 0x14, 0x03,
        0x44, 0x02, 0x02, 0xee, 0x92, 0x01, 0x79, 0x4a, 0x2b, 0xa4, 0xed, 0x5f, 0x43, 0x92, 0x9e,
        0x12, 0xbb, 0xfc, 0xa7, 0x16, 0x70, 0x23, 0x4b, 0xe4, 0x25, 0xad, 0x09, 0x34, 0xed, 0x3e,
        0x2b,
    ])
    .unwrap();
    for packet in [ack, plain, reliable] {
        // Populate sender-address caches before counting the hot path.
        let warm = sedsnet::wire_format::pack_packet(&packet);
        ALLOCATION_COUNT.with(|count| count.set(Some(0)));
        let packed = sedsnet::wire_format::pack_packet(&packet);
        let allocations = ALLOCATION_COUNT.with(|count| count.replace(None).unwrap());
        eprintln!(
            "small wire encoder: {} bytes, {allocations} allocations",
            packed.len()
        );
        assert!(
            allocations <= 2,
            "small packet encoding allocated {allocations} buffers; only header scratch and final shared frame are needed"
        );
        assert_eq!(packed, warm, "removing scratch buffers changed wire bytes");
        ALLOCATION_COUNT.with(|count| count.set(Some(0)));
        for _ in 0..64 {
            assert_eq!(
                sedsnet::wire_format::packet_wire_size(&packet),
                packed.len()
            );
        }
        let size_allocations = ALLOCATION_COUNT.with(|count| count.replace(None).unwrap());
        assert_eq!(
            size_allocations, 0,
            "wire sizing must not allocate a frame/header"
        );
        let decoded = sedsnet::wire_format::unpack_packet(&packed).unwrap();
        assert_eq!(decoded.packet_id(), packet.packet_id());
        assert_eq!(decoded.payload(), packet.payload());
    }
}

#[test]
fn frozen_receipt_wire_identity_does_not_allocate_metadata() {
    let _lock = TEST_LOCK.lock().unwrap();
    let hex = "0c010108ef01959502cd8dbb3b1403440202ee9201794a2ba4ed5f43929e12bbfca71670234be425ad0934ed3e2b";
    let bytes: Vec<u8> = hex
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    let expected = sedsnet::wire_format::unpack_packet(&bytes)
        .unwrap()
        .packet_id();
    assert_eq!(
        sedsnet::wire_format::packet_id_from_wire(&bytes).unwrap(),
        expected
    );
    let receipt = sedsnet::wire_format::unpack_packet(&bytes).unwrap();
    sedsnet::wire_format::pack_packet(&receipt); // Cache its canonical sender.
    ALLOCATION_COUNT.with(|count| count.set(Some(0)));
    let decoded = sedsnet::wire_format::unpack_packet(&bytes).unwrap();
    let decode_allocations = ALLOCATION_COUNT.with(|count| count.replace(None).unwrap());
    assert_eq!(decoded.packet_id(), expected);
    assert_eq!(
        decode_allocations, 1,
        "receipt targets used temporary owned storage"
    );
    ALLOCATION_COUNT.with(|count| count.set(Some(0)));
    for _ in 0..64 {
        assert_eq!(
            sedsnet::wire_format::packet_id_from_wire(&bytes).unwrap(),
            expected
        );
    }
    let allocations = ALLOCATION_COUNT.with(|count| count.replace(None).unwrap());
    assert_eq!(
        allocations, 0,
        "receipt identity built owned endpoint/contract metadata"
    );
}

#[test]
fn wire_decode_reuses_owned_metadata_without_duplicate_allocations() {
    let _lock = TEST_LOCK.lock().unwrap();
    let ep = register_endpoint_with_description("DECODE_ALLOC_SINK", "", false).unwrap();
    let ty = register_data_type_with_description(
        "DECODE_ALLOC_VALUE",
        "",
        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        0,
    )
    .unwrap();
    let packet = Packet::new(
        ty,
        &[ep],
        "DECODE_ALLOC_SOURCE",
        123,
        Arc::from(1.25f32.to_le_bytes()),
    )
    .unwrap();
    let wire = sedsnet::wire_format::pack_packet(&packet);
    // Warm schema/address lookup state before counting retained metadata.
    sedsnet::wire_format::unpack_packet(&wire).unwrap();
    ALLOCATION_COUNT.with(|count| count.set(Some(0)));
    let decoded = sedsnet::wire_format::unpack_packet(&wire).unwrap();
    let allocations = ALLOCATION_COUNT.with(|count| count.replace(None).unwrap());
    assert_eq!(decoded.payload(), packet.payload());
    assert_eq!(decoded.packet_id(), packet.packet_id());
    assert_eq!(
        allocations, 0,
        "temporary decoded metadata or payload allocations"
    );
}

#[test]
fn explicit_endpoint_bitmap_decodes_into_final_storage() {
    let _lock = TEST_LOCK.lock().unwrap();
    let a = register_endpoint_with_description("BITMAP_ALLOC_A", "", false).unwrap();
    let b = register_endpoint_with_description("BITMAP_ALLOC_B", "", false).unwrap();
    let ty = register_data_type_with_description(
        "BITMAP_ALLOC_VALUE",
        "",
        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
        &[a, b],
        ReliableMode::None,
        0,
    )
    .unwrap();
    // An explicit subset forces a bitmap instead of the default schema list.
    let packet = Packet::new(
        ty,
        &[b],
        "BITMAP_ALLOC_SOURCE",
        456,
        Arc::from(2.5f32.to_le_bytes()),
    )
    .unwrap();
    let wire = sedsnet::wire_format::pack_packet(&packet);
    sedsnet::wire_format::unpack_packet(&wire).unwrap();
    ALLOCATION_COUNT.with(|count| count.set(Some(0)));
    let decoded = sedsnet::wire_format::unpack_packet(&wire).unwrap();
    let allocations = ALLOCATION_COUNT.with(|count| count.replace(None).unwrap());
    assert_eq!(decoded.endpoints(), &[b]);
    assert_eq!(decoded.payload(), packet.payload());
    assert_eq!(decoded.packet_id(), packet.packet_id());
    assert_eq!(
        allocations, 1,
        "endpoint bitmap built temporary owned storage"
    );
}

#[test]
fn malformed_target_count_is_rejected_before_allocation() {
    let _lock = TEST_LOCK.lock().unwrap();
    let ep = register_endpoint_with_description("TARGET_BOUND_SINK", "", false).unwrap();
    let ty = register_data_type_with_description(
        "TARGET_BOUND_VALUE",
        "",
        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        0,
    )
    .unwrap();
    let packet = Packet::new(
        ty,
        &[ep],
        "TARGET_BOUND_SOURCE",
        1,
        Arc::from(1.0f32.to_le_bytes()),
    )
    .unwrap();
    let mut wire = sedsnet::wire_format::pack_packet(&packet).to_vec();
    // Add a CRC-valid contract claiming 127 target hashes but carrying none.
    wire[0] |= 0x04;
    let prefix = wire.len() - 4 - packet.payload().len();
    wire.splice(prefix..prefix, [2, 1, 127]);
    let crc_offset = wire.len() - 4;
    let crc = crc32fast::hash(&wire[..crc_offset]);
    wire[crc_offset..].copy_from_slice(&crc.to_le_bytes());
    ALLOCATION_COUNT.with(|count| count.set(Some(0)));
    let result = sedsnet::wire_format::unpack_packet(&wire);
    let allocations = ALLOCATION_COUNT.with(|count| count.replace(None).unwrap());
    assert!(matches!(
        result,
        Err(TelemetryError::Unpack("wire contract target count"))
    ));
    assert_eq!(
        allocations, 0,
        "untrusted target count allocated scratch storage"
    );
}

#[test]
fn waiting_ordered_receipts_do_not_allocate_idle_maintenance_scratch() {
    use sedsnet::discovery::{TopologyBoardNode, build_discovery_topology};
    let _lock = TEST_LOCK.lock().unwrap();
    let ep = register_endpoint_with_description("IDLE_RECEIPT_SINK", "", false).unwrap();
    let ty = register_data_type_with_description(
        "IDLE_RECEIPT_VALUE",
        "",
        MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::Ordered,
        0,
    )
    .unwrap();
    let router = Router::new_with_clock(
        RouterConfig::default().with_sender("IDLE_SOURCE"),
        Box::new(|| 0),
    );
    let side = router.add_side_packed("receipt-link", |_| Ok(()));
    let topology = build_discovery_topology(
        "IDLE_DESTINATION",
        0,
        &[TopologyBoardNode {
            sender_id: "IDLE_DESTINATION".into(),
            reachable_endpoints: vec![ep],
            reachable_timesync_sources: vec![],
            connections: vec![],
        }],
    )
    .unwrap();
    router.rx_from_side(&topology, side).unwrap();
    router.drain_queues_with_timeout(0).unwrap();
    for timestamp in 1..=3 {
        router
            .tx(Packet::new(ty, &[ep], "IDLE_SOURCE", timestamp, Arc::from([1])).unwrap())
            .unwrap();
    }
    router.drain_queues_with_timeout(0).unwrap();
    assert_eq!(
        router
            .export_runtime_stats()
            .reliable
            .end_to_end_pending_count,
        3
    );
    ALLOCATION_COUNT.with(|count| count.set(Some(0)));
    for _ in 0..100 {
        router.drain_queues_with_timeout(1).unwrap();
    }
    let allocations = ALLOCATION_COUNT.with(|count| count.replace(None).unwrap());
    assert_eq!(
        allocations, 0,
        "waiting receipts repeatedly allocated maintenance scratch"
    );
    assert_eq!(
        router
            .export_runtime_stats()
            .reliable
            .end_to_end_pending_count,
        3
    );
}

#[test]
fn best_effort_telemetry_keeps_small_frames_and_does_not_fill_receipt_window() {
    use sedsnet::discovery::{TopologyBoardNode, build_discovery_topology};
    let _lock = TEST_LOCK.lock().unwrap();
    let ep = register_endpoint_with_description("BEST_EFFORT_GS", "", false).unwrap();
    let ty = register_data_type_with_description(
        "BEST_EFFORT_SIX_FLOATS",
        "",
        MessageElement::Static(6, MessageDataType::Float32, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        0,
    )
    .unwrap();
    let router = Router::new_with_clock(RouterConfig::default().with_sender("FC"), Box::new(|| 0));
    let sizes = Arc::new(std::sync::Mutex::new(Vec::new()));
    let output = sizes.clone();
    let side = router.add_side_packed("radio", move |bytes| {
        if sedsnet::wire_format::peek_envelope(bytes).is_ok_and(|env| env.ty == ty) {
            output.lock().unwrap().push(bytes.len());
        }
        Ok(())
    });
    let topology = build_discovery_topology(
        "GS",
        0,
        &[TopologyBoardNode {
            sender_id: "GS".into(),
            reachable_endpoints: vec![ep],
            reachable_timesync_sources: vec![],
            connections: vec![],
        }],
    )
    .unwrap();
    router.rx_from_side(&topology, side).unwrap();
    router.drain_queues_with_timeout(0).unwrap();
    // No receiver receipts: a best-effort stream must still keep sending.
    // Exercise four times the normal retained-receipt window.
    for timestamp in 1..=64 {
        let packet = Packet::new(ty, &[ep], "FC", timestamp, Arc::from([0u8; 24])).unwrap();
        let plain_size = sedsnet::wire_format::pack_packet(&packet).len();
        router.tx(packet).unwrap();
        assert_eq!(
            router
                .export_runtime_stats()
                .reliable
                .end_to_end_pending_count,
            0,
            "best-effort telemetry retained a receipt/retry record"
        );
        let actual = *sizes.lock().unwrap().last().expect("telemetry sent");
        assert_eq!(
            actual, plain_size,
            "best-effort telemetry gained a frozen receipt contract"
        );
        assert!(
            actual <= 48,
            "six-float telemetry must fit one CAN-FD frame"
        );
    }
    assert_eq!(sizes.lock().unwrap().len(), 64);
}

extern "C" fn small_restart_probe(additional: usize, largest: usize) -> bool {
    additional <= 2048 && largest <= 512
}

#[test]
fn known_peer_restart_does_not_require_a_full_discovery_snapshot_under_pressure() {
    use sedsnet::discovery::{
        ADDRESS_MODE_STATIC, ADDRESS_STATE_APPROVED, AddressAdvertisement, LinkCapabilities,
        build_discovery_address,
    };
    use std::sync::atomic::AtomicU64;
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    let ep = register_endpoint_with_description("RESTART_RETURN_PATH", "", false).unwrap();
    let clock = Arc::new(AtomicU64::new(0));
    let tick = clock.clone();
    let router = Router::new_with_clock(
        RouterConfig::default(),
        Box::new(move || tick.load(Ordering::Relaxed)),
    );
    let side = router.add_side_packed("known-peer", |_| Ok(()));
    let mut ad = AddressAdvertisement {
        hostname: "BOOT_PEER".into(),
        address: 42,
        requested_address: 42,
        mode: ADDRESS_MODE_STATIC,
        state: ADDRESS_STATE_APPROVED,
        birth_ms: 0,
        owner_hash: 77,
        reachable_endpoints: vec![ep],
        reachable_network_variables: vec![],
        reachable_timesync_sources: vec![],
        link_capabilities: LinkCapabilities {
            version: 1,
            flags: 0,
            profile: 0,
            max_frame_bytes: 64,
            compact_header_target_bytes: 40,
            max_side_transport_templates: 8,
        },
    };
    router
        .rx_from_side(&build_discovery_address("BOOT_PEER", 1, &ad).unwrap(), side)
        .unwrap();
    router.clear_queues();
    // The peer restarts; ownership and route contents remain identical.
    clock.store(200_000, Ordering::Relaxed);
    ad.birth_ms = 200_000;
    let restarted = build_discovery_address("BOOT_PEER", 200_000, &ad).unwrap();
    sedsnet::memory_admission::set_probe(Some(small_restart_probe));
    router
        .rx_from_side(&restarted, side)
        .expect("known incarnation must recover with small headroom");
    assert!(router.export_topology().routes.iter().any(|route| {
        route
            .announcers
            .iter()
            .any(|peer| peer.sender_id == "BOOT_PEER" && peer.age_ms == 0)
    }));
    // A changed owner still needs normal transactional admission.
    ad.owner_hash += 1;
    sedsnet::memory_admission::set_probe(None);
    let different_owner = build_discovery_address("BOOT_PEER", 200_001, &ad).unwrap();
    sedsnet::memory_admission::set_probe(Some(small_restart_probe));
    assert!(matches!(
        router.rx_from_side(&different_owner, side),
        Err(TelemetryError::Io("memory pressure"))
    ));
    // A contender for the same requested address must still trigger collision
    // arbitration, even when the original owner and summary are unchanged.
    sedsnet::memory_admission::set_probe(None);
    let mut contender = ad.clone();
    contender.hostname = "BOOT_CONTENDER".into();
    contender.address = 43;
    contender.owner_hash = 88;
    router
        .rx_from_side(
            &build_discovery_address("BOOT_CONTENDER", 200_002, &contender).unwrap(),
            side,
        )
        .unwrap();
    assert!(router.address_book().iter().any(|entry| {
        entry.hostname.as_ref() == "BOOT_CONTENDER" && entry.requested_address == 42
    }));
    ad.owner_hash = 77;
    ad.birth_ms = 200_003;
    let contested_restart = build_discovery_address("BOOT_PEER", 200_003, &ad).unwrap();
    sedsnet::memory_admission::set_probe(Some(small_restart_probe));
    assert!(matches!(
        router.rx_from_side(&contested_restart, side),
        Err(TelemetryError::Io("memory pressure"))
    ));
}

static CACHED_ACCEPTS: AtomicUsize = AtomicUsize::new(0);
extern "C" fn fragmented_cached_probe(additional: usize, largest: usize, work: u32) -> bool {
    let accepted = work == sedsnet::memory_admission::WORK_CACHED_TRANSIT
        && additional <= 1280
        && largest <= 256;
    if accepted {
        CACHED_ACCEPTS.fetch_add(1, Ordering::Relaxed);
    }
    accepted
}

#[test]
fn cached_bridge_forwards_in_small_fragments_without_admitting_cold_work() {
    use sedsnet::discovery::{
        TopologyBoardNode, build_discovery_announce, build_discovery_topology,
    };
    use sedsnet::router::{NetworkVariablePermissions, RouterSideOptions};
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    let ep = register_endpoint_with_description("CACHED_FRAGMENT_SINK", "", false).unwrap();
    let ty = register_data_type_with_description(
        "CACHED_FRAGMENT_DATA",
        "",
        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        0,
    )
    .unwrap();
    let cold_ty = register_data_type_with_description(
        "COLD_FRAGMENT_DATA",
        "",
        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        0,
    )
    .unwrap();
    let sent = Arc::new(AtomicUsize::new(0));
    let router = Router::new_with_clock(RouterConfig::default(), Box::new(|| 0));
    let opts = RouterSideOptions::default().with_small_packet_transport(64);
    let ingress = router.add_side_packed_with_options("can", |_| Ok(()), opts.clone());
    let output = sent.clone();
    let egress = router.add_side_packed_with_options(
        "uart",
        move |_| {
            output.fetch_add(1, Ordering::Relaxed);
            Ok(())
        },
        opts,
    );
    router
        .rx_from_side(
            &build_discovery_topology(
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
            egress,
        )
        .unwrap();
    router.drain_queues_with_timeout(0).unwrap();
    let packet =
        |timestamp| Packet::from_f32_slice(ty, &[timestamp as f32], &[ep], timestamp).unwrap();
    let warm = sedsnet::wire_format::pack_packet(&packet(0));
    router.rx_packed_from_side(&warm, ingress).unwrap();
    let before = sent.load(Ordering::Relaxed);
    CACHED_ACCEPTS.store(0, Ordering::Relaxed);
    sedsnet::memory_admission::set_probe_v2(Some(fragmented_cached_probe));
    for timestamp in 1..=32 {
        router
            .rx_packed_queue_from_side(
                &sedsnet::wire_format::pack_packet(&packet(timestamp)),
                ingress,
            )
            .unwrap();
        router.drain_queues_with_timeout(0).unwrap();
    }
    assert_eq!(sent.load(Ordering::Relaxed) - before, 32);
    assert!(CACHED_ACCEPTS.load(Ordering::Relaxed) >= 64); // Handoff and dispatch both verify the cache.
    let cold = Packet::from_f32_slice(cold_ty, &[1.0], &[ep], 99).unwrap();
    assert!(matches!(
        router.rx_packed_queue_from_side(&sedsnet::wire_format::pack_packet(&cold), ingress),
        Err(TelemetryError::Io("memory pressure"))
    ));
    let discovery = build_discovery_announce("UNKNOWN_PEER", 99, &[]).unwrap();
    assert!(matches!(
        router.rx_packed_queue_from_side(&sedsnet::wire_format::pack_packet(&discovery), ingress),
        Err(TelemetryError::Io("memory pressure"))
    ));
    // A queue-time classification is not permission to decode later metadata.
    router
        .rx_packed_queue_from_side(&sedsnet::wire_format::pack_packet(&packet(100)), ingress)
        .unwrap();
    router
        .enable_network_variable(
            ty,
            NetworkVariablePermissions {
                read: true,
                write: true,
            },
        )
        .unwrap();
    assert!(matches!(
        router.drain_queues_with_timeout(0),
        Err(TelemetryError::Io("memory pressure"))
    ));
    assert_eq!(sent.load(Ordering::Relaxed) - before, 32);
    // The legacy setter disables the extended probe; no hint changes old callers.
    sedsnet::memory_admission::set_probe(None);
    router.drain_queues_with_timeout(0).unwrap();
}

#[test]
fn standalone_relay_uses_cached_scratch_and_rechecks_expired_routes() {
    for endpoint_count in [1, 3] {
        cached_relay_endpoint_count(endpoint_count);
    }
}

fn cached_relay_endpoint_count(endpoint_count: usize) {
    use sedsnet::discovery::{TopologyBoardNode, build_discovery_topology};
    use sedsnet::relay::{Relay, RelaySideOptions};
    use std::sync::atomic::AtomicU64;
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    let ep = register_endpoint_with_description(
        &format!("RELAY_CACHED_SINK_{endpoint_count}"),
        "",
        false,
    )
    .unwrap();
    let ep2 =
        register_endpoint_with_description(&format!("RELAY_CACHED_SD_{endpoint_count}"), "", false)
            .unwrap();
    let ep3 = register_endpoint_with_description(
        &format!("RELAY_CACHED_HEARTBEAT_{endpoint_count}"),
        "",
        false,
    )
    .unwrap();
    let endpoints = &([ep, ep2, ep3])[..endpoint_count];
    let ty = register_data_type_with_description(
        &format!("RELAY_CACHED_DATA_{endpoint_count}"),
        "",
        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
        endpoints,
        ReliableMode::None,
        0,
    )
    .unwrap();
    let clock = Arc::new(AtomicU64::new(0));
    let tick = clock.clone();
    let relay = Relay::new(Box::new(move || tick.load(Ordering::Relaxed)));
    let opts = RelaySideOptions::default().with_small_packet_transport(64);
    let ingress = relay.add_side_packed_with_options("can", |_| Ok(()), opts.clone());
    let sent = Arc::new(AtomicUsize::new(0));
    let output = sent.clone();
    let egress = relay.add_side_packed_with_options(
        "uart",
        move |_| {
            output.fetch_add(1, Ordering::Relaxed);
            Ok(())
        },
        opts,
    );
    relay
        .rx_from_side(
            egress,
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
        )
        .unwrap();
    relay.drain_queues_with_timeout(0).unwrap();
    let wire = |timestamp| {
        sedsnet::wire_format::pack_packet(
            &Packet::from_f32_slice(ty, &[timestamp as f32], endpoints, timestamp).unwrap(),
        )
    };
    relay.rx_packed_from_side(ingress, &wire(0)).unwrap();
    relay.drain_queues_with_timeout(0).unwrap();
    let before = sent.load(Ordering::Relaxed);
    sedsnet::memory_admission::set_probe_v2(Some(fragmented_cached_probe));
    for timestamp in 1..=32 {
        relay
            .rx_packed_from_side(ingress, &wire(timestamp))
            .unwrap();
        relay.drain_queues_with_timeout(0).unwrap();
    }
    assert_eq!(sent.load(Ordering::Relaxed) - before, 32);
    relay.rx_packed_from_side(ingress, &wire(100)).unwrap();
    clock.store(200_000, Ordering::Relaxed);
    assert!(matches!(
        relay.drain_queues_with_timeout(0),
        Err(TelemetryError::Io("memory pressure"))
    ));
    assert_eq!(sent.load(Ordering::Relaxed) - before, 32);
}

#[test]
fn repeated_topology_merge_reuses_retained_nodes_without_scratch_allocations() {
    let _lock = TEST_LOCK.lock().unwrap();
    use sedsnet::discovery::{TopologyBoardNode, merge_topology_boards};
    let board = |name: &str, endpoints: Vec<sedsnet::config::DataEndpoint>| TopologyBoardNode {
        sender_id: name.into(),
        reachable_endpoints: endpoints,
        reachable_timesync_sources: vec!["UTC".into()],
        connections: vec!["GS".into()],
    };
    let mut retained = vec![
        board("AB", vec![sedsnet::config::DataEndpoint(5)]),
        board("VB", vec![sedsnet::config::DataEndpoint(6)]),
    ];
    let refresh = retained.clone();
    ALLOCATION_COUNT.with(|n| n.set(Some(0)));
    let started = std::time::Instant::now();
    for _ in 0..1000 {
        merge_topology_boards(&mut retained, &refresh);
    }
    let elapsed = started.elapsed();
    let count = ALLOCATION_COUNT.with(|n| n.replace(None).unwrap());
    println!(
        "unchanged topology: {count} allocations; host nanoseconds per merge: {}",
        elapsed.as_nanos() / 1000
    );
    assert_eq!(
        count, 0,
        "unchanged topology cloned retained nodes or duplicate strings"
    );
    assert_eq!(retained, refresh);
    // Keep last-wins destination semantics, union source duplicates, and
    // normalize ordering/self connections without losing any new reachability.
    retained.insert(0, board("AB", vec![sedsnet::config::DataEndpoint(9)]));
    let mut updates = vec![
        board("AB", vec![sedsnet::config::DataEndpoint(7)]),
        board("AB", vec![sedsnet::config::DataEndpoint(8)]),
        board("FC", vec![]),
    ];
    updates[0].connections.push("AB".into());
    merge_topology_boards(&mut retained, &updates);
    assert_eq!(
        retained
            .iter()
            .map(|n| n.sender_id.as_str())
            .collect::<Vec<_>>(),
        vec!["AB", "FC", "VB"]
    );
    assert_eq!(
        retained[0].reachable_endpoints,
        vec![
            sedsnet::config::DataEndpoint(5),
            sedsnet::config::DataEndpoint(7),
            sedsnet::config::DataEndpoint(8)
        ]
    );
    assert_eq!(retained[0].connections, vec!["GS"]);
    assert_eq!(retained[0].reachable_timesync_sources, vec!["UTC"]);
}

#[test]
fn cached_two_and_three_endpoint_bridges_forward_without_general_scratch() {
    for endpoint_count in [2, 3] {
        cached_multi_endpoint_bridge(endpoint_count);
    }
}

fn cached_multi_endpoint_bridge(endpoint_count: usize) {
    use sedsnet::discovery::{
        TopologyBoardNode, build_discovery_announce, build_discovery_topology,
    };
    use sedsnet::router::{NetworkVariablePermissions, RouterSideOptions};
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    let ep = register_endpoint_with_description(
        &format!("CACHED_MULTI_FRAGMENT_SINK_{endpoint_count}"),
        "",
        false,
    )
    .unwrap();
    let ep2 = register_endpoint_with_description(
        &format!("CACHED_MULTI_SD_CARD_{endpoint_count}"),
        "",
        false,
    )
    .unwrap();
    let ep3 = register_endpoint_with_description(
        &format!("CACHED_MULTI_HEARTBEAT_{endpoint_count}"),
        "",
        false,
    )
    .unwrap();
    let endpoints = &([ep, ep2, ep3])[..endpoint_count];
    let ty = register_data_type_with_description(
        &format!("CACHED_MULTI_FRAGMENT_DATA_{endpoint_count}"),
        "",
        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
        endpoints,
        ReliableMode::None,
        0,
    )
    .unwrap();
    let cold_ty = register_data_type_with_description(
        &format!("COLD_MULTI_FRAGMENT_DATA_{endpoint_count}"),
        "",
        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
        endpoints,
        ReliableMode::None,
        0,
    )
    .unwrap();
    let sent = Arc::new(AtomicUsize::new(0));
    let router = Router::new_with_clock(RouterConfig::default(), Box::new(|| 0));
    let opts = RouterSideOptions::default().with_small_packet_transport(64);
    let ingress = router.add_side_packed_with_options("can", |_| Ok(()), opts.clone());
    let output = sent.clone();
    let egress = router.add_side_packed_with_options(
        "uart",
        move |_| {
            output.fetch_add(1, Ordering::Relaxed);
            Ok(())
        },
        opts,
    );
    router
        .rx_from_side(
            &build_discovery_topology(
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
            egress,
        )
        .unwrap();
    router.drain_queues_with_timeout(0).unwrap();
    let packet =
        |timestamp| Packet::from_f32_slice(ty, &[timestamp as f32], endpoints, timestamp).unwrap();
    let warm = sedsnet::wire_format::pack_packet(&packet(0));
    router.rx_packed_from_side(&warm, ingress).unwrap();
    let before = sent.load(Ordering::Relaxed);
    CACHED_ACCEPTS.store(0, Ordering::Relaxed);
    sedsnet::memory_admission::set_probe_v2(Some(fragmented_cached_probe));
    for timestamp in 1..=32 {
        router
            .rx_packed_queue_from_side(
                &sedsnet::wire_format::pack_packet(&packet(timestamp)),
                ingress,
            )
            .unwrap();
        router.drain_queues_with_timeout(0).unwrap();
    }
    assert_eq!(sent.load(Ordering::Relaxed) - before, 32);
    assert!(CACHED_ACCEPTS.load(Ordering::Relaxed) >= 64); // Handoff and dispatch both verify the cache.
    let cold = Packet::from_f32_slice(cold_ty, &[1.0], endpoints, 99).unwrap();
    assert!(matches!(
        router.rx_packed_queue_from_side(&sedsnet::wire_format::pack_packet(&cold), ingress),
        Err(TelemetryError::Io("memory pressure"))
    ));
    let discovery = build_discovery_announce("UNKNOWN_PEER", 99, &[]).unwrap();
    assert!(matches!(
        router.rx_packed_queue_from_side(&sedsnet::wire_format::pack_packet(&discovery), ingress),
        Err(TelemetryError::Io("memory pressure"))
    ));
    // A queue-time classification is not permission to decode later metadata.
    router
        .rx_packed_queue_from_side(&sedsnet::wire_format::pack_packet(&packet(100)), ingress)
        .unwrap();
    router
        .enable_network_variable(
            ty,
            NetworkVariablePermissions {
                read: true,
                write: true,
            },
        )
        .unwrap();
    assert!(matches!(
        router.drain_queues_with_timeout(0),
        Err(TelemetryError::Io("memory pressure"))
    ));
    assert_eq!(sent.load(Ordering::Relaxed) - before, 32);
    // The legacy setter disables the extended probe; no hint changes old callers.
    sedsnet::memory_admission::set_probe(None);
    router.drain_queues_with_timeout(0).unwrap();
}

extern "C" fn topology_only_headroom(additional: usize, largest: usize) -> bool {
    additional <= 7000 && largest <= 1024
}

#[test]
fn topology_request_recovers_named_baseline_without_schema_scratch() {
    check_topology_request_recovery(true);
}

#[test]
fn topology_recovery_without_preferred_master_uses_phase_peak() {
    check_topology_request_recovery(false);
}

#[test]
fn topology_recovery_with_overlapping_peer_views_uses_unique_union() {
    check_topology_request_views(true, true);
}

fn check_topology_request_recovery(preferred: bool) {
    check_topology_request_views(preferred, false);
}

fn check_topology_request_views(preferred: bool, overlapping: bool) {
    use sedsnet::discovery::{
        TopologyBoardNode, build_discovery_topology, build_discovery_topology_request,
        decode_discovery_topology,
    };
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    let ep = register_endpoint_with_description(
        if overlapping {
            "TOPOLOGY_UNION_RECOVERY_SINK"
        } else if preferred {
            "TOPOLOGY_RECOVERY_SINK"
        } else {
            "TOPOLOGY_ELECTION_RECOVERY_SINK"
        },
        "",
        false,
    )
    .unwrap();
    let cfg = RouterConfig::default().with_sender("GB");
    let cfg = if preferred {
        cfg.with_preferred_discovery_master("GS")
    } else {
        cfg
    };
    let router = Router::new_with_clock(cfg, Box::new(|| 0));
    let ingress = router.add_side_packed("can", |_| Ok(()));
    let names = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let output = names.clone();
    let egress = router.add_side_packet("uart", move |packet| {
        if packet.data_type() == sedsnet::config::DataType::DiscoveryTopology {
            output.lock().unwrap().extend(
                decode_discovery_topology(packet)?
                    .into_iter()
                    .map(|board| board.sender_id),
            );
        }
        Ok(())
    });
    for name in ["AB", "DAQ", "VB"] {
        router
            .rx_from_side(
                &build_discovery_topology(
                    name,
                    0,
                    &(if overlapping {
                        vec!["AB", "DAQ", "VB"]
                    } else {
                        vec![name]
                    })
                    .into_iter()
                    .map(|name| TopologyBoardNode {
                        sender_id: name.into(),
                        reachable_endpoints: vec![ep],
                        reachable_timesync_sources: vec![],
                        connections: vec!["GB".into()],
                    })
                    .collect::<Vec<_>>(),
                )
                .unwrap(),
                ingress,
            )
            .unwrap();
    }
    // The requester advertises its other network. None of those nodes belong
    // in the split-horizon response, or in its working-memory estimate.
    let near_graph = (0..12)
        .map(|index| TopologyBoardNode {
            sender_id: format!("AV_{index}"),
            reachable_endpoints: vec![ep],
            reachable_timesync_sources: vec![],
            connections: vec!["GS".into()],
        })
        .collect::<Vec<_>>();
    router
        .rx_from_side(
            &build_discovery_topology("GS", 0, &near_graph).unwrap(),
            egress,
        )
        .unwrap();
    router.drain_queues_with_timeout(0).unwrap();
    names.lock().unwrap().clear();
    extern "C" fn election_headroom(additional: usize, largest: usize) -> bool {
        additional <= 9000 && largest <= 2048
    }
    sedsnet::memory_admission::set_probe(Some(if preferred {
        topology_only_headroom
    } else {
        election_headroom
    }));
    // A restarted GS has no graph/dictionary. Its empty request must not
    // require an 8 KiB schema decode before the retained topology is returned.
    router
        .rx_from_side(&build_discovery_topology_request("GS", 1).unwrap(), egress)
        .unwrap();
    router.drain_queues_with_timeout(0).unwrap();
    let got = names.lock().unwrap();
    for name in ["AB", "DAQ", "GB", "VB"] {
        assert!(
            got.iter().any(|item| item == name),
            "missing {name}: {got:?}"
        );
    }
}

#[test]
fn relay_topology_request_recovers_named_baseline_without_schema_scratch() {
    use sedsnet::discovery::{
        TopologyBoardNode, build_discovery_topology, build_discovery_topology_request,
        decode_discovery_topology,
    };
    use sedsnet::relay::{Relay, RelayConfig};
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    let ep = register_endpoint_with_description("RELAY_TOPOLOGY_RECOVERY_SINK", "", false).unwrap();
    let relay = Relay::new_with_config(RelayConfig::default().with_sender("GB"), Box::new(|| 0));
    let ingress = relay.add_side_packed("can", |_| Ok(()));
    let names = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let output = names.clone();
    let egress = relay.add_side_packed("uart", move |bytes| {
        let packet = sedsnet::wire_format::unpack_packet(bytes)?;
        if packet.data_type() == sedsnet::config::DataType::DiscoveryTopology {
            output.lock().unwrap().extend(
                decode_discovery_topology(&packet)?
                    .into_iter()
                    .map(|board| board.sender_id),
            );
        }
        Ok(())
    });
    for name in ["AB", "DAQ", "VB"] {
        relay
            .rx_from_side(
                ingress,
                build_discovery_topology(
                    name,
                    0,
                    &[TopologyBoardNode {
                        sender_id: name.into(),
                        reachable_endpoints: vec![ep],
                        reachable_timesync_sources: vec![],
                        connections: vec!["GB".into()],
                    }],
                )
                .unwrap(),
            )
            .unwrap();
    }
    // The requester advertises its other network. None of those nodes belong
    // in the split-horizon response, or in its working-memory estimate.
    let near_graph = (0..12)
        .map(|index| TopologyBoardNode {
            sender_id: format!("AV_{index}"),
            reachable_endpoints: vec![ep],
            reachable_timesync_sources: vec![],
            connections: vec!["GS".into()],
        })
        .collect::<Vec<_>>();
    relay
        .rx_from_side(
            egress,
            build_discovery_topology("GS", 0, &near_graph).unwrap(),
        )
        .unwrap();
    relay.drain_queues_with_timeout(0).unwrap();
    names.lock().unwrap().clear();
    sedsnet::memory_admission::set_probe(Some(topology_only_headroom));
    relay
        .rx_from_side(egress, build_discovery_topology_request("GS", 1).unwrap())
        .unwrap();
    relay.drain_queues_with_timeout(0).unwrap();
    let got = names.lock().unwrap();
    for name in ["AB", "DAQ", "GB", "VB"] {
        assert!(
            got.iter().any(|item| item == name),
            "missing {name}: {got:?}"
        );
    }
}

#[test]
fn named_id_lookup_does_not_clone_schema_definitions() {
    let _lock = TEST_LOCK.lock().unwrap();
    let ep = register_endpoint_with_description(
        "ID_LOOKUP_SINK",
        "A retained endpoint description",
        false,
    )
    .unwrap();
    let ty = register_data_type_with_description(
        "ID_LOOKUP_VALUE",
        "A retained type description",
        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        0,
    )
    .unwrap();
    ALLOCATION_COUNT.with(|n| n.set(Some(0)));
    for _ in 0..1000 {
        assert_eq!(
            sedsnet::config::DataEndpoint::try_named("ID_LOOKUP_SINK"),
            Some(ep)
        );
        assert_eq!(
            sedsnet::config::DataType::try_named("ID_LOOKUP_VALUE"),
            Some(ty)
        );
        assert_eq!(
            sedsnet::config::DataType::try_named("ID_LOOKUP_MISSING"),
            None
        );
    }
    let allocations = ALLOCATION_COUNT.with(|n| n.replace(None).unwrap());
    assert_eq!(
        allocations, 0,
        "ID-only lookup copied names, descriptions or endpoint arrays"
    );
}

static CONTROL_HEADROOM_CALLS: AtomicUsize = AtomicUsize::new(0);
extern "C" fn headroom_after_two_bulk_evictions(_: usize, _: usize) -> bool {
    CONTROL_HEADROOM_CALLS.fetch_add(1, Ordering::Relaxed) >= 2
}

fn compact_status_frames(packet: &Packet) -> (Vec<u8>, Vec<u8>) {
    use sedsnet::router::RouterSideOptions;
    let frames = Arc::new(std::sync::Mutex::new(Vec::new()));
    let output = frames.clone();
    let sender = Router::new_with_clock(RouterConfig::default(), Box::new(|| 0));
    sender.add_side_packed_with_options(
        "wire",
        move |bytes| {
            output.lock().unwrap().push(bytes.to_vec());
            Ok(())
        },
        RouterSideOptions::default().with_small_packet_transport(128),
    );
    let bootstrap = Packet::new(
        packet.data_type(),
        packet.endpoints(),
        packet.sender(),
        0,
        Arc::<[u8]>::from(packet.payload()),
    )
    .unwrap();
    sender.tx(bootstrap).unwrap();
    sender.tx(packet.clone()).unwrap();
    let mut frames = frames.lock().unwrap();
    assert_eq!(frames.len(), 2);
    let compact = frames.pop().unwrap();
    let full = frames.pop().unwrap();
    assert!(full.starts_with(b"SDT\x01"));
    assert!(
        compact.starts_with(b"SDT\x02"),
        "expected compact status frame"
    );
    (full, compact)
}

#[test]
fn router_status_ingress_reclaims_bulk_but_preserves_control() {
    for compact in [false, true] {
        router_status_reclaim(compact);
    }
}

fn router_status_reclaim(compact: bool) {
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    let ep =
        register_endpoint_with_description(&format!("CONTROL_RECLAIM_LOCAL_{compact}"), "", false)
            .unwrap();
    let make_type = |name: &str, priority| {
        register_data_type_with_description(
            name,
            "",
            MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
            &[ep],
            ReliableMode::None,
            priority,
        )
        .unwrap()
    };
    let bulk = make_type(&format!("CONTROL_RECLAIM_BULK_{compact}"), 0);
    let status = make_type(&format!("CONTROL_RECLAIM_STATUS_{compact}"), 200);
    let protected = make_type(&format!("CONTROL_RECLAIM_PROTECTED_{compact}"), 201);
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let output = seen.clone();
    let router = Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(
            ep,
            move |packet| {
                output.lock().unwrap().push(packet.data_type());
                Ok(())
            },
        )]),
        Box::new(|| 0),
    );
    let opts = if compact {
        sedsnet::router::RouterSideOptions::default().with_small_packet_transport(128)
    } else {
        sedsnet::router::RouterSideOptions::default()
    };
    let side = router.add_side_packed_with_options("can", |_| Ok(()), opts);
    let packet = Packet::from_f32_slice(status, &[4.0], &[ep], 4).unwrap();
    let bytes = if compact {
        let (full, compact) = compact_status_frames(&packet);
        router.rx_packed_from_side(&full, side).unwrap();
        seen.lock().unwrap().clear();
        compact
    } else {
        sedsnet::wire_format::pack_packet(&packet).to_vec()
    };
    for (ty, time) in [(bulk, 1), (bulk, 2), (protected, 3)] {
        router
            .tx_queue(Packet::from_f32_slice(ty, &[time as f32], &[ep], time).unwrap())
            .unwrap();
    }
    CONTROL_HEADROOM_CALLS.store(0, Ordering::Relaxed);
    sedsnet::memory_admission::set_probe(Some(headroom_after_two_bulk_evictions));
    router.rx_packed_from_side(&bytes, side).unwrap();
    sedsnet::memory_admission::set_probe(None);
    router.drain_queues_with_timeout(0).unwrap();
    assert_eq!(*seen.lock().unwrap(), vec![status, protected]);
    // A CRC-corrupt high-priority frame must not evict anything.
    seen.lock().unwrap().clear();
    router
        .tx_queue(Packet::from_f32_slice(bulk, &[5.0], &[ep], 5).unwrap())
        .unwrap();
    let mut invalid = bytes.to_vec();
    *invalid.last_mut().unwrap() ^= 1;
    ALLOW.store(false, Ordering::Relaxed);
    sedsnet::memory_admission::set_probe(Some(probe));
    assert!(router.rx_packed_from_side(&invalid, side).is_err());
    sedsnet::memory_admission::set_probe(None);
    router.drain_queues_with_timeout(0).unwrap();
    assert_eq!(*seen.lock().unwrap(), vec![bulk]);
}

#[test]
fn relay_status_ingress_reclaims_bulk_but_preserves_control() {
    for compact in [false, true] {
        relay_status_reclaim(compact);
    }
}

fn relay_status_reclaim(compact: bool) {
    use sedsnet::discovery::{TopologyBoardNode, build_discovery_topology};
    use sedsnet::relay::Relay;
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    let ep = register_endpoint_with_description(
        &format!("RELAY_CONTROL_RECLAIM_SINK_{compact}"),
        "",
        false,
    )
    .unwrap();
    let make_type = |name: &str, priority| {
        register_data_type_with_description(
            name,
            "",
            MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
            &[ep],
            ReliableMode::None,
            priority,
        )
        .unwrap()
    };
    let bulk = make_type(&format!("RELAY_CONTROL_RECLAIM_BULK_{compact}"), 0);
    let status = make_type(&format!("RELAY_CONTROL_RECLAIM_STATUS_{compact}"), 200);
    let protected = make_type(&format!("RELAY_CONTROL_RECLAIM_PROTECTED_{compact}"), 201);
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let output = seen.clone();
    let relay = Relay::new(Box::new(|| 0));
    let opts = if compact {
        sedsnet::relay::RelaySideOptions::default().with_small_packet_transport(128)
    } else {
        sedsnet::relay::RelaySideOptions::default()
    };
    let ingress = relay.add_side_packed_with_options("can", |_| Ok(()), opts);
    let egress = relay.add_side_packed("uart", move |bytes| {
        let packet = sedsnet::wire_format::unpack_packet(bytes)?;
        if [bulk, status, protected].contains(&packet.data_type()) {
            output.lock().unwrap().push(packet.data_type());
        }
        Ok(())
    });
    relay
        .rx_from_side(
            egress,
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
        )
        .unwrap();
    relay.drain_queues_with_timeout(0).unwrap();
    let packet = Packet::from_f32_slice(status, &[4.0], &[ep], 4).unwrap();
    let bytes = if compact {
        let (full, compact) = compact_status_frames(&packet);
        relay.rx_packed_from_side(ingress, &full).unwrap();
        relay.drain_queues_with_timeout(0).unwrap();
        seen.lock().unwrap().clear();
        compact
    } else {
        sedsnet::wire_format::pack_packet(&packet).to_vec()
    };
    for (ty, time) in [(bulk, 1), (bulk, 2), (protected, 3)] {
        relay
            .rx_from_side(
                ingress,
                Packet::from_f32_slice(ty, &[time as f32], &[ep], time).unwrap(),
            )
            .unwrap();
    }
    CONTROL_HEADROOM_CALLS.store(0, Ordering::Relaxed);
    sedsnet::memory_admission::set_probe(Some(headroom_after_two_bulk_evictions));
    relay.rx_packed_from_side(ingress, &bytes).unwrap();
    sedsnet::memory_admission::set_probe(None);
    relay.drain_queues_with_timeout(0).unwrap();
    let got = seen.lock().unwrap();
    assert_eq!(got.len(), 2);
    assert!(got.contains(&status) && got.contains(&protected) && !got.contains(&bulk));
    drop(got);
    seen.lock().unwrap().clear();
    relay
        .rx_from_side(
            ingress,
            Packet::from_f32_slice(bulk, &[5.0], &[ep], 5).unwrap(),
        )
        .unwrap();
    let mut invalid = bytes.to_vec();
    *invalid.last_mut().unwrap() ^= 1;
    ALLOW.store(false, Ordering::Relaxed);
    sedsnet::memory_admission::set_probe(Some(probe));
    assert!(relay.rx_packed_from_side(ingress, &invalid).is_err());
    sedsnet::memory_admission::set_probe(None);
    relay.drain_queues_with_timeout(0).unwrap();
    assert_eq!(
        *seen.lock().unwrap(),
        vec![bulk],
        "corrupt compact control reclaimed unrelated traffic"
    );
}

#[test]
fn managed_subscription_request_avoids_full_schema_scratch() {
    use sedsnet::discovery::build_managed_variable_request;
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    let ep = register_endpoint_with_description("SUBSCRIPTION_HEADROOM_SINK", "", false).unwrap();
    let ty = register_data_type_with_description(
        "SUBSCRIPTION_HEADROOM_VALUE",
        "",
        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        0,
    )
    .unwrap();
    extern "C" fn subscription_headroom(additional: usize, largest: usize) -> bool {
        additional <= 5000 && largest <= 2048
    }
    let router = Router::new_with_clock(RouterConfig::default().with_sender("GB"), Box::new(|| 0));
    let side = router.add_side_packed("uart", |_| Ok(()));
    sedsnet::memory_admission::set_probe(Some(subscription_headroom));
    for time in 1..=3 {
        let packet = build_managed_variable_request("GS", time, ty).unwrap();
        let bytes = sedsnet::wire_format::pack_packet(&packet);
        router.rx_packed_from_side(&bytes, side).unwrap();
    }
    assert!(
        router
            .export_topology()
            .routes
            .iter()
            .any(|route| route.side_id == side && route.reachable_network_variables.contains(&ty))
    );
}

#[test]
fn relay_forwards_subscription_request_without_schema_scratch() {
    use sedsnet::discovery::build_managed_variable_request;
    use sedsnet::relay::Relay;
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    let ep =
        register_endpoint_with_description("RELAY_SUBSCRIPTION_HEADROOM_SINK", "", false).unwrap();
    let ty = register_data_type_with_description(
        "RELAY_SUBSCRIPTION_HEADROOM_VALUE",
        "",
        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        0,
    )
    .unwrap();
    let sent = Arc::new(AtomicUsize::new(0));
    let output = sent.clone();
    let relay = Relay::new(Box::new(|| 0));
    let side = relay.add_side_packed("upstream", |_| Ok(()));
    relay.add_side_packed("downstream", move |bytes| {
        if sedsnet::wire_format::peek_envelope(bytes)?.ty
            == sedsnet::config::DataType::ManagedVariableRequest
        {
            output.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    });
    extern "C" fn subscription_headroom(additional: usize, largest: usize) -> bool {
        additional <= 5000 && largest <= 2048
    }
    sedsnet::memory_admission::set_probe(Some(subscription_headroom));
    let packet = build_managed_variable_request("GS", 1, ty).unwrap();
    relay
        .rx_packed_from_side(side, &sedsnet::wire_format::pack_packet(&packet))
        .unwrap();
    relay.drain_queues_with_timeout(0).unwrap();
    assert_eq!(sent.load(Ordering::Relaxed), 1);
}

#[test]
fn topology_summary_does_not_copy_repeated_sources_or_endpoints() {
    use sedsnet::discovery::{TopologyBoardNode, summarize_topology_boards};
    let _lock = TEST_LOCK.lock().unwrap();
    let ep = register_endpoint_with_description("SUMMARY_UNIQUE_SINK", "", false).unwrap();
    let board = TopologyBoardNode {
        sender_id: "BOARD".into(),
        reachable_endpoints: vec![ep, sedsnet::config::DataEndpoint::Discovery],
        reachable_timesync_sources: vec!["UTC".into()],
        connections: vec![],
    };
    let boards = vec![board; 1000];
    ALLOCATION_COUNT.with(|count| count.set(Some(0)));
    let (endpoints, sources) = summarize_topology_boards(&boards);
    let count = ALLOCATION_COUNT.with(|n| n.replace(None).unwrap());
    assert!(count <= 6, "summary duplicated repeated fields: {count}");
    assert_eq!(endpoints, vec![ep]);
    assert_eq!(sources, vec!["UTC"]);
}

#[test]
fn topology_updates_move_new_nodes_and_do_not_clone_retained_graphs() {
    use sedsnet::discovery::{DiscoveryTopologyUpdate, TopologyBoardNode, apply_topology_update};
    let _lock = TEST_LOCK.lock().unwrap();
    let board = |name: &str, ep| TopologyBoardNode {
        sender_id: name.into(),
        reachable_endpoints: vec![sedsnet::config::DataEndpoint(ep)],
        reachable_timesync_sources: vec!["UTC".into()],
        connections: vec!["GS".into()],
    };
    let mut retained = vec![board("AB", 5), board("VB", 6)];
    // Prepare input outside the measured region: decoding already owns it.
    let updates: Vec<_> = (0..1000)
        .map(|i| DiscoveryTopologyUpdate {
            incremental: i % 2 == 0,
            boards: retained.clone(),
            removed: vec![],
        })
        .collect();
    ALLOCATION_COUNT.with(|n| n.set(Some(0)));
    for update in updates {
        assert!(!apply_topology_update(&mut retained, update));
    }
    let count = ALLOCATION_COUNT.with(|n| n.replace(None).unwrap());
    assert_eq!(count, 0, "unchanged update copied the retained graph");
    let update = DiscoveryTopologyUpdate {
        incremental: true,
        boards: vec![board("VB", 7), board("FC", 8)],
        removed: vec!["AB".into(), "VB".into()],
    };
    retained.reserve(1);
    ALLOCATION_COUNT.with(|n| n.set(Some(0)));
    assert!(apply_topology_update(&mut retained, update));
    let count = ALLOCATION_COUNT.with(|n| n.replace(None).unwrap());
    assert_eq!(count, 0, "decoded replacement buffers were copied");
    assert_eq!(
        retained
            .iter()
            .map(|n| n.sender_id.as_str())
            .collect::<Vec<_>>(),
        vec!["FC", "VB"]
    );
    assert_eq!(
        retained[1].reachable_endpoints,
        vec![sedsnet::config::DataEndpoint(7)]
    );
    // Removing and replacing the same node with identical content is unchanged.
    let same = retained[1].clone();
    assert!(!apply_topology_update(
        &mut retained,
        DiscoveryTopologyUpdate {
            incremental: true,
            boards: vec![same],
            removed: vec!["VB".into()],
        }
    ));
    assert!(apply_topology_update(
        &mut retained,
        DiscoveryTopologyUpdate {
            incremental: false,
            boards: vec![],
            removed: vec![],
        }
    ));
    assert!(retained.is_empty());
}

static SMALL_CONTROL_ACCEPTS: AtomicUsize = AtomicUsize::new(0);
extern "C" fn only_small_control(additional: usize, largest: usize, work: u32) -> bool {
    let allowed = work == sedsnet::memory_admission::WORK_SMALL_PROTECTED
        && (2048..=2432).contains(&additional)
        && largest <= 160;
    if allowed {
        SMALL_CONTROL_ACCEPTS.fetch_add(1, Ordering::Relaxed);
    }
    allowed
}

#[test]
fn bounded_reliable_control_uses_reserved_admission_in_router_and_relay() {
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    let ep = register_endpoint_with_description("SMALL_CONTROL_SINK", "", false).unwrap();
    let make = |name, size, priority, reliability| {
        register_data_type_with_description(
            name,
            "",
            MessageElement::Static(size, MessageDataType::UInt8, MessageClass::Data),
            &[ep],
            reliability,
            priority,
        )
        .unwrap()
    };
    let control = make("SMALL_CONTROL_VALID", 2, 200, ReliableMode::Ordered);
    let bulk = make("SMALL_CONTROL_BULK", 2, 199, ReliableMode::Ordered);
    let large = make("SMALL_CONTROL_LARGE", 256, 255, ReliableMode::Ordered);
    let unreliable = make("SMALL_CONTROL_UNRELIABLE", 2, 255, ReliableMode::None);
    let wire = |ty, size| {
        sedsnet::wire_format::pack_packet(
            &Packet::new(ty, &[ep], "CONTROL_SOURCE", 1, Arc::from(vec![1u8; size])).unwrap(),
        )
        .to_vec()
    };
    let good = wire(control, 2);
    let mut bad_crc = good.clone();
    *bad_crc.last_mut().unwrap() ^= 1;
    let mut compressed = good.clone();
    compressed[0] |= 1;
    let n = compressed.len();
    let crc = crc32fast::hash(&compressed[..n - 4]);
    compressed[n - 4..].copy_from_slice(&crc.to_le_bytes());
    let mut encrypted = good.clone();
    encrypted[0] |= 0x10;
    let n = encrypted.len();
    let crc = crc32fast::hash(&encrypted[..n - 4]);
    encrypted[n - 4..].copy_from_slice(&crc.to_le_bytes());
    let rejected = [
        wire(bulk, 2),
        wire(large, 256),
        wire(unreliable, 2),
        bad_crc,
        compressed,
        encrypted,
    ];
    let router = Router::new_with_clock(RouterConfig::default(), Box::new(|| 0));
    let side = router.add_side_packed("control-in", |_| Ok(()));
    let relay = sedsnet::relay::Relay::new(Box::new(|| 0));
    let relay_side = relay.add_side_packed("control-in", |_| Ok(()));
    SMALL_CONTROL_ACCEPTS.store(0, Ordering::Relaxed);
    sedsnet::memory_admission::set_probe_v2(Some(only_small_control));
    router.rx_packed_queue_from_side(&good, side).unwrap();
    relay.rx_packed_from_side(relay_side, &good).unwrap();
    assert_eq!(SMALL_CONTROL_ACCEPTS.load(Ordering::Relaxed), 2);
    for frame in rejected {
        assert!(router.rx_packed_queue_from_side(&frame, side).is_err());
        assert!(relay.rx_packed_from_side(relay_side, &frame).is_err());
    }
    assert_eq!(SMALL_CONTROL_ACCEPTS.load(Ordering::Relaxed), 2);
    // A legacy callback still gets the original conservative estimate.
    sedsnet::memory_admission::set_probe(Some(probe));
    ALLOW.store(false, Ordering::Relaxed);
    assert!(router.rx_packed_queue_from_side(&good, side).is_err());
}
