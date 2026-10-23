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
    static LIVE_ALLOCATION_DELTA: std::cell::Cell<Option<isize>> = const { std::cell::Cell::new(None) };
    static PEAK_ALLOCATION_DELTA: std::cell::Cell<isize> = const { std::cell::Cell::new(0) };
    static MAX_ALLOCATION: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static ALLOCATION_COUNT: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static REFUSE_CONTIGUOUS: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static CONTIGUOUS_REFUSALS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;
unsafe impl std::alloc::GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        let _ = LIVE_ALLOCATION_DELTA.try_with(|n| {
            if let Some(old) = n.get() {
                let current = old + layout.size() as isize;
                n.set(Some(current));
                let _ = PEAK_ALLOCATION_DELTA.try_with(|p| p.set(p.get().max(current)));
            }
        });
        let _ = MAX_ALLOCATION.try_with(|largest| {
            if let Some(n) = largest.get() {
                largest.set(Some(n.max(layout.size())));
            }
        });
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
        let _ = LIVE_ALLOCATION_DELTA.try_with(|n| {
            if let Some(old) = n.get() {
                n.set(Some(old - layout.size() as isize));
            }
        });
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

// Build a real migration-safe wire frame without exposing private Packet
// constructors. Protocol codes: static flag64, Float32=1, UInt8=2, Data=0.
fn cached_inline_test_wire(packet: &Packet, shape: Option<(u8, u8)>) -> Vec<u8> {
    let mut wire = sedsnet::wire_format::pack_packet(packet).to_vec();
    if let Some((primitive, count)) = shape {
        assert_eq!(wire[0] & 0x17, 0, "fixture expects plain best-effort input");
        wire[0] |= 4;
        let start = wire.len() - 4 - packet.payload().len();
        wire.splice(start..start, [3, 2, 64 | primitive, count]);
        let crc_offset = wire.len() - 4;
        let crc = crc32fast::hash(&wire[..crc_offset]);
        wire[crc_offset..].copy_from_slice(&crc.to_le_bytes());
    }
    wire
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
    let mut opts = RouterSideOptions::default().with_small_packet_transport(64);
    opts.max_side_transport_templates = 1;
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
    let packet = |timestamp| {
        Packet::new(
            ty,
            &[ep],
            "CACHED_SOURCE",
            timestamp,
            Arc::<[u8]>::from((timestamp as f32).to_le_bytes()),
        )
        .unwrap()
    };
    let warm = sedsnet::wire_format::pack_packet(&packet(0));
    router.rx_packed_from_side(&warm, ingress).unwrap();
    let announce = build_discovery_announce(packet(0).sender(), 0, &[]).unwrap();
    router.rx_from_side(&announce, ingress).unwrap();
    router.drain_queues_with_timeout(0).unwrap();
    // A different warm type evicts the one-entry optional TX dictionary.
    // Only cached bounded work is admitted below; it must forward canonical
    // bytes rather than allocate a replacement compression template.
    let churn_ty = register_data_type_with_description(
        "CACHED_FRAGMENT_CHURN",
        "",
        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        0,
    )
    .unwrap();
    let churn = Packet::from_f32_slice(churn_ty, &[0.0], &[ep], 0).unwrap();
    router
        .rx_packed_from_side(&sedsnet::wire_format::pack_packet(&churn), ingress)
        .unwrap();
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
    let unknown = Packet::new(
        ty,
        &[ep],
        "UNDISCOVERED_SOURCE",
        99,
        Arc::<[u8]>::from(0f32.to_le_bytes()),
    )
    .unwrap();
    assert!(matches!(
        router.rx_packed_queue_from_side(&sedsnet::wire_format::pack_packet(&unknown), ingress),
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
        for inline_contract in [false, true] {
            cached_relay_endpoint_count(endpoint_count, inline_contract, false);
        }
    }
}

fn cached_relay_endpoint_count(endpoint_count: usize, inline_contract: bool, wrapped: bool) {
    use sedsnet::discovery::{
        TopologyBoardNode, build_discovery_announce, build_discovery_topology,
    };
    use sedsnet::relay::{Relay, RelaySideOptions};
    use std::sync::atomic::AtomicU64;
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    let suffix = format!("{endpoint_count}_{inline_contract}_{wrapped}");
    let ep = register_endpoint_with_description(&format!("RELAY_CACHED_SINK_{suffix}"), "", false)
        .unwrap();
    let ep2 = register_endpoint_with_description(&format!("RELAY_CACHED_SD_{suffix}"), "", false)
        .unwrap();
    let ep3 =
        register_endpoint_with_description(&format!("RELAY_CACHED_HEARTBEAT_{suffix}"), "", false)
            .unwrap();
    let endpoints = &([ep, ep2, ep3])[..endpoint_count];
    let ty = register_data_type_with_description(
        &format!("RELAY_CACHED_DATA_{suffix}"),
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
    let mut opts = RelaySideOptions::default().with_small_packet_transport(64);
    opts.max_side_transport_templates = 1;
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
    let packet = |timestamp| {
        Packet::new(
            ty,
            endpoints,
            "RELAY_SOURCE",
            timestamp,
            Arc::<[u8]>::from((timestamp as f32).to_le_bytes()),
        )
        .unwrap()
    };
    let wire =
        |timestamp| cached_inline_test_wire(&packet(timestamp), inline_contract.then_some((1, 1)));
    relay.rx_packed_from_side(ingress, &wire(0)).unwrap();
    relay.drain_queues_with_timeout(0).unwrap();
    relay
        .rx_from_side(
            ingress,
            build_discovery_announce("RELAY_SOURCE", 0, &[]).unwrap(),
        )
        .unwrap();
    relay.drain_queues_with_timeout(0).unwrap();
    // A different warm type evicts the one-entry optional TX dictionary.
    // Only cached bounded work is admitted below; it must forward canonical
    // bytes rather than allocate a replacement compression template.
    let churn_ty = register_data_type_with_description(
        &format!("RELAY_CACHED_CHURN_{suffix}"),
        "",
        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
        endpoints,
        ReliableMode::None,
        0,
    )
    .unwrap();
    let churn = Packet::from_f32_slice(churn_ty, &[0.0], endpoints, 0).unwrap();
    relay
        .rx_packed_from_side(ingress, &sedsnet::wire_format::pack_packet(&churn))
        .unwrap();
    relay.drain_queues_with_timeout(0).unwrap();
    assert_eq!(wire(0)[0] & 4 != 0, inline_contract);
    let mismatched = cached_inline_test_wire(&packet(90), Some((2, 4)));
    let compact_frames = if wrapped {
        let (full, _) = compact_status_frames(&packet(0));
        relay.rx_packed_from_side(ingress, &full).unwrap();
        relay.drain_queues_with_timeout(0).unwrap();
        (1..=32)
            .map(|ts| compact_status_frames(&packet(ts)).1)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let before = sent.load(Ordering::Relaxed);
    sedsnet::memory_admission::set_probe_v2(Some(if wrapped {
        compact_cached_probe
    } else {
        fragmented_cached_probe
    }));
    for timestamp in 1..=32 {
        let canonical;
        let input = if wrapped {
            compact_frames[timestamp as usize - 1].as_slice()
        } else {
            canonical = wire(timestamp);
            canonical.as_slice()
        };
        relay.rx_packed_from_side(ingress, input).unwrap();
        relay.drain_queues_with_timeout(0).unwrap();
    }
    assert_eq!(sent.load(Ordering::Relaxed) - before, 32);
    assert!(matches!(
        relay.rx_packed_from_side(ingress, &mismatched),
        Err(TelemetryError::Io("memory pressure"))
    ));
    let unknown = Packet::new(
        ty,
        endpoints,
        "UNDISCOVERED_RELAY_SOURCE",
        99,
        Arc::<[u8]>::from(0f32.to_le_bytes()),
    )
    .unwrap();
    assert!(matches!(
        relay.rx_packed_from_side(ingress, &sedsnet::wire_format::pack_packet(&unknown)),
        Err(TelemetryError::Io("memory pressure"))
    ));
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
        for inline_contract in [false, true] {
            cached_multi_endpoint_bridge(endpoint_count, inline_contract);
        }
    }
}

fn cached_multi_endpoint_bridge(endpoint_count: usize, inline_contract: bool) {
    use sedsnet::discovery::{
        TopologyBoardNode, build_discovery_announce, build_discovery_topology,
    };
    use sedsnet::router::{NetworkVariablePermissions, RouterSideOptions};
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    let suffix = format!("{endpoint_count}_{inline_contract}");
    let ep = register_endpoint_with_description(
        &format!("CACHED_MULTI_FRAGMENT_SINK_{suffix}"),
        "",
        false,
    )
    .unwrap();
    let ep2 =
        register_endpoint_with_description(&format!("CACHED_MULTI_SD_CARD_{suffix}"), "", false)
            .unwrap();
    let ep3 =
        register_endpoint_with_description(&format!("CACHED_MULTI_HEARTBEAT_{suffix}"), "", false)
            .unwrap();
    let endpoints = &([ep, ep2, ep3])[..endpoint_count];
    let ty = register_data_type_with_description(
        &format!("CACHED_MULTI_FRAGMENT_DATA_{suffix}"),
        "",
        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
        endpoints,
        ReliableMode::None,
        0,
    )
    .unwrap();
    let cold_ty = register_data_type_with_description(
        &format!("COLD_MULTI_FRAGMENT_DATA_{suffix}"),
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
    let wire =
        |timestamp| cached_inline_test_wire(&packet(timestamp), inline_contract.then_some((1, 1)));
    let warm = wire(0);
    router.rx_packed_from_side(&warm, ingress).unwrap();
    assert_eq!(wire(0)[0] & 4 != 0, inline_contract);
    let mismatched = cached_inline_test_wire(&packet(90), Some((2, 4)));
    let before = sent.load(Ordering::Relaxed);
    CACHED_ACCEPTS.store(0, Ordering::Relaxed);
    sedsnet::memory_admission::set_probe_v2(Some(fragmented_cached_probe));
    for timestamp in 1..=32 {
        router
            .rx_packed_queue_from_side(&wire(timestamp), ingress)
            .unwrap();
        router.drain_queues_with_timeout(0).unwrap();
    }
    assert_eq!(sent.load(Ordering::Relaxed) - before, 32);
    assert!(matches!(
        router.rx_packed_queue_from_side(&mismatched, ingress),
        Err(TelemetryError::Io("memory pressure"))
    ));
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
    let unknown = Packet::new(
        ty,
        &[ep],
        "UNDISCOVERED_SOURCE",
        99,
        Arc::<[u8]>::from(0f32.to_le_bytes()),
    )
    .unwrap();
    assert!(matches!(
        router.rx_packed_queue_from_side(&sedsnet::wire_format::pack_packet(&unknown), ingress),
        Err(TelemetryError::Io("memory pressure"))
    ));
    // A queue-time classification is not permission to decode later metadata.
    router
        .rx_packed_queue_from_side(&wire(100), ingress)
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

#[test]
fn topology_encoding_does_not_clone_normalized_graph_strings() {
    use sedsnet::discovery::{
        TopologyBoardNode, build_discovery_topology, build_discovery_topology_delta,
        decode_discovery_topology_update, normalize_topology_boards,
    };
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    let ep = register_endpoint_with_description("TOPOLOGY_CODEC_ALLOC_DEST", "", false).unwrap();
    build_discovery_topology("WARMUP", 0, &[]).unwrap();
    for count in [4, 32, 128] {
        let mut graph = (0..count)
            .map(|index| TopologyBoardNode {
                sender_id: format!("BOARD_{index:03}"),
                reachable_endpoints: vec![ep],
                reachable_timesync_sources: vec!["GPS_A".into(), "GPS_B".into()],
                connections: vec!["EDGE_A".into(), "EDGE_B".into()],
            })
            .collect::<Vec<_>>();
        normalize_topology_boards(&mut graph);
        let original = graph.clone();
        let removed = vec!["REMOVED_B".into(), "REMOVED_A".into()];
        for delta in [false, true] {
            ALLOCATION_COUNT.with(|n| n.set(Some(0)));
            let packet = if delta {
                build_discovery_topology_delta("GB", 1, &graph, &removed)
            } else {
                build_discovery_topology("GB", 1, &graph)
            }
            .unwrap();
            let allocations = ALLOCATION_COUNT.with(|n| n.replace(None).unwrap());
            println!("topology nodes={count} delta={delta} allocations={allocations}");
            assert!(
                allocations <= 8,
                "graph codec allocated {allocations} times: nodes={count}, delta={delta}"
            );
            let decoded = decode_discovery_topology_update(&packet).unwrap();
            assert_eq!(decoded.boards, original);
            assert_eq!(decoded.incremental, delta);
            assert_eq!(
                decoded.removed,
                if delta {
                    vec!["REMOVED_A", "REMOVED_B"]
                } else {
                    vec![]
                }
            );
            assert_eq!(graph, original, "encoding mutated its borrowed graph");
        }
        // Noncanonical public inputs keep the existing normalization behavior.
        let canonical = build_discovery_topology("GB", 1, &graph).unwrap();
        graph.reverse();
        for board in &mut graph {
            board.connections.reverse();
            board.connections.push(board.sender_id.clone());
            board.connections.push("EDGE_A".into());
            board.reachable_timesync_sources.reverse();
            board.reachable_timesync_sources.push("GPS_A".into());
            board.reachable_endpoints.push(ep);
        }
        graph.push(graph[0].clone());
        let normalized = build_discovery_topology("GB", 1, &graph).unwrap();
        assert_eq!(normalized.payload(), canonical.payload());
    }
}

#[test]
fn memory_counters_are_allocation_free_even_when_admission_refuses_work() {
    let _lock = TEST_LOCK.lock().unwrap();
    let router = Router::new(RouterConfig::new([]));
    router.add_side_packed("memory-profile", |_| Ok(()));
    let _reset = Reset;
    ALLOW.store(false, Ordering::Relaxed);
    sedsnet::memory_admission::set_probe(Some(probe));
    ALLOCATION_COUNT.with(|n| n.set(Some(0)));
    let counters = router.memory_counters();
    let allocations = ALLOCATION_COUNT.with(|n| n.replace(None).unwrap());
    assert_eq!(allocations, 0);
    assert_eq!(counters[0], 1);
    assert!(counters[1] > 0);
    assert_eq!(counters[3], 0);
    assert_eq!(counters[4], 0);
    assert!(counters[5] > 0);
    assert_eq!(counters[13], 0);
}

#[test]
fn sparse_router_and_relay_side_metadata_avoids_large_btree_leaf_allocations() {
    let _lock = TEST_LOCK.lock().unwrap();
    // Exclude registry and queue initialization from side-table measurement.
    let _ = sedsnet::config::schema_fingerprint();
    let router = Router::new(RouterConfig::new([]));
    MAX_ALLOCATION.with(|n| n.set(Some(0)));
    router.add_side_packed("can", |_| Ok(()));
    router.add_side_packed("uart", |_| Ok(()));
    let largest_router = MAX_ALLOCATION.with(|n| n.replace(None).unwrap());
    assert!(
        largest_router <= 1024,
        "router side metadata requested {largest_router} bytes"
    );
    let relay = sedsnet::relay::Relay::new(Box::new(|| 0));
    MAX_ALLOCATION.with(|n| n.set(Some(0)));
    relay.add_side_packed("can", |_| Ok(()));
    relay.add_side_packed("uart", |_| Ok(()));
    let largest_relay = MAX_ALLOCATION.with(|n| n.replace(None).unwrap());
    assert!(
        largest_relay <= 1024,
        "relay side metadata requested {largest_relay} bytes"
    );
}

#[test]
fn sparse_managed_cache_avoids_large_leaf_and_reuses_entry_on_updates() {
    let _lock = TEST_LOCK.lock().unwrap();
    let ep = register_endpoint_with_description("SPARSE_CACHE_EP", "", false).unwrap();
    let ty = register_data_type_with_description(
        "SPARSE_CACHE_VALUE",
        "",
        MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        16,
    )
    .unwrap();
    let router = Router::new(RouterConfig::new([]));
    router
        .enable_network_variable(
            ty,
            sedsnet::router::NetworkVariablePermissions {
                read: true,
                write: true,
            },
        )
        .unwrap();
    let first = Packet::new(ty, &[ep], "GS", 1, vec![1].into()).unwrap();
    let changed = Packet::new(ty, &[ep], "GS", 2, vec![2].into()).unwrap();
    MAX_ALLOCATION.with(|n| n.set(Some(0)));
    router.seed_managed_variable(first).unwrap();
    let largest = MAX_ALLOCATION.with(|n| n.replace(None).unwrap());
    assert!(
        largest <= 512,
        "sparse managed cache requested {largest} bytes"
    );
    ALLOCATION_COUNT.with(|n| n.set(Some(0)));
    router.seed_managed_variable(changed).unwrap();
    let allocations = ALLOCATION_COUNT.with(|n| n.replace(None).unwrap());
    assert_eq!(
        allocations, 0,
        "a managed-value update must reuse its entry"
    );
    assert_eq!(router.cached_managed_variable(ty).unwrap().payload(), &[2]);
}

#[test]
fn duplicate_topology_refresh_fits_small_headroom_on_router_and_relay() {
    use sedsnet::discovery::{
        TopologyBoardNode, build_discovery_topology, build_discovery_topology_delta,
    };
    use sedsnet::relay::Relay;
    use std::sync::atomic::AtomicU64;
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    let boards: Vec<_> = (0..32)
        .map(|n| TopologyBoardNode {
            sender_id: format!("NOOP_PEER_{n:02}"),
            reachable_endpoints: vec![sedsnet::config::DataEndpoint(800 + n)],
            reachable_timesync_sources: vec!["UTC".into()],
            connections: vec!["GS".into()],
        })
        .collect();
    let full = build_discovery_topology("NOOP_PEER_00", 1, &boards).unwrap();
    let delta =
        build_discovery_topology_delta("NOOP_PEER_00", 2, &boards[3..5], &["ALREADY_GONE".into()])
            .unwrap();
    let mut changed = boards.clone();
    changed[0]
        .reachable_endpoints
        .push(sedsnet::config::DataEndpoint(900));
    let changed = build_discovery_topology("NOOP_PEER_00", 3, &changed).unwrap();
    let clock = Arc::new(AtomicU64::new(1));
    let tick = clock.clone();
    let router = Router::new_with_clock(
        RouterConfig::default(),
        Box::new(move || tick.load(Ordering::Relaxed)),
    );
    let side = router.add_side_packed("noop", |_| Ok(()));
    let relay_tick = clock.clone();
    let relay = Relay::new(Box::new(move || relay_tick.load(Ordering::Relaxed)));
    let relay_side = relay.add_side_packed("noop", |_| Ok(()));
    router.rx_from_side(&full, side).unwrap();
    relay.rx_from_side(relay_side, full.clone()).unwrap();
    relay.process_rx_queue().unwrap();
    router.clear_queues();
    relay.clear_queues();
    // The full retained side is several KiB; ordinary guarded graph cloning
    // cannot pass this admission limit. An exact retry must still renew life.
    extern "C" fn tiny(additional: usize, largest: usize) -> bool {
        additional <= 1024 && largest <= 128
    }
    sedsnet::memory_admission::set_probe(Some(tiny));
    MAX_ALLOCATION.with(|n| n.set(Some(0)));
    for time in 2..12 {
        clock.store(time * 1000, Ordering::Relaxed);
        router.rx_from_side(&full, side).unwrap();
        router.rx_from_side(&delta, side).unwrap();
        relay.rx_from_side(relay_side, full.clone()).unwrap();
        relay.rx_from_side(relay_side, delta.clone()).unwrap();
        relay.process_rx_queue().unwrap();
    }
    let largest = MAX_ALLOCATION.with(|n| n.replace(None).unwrap());
    assert!(
        largest <= full.payload().len() + 256,
        "duplicate topology allocated a graph-sized block: {largest}"
    );
    assert!(matches!(
        router.rx_from_side(&changed, side),
        Err(TelemetryError::Io("memory pressure"))
    ));
    relay.rx_from_side(relay_side, changed).unwrap();
    assert!(matches!(
        relay.process_rx_queue(),
        Err(TelemetryError::Io("memory pressure"))
    ));
    sedsnet::memory_admission::set_probe(None);
    assert!(
        router
            .export_topology()
            .routes
            .iter()
            .flat_map(|r| &r.announcers)
            .any(|p| p.sender_id == "NOOP_PEER_00" && p.age_ms == 0)
    );
    assert!(
        relay
            .export_topology()
            .routes
            .iter()
            .flat_map(|r| &r.announcers)
            .any(|p| p.sender_id == "NOOP_PEER_00" && p.age_ms == 0)
    );
}

#[test]
fn unchanged_unsequenced_topology_wire_needs_no_allocations_or_queue_headroom() {
    use sedsnet::discovery::{
        TopologyBoardNode, build_discovery_topology, build_discovery_topology_delta,
    };
    use sedsnet::relay::Relay;
    use sedsnet::wire_format::{ReliableHeader, pack_packet, pack_packet_with_reliable};
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    let nodes = vec![TopologyBoardNode {
        sender_id: "PX".into(),
        reachable_endpoints: vec![sedsnet::config::DataEndpoint(1200)],
        reachable_timesync_sources: vec![],
        connections: vec![],
    }];
    let full = build_discovery_topology("PX", 1, &nodes).unwrap();
    let wire = pack_packet(&full);
    let empty_delta = pack_packet(&build_discovery_topology_delta("PX", 2, &[], &[]).unwrap());
    assert_eq!(wire[0] & 1, 0, "fixture must exercise uncompressed wire");
    assert_eq!(empty_delta[0] & 1, 0);
    let mut changed_nodes = nodes.clone();
    changed_nodes[0]
        .reachable_endpoints
        .push(sedsnet::config::DataEndpoint(1201));
    let changed = pack_packet(&build_discovery_topology("PX", 3, &changed_nodes).unwrap());
    let sequenced = pack_packet_with_reliable(
        &full,
        ReliableHeader {
            flags: 0,
            seq: 7,
            ack: 0,
        },
    );
    let piggyback = pack_packet_with_reliable(
        &full,
        ReliableHeader {
            flags: sedsnet::wire_format::RELIABLE_FLAG_UNSEQUENCED,
            seq: 0,
            ack: 9,
        },
    );
    let router = Router::new_with_clock(RouterConfig::default(), Box::new(|| 0));
    let side = router.add_side_packed("can", |_| Ok(()));
    let relay = Relay::new(Box::new(|| 0));
    let relay_side = relay.add_side_packed("can", |_| Ok(()));
    router.rx_from_side(&full, side).unwrap();
    relay.rx_from_side(relay_side, full.clone()).unwrap();
    relay.process_rx_queue().unwrap();
    router.clear_queues();
    relay.clear_queues();
    ALLOW.store(false, Ordering::Relaxed);
    sedsnet::memory_admission::set_probe(Some(probe));
    ALLOCATION_COUNT.with(|n| n.set(Some(0)));
    for _ in 0..20 {
        router.rx_packed_queue_from_side(&wire, side).unwrap();
        router
            .rx_packed_queue_from_side(&empty_delta, side)
            .unwrap();
        relay.rx_packed_from_side(relay_side, &wire).unwrap();
        relay.rx_packed_from_side(relay_side, &empty_delta).unwrap();
    }
    let allocations = ALLOCATION_COUNT.with(|n| n.replace(None).unwrap());
    assert_eq!(
        allocations, 0,
        "known unsequenced retries should borrow retained state"
    );
    for frame in [&changed, &sequenced, &piggyback] {
        assert!(matches!(
            router.rx_packed_queue_from_side(frame, side),
            Err(TelemetryError::Io("memory pressure"))
        ));
        assert!(matches!(
            relay.rx_packed_from_side(relay_side, frame),
            Err(TelemetryError::Io("memory pressure"))
        ));
    }
    let mut corrupt = wire.to_vec();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert!(router.rx_packed_queue_from_side(&corrupt, side).is_err());
    assert!(relay.rx_packed_from_side(relay_side, &corrupt).is_err());
    let unknown = pack_packet(&build_discovery_topology("UNKNOWN", 4, &nodes).unwrap());
    assert!(matches!(
        router.rx_packed_queue_from_side(&unknown, side),
        Err(TelemetryError::Io("memory pressure"))
    ));
    assert!(matches!(
        relay.rx_packed_from_side(relay_side, &unknown),
        Err(TelemetryError::Io("memory pressure"))
    ));
}

// A compact wrapper first allocates only bounded reconstruction buffers. Full
// routing/decoder admission must still run when the owned frame is dispatched.
extern "C" fn compact_cached_probe(additional: usize, largest: usize, work: u32) -> bool {
    (work == sedsnet::memory_admission::WORK_GENERAL
        && additional > 512
        && additional <= 1024
        && largest <= 256)
        || fragmented_cached_probe(additional, largest, work)
}

#[test]
fn compact_cached_bridge_admits_only_reconstruction_before_cached_dispatch() {
    use sedsnet::discovery::{
        TopologyBoardNode, build_discovery_announce, build_discovery_topology,
    };
    use sedsnet::router::{NetworkVariablePermissions, RouterSideOptions};
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    let ep = register_endpoint_with_description("COMPACT_CACHED_FRAGMENT_SINK", "", false).unwrap();
    let ty = register_data_type_with_description(
        "COMPACT_CACHED_FRAGMENT_DATA",
        "",
        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        0,
    )
    .unwrap();
    let cold_ty = register_data_type_with_description(
        "COMPACT_COLD_FRAGMENT_DATA",
        "",
        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        0,
    )
    .unwrap();
    let sent = Arc::new(AtomicUsize::new(0));
    let router = Router::new_with_clock(RouterConfig::default(), Box::new(|| 0));
    let mut opts = RouterSideOptions::default().with_small_packet_transport(64);
    opts.max_side_transport_templates = 1;
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
    let packet = |timestamp| {
        Packet::new(
            ty,
            &[ep],
            "CACHED_SOURCE",
            timestamp,
            Arc::<[u8]>::from((timestamp as f32).to_le_bytes()),
        )
        .unwrap()
    };
    let warm = sedsnet::wire_format::pack_packet(&packet(0));
    router.rx_packed_from_side(&warm, ingress).unwrap();
    let announce = build_discovery_announce(packet(0).sender(), 0, &[]).unwrap();
    router.rx_from_side(&announce, ingress).unwrap();
    router.drain_queues_with_timeout(0).unwrap();
    // A different warm type evicts the one-entry optional TX dictionary.
    // Only cached bounded work is admitted below; it must forward canonical
    // bytes rather than allocate a replacement compression template.
    let churn_ty = register_data_type_with_description(
        "COMPACT_CACHED_FRAGMENT_CHURN",
        "",
        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        0,
    )
    .unwrap();
    let churn = Packet::from_f32_slice(churn_ty, &[0.0], &[ep], 0).unwrap();
    router
        .rx_packed_from_side(&sedsnet::wire_format::pack_packet(&churn), ingress)
        .unwrap();
    let (full, _) = compact_status_frames(&packet(0));
    router.rx_packed_from_side(&full, ingress).unwrap();
    router.drain_queues_with_timeout(0).unwrap();
    let compact_frames = (1..=32)
        .map(|ts| compact_status_frames(&packet(ts)).1)
        .collect::<Vec<_>>();
    let before = sent.load(Ordering::Relaxed);
    CACHED_ACCEPTS.store(0, Ordering::Relaxed);
    sedsnet::memory_admission::set_probe_v2(Some(compact_cached_probe));
    for compact in &compact_frames {
        router.rx_packed_queue_from_side(compact, ingress).unwrap();
        router.drain_queues_with_timeout(0).unwrap();
    }
    assert_eq!(sent.load(Ordering::Relaxed) - before, 32);
    assert!(CACHED_ACCEPTS.load(Ordering::Relaxed) >= 64); // Queueing and dispatch verify the cache.
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
    let unknown = Packet::new(
        ty,
        &[ep],
        "UNDISCOVERED_SOURCE",
        99,
        Arc::<[u8]>::from(0f32.to_le_bytes()),
    )
    .unwrap();
    assert!(matches!(
        router.rx_packed_queue_from_side(&sedsnet::wire_format::pack_packet(&unknown), ingress),
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
fn compact_cached_relay_admits_only_reconstruction_before_cached_dispatch() {
    for endpoints in [1, 3] {
        cached_relay_endpoint_count(endpoints, false, true);
    }
}

// A captured gateway OOM occurred while constructing a full discovery reply.
// The old schema branch checked a fixed 8 KiB and skipped the learned graph.
static FIRST_SNAPSHOT_SCRATCH: AtomicUsize = AtomicUsize::new(0);
extern "C" fn reject_snapshot_scratch(additional: usize, _largest: usize) -> bool {
    let _ =
        FIRST_SNAPSHOT_SCRATCH.compare_exchange(0, additional, Ordering::SeqCst, Ordering::SeqCst);
    false
}
fn large_snapshot_graph() -> Vec<sedsnet::discovery::TopologyBoardNode> {
    (0..16)
        .map(|i| sedsnet::discovery::TopologyBoardNode {
            sender_id: format!("NODE_{i:02}_{}", "long_name".repeat(12)),
            reachable_endpoints: vec![],
            reachable_timesync_sources: vec![],
            connections: vec!["GB".into()],
        })
        .collect()
}
#[test]
fn router_full_schema_snapshot_admits_learned_graph_before_allocating() {
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    let router = Router::new_with_clock(RouterConfig::default().with_sender("GB"), Box::new(|| 0));
    router.add_side_packed("radio", |_| Ok(()));
    let ingress = router.add_side_packed("can", |_| Ok(()));
    router
        .rx_from_side(
            &sedsnet::discovery::build_discovery_topology("PEER", 0, &large_snapshot_graph())
                .unwrap(),
            ingress,
        )
        .unwrap();
    router.drain_queues_with_timeout(0).unwrap();
    let retained_routes = router.export_topology().routes;
    assert!(!retained_routes.is_empty());
    FIRST_SNAPSHOT_SCRATCH.store(0, Ordering::SeqCst);
    sedsnet::memory_admission::set_probe(Some(reject_snapshot_scratch));
    ALLOCATION_COUNT.with(|n| n.set(Some(0)));
    assert!(matches!(
        router.announce_discovery(),
        Err(TelemetryError::Io("memory pressure"))
    ));
    let allocations = ALLOCATION_COUNT.with(|n| n.replace(None).unwrap());
    assert_eq!(allocations, 0, "refused snapshot allocated working storage");
    let scratch = FIRST_SNAPSHOT_SCRATCH.load(Ordering::SeqCst);
    assert!(
        scratch > 8192,
        "full schema bypassed retained graph: {scratch}"
    );
    sedsnet::memory_admission::set_probe(None);
    assert_eq!(router.export_topology().routes, retained_routes);
    router.announce_discovery().unwrap();
    router.drain_queues_with_timeout(0).unwrap();
}
#[test]
fn relay_full_schema_snapshot_admits_learned_graph_before_allocating() {
    use sedsnet::relay::{Relay, RelayConfig};
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    let relay = Relay::new_with_config(RelayConfig::default().with_sender("GB"), Box::new(|| 0));
    relay.add_side_packed("radio", |_| Ok(()));
    let ingress = relay.add_side_packed("can", |_| Ok(()));
    relay
        .rx_from_side(
            ingress,
            sedsnet::discovery::build_discovery_topology("PEER", 0, &large_snapshot_graph())
                .unwrap(),
        )
        .unwrap();
    relay.drain_queues_with_timeout(0).unwrap();
    let retained_routes = relay.export_topology().routes;
    assert!(!retained_routes.is_empty());
    FIRST_SNAPSHOT_SCRATCH.store(0, Ordering::SeqCst);
    sedsnet::memory_admission::set_probe(Some(reject_snapshot_scratch));
    ALLOCATION_COUNT.with(|n| n.set(Some(0)));
    assert!(matches!(
        relay.announce_discovery(),
        Err(TelemetryError::Io("memory pressure"))
    ));
    let allocations = ALLOCATION_COUNT.with(|n| n.replace(None).unwrap());
    assert_eq!(allocations, 0, "refused snapshot allocated working storage");
    let scratch = FIRST_SNAPSHOT_SCRATCH.load(Ordering::SeqCst);
    assert!(
        scratch > 8192,
        "full schema bypassed retained graph: {scratch}"
    );
    sedsnet::memory_admission::set_probe(None);
    assert_eq!(relay.export_topology().routes, retained_routes);
    relay.announce_discovery().unwrap();
    relay.drain_queues_with_timeout(0).unwrap();
}

#[cfg(feature = "compression")]
#[test]
fn compressed_opaque_transit_uses_bounded_admission_on_router_and_relay() {
    use sedsnet::discovery::{
        TopologyBoardNode, build_discovery_announce, build_discovery_topology,
    };
    use sedsnet::relay::{Relay, RelaySideOptions};
    use sedsnet::router::{NetworkVariablePermissions, RouterSideOptions};
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    let ep = register_endpoint_with_description("COMPRESSED_TRANSIT_SINK", "", false).unwrap();
    let ty = register_data_type_with_description(
        "COMPRESSED_TRANSIT_DATA",
        "",
        MessageElement::Static(256, MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        0,
    )
    .unwrap();
    let packet = |ts| {
        Packet::new(
            ty,
            &[ep],
            "COMPRESSED_TRANSIT_SOURCE",
            ts,
            Arc::<[u8]>::from([0u8; 256]),
        )
        .unwrap()
    };
    let raw = |ts| sedsnet::wire_format::pack_packet(&packet(ts));
    assert_ne!(
        raw(0)[0] & 1,
        0,
        "fixture must exercise actual zstd compression"
    );
    assert!(raw(0).len() <= 64);
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
    let announce = build_discovery_announce("COMPRESSED_TRANSIT_SOURCE", 0, &[]).unwrap();
    let router = Router::new_with_clock(RouterConfig::default(), Box::new(|| 0));
    let opts = RouterSideOptions::default();
    let ri = router.add_side_packed_with_options("can", |_| Ok(()), opts.clone());
    let router_out = Arc::new(std::sync::Mutex::new(Vec::new()));
    let out = router_out.clone();
    let ro = router.add_side_packed_with_options(
        "uart",
        move |b| {
            out.lock().unwrap().push(b.to_vec());
            Ok(())
        },
        opts,
    );
    router.rx_from_side(&topology, ro).unwrap();
    router.rx_from_side(&announce, ri).unwrap();
    router.drain_queues_with_timeout(0).unwrap();
    router.rx_packed_from_side(&raw(0), ri).unwrap();
    router_out.lock().unwrap().clear();

    let relay = Relay::new(Box::new(|| 0));
    let opts = RelaySideOptions::default();
    let li = relay.add_side_packed_with_options("can", |_| Ok(()), opts.clone());
    let relay_out = Arc::new(std::sync::Mutex::new(Vec::new()));
    let out = relay_out.clone();
    let lo = relay.add_side_packed_with_options(
        "uart",
        move |b| {
            out.lock().unwrap().push(b.to_vec());
            Ok(())
        },
        opts,
    );
    relay.rx_from_side(lo, topology).unwrap();
    relay.rx_from_side(li, announce).unwrap();
    relay.drain_queues_with_timeout(0).unwrap();
    relay.rx_packed_from_side(li, &raw(0)).unwrap();
    relay.drain_queues_with_timeout(0).unwrap();
    relay_out.lock().unwrap().clear();
    CACHED_ACCEPTS.store(0, Ordering::Relaxed);
    sedsnet::memory_admission::set_probe_v2(Some(fragmented_cached_probe));
    for ts in 1..=32 {
        let bytes = raw(ts);
        router.rx_packed_queue_from_side(&bytes, ri).unwrap();
        router.drain_queues_with_timeout(0).unwrap();
        relay.rx_packed_from_side(li, &bytes).unwrap();
        relay.drain_queues_with_timeout(0).unwrap();
        for output in [&router_out, &relay_out] {
            let wire = output.lock().unwrap().pop().unwrap();
            // Small-packet transport may add the ordinary full wrapper even
            // with dictionaries disabled; the canonical payload must be exact.
            if wire.starts_with(b"SDT\x01") {
                let n = wire.len();
                assert_eq!(crc32fast::hash(&wire[..n - 4]).to_le_bytes(), wire[n - 4..]);
                assert_eq!(&wire[4..n - 4], bytes.as_ref());
            } else {
                assert_eq!(wire, bytes.as_ref());
            }
        }
    }
    assert!(CACHED_ACCEPTS.load(Ordering::Relaxed) >= 128);
    // Corruption still fails CRC validation; compression is never permission
    // to treat bytes as locally decoded or skip current role checks.
    let mut corrupt = raw(40).to_vec();
    let n = corrupt.len();
    corrupt[n - 1] ^= 1;
    assert!(router.rx_packed_queue_from_side(&corrupt, ri).is_err());
    assert!(relay.rx_packed_from_side(li, &corrupt).is_err());
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
        router.rx_packed_queue_from_side(&raw(41), ri),
        Err(TelemetryError::Io("memory pressure"))
    ));
}

static CHUNK_ADMISSION_CALLS: AtomicUsize = AtomicUsize::new(0);
extern "C" fn retry_chunk_after_reclaim(_: usize, _: usize, _: u32) -> bool {
    CHUNK_ADMISSION_CALLS.fetch_add(1, Ordering::Relaxed) > 0 && ALLOW.load(Ordering::Relaxed)
}

#[test]
fn fragment_pressure_reclaims_bulk_and_accepts_duplicate_without_new_allocation() {
    use sedsnet::relay::Relay;
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    let ep = register_endpoint_with_description("CHUNK_PRESSURE_SINK", "", false).unwrap();
    let ty = register_data_type_with_description(
        "CHUNK_PRESSURE_DATA",
        "",
        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        0,
    )
    .unwrap();
    let packet = Packet::from_f32_slice(ty, &[1.0], &[ep], 0).unwrap();
    let control_ty = register_data_type_with_description(
        "CHUNK_PROTECTED_CONTROL",
        "",
        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        230,
    )
    .unwrap();
    let control = Packet::from_f32_slice(control_ty, &[1.0], &[ep], 0).unwrap();
    // Same framing and 40-fragment transfer size as the captured gateway rejects.
    let mut fragment = b"SDT\x03".to_vec();
    fragment.extend_from_slice(&1234u32.to_le_bytes());
    fragment.extend_from_slice(&38u16.to_le_bytes());
    fragment.extend_from_slice(&40u16.to_le_bytes());
    fragment.extend_from_slice(&[7u8; 94]);
    fragment.extend_from_slice(&crc32fast::hash(&fragment).to_le_bytes());
    for use_relay in [false, true] {
        sedsnet::memory_admission::set_probe(None);
        ALLOW.store(true, Ordering::Relaxed);
        let router = Router::new_with_clock(RouterConfig::default(), Box::new(|| 0));
        let ri = router.add_side_packed("can", |_| Ok(()));
        let relay = Relay::new(Box::new(|| 0));
        let li = relay.add_side_packed("can", |_| Ok(()));
        if use_relay {
            relay.rx_from_side(li, packet.clone()).unwrap();
        } else {
            router.rx_queue_from_side(packet.clone(), ri).unwrap();
        }
        CHUNK_ADMISSION_CALLS.store(0, Ordering::Relaxed);
        sedsnet::memory_admission::set_probe_v2(Some(retry_chunk_after_reclaim));
        if use_relay {
            relay.rx_packed_from_side(li, &fragment).unwrap();
        } else {
            router.rx_packed_queue_from_side(&fragment, ri).unwrap();
        }
        assert_eq!(
            CHUNK_ADMISSION_CALLS.load(Ordering::Relaxed),
            3,
            "one failed preflight, one bulk eviction, successful retry and descriptor admission"
        );
        // Retrying an already retained fragment allocates nothing and must not
        // be rejected (or evict another packet) merely because headroom fell.
        ALLOW.store(false, Ordering::Relaxed);
        CHUNK_ADMISSION_CALLS.store(0, Ordering::Relaxed);
        MAX_ALLOCATION.with(|n| n.set(Some(0)));
        let duplicate = if use_relay {
            relay.rx_packed_from_side(li, &fragment)
        } else {
            router.rx_packed_queue_from_side(&fragment, ri)
        };
        let allocation = MAX_ALLOCATION.with(|n| n.replace(None));
        duplicate.unwrap();
        assert_eq!(allocation, Some(0));
        assert_eq!(CHUNK_ADMISSION_CALLS.load(Ordering::Relaxed), 0);
        sedsnet::memory_admission::set_probe(None);
        if use_relay {
            relay.rx_from_side(li, control.clone()).unwrap();
        } else {
            router.rx_queue_from_side(control.clone(), ri).unwrap();
        }
        sedsnet::memory_admission::set_probe_v2(Some(retry_chunk_after_reclaim));
        // No reclaimable work: a different fragment is still refused. The
        // accepted assembly is preserved for retry; no relaxed allocation guard.
        fragment[8..10].copy_from_slice(&39u16.to_le_bytes());
        let n = fragment.len();
        let crc = crc32fast::hash(&fragment[..n - 4]);
        fragment[n - 4..].copy_from_slice(&crc.to_le_bytes());
        let rejected = if use_relay {
            relay.rx_packed_from_side(li, &fragment)
        } else {
            router.rx_packed_queue_from_side(&fragment, ri)
        };
        assert!(matches!(
            rejected,
            Err(TelemetryError::Io("memory pressure"))
        ));
        assert_eq!(
            CHUNK_ADMISSION_CALLS.load(Ordering::Relaxed),
            1,
            "protected controls must not be evicted to retry the allocation"
        );
        fragment[8..10].copy_from_slice(&38u16.to_le_bytes());
        let crc = crc32fast::hash(&fragment[..n - 4]);
        fragment[n - 4..].copy_from_slice(&crc.to_le_bytes());
    }
}

#[test]
fn warmed_relay_transit_dispatch_has_a_bounded_allocation_budget() {
    use sedsnet::discovery::{TopologyBoardNode, build_discovery_topology};
    use sedsnet::relay::Relay;
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    let ep = register_endpoint_with_description("RELAY_DISPATCH_BUDGET_SINK", "", false).unwrap();
    let ty = register_data_type_with_description(
        "RELAY_DISPATCH_BUDGET_DATA",
        "",
        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        0,
    )
    .unwrap();
    let relay = Relay::new(Box::new(|| 0));
    let ingress = relay.add_side_packed("can", |_| Ok(()));
    let sent = Arc::new(AtomicUsize::new(0));
    let counter = sent.clone();
    let egress = relay.add_side_packed("ethernet", move |_| {
        counter.fetch_add(1, Ordering::Relaxed);
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
    let mut total = 0;
    for ts in 0..=32 {
        let pkt = Packet::from_f32_slice(ty, &[ts as f32], &[ep], ts).unwrap();
        relay
            .rx_packed_from_side(ingress, &sedsnet::wire_format::pack_packet(&pkt))
            .unwrap();
        if ts != 0 {
            ALLOCATION_COUNT.with(|n| n.set(Some(0)));
        }
        let result = relay.drain_queues_with_timeout(0);
        if ts != 0 {
            total += ALLOCATION_COUNT.with(|n| n.replace(None).unwrap());
        }
        result.unwrap();
    }
    assert!(sent.load(Ordering::Relaxed) >= 33);
    assert!(
        total <= 64,
        "warmed opaque dispatch allocated {total} objects for 32 packets; owned header arrays must not be recreated"
    );
}

extern "C" fn assembly_headroom_probe(additional: usize, _: usize) -> bool {
    let delta = LIVE_ALLOCATION_DELTA.with(|n| n.get().unwrap_or(0));
    let available = 6600isize - delta;
    available >= 0 && additional.saturating_add(4096) <= available as usize
}

#[test]
fn fragmented_known_topology_recovers_without_two_full_working_copies() {
    use sedsnet::discovery::{TopologyBoardNode, build_discovery_topology};
    use sedsnet::relay::Relay;
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    let ep = register_endpoint_with_description("ASSEMBLY_HEADROOM_SINK", "", false).unwrap();
    let boards = (0..32)
        .map(|i| TopologyBoardNode {
            sender_id: if i == 0 {
                "ASSEMBLY_SOURCE".into()
            } else {
                format!("NODE_{i:02}_{}", "X".repeat(88))
            },
            reachable_endpoints: vec![ep],
            reachable_timesync_sources: vec![],
            connections: vec![],
        })
        .collect::<Vec<_>>();
    let topology = build_discovery_topology("ASSEMBLY_SOURCE", 0, &boards).unwrap();
    let tuning = sedsnet::config::runtime_tuning_config();
    let mut plain = tuning;
    plain.payload_compress_threshold = usize::MAX;
    sedsnet::config::set_runtime_tuning_config(plain).unwrap();
    let wire = sedsnet::wire_format::pack_packet(&topology);
    sedsnet::config::set_runtime_tuning_config(tuning).unwrap();
    assert_eq!(wire[0] & 1, 0);
    assert!((3000..5000).contains(&wire.len()), "{}", wire.len());
    let chunks = wire
        .chunks(94)
        .enumerate()
        .map(|(index, bytes)| {
            let mut out = b"SDT\x03".to_vec();
            out.extend_from_slice(&8765u32.to_le_bytes());
            out.extend_from_slice(&(index as u16).to_le_bytes());
            out.extend_from_slice(&(wire.len().div_ceil(94) as u16).to_le_bytes());
            out.extend_from_slice(bytes);
            out.extend_from_slice(&crc32fast::hash(&out).to_le_bytes());
            out
        })
        .collect::<Vec<_>>();
    for use_relay in [false, true] {
        sedsnet::memory_admission::set_probe(None);
        // This budget isolates working-headroom from retained graph accounting.
        // The allocator model below, not this queue ceiling, permits only 6600
        // free bytes above the already retained fragment/graph baseline.
        let memory = sedsnet::config::RuntimeMemoryConfig::new(65536, 16, 1024, 1.25).unwrap();
        let router = Router::new_with_clock(
            RouterConfig::default().with_memory_config(memory).unwrap(),
            Box::new(|| 0),
        );
        let ri = router.add_side_packed("can", |_| Ok(()));
        let relay = Relay::new_with_config(
            sedsnet::relay::RelayConfig::default()
                .with_memory_config(memory)
                .unwrap(),
            Box::new(|| 0),
        );
        let li = relay.add_side_packed("can", |_| Ok(()));
        if use_relay {
            relay.rx_from_side(li, topology.clone()).unwrap();
            relay.drain_queues_with_timeout(0).unwrap();
        } else {
            router.rx_from_side(&topology, ri).unwrap();
            router.drain_queues_with_timeout(0).unwrap();
        }
        for part in &chunks[..chunks.len() - 1] {
            if use_relay {
                relay.rx_packed_from_side(li, part).unwrap();
            } else {
                router.rx_packed_queue_from_side(part, ri).unwrap();
            }
        }
        LIVE_ALLOCATION_DELTA.with(|n| n.set(Some(0)));
        PEAK_ALLOCATION_DELTA.with(|n| n.set(0));
        sedsnet::memory_admission::set_probe(Some(assembly_headroom_probe));
        let result = if use_relay {
            relay.rx_packed_from_side(li, chunks.last().unwrap())
        } else {
            router.rx_packed_queue_from_side(chunks.last().unwrap(), ri)
        };
        LIVE_ALLOCATION_DELTA.with(|n| n.set(None));
        let peak = PEAK_ALLOCATION_DELTA.with(|n| n.get());
        sedsnet::memory_admission::set_probe(None);
        assert!(
            result.is_ok(),
            "relay={use_relay}, peak={peak}, error={result:?}"
        );
        assert!(
            peak <= 6600 - 4096,
            "assembly consumed protected reserve: {peak}"
        );
    }
}

#[test]
fn c_metadata_queries_do_not_clone_owned_type_definitions() {
    unsafe extern "C" {
        fn seds_dtype_get_info(
            ty: u32,
            eps: *mut u32,
            cap: usize,
            out: *mut core::ffi::c_void,
        ) -> i32;
        fn seds_dtype_get_info_by_name(
            name: *const core::ffi::c_char,
            len: usize,
            eps: *mut u32,
            cap: usize,
            out: *mut core::ffi::c_void,
        ) -> i32;
    }
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    let ep = register_endpoint_with_description("C_METADATA_BUDGET_SINK", "", false).unwrap();
    let name = "C_METADATA_BUDGET_DATA";
    let ty = register_data_type_with_description(
        name,
        "C metadata must borrow retained definitions",
        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        0,
    )
    .unwrap();
    let mut storage = [0usize; 32];
    let mut endpoints = [0u32; 3];
    ALLOCATION_COUNT.with(|n| n.set(Some(0)));
    for _ in 0..32 {
        assert_eq!(
            unsafe {
                seds_dtype_get_info(
                    ty.as_u32(),
                    endpoints.as_mut_ptr(),
                    3,
                    storage.as_mut_ptr().cast(),
                )
            },
            0
        );
        assert_eq!(
            unsafe {
                seds_dtype_get_info_by_name(
                    name.as_ptr().cast(),
                    name.len(),
                    endpoints.as_mut_ptr(),
                    3,
                    storage.as_mut_ptr().cast(),
                )
            },
            0
        );
    }
    let count = ALLOCATION_COUNT.with(|n| n.replace(None).unwrap());
    assert_eq!(endpoints[0], ep.as_u32());
    assert_eq!(
        count, 0,
        "C type queries allocated owned schema names/description/endpoints"
    );
}

#[test]
fn duplicate_fragment_retries_cannot_keep_stalled_transfers_alive() {
    use sedsnet::relay::Relay;
    use std::sync::atomic::AtomicU64;
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    let mut fragment = b"SDT\x03".to_vec();
    fragment.extend_from_slice(&4321u32.to_le_bytes());
    fragment.extend_from_slice(&0u16.to_le_bytes());
    fragment.extend_from_slice(&2u16.to_le_bytes());
    fragment.extend_from_slice(&[5u8; 94]);
    fragment.extend_from_slice(&crc32fast::hash(&fragment).to_le_bytes());
    for use_relay in [false, true] {
        sedsnet::memory_admission::set_probe(None);
        ALLOW.store(true, Ordering::Relaxed);
        let clock = Arc::new(AtomicU64::new(0));
        let tick = clock.clone();
        let router = Router::new_with_clock(
            RouterConfig::default(),
            Box::new(move || tick.load(Ordering::Relaxed)),
        );
        let ri = router.add_side_packed("can", |_| Ok(()));
        let tick = clock.clone();
        let relay = Relay::new(Box::new(move || tick.load(Ordering::Relaxed)));
        let li = relay.add_side_packed("can", |_| Ok(()));
        if use_relay {
            relay.rx_packed_from_side(li, &fragment).unwrap();
        } else {
            router.rx_packed_queue_from_side(&fragment, ri).unwrap();
        }
        ALLOW.store(false, Ordering::Relaxed);
        sedsnet::memory_admission::set_probe(Some(probe));
        for now in [1000, 2000] {
            clock.store(now, Ordering::Relaxed);
            if use_relay {
                relay.rx_packed_from_side(li, &fragment).unwrap();
            } else {
                router.rx_packed_queue_from_side(&fragment, ri).unwrap();
            }
        }
        clock.store(2100, Ordering::Relaxed);
        let result = if use_relay {
            relay.rx_packed_from_side(li, &fragment)
        } else {
            router.rx_packed_queue_from_side(&fragment, ri)
        };
        assert!(
            matches!(result, Err(TelemetryError::Io("memory pressure"))),
            "relay={use_relay}: a stale assembly must expire; a retry then requires fresh admission"
        );
        if !use_relay {
            assert_eq!(router.memory_counters()[13], 0);
        }
    }
}

#[test]
fn unchanged_address_liveness_inspection_does_not_allocate_under_pressure() {
    use sedsnet::discovery::{
        ADDRESS_MODE_STATIC, ADDRESS_STATE_APPROVED, AddressAdvertisement, LinkCapabilities,
        build_discovery_address,
    };
    use sedsnet::relay::Relay;
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    let old = sedsnet::config::runtime_tuning_config();
    struct Restore(sedsnet::config::RuntimeTuningConfig);
    impl Drop for Restore {
        fn drop(&mut self) {
            sedsnet::config::set_runtime_tuning_config(self.0).unwrap();
        }
    }
    let _restore = Restore(old);
    let mut tuning = old;
    tuning.payload_compress_threshold = usize::MAX;
    sedsnet::config::set_runtime_tuning_config(tuning).unwrap();
    let ep = register_endpoint_with_description("BORROWED_ADDRESS_EP", "", false).unwrap();
    let ad = AddressAdvertisement {
        hostname: "ADDRESS_PEER".into(),
        address: 42,
        requested_address: 42,
        mode: ADDRESS_MODE_STATIC,
        state: ADDRESS_STATE_APPROVED,
        birth_ms: 0,
        owner_hash: 77,
        reachable_endpoints: vec![ep],
        reachable_network_variables: vec![],
        reachable_timesync_sources: vec!["peer-clock".into()],
        link_capabilities: LinkCapabilities {
            version: 1,
            flags: 0,
            profile: 0,
            max_frame_bytes: 64,
            compact_header_target_bytes: 40,
            max_side_transport_templates: 8,
        },
    };
    for use_relay in [false, true] {
        sedsnet::memory_admission::set_probe(None);
        let router = Router::new(RouterConfig::default());
        let ri = router.add_side_packed("peer", |_| Ok(()));
        let relay = Relay::new(Box::new(|| 0));
        let li = relay.add_side_packed("peer", |_| Ok(()));
        let pkt = build_discovery_address("ADDRESS_PEER", 1, &ad).unwrap();
        if use_relay {
            relay.rx_from_side(li, pkt.clone()).unwrap();
            relay.process_rx_queue().unwrap();
            relay.clear_queues();
        } else {
            router.rx_from_side(&pkt, ri).unwrap();
            router.clear_queues();
        }
        let wire = sedsnet::wire_format::pack_packet(&pkt);
        assert_eq!(wire[0] & 1, 0);
        ALLOW.store(false, Ordering::Relaxed);
        sedsnet::memory_admission::set_probe(Some(probe));
        ALLOCATION_COUNT.with(|n| n.set(Some(0)));
        for _ in 0..32 {
            if use_relay {
                assert!(matches!(
                    relay.rx_packed_from_side(li, &wire),
                    Err(TelemetryError::Io("memory pressure"))
                ));
            } else {
                router.rx_packed_queue_from_side(&wire, ri).unwrap();
            }
        }
        let allocations = ALLOCATION_COUNT.with(|n| n.replace(None).unwrap());
        assert_eq!(
            allocations, 0,
            "relay={use_relay}: repeated address summaries must stay borrowed"
        );
        let mut bad = wire.to_vec();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        let invalid = if use_relay {
            relay.rx_packed_from_side(li, &bad)
        } else {
            router.rx_packed_queue_from_side(&bad, ri)
        };
        assert!(invalid.is_err());
        sedsnet::memory_admission::set_probe(None);
        let mut changed = ad.clone();
        changed.reachable_endpoints.push(
            register_endpoint_with_description(
                if use_relay {
                    "ADDRESS_CHANGED_RELAY"
                } else {
                    "ADDRESS_CHANGED_ROUTER"
                },
                "",
                false,
            )
            .unwrap(),
        );
        let changed = sedsnet::wire_format::pack_packet(
            &build_discovery_address("ADDRESS_PEER", 2, &changed).unwrap(),
        );
        sedsnet::memory_admission::set_probe(Some(probe));
        let result = if use_relay {
            relay.rx_packed_from_side(li, &changed)
        } else {
            router.rx_packed_queue_from_side(&changed, ri)
        };
        assert!(
            matches!(result, Err(TelemetryError::Io("memory pressure"))),
            "changed routing must retain normal admission"
        );
    }
}

#[test]
fn transparent_relay_forwards_repeated_addresses_for_global_collision_arbitration() {
    use sedsnet::discovery::{
        ADDRESS_MODE_STATIC, ADDRESS_STATE_APPROVED, AddressAdvertisement, LinkCapabilities,
        build_discovery_address,
    };
    use sedsnet::relay::Relay;
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    let tuning = sedsnet::config::runtime_tuning_config();
    let mut plain = tuning;
    plain.payload_compress_threshold = usize::MAX;
    sedsnet::config::set_runtime_tuning_config(plain).unwrap();
    let ad = AddressAdvertisement {
        hostname: "TRANSPARENT_ADDRESS".into(),
        address: 42,
        requested_address: 42,
        mode: ADDRESS_MODE_STATIC,
        state: ADDRESS_STATE_APPROVED,
        birth_ms: 1,
        owner_hash: 77,
        reachable_endpoints: vec![],
        reachable_network_variables: vec![],
        reachable_timesync_sources: vec![],
        link_capabilities: LinkCapabilities {
            version: 1,
            flags: 0,
            profile: 0,
            max_frame_bytes: 0,
            compact_header_target_bytes: 0,
            max_side_transport_templates: 0,
        },
    };
    let relay = Relay::new(Box::new(|| 0));
    let src = relay.add_side_packed("in", |_| Ok(()));
    let seen = Arc::new(AtomicUsize::new(0));
    let count = seen.clone();
    relay.add_side_packed("out", move |wire| {
        if sedsnet::wire_format::peek_frame_info(wire)?.envelope.ty
            == sedsnet::config::DataType::DiscoveryAddress
        {
            count.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    });
    for timestamp in [1, 2] {
        let wire = sedsnet::wire_format::pack_packet(
            &build_discovery_address("TRANSPARENT_ADDRESS", timestamp, &ad).unwrap(),
        );
        relay.rx_packed_from_side(src, &wire).unwrap();
        relay.process_all_queues().unwrap();
    }
    sedsnet::config::set_runtime_tuning_config(tuning).unwrap();
    assert_eq!(
        seen.load(Ordering::Relaxed),
        2,
        "unchanged addresses must cross transparent relays too"
    );
}

static FRAGMENT_WORK: AtomicUsize = AtomicUsize::new(0);
static FRAGMENT_LARGEST: AtomicUsize = AtomicUsize::new(0);
extern "C" fn bounded_fragment_probe(additional: usize, largest: usize, _: u32) -> bool {
    FRAGMENT_WORK.store(additional, Ordering::Relaxed);
    FRAGMENT_LARGEST.store(largest, Ordering::Relaxed);
    additional <= 1600 && largest <= 1024
}

#[test]
fn retained_fragment_insertion_does_not_charge_complete_packet_decoder() {
    use sedsnet::relay::Relay;
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    for use_relay in [false, true] {
        sedsnet::memory_admission::set_probe(None);
        let router = Router::new_with_clock(RouterConfig::default(), Box::new(|| 0));
        let ri = router.add_side_packed("can", |_| Ok(()));
        let relay = Relay::new(Box::new(|| 0));
        let li = relay.add_side_packed("can", |_| Ok(()));
        let mut fragment = b"SDT\x03".to_vec();
        fragment.extend_from_slice(&12345u32.to_le_bytes());
        fragment.extend_from_slice(&0u16.to_le_bytes());
        fragment.extend_from_slice(&65u16.to_le_bytes());
        fragment.extend_from_slice(&[7u8; 94]);
        fragment.extend_from_slice(&[0u8; 4]);
        for index in 0..64u16 {
            // Alternating ends exercises out-of-order B-tree node splits.
            let index = if index % 2 == 0 {
                index / 2
            } else {
                63 - index / 2
            };
            fragment[8..10].copy_from_slice(&index.to_le_bytes());
            let n = fragment.len();
            let crc = crc32fast::hash(&fragment[..n - 4]);
            fragment[n - 4..].copy_from_slice(&crc.to_le_bytes());
            LIVE_ALLOCATION_DELTA.with(|v| v.set(Some(0)));
            PEAK_ALLOCATION_DELTA.with(|v| v.set(0));
            MAX_ALLOCATION.with(|v| v.set(Some(0)));
            let result = if use_relay {
                relay.rx_packed_from_side(li, &fragment)
            } else {
                router.rx_packed_queue_from_side(&fragment, ri)
            };
            let peak = PEAK_ALLOCATION_DELTA.with(|v| v.get());
            LIVE_ALLOCATION_DELTA.with(|v| v.set(None));
            let largest = MAX_ALLOCATION.with(|v| v.replace(None).unwrap());
            result.unwrap();
            if index == 0 {
                sedsnet::memory_admission::set_probe_v2(Some(bounded_fragment_probe));
            } else {
                assert!(
                    peak <= FRAGMENT_WORK.load(Ordering::Relaxed) as isize,
                    "relay={use_relay} index={index} peak={peak} largest={largest} shared={}",
                    core::mem::size_of::<sedsnet::SharedBytes>()
                );
                assert!(
                    largest <= FRAGMENT_LARGEST.load(Ordering::Relaxed),
                    "relay={use_relay} index={index} largest={largest}"
                );
            }
        }
        // Exceeding the bounded tree requires the original full guard too.
        fragment[8..10].copy_from_slice(&64u16.to_le_bytes());
        let n = fragment.len();
        let crc = crc32fast::hash(&fragment[..n - 4]);
        fragment[n - 4..].copy_from_slice(&crc.to_le_bytes());
        let result = if use_relay {
            relay.rx_packed_from_side(li, &fragment)
        } else {
            router.rx_packed_queue_from_side(&fragment, ri)
        };
        assert!(matches!(result, Err(TelemetryError::Io("memory pressure"))));
        // A new transfer still needs the full initial allocation guard.
        fragment[4..8].copy_from_slice(&54321u32.to_le_bytes());
        let n = fragment.len();
        let crc = crc32fast::hash(&fragment[..n - 4]);
        fragment[n - 4..].copy_from_slice(&crc.to_le_bytes());
        let result = if use_relay {
            relay.rx_packed_from_side(li, &fragment)
        } else {
            router.rx_packed_queue_from_side(&fragment, ri)
        };
        assert!(matches!(result, Err(TelemetryError::Io("memory pressure"))));
    }
}

#[test]
fn scheduling_metadata_queries_do_not_allocate_for_known_or_unknown_types() {
    let _lock = TEST_LOCK.lock().unwrap();
    let ep = register_endpoint_with_description("DELIVERY_META_SINK", "", false).unwrap();
    let ty = register_data_type_with_description(
        "DELIVERY_META_DATA",
        "",
        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
        &[ep],
        ReliableMode::Unordered,
        123,
    )
    .unwrap();
    let unknown = sedsnet::config::DataType(u32::MAX);
    assert!(!sedsnet::config::data_type_exists(unknown));
    ALLOCATION_COUNT.with(|v| v.set(Some(0)));
    for _ in 0..64 {
        assert!(sedsnet::is_reliable_type(ty));
        assert_eq!(sedsnet::reliable_mode(ty), ReliableMode::Unordered);
        assert_eq!(sedsnet::message_priority(ty), 123);
        assert!(!sedsnet::is_reliable_type(unknown));
        assert_eq!(sedsnet::reliable_mode(unknown), ReliableMode::None);
        assert_eq!(sedsnet::message_priority(unknown), 0);
    }
    let allocations = ALLOCATION_COUNT.with(|v| v.replace(None).unwrap());
    assert_eq!(allocations, 0);
    for (mode, priority) in [
        (sedsnet::ReliableMode::Unordered, 231),
        (sedsnet::ReliableMode::Ordered, 241),
        (sedsnet::ReliableMode::None, 0),
    ] {
        let mut definition = sedsnet::config::data_type_definition(ty).unwrap();
        definition.reliable = mode;
        definition.priority = priority;
        sedsnet::config::merge_owned_schema_snapshot_with_budget(
            sedsnet::config::OwnedRuntimeSchemaSnapshot {
                endpoints: vec![],
                types: vec![definition],
            },
            usize::MAX,
        )
        .unwrap();
        // Conflicting wire contracts use the deterministic merge winner.
        // The fast accessors must reflect that current winner, never a cache.
        let current = sedsnet::config::data_type_definition(ty).unwrap();
        assert_eq!(sedsnet::reliable_mode(ty), current.reliable);
        assert_eq!(
            sedsnet::is_reliable_type(ty),
            current.reliable != sedsnet::ReliableMode::None
        );
        assert_eq!(sedsnet::message_priority(ty), current.priority);
        if mode == sedsnet::ReliableMode::Unordered && priority == 231 {
            assert_eq!(current.priority, 231);
        }
    }
}

#[test]
fn full_topology_response_has_bounded_snapshot_allocation_peak() {
    let _lock = TEST_LOCK.lock().unwrap();
    let _reset = Reset;
    let router = Router::new_with_clock(
        RouterConfig::default()
            .with_sender("GB")
            .with_preferred_discovery_master("GS"),
        Box::new(|| 0),
    );
    let ingress = router.add_side_packed("can", |_| Ok(()));
    let packets = Arc::new(AtomicUsize::new(0));
    let count = packets.clone();
    let requester = router.add_side_packet("uart", move |packet| {
        if packet.data_type() == sedsnet::config::DataType::DiscoveryTopology {
            count.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    });
    router
        .rx_from_side(
            &sedsnet::discovery::build_discovery_topology("PEER", 0, &large_snapshot_graph())
                .unwrap(),
            ingress,
        )
        .unwrap();
    router.drain_queues_with_timeout(0).unwrap();
    let request = sedsnet::discovery::build_discovery_topology_request("GS", 0).unwrap();
    let before = packets.load(Ordering::Relaxed);
    LIVE_ALLOCATION_DELTA.with(|n| n.set(Some(0)));
    PEAK_ALLOCATION_DELTA.with(|n| n.set(0));
    ALLOCATION_COUNT.with(|n| n.set(Some(0)));
    router.rx_from_side(&request, requester).unwrap();
    router.drain_queues_with_timeout(0).unwrap();
    let allocations = ALLOCATION_COUNT.with(|n| n.replace(None).unwrap());
    let peak = PEAK_ALLOCATION_DELTA.with(|n| n.get());
    LIVE_ALLOCATION_DELTA.with(|n| n.set(None));
    assert!(packets.load(Ordering::Relaxed) > before);
    println!("full topology response: allocations={allocations} peak_bytes={peak}");
    assert!(
        allocations <= 500,
        "discovery election cloned graph names: {allocations} allocations"
    );
    assert!(
        peak <= 17500,
        "discovery response retained excess graph scratch: {peak} bytes"
    );
}
