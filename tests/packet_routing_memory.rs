#![cfg(all(feature = "std", feature = "discovery", not(feature = "compression")))]
use sedsnet::config::{register_data_type_with_description, register_endpoint_with_description};
use sedsnet::discovery::{TopologyBoardNode, build_discovery_topology};
use sedsnet::packet::Packet;
use sedsnet::router::{Router, RouterConfig};
use sedsnet::{MessageClass, MessageDataType, MessageElement, ReliableMode};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
thread_local! { static COUNT: Cell<Option<usize>> = const { Cell::new(None) }; }
thread_local! { static LARGE: Cell<Option<usize>> = const { Cell::new(None) }; }
struct Counter;
#[global_allocator]
static ALLOCATOR: Counter = Counter;
unsafe impl GlobalAlloc for Counter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = COUNT.try_with(|n| {
            if let Some(v) = n.get() {
                n.set(Some(v + 1));
            }
        });
        if layout.size() >= 3000 {
            let _ = LARGE.try_with(|n| {
                if let Some(v) = n.get() {
                    n.set(Some(v + 1));
                }
            });
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        unsafe { System.dealloc(p, layout) }
    }
}
#[test]
fn packed_best_effort_forwarding_has_bounded_allocation_work() {
    let ep = register_endpoint_with_description("PERF_SINK", "", false).unwrap();
    let ty = register_data_type_with_description(
        "PERF_VALUE",
        "",
        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        0,
    )
    .unwrap();
    let router = Router::new_with_clock(RouterConfig::default(), Box::new(|| 0));
    let sent = Arc::new(AtomicUsize::new(0));
    let echoes = Arc::new(AtomicUsize::new(0));
    let echoes2 = echoes.clone();
    let ingress = router.add_side_packed("can", move |_| {
        echoes2.fetch_add(1, Ordering::Relaxed);
        Ok(())
    });
    let sent2 = sent.clone();
    let egress = router.add_side_packed("uart", move |_| {
        sent2.fetch_add(1, Ordering::Relaxed);
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
    router.rx_from_side(&topology, egress).unwrap();
    router.process_all_queues().unwrap();
    let frames = (1..=1000)
        .map(|i| {
            let pkt = Packet::from_f32_slice(ty, &[i as f32], &[ep], i).unwrap();
            sedsnet::wire_format::pack_packet(&pkt)
        })
        .collect::<Vec<_>>();
    let before = sent.load(Ordering::Relaxed);
    let before_echoes = echoes.load(Ordering::Relaxed);
    COUNT.with(|n| n.set(Some(0)));
    for frame in &frames {
        router.rx_packed_from_side(frame, ingress).unwrap();
    }
    let allocations = COUNT.with(|n| n.replace(None).unwrap());
    assert_eq!(sent.load(Ordering::Relaxed) - before, 1000);
    assert_eq!(echoes.load(Ordering::Relaxed), before_echoes);
    println!("allocations per forwarded packet: {}", allocations / 1000);
    // The release suite also seeds an IPC/schema fixture (29 allocations per
    // packet versus 17 with only built-ins); both must remain far below the
    // original forwarding path's 273 allocations per packet.
    assert!(
        allocations <= 35_000,
        "excessive routing allocations: {allocations}"
    );
    // Reject a corrupted checksum; do not forward or silently accept it.
    let mut corrupt = frames[0].to_vec();
    corrupt[3] ^= 1;
    assert!(router.rx_packed_from_side(&corrupt, ingress).is_err());
    assert_eq!(sent.load(Ordering::Relaxed) - before, 1000);
}

#[test]
fn large_transit_payload_is_not_decoded_by_ack_route_checks() {
    let ep = register_endpoint_with_description("LARGE_TRANSIT", "", false).unwrap();
    let ty = register_data_type_with_description(
        "LARGE_TRANSIT_DATA",
        "",
        MessageElement::Dynamic(MessageDataType::Binary, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        0,
    )
    .unwrap();
    let router = Router::new_with_clock(RouterConfig::default(), Box::new(|| 0));
    let ingress = router.add_side_packed("can", |_| Ok(()));
    let count = Arc::new(AtomicUsize::new(0));
    let output = count.clone();
    let egress = router.add_side_packed("uart", move |_| {
        output.fetch_add(1, Ordering::Relaxed);
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
    router.rx_from_side(&topology, egress).unwrap();
    router.process_all_queues().unwrap();
    let packet = Packet::new(ty, &[ep], "DAQ", 1, Arc::from(vec![0x5a; 3600])).unwrap();
    let packed = sedsnet::wire_format::pack_packet(&packet);
    let before = count.load(Ordering::Relaxed);
    LARGE.with(|n| n.set(Some(0)));
    router.rx_packed_from_side(&packed, ingress).unwrap();
    let large = LARGE.with(|n| n.replace(None).unwrap());
    assert_eq!(count.load(Ordering::Relaxed) - before, 1);
    // Own ingress once; forwarding must share it, not decode its payload.
    assert_eq!(large, 1, "transit retained extra full-size payload buffers");
}
