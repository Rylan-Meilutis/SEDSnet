#![cfg(all(feature = "std", feature = "discovery"))]
use sedsnet::config::{register_data_type_with_description, register_endpoint};
use sedsnet::diagnostics::ReliablePendingRow;
use sedsnet::discovery::{TopologyBoardNode, build_discovery_topology};
use sedsnet::packet::Packet;
use sedsnet::router::{Router, RouterConfig, RouterSideOptions};
use sedsnet::{MessageClass, MessageDataType, MessageElement, ReliableMode};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

struct Counter;
static TRACK: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
#[global_allocator]
static ALLOCATOR: Counter = Counter;
unsafe impl GlobalAlloc for Counter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if TRACK.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if TRACK.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if TRACK.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.realloc(ptr, layout, size) }
    }
}

#[test]
fn pending_snapshot_is_paginated_without_allocating_or_mutating_delivery() {
    let ep = register_endpoint("PENDING_COPY_READER", false).unwrap();
    let ty = register_data_type_with_description(
        "PENDING_COPY_CONTROL",
        "",
        MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::Ordered,
        16,
    )
    .unwrap();
    let node = Router::new_with_clock(RouterConfig::new([]).with_sender("GS"), Box::new(|| 0));
    let side = node.add_side_packed_with_options(
        "radio",
        |_| Ok(()),
        RouterSideOptions {
            reliable_enabled: false,
            header_template_enabled: false,
            ..Default::default()
        },
    );
    let topology = build_discovery_topology(
        "FC",
        0,
        &[TopologyBoardNode {
            sender_id: "FC".into(),
            reachable_endpoints: vec![ep],
            reachable_timesync_sources: vec![],
            connections: vec!["GS".into()],
        }],
    )
    .unwrap();
    node.rx_from_side(&topology, side).unwrap();
    node.tx(Packet::new(ty, &[ep], "GS", 1, Arc::<[u8]>::from([1])).unwrap())
        .unwrap();
    assert_eq!(node.export_reliable_pending_stats().len(), 1);
    let mut rows = [ReliablePendingRow::default(); 2];
    ALLOCATIONS.store(0, Ordering::Relaxed);
    TRACK.store(true, Ordering::Relaxed);
    let total = node.copy_reliable_pending_stats(0, &mut rows);
    TRACK.store(false, Ordering::Relaxed);
    assert_eq!(ALLOCATIONS.load(Ordering::Relaxed), 0);
    assert_eq!(total, 1);
    assert_eq!(rows[0].data_type, ty.as_u32());
    assert_eq!(rows[0].pending_count, 1);
    assert_ne!(rows[0].pending_owners[0], 0);
    assert_eq!(&rows[0].pending_owners[1..], &[0; 3]);
    assert_eq!(rows[1], ReliablePendingRow::default());
    let original = node.export_reliable_pending_stats();
    assert_eq!(node.copy_reliable_pending_stats(1, &mut rows), 1);
    assert_eq!(rows, [ReliablePendingRow::default(); 2]);
    assert_eq!(node.export_reliable_pending_stats(), original);
    assert_eq!(std::mem::size_of::<ReliablePendingRow>(), 64);
}
