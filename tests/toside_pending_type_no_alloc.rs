#![cfg(all(feature = "std", feature = "discovery"))]
use sedsnet::{
    MessageClass, MessageDataType, MessageElement, ReliableMode, config,
    packet::Packet,
    router::{Router, RouterConfig},
    wire_format,
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};
thread_local! {static COUNT:Cell<Option<usize>>=const{Cell::new(None)};}
struct Counting;
#[global_allocator]
static ALLOCATOR: Counting = Counting;
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let _ = COUNT.try_with(|c| {
            if let Some(n) = c.get() {
                c.set(Some(n + 1))
            }
        });
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
}
#[test]
fn queued_toside_inspection_allocates_and_pins_nothing() {
    #[cfg(feature = "compact-packet-store")]
    let store = sedsnet::packet_store::PacketStore::new(262144, 256, 262144).unwrap();
    #[cfg(feature = "compact-packet-store")]
    sedsnet::packet_store::set_default_store(Some(store.clone()));
    let ep = config::register_endpoint("TOSIDE_ALLOC_DEST", false).unwrap();
    let bulk = config::register_data_type_with_description(
        "TOSIDE_ALLOC_BULK",
        "",
        MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        16,
    )
    .unwrap();
    let stop = config::register_data_type_with_description(
        "TOSIDE_ALLOC_STOP",
        "",
        MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::Unordered,
        240,
    )
    .unwrap();
    let node = Router::new(RouterConfig::new([]).with_sender("toside-allocation-router"));
    let upstream = node.add_side_packed("upstream", |_| Ok(()));
    let downstream = node.add_side_packed("downstream", |_| Ok(()));
    node.rx_from_side(
        &sedsnet::discovery::build_discovery_announce("toside-allocation-leaf", 1, &[ep]).unwrap(),
        downstream,
    )
    .unwrap();
    node.process_all_queues_with_timeout(0).unwrap();
    node.clear_queues();
    #[cfg(feature = "compact-packet-store")]
    let baseline = store.stats();
    let mut noise = 0x13572468u32;
    let data: Vec<u8> = (0..1024)
        .map(|_| {
            noise ^= noise << 13;
            noise ^= noise >> 17;
            noise ^= noise << 5;
            noise as u8
        })
        .collect();
    let packet = Packet::new(bulk, &[ep], "toside-allocation-writer", 100, data.into()).unwrap();
    let id = packet.packet_id();
    let raw = wire_format::pack_packet(&packet);
    let raw_len = raw.len();
    node.rx_packed_queue_from_side(&raw, upstream).unwrap();
    drop(raw);
    drop(packet);
    node.process_rx_queue_with_timeout(0).unwrap();
    assert_eq!(
        node.queue_counters()[11],
        0,
        "the proof must not be an E2E retained owner"
    );
    assert!(node.has_pending_reliable_tx_type(bulk));
    assert!(!node.has_pending_reliable_tx_type(stop));
    #[cfg(feature = "compact-packet-store")]
    let before = store.stats();
    #[cfg(feature = "compact-packet-store")]
    {
        assert!(before.live_handles > baseline.live_handles);
        assert!(before.live_bytes >= baseline.live_bytes + raw_len);
        assert_eq!(before.pinned_bytes, 0);
    }
    COUNT.with(|c| c.set(Some(0)));
    for _ in 0..1000 {
        assert!(node.has_pending_reliable_tx_type(bulk));
        assert!(!node.has_pending_reliable_tx_type(stop));
    }
    let count = COUNT.with(|c| c.replace(None)).unwrap();
    assert_eq!(count, 0);
    #[cfg(feature = "compact-packet-store")]
    {
        assert_eq!(store.stats(), before);
        eprintln!(
            "TOSIDE_PARKED_QUERY: baseline={baseline:?} before={before:?} after={:?}",
            store.stats()
        );
    }
    eprintln!(
        "TOSIDE_QUERY_ALLOCATIONS: calls=2000 allocations={count} id={id} raw_len={raw_len} known_type={} stop_type={}",
        bulk.as_u32(),
        stop.as_u32()
    );
}
