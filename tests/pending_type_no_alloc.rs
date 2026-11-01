#![cfg(all(feature = "std", feature = "discovery"))]
use sedsnet::{
    MessageClass, MessageDataType, MessageElement, ReliableMode, TelemetryError, config,
    packet::Packet,
    router::{Router, RouterConfig},
    wire_format,
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
thread_local! {static COUNT:Cell<Option<usize>>=const {Cell::new(None)};}
struct Counting;
#[global_allocator]
static ALLOCATOR: Counting = Counting;
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = COUNT.try_with(|c| {
            if let Some(n) = c.get() {
                c.set(Some(n + 1))
            }
        });
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
}
#[test]
fn known_packed_pending_type_queries_allocate_and_pin_nothing() {
    #[cfg(feature = "compact-packet-store")]
    let store = sedsnet::packet_store::PacketStore::new(65536, 128, 65536).unwrap();
    #[cfg(feature = "compact-packet-store")]
    sedsnet::packet_store::set_default_store(Some(store.clone()));
    let ep = config::register_endpoint("PENDING_ALLOC_LEAF", false).unwrap();
    let ty = config::register_data_type_with_description(
        "PENDING_ALLOC_BULK",
        "",
        MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::Ordered,
        16,
    )
    .unwrap();
    let other = config::register_data_type_with_description(
        "PENDING_ALLOC_OTHER",
        "",
        MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::Unordered,
        200,
    )
    .unwrap();
    let observed = Arc::new(AtomicU64::new(0));
    let observed_wire = observed.clone();
    let router = Router::new(RouterConfig::new([]).with_sender("host"));
    let side = router.add_side_packed("busy", move |wire| {
        if wire_format::peek_frame_info(wire).is_ok_and(|f| f.envelope.ty == ty) {
            observed_wire.store(
                wire_format::packet_id_from_wire(wire).unwrap(),
                Ordering::Relaxed,
            );
            Err(TelemetryError::Io("test busy"))
        } else {
            Ok(())
        }
    });
    router
        .rx_from_side(
            &sedsnet::discovery::build_discovery_announce("leaf", 123, &[ep]).unwrap(),
            side,
        )
        .unwrap();
    router.process_all_queues_with_timeout(0).unwrap();
    let mut noise = 0x13572468u32;
    let payload: Vec<u8> = (0..1024)
        .map(|_| {
            noise ^= noise << 13;
            noise ^= noise >> 17;
            noise ^= noise << 5;
            noise as u8
        })
        .collect();
    let packet = Packet::new_with_nonce(ty, &[ep], "host", 100, 77, payload.into()).unwrap();
    let id = packet.packet_id();
    router
        .tx_packed_queue(wire_format::pack_packet(&packet))
        .unwrap();
    drop(packet);
    let _ = router.process_all_queues_with_timeout(0);
    // The diagnostic owner export materializes Packed bytes in compact builds;
    // use the exact submitted/observed wire ID and nonmaterializing owner count.
    assert_eq!(observed.load(Ordering::Relaxed), id);
    assert_eq!(router.queue_counters()[11], 1);
    #[cfg(feature = "compact-packet-store")]
    let before = store.stats();
    #[cfg(feature = "compact-packet-store")]
    {
        assert!(
            before.live_handles > 0,
            "actual parked payload witness required"
        );
        assert_eq!(before.pinned_bytes, 0);
    }
    COUNT.with(|c| c.set(Some(0)));
    for _ in 0..1000 {
        assert!(router.has_pending_reliable_tx_type(ty));
        assert!(!router.has_pending_reliable_tx_type(other));
    }
    let count = COUNT.with(|c| c.replace(None)).unwrap();
    assert_eq!(count, 0);
    #[cfg(feature = "compact-packet-store")]
    {
        let after = store.stats();
        assert_eq!(
            after, before,
            "query must not materialize, pin or compact payloads"
        );
        eprintln!("PENDING_QUERY_ARENA: before={before:?} after={after:?}");
    }
    #[cfg(feature = "compact-packet-store")]
    let export_before = store.stats();
    let owners = router.export_reliable_pending_stats();
    assert_eq!(owners.len(), 1);
    assert_eq!((owners[0].packet_id, owners[0].data_type), (id, ty));
    #[cfg(feature = "compact-packet-store")]
    {
        assert_eq!(
            store.stats(),
            export_before,
            "known-type export must not materialize or pin the owner"
        );
        eprintln!(
            "PENDING_TYPE_EXPORT: before={export_before:?} after={:?} returned_type={}",
            store.stats(),
            owners[0].data_type.as_u32()
        );
    }
    eprintln!(
        "PENDING_QUERY_ALLOCATION: queries=2000 allocations={count} exact_id={id} type={}",
        ty.as_u32()
    );
}
