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
    sync::{Arc, Condvar, Mutex, mpsc},
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
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        unsafe { System.dealloc(p, layout) }
    }
}
#[test]
fn held_known_active_queries_allocate_and_pin_nothing() {
    #[cfg(feature = "compact-packet-store")]
    let store = sedsnet::packet_store::PacketStore::new(65536, 128, 65536).unwrap();
    #[cfg(feature = "compact-packet-store")]
    sedsnet::packet_store::set_default_store(Some(store.clone()));
    let ep = config::register_endpoint("ACTIVE_ALLOC_LEAF", false).unwrap();
    let ty = config::register_data_type_with_description(
        "ACTIVE_ALLOC_DATA",
        "",
        MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        0,
    )
    .unwrap();
    let other = config::register_data_type_with_description(
        "ACTIVE_ALLOC_OTHER",
        "",
        MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::Unordered,
        200,
    )
    .unwrap();
    let router = Arc::new(Router::new(
        RouterConfig::new([]).with_sender("active-allocation-host"),
    ));
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let hold = gate.clone();
    let (tx, rx) = mpsc::sync_channel(1);
    let side = router.add_side_packed("held", move |wire| {
        if wire_format::peek_frame_info(wire).is_ok_and(|frame| frame.envelope.ty == ty) {
            tx.send(()).unwrap();
            let (lock, cv) = &*hold;
            let mut ready = lock.lock().unwrap();
            while !*ready {
                ready = cv.wait(ready).unwrap();
            }
        }
        Ok(())
    });
    router
        .rx_from_side(
            &sedsnet::discovery::build_discovery_announce("active-allocation-leaf", 1, &[ep])
                .unwrap(),
            side,
        )
        .unwrap();
    router.process_all_queues_with_timeout(0).unwrap();
    let packet = Packet::new_with_nonce(
        ty,
        &[ep],
        "active-allocation-host",
        100,
        22,
        Arc::from([7u8].as_slice()),
    )
    .unwrap();
    router
        .tx_packed_queue(wire_format::pack_packet(&packet))
        .unwrap();
    drop(packet);
    let worker = router.clone();
    let task = std::thread::spawn(move || worker.process_all_queues_with_timeout(0));
    let entered = rx.recv_timeout(std::time::Duration::from_secs(2));
    #[cfg(feature = "compact-packet-store")]
    let before = store.stats();
    COUNT.with(|c| c.set(Some(0)));
    let mut exact = true;
    for _ in 0..1000 {
        exact &= router.has_pending_reliable_tx_type(ty);
        exact &= !router.has_pending_reliable_tx_type(other);
    }
    let allocations = COUNT.with(|c| c.replace(None)).unwrap();
    #[cfg(feature = "compact-packet-store")]
    let after = store.stats();
    {
        let (lock, cv) = &*gate;
        *lock.lock().unwrap() = true;
        cv.notify_all();
    }
    let finished = task.join().unwrap();
    assert!(entered.is_ok());
    finished.unwrap();
    assert!(exact);
    assert_eq!(allocations, 0);
    assert!(!router.has_pending_reliable_tx_type(ty));
    #[cfg(feature = "compact-packet-store")]
    {
        assert!(before.live_handles > 0);
        assert_eq!(
            before, after,
            "queries must not pin/materialize/compact held bytes"
        );
        eprintln!("ACTIVE_QUERY_ARENA before={before:?} after={after:?}");
    }
    eprintln!("ACTIVE_QUERY_ALLOCATION calls=2000 allocations={allocations}");
}
