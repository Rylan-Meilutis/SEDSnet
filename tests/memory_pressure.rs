#![cfg(all(feature = "std", feature = "discovery"))]
use sedsnet::config::{register_data_type_with_description, register_endpoint_with_description};
use sedsnet::packet::Packet;
use sedsnet::router::{EndpointHandler, Router, RouterConfig};
use sedsnet::{MessageClass, MessageDataType, MessageElement, ReliableMode, TelemetryError};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
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
