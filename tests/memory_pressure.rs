#![cfg(all(feature = "std", feature = "discovery"))]
use sedsnet::config::{register_data_type_with_description, register_endpoint_with_description};
use sedsnet::packet::Packet;
use sedsnet::router::{EndpointHandler, Router, RouterConfig};
use sedsnet::{MessageClass, MessageDataType, MessageElement, ReliableMode, TelemetryError};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
static ALLOW: AtomicBool = AtomicBool::new(true);
extern "C" fn probe(_additional: usize, _largest: usize) -> bool {
    ALLOW.load(Ordering::Relaxed)
}
struct Reset;
impl Drop for Reset {
    fn drop(&mut self) {
        sedsnet::memory_admission::set_probe(None);
    }
}

#[test]
fn pressure_rejects_new_ingress_while_retained_work_dispatches_and_recovers() {
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
    router.tx_queue(Packet::from_f32_slice(ty, &[5.0], &[ep], 5).unwrap()).unwrap();
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
