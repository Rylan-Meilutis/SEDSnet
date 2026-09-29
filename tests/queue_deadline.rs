use sedsnet::config::{register_data_type_with_description, register_endpoint_with_description};
use sedsnet::packet::Packet;
use sedsnet::router::{EndpointHandler, Router, RouterConfig};
use sedsnet::{MessageClass, MessageDataType, MessageElement, ReliableMode};
use std::sync::{
    Arc,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};

#[test]
fn one_millisecond_budget_services_multiple_packets_and_stops_at_deadline() {
    let ep =
        register_endpoint_with_description("BUDGET_TEST", "queue deadline test", false).unwrap();
    let ty = register_data_type_with_description(
        "BUDGET_TEST_DATA",
        "queue deadline test",
        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        0,
    )
    .unwrap();
    let clock = Arc::new(AtomicU64::new(0));
    let step = Arc::new(AtomicU64::new(0));
    let hits = Arc::new(AtomicUsize::new(0));
    let (c, s, h) = (clock.clone(), step.clone(), hits.clone());
    let handler = EndpointHandler::new_packet_handler(ep, move |_| {
        h.fetch_add(1, Ordering::SeqCst);
        c.fetch_add(s.load(Ordering::SeqCst), Ordering::SeqCst);
        Ok(())
    });
    let c = clock.clone();
    let router = Router::new_with_clock(
        RouterConfig::new(vec![handler]),
        Box::new(move || c.load(Ordering::SeqCst)),
    );
    let queue = |base: u64| {
        for i in 0..12 {
            router
                .tx_queue(Packet::from_f32_slice(ty, &[i as f32], &[ep], base + i).unwrap())
                .unwrap();
        }
    };
    queue(0);
    router.process_all_queues_with_timeout(1).unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        12,
        "1 ms must not round TX to one packet per pass"
    );
    step.store(1, Ordering::SeqCst);
    queue(20);
    router.process_all_queues_with_timeout(1).unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        13,
        "stop after the callback consumes the deadline"
    );
    router.process_all_queues_with_timeout(0).unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        24,
        "zero budget still drains completely"
    );
}
