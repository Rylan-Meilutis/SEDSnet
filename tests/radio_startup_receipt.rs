#![cfg(all(feature = "std", feature = "discovery"))]
use sedsnet::config::DataType;
use sedsnet::config::{
    RuntimeTuningConfig, register_data_type_with_description, register_endpoint_with_description,
    runtime_tuning_config, set_runtime_tuning_config,
};
use sedsnet::discovery::{TopologyBoardNode, build_discovery_topology};
use sedsnet::packet::Packet;
use sedsnet::router::{EndpointHandler, Router, RouterConfig};
use sedsnet::{MessageClass, MessageDataType, MessageElement, ReliableMode, TelemetryError};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};

struct Restore(RuntimeTuningConfig);
impl Drop for Restore {
    fn drop(&mut self) {
        set_runtime_tuning_config(self.0).unwrap();
    }
}

#[test]
fn captured_radio_startup_receipt_survives_bounded_retry_tuning() {
    let saved = runtime_tuning_config();
    let _restore = Restore(saved);
    let ep = register_endpoint_with_description("LATE_RADIO_GS", "", false).unwrap();
    let ty = register_data_type_with_description(
        "LATE_RADIO_WARNING",
        "",
        MessageElement::Dynamic(MessageDataType::String, MessageClass::Data),
        &[ep],
        ReliableMode::Ordered,
        0,
    )
    .unwrap();
    for retries in [8, 24] {
        let mut tuning = saved;
        tuning.reliable_max_retries = retries;
        tuning.reliable_retransmit_ms = 200;
        set_runtime_tuning_config(tuning).unwrap();
        assert_eq!(
            runtime_tuning_config().reliable_max_end_to_end_pending,
            saved.reliable_max_end_to_end_pending
        );
        assert_eq!(
            runtime_tuning_config().reliable_max_pending,
            saved.reliable_max_pending
        );
        let now = Arc::new(AtomicU64::new(592));
        let clock = now.clone();
        let source = Router::new_with_clock(
            RouterConfig::default().with_sender("FC"),
            Box::new(move || clock.load(Ordering::Relaxed)),
        );
        let frames = Arc::new(Mutex::new(Vec::new()));
        let output = frames.clone();
        let side = source.add_side_packed("radio", move |wire| {
            if sedsnet::wire_format::peek_envelope(wire).is_ok_and(|e| e.ty == ty) {
                output.lock().unwrap().push(wire.to_vec());
            }
            Ok(())
        });
        let count = Arc::new(AtomicUsize::new(0));
        let delivered = count.clone();
        let clock = now.clone();
        let sink = Router::new_with_clock(
            RouterConfig::new([EndpointHandler::new_packet_handler(ep, move |_| {
                delivered.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })])
            .with_sender("GS"),
            Box::new(move || clock.load(Ordering::Relaxed)),
        );
        let receipts = Arc::new(Mutex::new(Vec::new()));
        let output = receipts.clone();
        let sink_side = sink.add_side_packed("radio", move |wire| {
            if sedsnet::wire_format::peek_envelope(wire)
                .is_ok_and(|e| e.ty == DataType::ReliableAck)
            {
                output.lock().unwrap().push(wire.to_vec());
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
        source.rx_from_side(&topology, side).unwrap();
        source.drain_queues_with_timeout(0).unwrap();
        source
            .tx(Packet::new(
                ty,
                &[ep],
                "FC",
                441,
                Arc::<[u8]>::from(&b"SD unavailable; flight/network continue"[..]),
            )
            .unwrap())
            .unwrap();
        let wire = frames.lock().unwrap()[0].clone();
        sink.rx_packed_from_side(&wire, sink_side).unwrap();
        sink.drain_queues_with_timeout(0).unwrap();
        let receipt = receipts
            .lock()
            .unwrap()
            .first()
            .expect("receiver generated actual receipt")
            .clone();
        let mut exhausted = None;
        for ms in (792..=2792).step_by(200) {
            now.store(ms, Ordering::Relaxed);
            if let Err(error) = source.drain_queues_with_timeout(0) {
                exhausted = Some((ms, error));
                break;
            }
        }
        if retries == 8 {
            assert!(matches!(
                exhausted,
                Some((
                    2392,
                    TelemetryError::HandlerError("ordered end-to-end delivery exhausted retries")
                ))
            ));
        } else {
            assert!(
                exhausted.is_none(),
                "late radio receipt must remain within bounded retry window: {exhausted:?}"
            );
            assert_eq!(
                source
                    .export_runtime_stats()
                    .reliable
                    .end_to_end_pending_count,
                1
            );
        }
        now.store(2820, Ordering::Relaxed);
        source.rx_packed_from_side(&receipt, side).unwrap();
        source.drain_queues_with_timeout(0).unwrap();
        assert_eq!(
            source
                .export_runtime_stats()
                .reliable
                .end_to_end_pending_count,
            0
        );
        assert_eq!(count.load(Ordering::Relaxed), 1);
        now.store(10000, Ordering::Relaxed);
        source.drain_queues_with_timeout(0).unwrap();
    }
}
