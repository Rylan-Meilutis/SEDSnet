//! Incomplete foreign catalogs must share admission with queued work.
//! All definitions are caller-owned; no application identifiers enter the SDK.
#![cfg(all(feature = "std", feature = "discovery"))]

use sedsnet::{
    E2eEncryptionPolicy, MessageClass, MessageDataType, MessageElement, ReliableMode,
    config::{
        self, DataEndpoint, DataType, OwnedDataTypeDefinition, OwnedRuntimeSchemaSnapshot,
        RuntimeMemoryConfig,
    },
    discovery,
    packet::Packet,
    relay::{Relay, RelayConfig},
    router::{EndpointHandler, Router, RouterConfig},
    wire_format,
};
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};

const BUDGET: usize = 32 * 1024;
type Wire = Arc<Mutex<VecDeque<Vec<u8>>>>;

fn isolated(name: &str, run: impl FnOnce()) {
    if std::env::var("SEDSNET_EGRESS_CREDIT_CHILD").as_deref() == Ok(name) {
        run();
        return;
    }
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env("SEDSNET_EGRESS_CREDIT_CHILD", name)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{name}: {}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}
fn memory() -> RuntimeMemoryConfig {
    RuntimeMemoryConfig::new(BUDGET, 16, 2048, 1.0).unwrap()
}
fn definition(prefix: &str, reliable: ReliableMode) -> (DataEndpoint, DataType) {
    let ep = config::register_endpoint_with_description(&format!("{prefix}_ENDPOINT"), "", false)
        .unwrap();
    let ty = config::register_data_type_with_description(
        &format!("{prefix}_REPORT"),
        "",
        MessageElement::Static(44, MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        reliable,
        0,
    )
    .unwrap();
    (ep, ty)
}
fn catalog(prefix: &str) -> (Vec<u8>, DataType) {
    let types = (0..64)
        .map(|index| {
            let name = format!("{prefix}_CALLER_DEFINED_REPORT_{index:03}");
            OwnedDataTypeDefinition {
                id: DataType::identity(&name),
                name,
                description: String::new(),
                element: MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
                endpoints: vec![],
                reliable: ReliableMode::None,
                priority: 0,
                e2e_encryption: E2eEncryptionPolicy::PreferOff,
            }
        })
        .collect::<Vec<_>>();
    let marker = types[0].id;
    assert!(!config::data_type_exists(marker));
    let packet = discovery::build_discovery_schema_from_owned_snapshot(
        prefix,
        1,
        OwnedRuntimeSchemaSnapshot {
            endpoints: vec![],
            types,
        },
    )
    .unwrap();
    (wire_format::pack_packet(&packet).to_vec(), marker)
}
fn fragment(id: u32, index: usize, parts: &[&[u8]]) -> Vec<u8> {
    let mut bytes = b"SDT\x03".to_vec();
    bytes.extend_from_slice(&id.to_le_bytes());
    bytes.extend_from_slice(&(index as u16).to_le_bytes());
    bytes.extend_from_slice(&(parts.len() as u16).to_le_bytes());
    bytes.extend_from_slice(parts[index]);
    bytes.extend_from_slice(&crc32fast::hash(&bytes).to_le_bytes());
    bytes
}

#[test]
fn incomplete_catalogs_leave_ordinary_admission_credit() {
    isolated(
        "incomplete_catalogs_leave_ordinary_admission_credit",
        || {
            let (ep, ty) = definition("CREDIT_ADMISSION", ReliableMode::None);
            let clock = Arc::new(AtomicU64::new(0));
            let now = clock.clone();
            let hits = Arc::new(AtomicUsize::new(0));
            let seen = hits.clone();
            let node = Router::new_with_clock(
                RouterConfig::new([EndpointHandler::new_packet_handler(ep, move |_| {
                    seen.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                })])
                .with_sender("CALLER")
                .with_memory_config(memory())
                .unwrap(),
                Box::new(move || now.load(Ordering::Relaxed)),
            );
            let sides = [
                node.add_side_packed("first", |_| Ok(())),
                node.add_side_packed("second", |_| Ok(())),
            ];
            node.clear_queues();
            let (raw, _) = catalog("INCOMPLETE_FOREIGN_CATALOG");
            let parts = raw.chunks(112).collect::<Vec<_>>();
            let mut admitted = 0;
            let mut peak = 0;
            for round in 0..8 {
                for (link, side) in sides.into_iter().enumerate() {
                    for index in 0..parts.len() - 1 {
                        clock.fetch_add(1, Ordering::Relaxed);
                        node.rx_packed_queue_from_side(
                            &fragment(10 + round * 2 + link as u32, index, &parts),
                            side,
                        )
                        .unwrap();
                        let before = node.memory_counters();
                        peak = peak.max(before[2]);
                        let mut value = [0u8; 44];
                        value[..8].copy_from_slice(&clock.load(Ordering::Relaxed).to_le_bytes());
                        let result = node.log_queue(ty, &value);
                        assert!(
                            result.is_ok(),
                            "incomplete ingress blocked ordinary admission: {result:?}; queue={:?}; memory={before:?}",
                            node.queue_counters()
                        );
                        admitted += 1;
                        node.process_tx_queue().unwrap();
                        assert!(node.memory_counters()[2] <= BUDGET as u32);
                    }
                }
            }
            assert_eq!(hits.load(Ordering::Relaxed), admitted);
            assert!(
                peak > (BUDGET / 2) as u32,
                "fixture did not create shared pressure"
            );
        },
    );
}

#[test]
fn reliable_owners_and_interleaved_catalogs_both_progress() {
    isolated(
        "reliable_owners_and_interleaved_catalogs_both_progress",
        || {
            let (ep, ty) = definition("CREDIT_RELIABLE", ReliableMode::Unordered);
            let clock = Arc::new(AtomicU64::new(0));
            let now = clock.clone();
            let outgoing: Wire = Arc::default();
            let returning: Wire = Arc::default();
            let hits = Arc::new(AtomicUsize::new(0));
            let seen = hits.clone();
            let receipts = Arc::new(AtomicUsize::new(0));
            let ack_seen = receipts.clone();
            let source = Router::new_with_clock(
                RouterConfig::new([])
                    .with_sender("PUBLISHER")
                    .with_memory_config(memory())
                    .unwrap(),
                Box::new(move || now.load(Ordering::Relaxed)),
            );
            let tx = outgoing.clone();
            let first = source.add_side_packed("first", move |b| {
                tx.lock().unwrap().push_back(b.to_vec());
                Ok(())
            });
            let second = source.add_side_packed("second", |_| Ok(()));
            let now = clock.clone();
            let sink = Router::new_with_clock(
                RouterConfig::new([EndpointHandler::new_packet_handler(ep, move |p| {
                    assert_eq!(p.payload().len(), 44);
                    seen.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                })])
                .with_sender("SUBSCRIBER")
                .with_memory_config(memory())
                .unwrap(),
                Box::new(move || now.load(Ordering::Relaxed)),
            );
            let tx = returning.clone();
            let sink_side = sink.add_side_packed("first", move |b| {
                if wire_format::peek_envelope(b).is_ok_and(|e| e.ty == DataType::ReliableAck) {
                    ack_seen.fetch_add(1, Ordering::Relaxed);
                }
                tx.lock().unwrap().push_back(b.to_vec());
                Ok(())
            });
            source.clear_queues();
            sink.clear_queues();
            source
                .rx_from_side(
                    &discovery::build_discovery_announce("SUBSCRIBER", 1, &[ep]).unwrap(),
                    first,
                )
                .unwrap();
            source.clear_queues();
            let catalogs = [catalog("FOREIGN_ALPHA"), catalog("FOREIGN_BETA")];
            let parts = catalogs
                .each_ref()
                .map(|(raw, _)| raw.chunks(112).collect::<Vec<_>>());
            let mut cursors = [0; 2];
            let mut complete = [false; 2];
            let mut pending_peak = 0;
            for tick in 0..400u64 {
                clock.store(tick * 16, Ordering::Relaxed);
                if tick % 2 == 0 {
                    for stream in 0..2 {
                        if complete[stream] {
                            continue;
                        }
                        let i = cursors[stream];
                        source
                            .rx_packed_queue_from_side(
                                &fragment(100 + stream as u32, i, &parts[stream]),
                                [first, second][stream],
                            )
                            .unwrap();
                        cursors[stream] = (i + 1) % parts[stream].len();
                    }
                }
                let mut value = [0u8; 44];
                value[..8].copy_from_slice(&(tick * 16).to_le_bytes());
                source.log_queue(ty, &value).unwrap();
                for _ in 0..4 {
                    source.process_tx_queue().unwrap();
                    pending_peak = pending_peak.max(
                        source
                            .export_runtime_stats()
                            .reliable
                            .end_to_end_pending_count,
                    );
                    while let Some(bytes) = outgoing.lock().unwrap().pop_front() {
                        sink.rx_packed_queue_from_side(&bytes, sink_side).unwrap();
                    }
                    sink.process_all_queues().unwrap();
                    while let Some(bytes) = returning.lock().unwrap().pop_front() {
                        source.rx_packed_queue_from_side(&bytes, first).unwrap();
                    }
                    source.process_rx_queue().unwrap();
                }
                complete = catalogs
                    .each_ref()
                    .map(|(_, marker)| config::data_type_exists(*marker));
                assert!(source.memory_counters()[2] <= BUDGET as u32);
            }
            assert!(
                complete.into_iter().all(|done| done),
                "catalogs never completed under continuous reports"
            );
            assert_eq!(
                hits.load(Ordering::Relaxed),
                400,
                "accepted reliable owners repeated or vanished"
            );
            assert!(receipts.load(Ordering::Relaxed) >= 400);
            assert!(pending_peak > 0);
            assert_eq!(
                source
                    .export_runtime_stats()
                    .reliable
                    .end_to_end_pending_count,
                0
            );
        },
    );
}

#[test]
fn forwarding_only_role_preserves_transit_admission() {
    isolated("forwarding_only_role_preserves_transit_admission", || {
        let (ep, ty) = definition("CREDIT_TRANSIT", ReliableMode::None);
        let clock = Arc::new(AtomicU64::new(0));
        let now = clock.clone();
        let hits = Arc::new(AtomicUsize::new(0));
        let seen = hits.clone();
        let relay = Relay::new_with_config(
            RelayConfig::default()
                .with_sender("FORWARDER")
                .with_memory_config(memory())
                .unwrap(),
            Box::new(move || now.load(Ordering::Relaxed)),
        );
        let first = relay.add_side_packed("first", |_| Ok(()));
        let second = relay.add_side_packed("second", move |bytes| {
            if wire_format::peek_envelope(bytes).is_ok_and(|e| e.ty == ty) {
                seen.fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        });
        relay.clear_queues();
        relay
            .rx_from_side(
                second,
                discovery::build_discovery_announce("TRANSIT_SUBSCRIBER", 1, &[ep]).unwrap(),
            )
            .unwrap();
        relay.process_all_queues().unwrap();
        let (raw, _) = catalog("TRANSIT_FOREIGN_CATALOG");
        let parts = raw.chunks(112).collect::<Vec<_>>();
        let mut sent = 0;
        for round in 0..4 {
            for side in [first, second] {
                for index in 0..parts.len() - 1 {
                    clock.fetch_add(1, Ordering::Relaxed);
                    relay
                        .rx_packed_from_side(
                            side,
                            &fragment(200 + round * 2 + side as u32, index, &parts),
                        )
                        .unwrap();
                    let mut value = [0u8; 44];
                    value[..8].copy_from_slice(&clock.load(Ordering::Relaxed).to_le_bytes());
                    relay
                        .rx_from_side(
                            first,
                            Packet::new(
                                ty,
                                &[ep],
                                "ORIGINAL_PUBLISHER",
                                clock.load(Ordering::Relaxed),
                                Arc::<[u8]>::from(value),
                            )
                            .unwrap(),
                        )
                        .unwrap();
                    relay.process_all_queues().unwrap();
                    sent += 1;
                    assert!(relay.export_runtime_stats().queues.shared_queue_bytes_used <= BUDGET);
                }
            }
        }
        assert_eq!(
            hits.load(Ordering::Relaxed),
            sent,
            "forwarding-only role lost admitted transit"
        );
    });
}
