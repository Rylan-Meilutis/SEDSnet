//! Tests specifically for RX/relay deduplication behavior.

use crate::config::{DataEndpoint, DataType};
use crate::discovery::build_discovery_announce;
use crate::relay::Relay;
use crate::router::{Clock, EndpointHandler, Router, RouterConfig, RouterSideOptions};
use crate::tests::packed_frame_type;
use crate::tests::timeout_tests::StepClock;
use crate::{TelemetryResult, packet::Packet, wire_format};

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Simple clock that always returns 0.
fn zero_clock() -> Box<dyn Clock + Send + Sync> {
    Box::new(|| 0u64)
}

// Compression tests need explicitly best-effort traffic. The loaded runtime
// schema may mark GPS_DATA reliable, which now intentionally uses full headers.
fn best_effort_type() -> DataType {
    static TYPE: std::sync::OnceLock<DataType> = std::sync::OnceLock::new();
    *TYPE.get_or_init(|| {
        crate::tests::ensure_common_test_schema();
        crate::config::register_data_type_with_description(
            "DEDUPE_BEST_EFFORT_DATA",
            "compact transport regression fixture",
            crate::MessageElement::Static(
                3,
                crate::MessageDataType::Float32,
                crate::MessageClass::Data,
            ),
            &[DataEndpoint::named("RADIO"), DataEndpoint::named("SD_CARD")],
            crate::ReliableMode::None,
            1,
        )
        .unwrap()
    })
}

fn wire_for_value(v: u64) -> Arc<[u8]> {
    let pkt = Packet::from_f32_slice(
        best_effort_type(),
        &[v as f32, 0.0, 0.0],
        &[DataEndpoint::named("SD_CARD")],
        v,
    )
    .unwrap();
    wire_format::pack_packet(&pkt)
}

fn advertise_side(relay: &Relay, side: usize, sender: &str) {
    crate::tests::ensure_common_test_schema();
    let pkt = build_discovery_announce(sender, 0, &[DataEndpoint::named("SD_CARD")]).unwrap();
    relay.rx_from_side(side, pkt).unwrap();
}

// -----------------------------------------------------------------------
// Router dedupe tests
// -----------------------------------------------------------------------

/// Repeatedly calling `rx_packed` with the *same* wire frame must only
/// deliver it once to local handlers.
#[test]
fn router_rx_packed_deduplicates_identical_frames() {
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_c = hits.clone();

    let handler = EndpointHandler::new_packet_handler(
        DataEndpoint::named("SD_CARD"),
        move |_pkt: &Packet| {
            hits_c.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    );

    // Router with no TX; only RX + local fan-out.
    let r = Router::new_with_clock(RouterConfig::new(vec![handler]), zero_clock());

    // Build a single wire frame we will reuse.
    let pkt = Packet::from_f32_slice(
        best_effort_type(),
        &[1.0_f32, 2.0, 3.0],
        &[DataEndpoint::named("SD_CARD")],
        0,
    )
    .unwrap();
    let wire = wire_format::pack_packet(&pkt);

    // Feed the identical frame many times.
    for _ in 0..5 {
        r.rx_packed(&wire).unwrap();
    }

    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "rx_packed should deliver identical frames only once"
    );
}

/// Even if time advances between deliveries, the same frame must still be
/// deduped (i.e. dedupe is not time-window based).
#[test]
fn router_rx_packed_dedup_persists_across_time_advance() {
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_c = hits.clone();

    let handler = EndpointHandler::new_packet_handler(
        DataEndpoint::named("SD_CARD"),
        move |_pkt: &Packet| {
            hits_c.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    );

    // Step clock that advances every time we look at it.
    let clock = StepClock::new_box(0, 1);
    let r = Router::new_with_clock(RouterConfig::new(vec![handler]), clock);

    let pkt = Packet::from_f32_slice(
        best_effort_type(),
        &[1.0_f32, 2.0, 3.0],
        &[DataEndpoint::named("SD_CARD")],
        0,
    )
    .unwrap();
    let wire = wire_format::pack_packet(&pkt);

    // First time → delivered.
    r.rx_packed(&wire).unwrap();
    // Time advances inside router via Clock, but dedupe should still drop it.
    r.rx_packed(&wire).unwrap();

    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "dedupe should persist even as clock advances"
    );
}

/// Two *different* frames must both be delivered, never deduped against
/// each other.
#[test]
fn router_rx_packed_does_not_dedupe_different_frames() {
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_c = hits.clone();

    let handler = EndpointHandler::new_packet_handler(
        DataEndpoint::named("SD_CARD"),
        move |_pkt: &Packet| {
            hits_c.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    );

    let r = Router::new_with_clock(RouterConfig::new(vec![handler]), zero_clock());

    // Frame A
    let pkt_a = Packet::from_f32_slice(
        best_effort_type(),
        &[1.0_f32, 2.0, 3.0],
        &[DataEndpoint::named("SD_CARD")],
        0,
    )
    .unwrap();
    let wire_a = wire_format::pack_packet(&pkt_a);

    // Frame B (different payload)
    let pkt_b = Packet::from_f32_slice(
        best_effort_type(),
        &[4.0_f32, 5.0, 6.0],
        &[DataEndpoint::named("SD_CARD")],
        0,
    )
    .unwrap();
    let wire_b = wire_format::pack_packet(&pkt_b);

    r.rx_packed(&wire_a).unwrap();
    r.rx_packed(&wire_b).unwrap();

    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "different frames must never be deduplicated"
    );
}

#[test]
fn router_rx_packed_does_not_dedupe_same_payload_same_ms_when_nonce_differs() {
    crate::tests::ensure_common_test_schema();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_c = hits.clone();

    let handler = EndpointHandler::new_packet_handler(
        DataEndpoint::named("SD_CARD"),
        move |_pkt: &Packet| {
            hits_c.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    );

    let r = Router::new_with_clock(RouterConfig::new(vec![handler]), zero_clock());

    let pkt_a = Packet::from_f32_slice(
        best_effort_type(),
        &[1.0_f32, 2.0, 3.0],
        &[DataEndpoint::named("SD_CARD")],
        0,
    )
    .unwrap();
    let pkt_b = Packet::from_f32_slice(
        best_effort_type(),
        &[1.0_f32, 2.0, 3.0],
        &[DataEndpoint::named("SD_CARD")],
        0,
    )
    .unwrap();

    let wire_a = wire_format::pack_packet(&pkt_a);
    let wire_b = wire_format::pack_packet(&pkt_b);

    r.rx_packed(&wire_a).unwrap();
    r.rx_packed(&wire_b).unwrap();

    assert_ne!(pkt_a.nonce(), pkt_b.nonce());
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[test]
fn packed_side_header_templates_reduce_followup_frame_size() {
    crate::tests::ensure_common_test_schema();
    let delivered = Arc::new(AtomicUsize::new(0));
    let delivered_c = delivered.clone();
    let receiver = Arc::new(Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(
            DataEndpoint::named("SD_CARD"),
            move |_pkt: &Packet| {
                delivered_c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )]),
        zero_clock(),
    ));
    let receiver_side_id = Arc::new(Mutex::new(None));
    let receiver_side_id_c = receiver_side_id.clone();
    let frames = Arc::new(Mutex::new(Vec::<usize>::new()));
    let frames_c = frames.clone();
    let receiver_c = receiver.clone();

    let sender = Router::new_with_clock(RouterConfig::default(), zero_clock());
    sender.add_side_packed_small_packets(
        "link",
        move |bytes: &[u8]| {
            frames_c.lock().unwrap().push(bytes.len());
            let side = receiver_side_id_c
                .lock()
                .unwrap()
                .expect("receiver side id");
            receiver_c.rx_packed_from_side(bytes, side)
        },
        0,
    );
    let rx_side = receiver.add_side_packed_with_options(
        "link",
        |_bytes| Ok(()),
        RouterSideOptions {
            header_template_enabled: true,
            ..RouterSideOptions::default()
        },
    );
    *receiver_side_id.lock().unwrap() = Some(rx_side);

    let pkt_a = Packet::from_f32_slice(
        best_effort_type(),
        &[1.0_f32, 2.0, 3.0],
        &[DataEndpoint::named("SD_CARD")],
        10_000,
    )
    .unwrap()
    .with_nonce(11);
    let pkt_b = Packet::from_f32_slice(
        best_effort_type(),
        &[4.0_f32, 5.0, 6.0],
        &[DataEndpoint::named("SD_CARD")],
        10_001,
    )
    .unwrap()
    .with_nonce(12);

    sender.tx(pkt_a).unwrap();
    sender.tx(pkt_b).unwrap();

    let lens = frames.lock().unwrap();
    assert_eq!(delivered.load(Ordering::SeqCst), 2);
    assert_eq!(lens.len(), 2);
    assert!(lens[1] < lens[0], "second frame should use compact header");

    let stats = sender.export_runtime_stats();
    let side = stats
        .sides
        .iter()
        .find(|side| side.side_name == "link")
        .expect("link side stats");
    assert!(side.header_template_enabled);
    assert_eq!(side.side_transport_profile, "ipv6_like");
    assert_eq!(side.side_transport_full_frames, 1);
    assert_eq!(side.side_transport_compact_frames, 1);
    assert_eq!(side.side_transport_compact_delta_frames, 0);
    assert!(side.side_transport_bytes_saved > 0);
    assert_eq!(
        side.compact_header_target_bytes,
        crate::router::IPV6_LIKE_COMPACT_HEADER_TARGET_BYTES
    );
    assert!(
        side.side_transport_min_compact_overhead_bytes
            .expect("compact overhead")
            <= side.compact_header_target_bytes,
        "simple compact follow-up frames should fit the configured overhead target"
    );
    assert_eq!(side.side_transport_compact_target_misses, 0);
}

#[test]
fn compact_templates_from_multiple_bus_producers_do_not_alias() {
    crate::tests::ensure_common_test_schema();
    let delivered = Arc::new(Mutex::new(Vec::<String>::new()));
    let delivered_c = delivered.clone();
    let receiver = Router::new_with_clock(
        RouterConfig::new([EndpointHandler::new_packet_handler(
            DataEndpoint::named("SD_CARD"),
            move |packet| {
                delivered_c
                    .lock()
                    .unwrap()
                    .push(packet.sender().to_string());
                Ok(())
            },
        )]),
        zero_clock(),
    );
    let receiver_side = receiver.add_side_packed_with_options(
        "shared-can",
        |_| Ok(()),
        RouterSideOptions {
            header_template_enabled: true,
            max_side_transport_templates: 8,
            ..RouterSideOptions::default()
        },
    );

    let frames_a = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let frames_b = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let make_sender = |name: &'static str, frames: Arc<Mutex<Vec<Vec<u8>>>>| {
        let router =
            Router::new_with_clock(RouterConfig::default().with_sender(name), zero_clock());
        router.add_side_packed_with_options(
            "shared-can",
            move |bytes| {
                frames.lock().unwrap().push(bytes.to_vec());
                Ok(())
            },
            RouterSideOptions {
                header_template_enabled: true,
                max_side_transport_templates: 8,
                ..RouterSideOptions::default()
            },
        );
        router
    };
    let sender_a = make_sender("PRODUCER_A", frames_a.clone());
    let sender_b = make_sender("PRODUCER_B", frames_b.clone());

    for (router, sender, base) in [
        (&sender_a, "PRODUCER_A", 10u16),
        (&sender_b, "PRODUCER_B", 20u16),
    ] {
        for offset in 0..2u16 {
            router
                .tx(Packet::new(
                    best_effort_type(),
                    &[DataEndpoint::named("SD_CARD")],
                    sender,
                    u64::from(base + offset),
                    Arc::from(
                        [f32::from(offset), 0.0, 0.0]
                            .into_iter()
                            .flat_map(f32::to_le_bytes)
                            .collect::<Vec<_>>(),
                    ),
                )
                .unwrap()
                .with_nonce(base + offset))
                .unwrap();
        }
    }

    let a = frames_a.lock().unwrap().clone();
    let b = frames_b.lock().unwrap().clone();
    assert_eq!(a.len(), 2);
    assert_eq!(b.len(), 2);
    for frame in [&a[0], &b[0], &a[1], &b[1]] {
        receiver
            .rx_packed_from_side(frame.as_slice(), receiver_side)
            .unwrap();
    }
    assert_eq!(
        *delivered.lock().unwrap(),
        vec!["PRODUCER_A", "PRODUCER_B", "PRODUCER_A", "PRODUCER_B"]
    );
}

#[cfg(feature = "discovery")]
#[test]
fn compact_templates_are_disabled_after_shared_bus_discovery() {
    crate::tests::ensure_common_test_schema();
    let frames = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let frames_c = frames.clone();
    let sender = Router::new_with_clock(RouterConfig::default().with_sender("LOCAL"), zero_clock());
    let side = sender.add_side_packed_with_options(
        "shared-can",
        move |bytes| {
            frames_c.lock().unwrap().push(bytes.to_vec());
            Ok(())
        },
        RouterSideOptions {
            header_template_enabled: true,
            max_side_transport_templates: 8,
            ..RouterSideOptions::default()
        },
    );
    for peer in ["PEER_A", "PEER_B"] {
        sender
            .rx_from_side(
                &build_discovery_announce(peer, 0, &[DataEndpoint::named("SD_CARD")]).unwrap(),
                side,
            )
            .unwrap();
    }
    frames.lock().unwrap().clear();

    for nonce in 1..=2u16 {
        sender
            .tx(Packet::from_f32_slice(
                best_effort_type(),
                &[f32::from(nonce), 0.0, 0.0],
                &[DataEndpoint::named("SD_CARD")],
                u64::from(nonce),
            )
            .unwrap()
            .with_nonce(nonce))
            .unwrap();
    }
    let stats = sender.export_runtime_stats();
    let side = stats
        .sides
        .iter()
        .find(|side| side.side_name == "shared-can")
        .unwrap();
    assert_eq!(side.side_transport_tx_template_count, 0);
    assert_eq!(side.side_transport_compact_frames, 0);
}

#[test]
fn chunk_transfer_ids_do_not_collide_across_bus_producers() {
    crate::tests::ensure_common_test_schema();
    let ty = DataType::try_named("SHARED_BUS_CHUNK_TEST").unwrap_or_else(|| {
        crate::config::register_data_type_with_description(
            "SHARED_BUS_CHUNK_TEST",
            "multi-producer chunk reassembly regression test",
            crate::MessageElement::Dynamic(
                crate::MessageDataType::Binary,
                crate::MessageClass::Data,
            ),
            &[DataEndpoint::named("SD_CARD")],
            crate::ReliableMode::None,
            1,
        )
        .unwrap()
    });
    let delivered = Arc::new(Mutex::new(Vec::<(String, Vec<u8>)>::new()));
    let delivered_c = delivered.clone();
    let receiver = Router::new_with_clock(
        RouterConfig::new([EndpointHandler::new_packet_handler(
            DataEndpoint::named("SD_CARD"),
            move |packet| {
                delivered_c
                    .lock()
                    .unwrap()
                    .push((packet.sender().to_string(), packet.payload().to_vec()));
                Ok(())
            },
        )]),
        zero_clock(),
    );
    let receiver_side = receiver.add_side_packed_with_options(
        "shared-can",
        |_| Ok(()),
        RouterSideOptions {
            max_frame_bytes: 64,
            ..RouterSideOptions::default()
        },
    );

    let capture = |sender: &'static str, salt: u8| {
        let frames = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let frames_c = frames.clone();
        let router =
            Router::new_with_clock(RouterConfig::default().with_sender(sender), zero_clock());
        router.add_side_packed_with_options(
            "shared-can",
            move |bytes| {
                frames_c.lock().unwrap().push(bytes.to_vec());
                Ok(())
            },
            RouterSideOptions {
                max_frame_bytes: 64,
                ..RouterSideOptions::default()
            },
        );
        router
            .tx(Packet::new(
                ty,
                &[DataEndpoint::named("SD_CARD")],
                sender,
                u64::from(salt),
                Arc::from(
                    (0..180u16)
                        .map(|value| (value as u8).wrapping_add(salt))
                        .collect::<Vec<_>>(),
                ),
            )
            .unwrap()
            .with_nonce(u16::from(salt)))
            .unwrap();
        let captured = frames.lock().unwrap().clone();
        assert!(captured.len() > 1);
        let application_transfer_id =
            u32::from_le_bytes(captured.last().unwrap()[4..8].try_into().unwrap());
        captured
            .into_iter()
            .filter(|frame| {
                frame.starts_with(b"SDT\x03")
                    && u32::from_le_bytes(frame[4..8].try_into().unwrap())
                        == application_transfer_id
            })
            .collect::<Vec<_>>()
    };
    let a = capture("PRODUCER_A", 0x11);
    let b = capture("PRODUCER_B", 0x77);
    let transfer_id = |frame: &[u8]| {
        assert_eq!(&frame[..4], b"SDT\x03");
        u32::from_le_bytes(frame[4..8].try_into().unwrap())
    };
    assert_ne!(transfer_id(&a[0]), transfer_id(&b[0]));
    for index in 0..a.len().max(b.len()) {
        if let Some(frame) = a.get(index) {
            receiver.rx_packed_from_side(frame, receiver_side).unwrap();
        }
        if let Some(frame) = b.get(index) {
            receiver.rx_packed_from_side(frame, receiver_side).unwrap();
        }
    }
    let delivered = delivered.lock().unwrap();
    assert_eq!(delivered.len(), 2, "delivered={delivered:?}");
    let expected_a = (0..180u16)
        .map(|value| (value as u8).wrapping_add(0x11))
        .collect::<Vec<_>>();
    let expected_b = (0..180u16)
        .map(|value| (value as u8).wrapping_add(0x77))
        .collect::<Vec<_>>();
    assert!(delivered.contains(&("PRODUCER_A".into(), expected_a)));
    assert!(delivered.contains(&("PRODUCER_B".into(), expected_b)));
}

#[test]
fn packed_side_header_templates_preserve_absolute_unchanged_timestamps() {
    crate::tests::ensure_common_test_schema();
    let delivered_payloads = Arc::new(Mutex::new(Vec::<Vec<f32>>::new()));
    let delivered_payloads_c = delivered_payloads.clone();
    let receiver = Arc::new(Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(
            DataEndpoint::named("SD_CARD"),
            move |pkt: &Packet| {
                let mut payload = Vec::with_capacity(pkt.payload().len() / 4);
                for chunk in pkt.payload().as_chunks::<4>().0 {
                    payload.push(f32::from_le_bytes(*chunk));
                }
                delivered_payloads_c.lock().unwrap().push(payload);
                Ok(())
            },
        )]),
        zero_clock(),
    ));
    let receiver_side_id = Arc::new(Mutex::new(None));
    let receiver_side_id_c = receiver_side_id.clone();
    let frames = Arc::new(Mutex::new(Vec::<usize>::new()));
    let frames_c = frames.clone();
    let receiver_c = receiver.clone();

    let sender = Router::new_with_clock(RouterConfig::default(), zero_clock());
    sender.add_side_packed_with_options(
        "link",
        move |bytes: &[u8]| {
            frames_c.lock().unwrap().push(bytes.len());
            let side = receiver_side_id_c
                .lock()
                .unwrap()
                .expect("receiver side id");
            receiver_c.rx_packed_from_side(bytes, side)
        },
        RouterSideOptions {
            header_template_enabled: true,
            compact_header_target_bytes: 20,
            ..RouterSideOptions::default()
                .with_omitted_unchanged_compact_timestamps_for_type(best_effort_type())
        },
    );
    let rx_side = receiver.add_side_packed_with_options(
        "link",
        |_bytes| Ok(()),
        RouterSideOptions {
            header_template_enabled: true,
            compact_header_target_bytes: 20,
            ..RouterSideOptions::default()
                .with_omitted_unchanged_compact_timestamps_for_type(best_effort_type())
        },
    );
    *receiver_side_id.lock().unwrap() = Some(rx_side);

    let pkt_a = Packet::from_f32_slice(
        best_effort_type(),
        &[1.0_f32, 2.0, 3.0],
        &[DataEndpoint::named("SD_CARD")],
        10_000,
    )
    .unwrap()
    .with_nonce(21);
    let pkt_b = Packet::from_f32_slice(
        best_effort_type(),
        &[4.0_f32, 5.0, 6.0],
        &[DataEndpoint::named("SD_CARD")],
        10_000,
    )
    .unwrap()
    .with_nonce(22);

    sender.tx(pkt_a).unwrap();
    sender.tx(pkt_b).unwrap();

    let lens = frames.lock().unwrap();
    assert_eq!(lens.len(), 2);
    assert!(lens[1] < lens[0], "second frame should use compact header");
    drop(lens);

    let delivered = delivered_payloads.lock().unwrap();
    assert_eq!(delivered.len(), 2);
    assert_eq!(delivered[0], vec![1.0, 2.0, 3.0]);
    assert_eq!(delivered[1], vec![4.0, 5.0, 6.0]);
    drop(delivered);

    let stats = sender.export_runtime_stats();
    let side = stats
        .sides
        .iter()
        .find(|side| side.side_name == "link")
        .expect("link side stats");
    assert_eq!(side.side_transport_full_frames, 1);
    assert_eq!(side.side_transport_compact_frames, 1);
    assert_eq!(side.side_transport_compact_delta_frames, 0);
    assert_eq!(side.side_transport_compact_omitted_timestamp_frames, 0);
    assert!(side.side_transport_bytes_saved > 0);
    assert_eq!(side.side_transport_compact_target_misses, 0);
}

#[test]
fn packed_side_timestamp_omission_policy_does_not_apply_to_other_types() {
    crate::tests::ensure_common_test_schema();
    let other_ty = DataType::try_named("POLICY_OTHER_DATA").unwrap_or_else(|| {
        use crate::config::register_data_type_with_description;
        use crate::{MessageClass, MessageDataType, MessageElement, ReliableMode};
        register_data_type_with_description(
            "POLICY_OTHER_DATA",
            "test type that should not inherit GPS timestamp omission policy",
            MessageElement::Static(3, MessageDataType::Float32, MessageClass::Data),
            &[DataEndpoint::named("SD_CARD")],
            ReliableMode::None,
            1,
        )
        .expect("register POLICY_OTHER_DATA")
    });
    let delivered = Arc::new(AtomicUsize::new(0));
    let delivered_c = delivered.clone();
    let receiver = Arc::new(Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(
            DataEndpoint::named("SD_CARD"),
            move |_pkt: &Packet| {
                delivered_c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )]),
        zero_clock(),
    ));
    let receiver_side_id = Arc::new(Mutex::new(None));
    let receiver_side_id_c = receiver_side_id.clone();
    let receiver_c = receiver.clone();

    let sender = Router::new_with_clock(RouterConfig::default(), zero_clock());
    sender.add_side_packed_with_options(
        "link",
        move |bytes: &[u8]| {
            let side = receiver_side_id_c
                .lock()
                .unwrap()
                .expect("receiver side id");
            receiver_c.rx_packed_from_side(bytes, side)
        },
        RouterSideOptions {
            header_template_enabled: true,
            compact_header_target_bytes: 20,
            ..RouterSideOptions::default()
                .with_omitted_unchanged_compact_timestamps_for_type(best_effort_type())
        },
    );
    let rx_side = receiver.add_side_packed_with_options(
        "link",
        |_bytes| Ok(()),
        RouterSideOptions {
            header_template_enabled: true,
            compact_header_target_bytes: 20,
            ..RouterSideOptions::default()
                .with_omitted_unchanged_compact_timestamps_for_type(best_effort_type())
        },
    );
    *receiver_side_id.lock().unwrap() = Some(rx_side);

    let pkt_a = Packet::from_f32_slice(
        other_ty,
        &[1.0_f32, 2.0, 3.0],
        &[DataEndpoint::named("SD_CARD")],
        10_000,
    )
    .unwrap()
    .with_nonce(31);
    let pkt_b = Packet::from_f32_slice(
        other_ty,
        &[4.0_f32, 5.0, 6.0],
        &[DataEndpoint::named("SD_CARD")],
        10_000,
    )
    .unwrap()
    .with_nonce(32);

    sender.tx(pkt_a).unwrap();
    sender.tx(pkt_b).unwrap();

    assert_eq!(delivered.load(Ordering::SeqCst), 2);
    let stats = sender.export_runtime_stats();
    let side = stats
        .sides
        .iter()
        .find(|side| side.side_name == "link")
        .expect("link side stats");
    assert_eq!(side.side_transport_full_frames, 1);
    assert_eq!(side.side_transport_compact_frames, 1);
    assert_eq!(side.side_transport_compact_delta_frames, 0);
    assert_eq!(side.side_transport_compact_omitted_timestamp_frames, 0);
}

#[test]
fn packed_side_template_dictionary_is_bounded() {
    crate::tests::ensure_common_test_schema();
    let receiver = Arc::new(Router::new_with_clock(
        RouterConfig::default(),
        zero_clock(),
    ));
    let receiver_side_id = Arc::new(Mutex::new(None));
    let receiver_side_id_c = receiver_side_id.clone();
    let receiver_c = receiver.clone();

    let sender = Router::new_with_clock(RouterConfig::default(), zero_clock());
    sender.add_side_packed_with_options(
        "bounded-link",
        move |bytes: &[u8]| {
            let side = receiver_side_id_c
                .lock()
                .unwrap()
                .expect("receiver side id");
            receiver_c.rx_packed_from_side(bytes, side)
        },
        RouterSideOptions {
            header_template_enabled: true,
            max_side_transport_templates: 1,
            ..RouterSideOptions::default()
        },
    );
    let rx_side = receiver.add_side_packed_with_options(
        "bounded-link",
        |_bytes| Ok(()),
        RouterSideOptions {
            header_template_enabled: true,
            max_side_transport_templates: 1,
            ..RouterSideOptions::default()
        },
    );
    *receiver_side_id.lock().unwrap() = Some(rx_side);

    for (sender_id, ts, nonce) in [("SRC_A", 1, 1), ("SRC_B", 2, 2), ("SRC_A", 3, 3)] {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(ts as f32).to_le_bytes());
        payload.extend_from_slice(&0.0f32.to_le_bytes());
        payload.extend_from_slice(&0.0f32.to_le_bytes());
        let pkt = Packet::new(
            best_effort_type(),
            &[DataEndpoint::named("SD_CARD")],
            sender_id,
            ts,
            Arc::<[u8]>::from(payload),
        )
        .unwrap()
        .with_nonce(nonce);
        sender.tx(pkt).unwrap();
    }

    let stats = sender.export_runtime_stats();
    let side = stats
        .sides
        .iter()
        .find(|side| side.side_name == "bounded-link")
        .expect("bounded side stats");
    assert_eq!(side.max_side_transport_templates, 1);
    assert_eq!(side.side_transport_profile, "template");
    assert_eq!(side.side_transport_tx_template_count, 1);
    assert_eq!(side.side_transport_full_frames, 3);
    assert_eq!(side.side_transport_compact_frames, 0);
    assert!(side.side_transport_template_evictions >= 2);
}

#[test]
fn bounded_side_template_dictionaries_remain_synchronized() {
    crate::tests::ensure_common_test_schema();
    // Compare one-way template evictions only; generated ACKs use their own
    // templates and legitimately add to the receiver side eviction counter.
    let delivered = Arc::new(AtomicUsize::new(0));
    let delivered_c = delivered.clone();
    let receiver = Arc::new(Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(
            DataEndpoint::named("SD_CARD"),
            move |_pkt: &Packet| {
                delivered_c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )])
        .with_reliable_enabled(false),
        zero_clock(),
    ));
    let receiver_side_id = Arc::new(Mutex::new(None));
    let receiver_side_id_c = receiver_side_id.clone();
    let receiver_c = receiver.clone();

    let sender = Router::new_with_clock(RouterConfig::default(), zero_clock());
    sender.add_side_packed_with_options(
        "bounded-link",
        move |bytes: &[u8]| {
            let side = receiver_side_id_c
                .lock()
                .unwrap()
                .expect("receiver side id");
            receiver_c.rx_packed_from_side(bytes, side)
        },
        RouterSideOptions {
            header_template_enabled: true,
            max_side_transport_templates: 2,
            ..RouterSideOptions::default()
        },
    );
    let rx_side = receiver.add_side_packed_with_options(
        "bounded-link",
        |_bytes| Ok(()),
        RouterSideOptions {
            header_template_enabled: true,
            max_side_transport_templates: 2,
            ..RouterSideOptions::default()
        },
    );
    *receiver_side_id.lock().unwrap() = Some(rx_side);

    let sources = ["SRC_A", "SRC_B", "SRC_C", "SRC_A", "SRC_B", "SRC_C"];
    for (index, sender_id) in sources.into_iter().enumerate() {
        let payload: Arc<[u8]> = [index as f32, 0.0, 0.0]
            .into_iter()
            .flat_map(f32::to_le_bytes)
            .collect::<Vec<_>>()
            .into();
        let pkt = Packet::new(
            best_effort_type(),
            &[DataEndpoint::named("SD_CARD")],
            sender_id,
            index as u64,
            payload,
        )
        .unwrap()
        .with_nonce(index as u16 + 1);
        sender.tx(pkt).unwrap();
    }

    assert_eq!(delivered.load(Ordering::SeqCst), sources.len());
    let tx_stats = sender.export_runtime_stats();
    let tx_side = tx_stats
        .sides
        .iter()
        .find(|side| side.side_name == "bounded-link")
        .expect("bounded sender side stats");
    let rx_stats = receiver.export_runtime_stats();
    let rx_side = rx_stats
        .sides
        .iter()
        .find(|side| side.side_name == "bounded-link")
        .expect("bounded receiver side stats");
    assert_eq!(tx_side.side_transport_tx_template_count, 2);
    assert_eq!(rx_side.side_transport_rx_template_count, 2);
    assert!(tx_side.side_transport_template_evictions > 0);
    assert_eq!(
        tx_side.side_transport_template_evictions,
        rx_side.side_transport_template_evictions
    );
}

#[test]
fn packed_sender_honors_smaller_discovered_peer_template_capacity() {
    crate::tests::ensure_common_test_schema();
    let delivered = Arc::new(AtomicUsize::new(0));
    let delivered_c = delivered.clone();
    let receiver = Arc::new(Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(
            DataEndpoint::named("SD_CARD"),
            move |_pkt: &Packet| {
                delivered_c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )]),
        zero_clock(),
    ));
    let receiver_side_id = Arc::new(Mutex::new(None));
    let receiver_side_id_c = receiver_side_id.clone();
    let receiver_c = receiver.clone();

    let sender = Router::new_with_clock(RouterConfig::default(), zero_clock());
    let sender_side = sender.add_side_packed_with_options(
        "mismatched-link",
        move |bytes: &[u8]| {
            let side = receiver_side_id_c
                .lock()
                .unwrap()
                .expect("receiver side id");
            receiver_c.rx_packed_from_side(bytes, side)
        },
        RouterSideOptions {
            header_template_enabled: true,
            max_side_transport_templates: 8,
            ..RouterSideOptions::default()
        },
    );
    let rx_side = receiver.add_side_packed_with_options(
        "mismatched-link",
        |_bytes| Ok(()),
        RouterSideOptions {
            header_template_enabled: true,
            max_side_transport_templates: 4,
            ..RouterSideOptions::default()
        },
    );
    *receiver_side_id.lock().unwrap() = Some(rx_side);

    /* Populate the larger sender dictionary before discovery so learning
     * the constrained peer must actively shrink existing state. */
    for (index, sender_id) in ["SRC_A", "SRC_B", "SRC_C", "SRC_D", "SRC_E", "SRC_F"]
        .into_iter()
        .enumerate()
    {
        let payload: Arc<[u8]> = [index as f32, 0.0, 0.0]
            .into_iter()
            .flat_map(f32::to_le_bytes)
            .collect::<Vec<_>>()
            .into();
        sender
            .tx(Packet::new(
                best_effort_type(),
                &[DataEndpoint::named("SD_CARD")],
                sender_id,
                index as u64 + 1,
                payload,
            )
            .unwrap()
            .with_nonce(index as u16 + 100))
            .unwrap();
    }
    let before_discovery = sender.export_runtime_stats();
    let before_side = before_discovery
        .sides
        .iter()
        .find(|side| side.side_name == "mismatched-link")
        .expect("sender side before discovery");
    assert_eq!(before_side.side_transport_tx_template_count, 6);

    let peer_advertisement = crate::discovery::AddressAdvertisement {
        hostname: "RECEIVER".into(),
        address: 42,
        requested_address: 0,
        mode: crate::discovery::ADDRESS_MODE_DYNAMIC,
        state: crate::discovery::ADDRESS_STATE_APPROVED,
        birth_ms: 0,
        owner_hash: 42,
        reachable_endpoints: vec![DataEndpoint::named("SD_CARD")],
        reachable_network_variables: Vec::new(),
        reachable_timesync_sources: Vec::new(),
        link_capabilities: crate::discovery::LinkCapabilities {
            version: 1,
            flags: crate::discovery::LINK_CAPABILITY_HEADER_TEMPLATES,
            profile: crate::discovery::LINK_PROFILE_TEMPLATE,
            max_frame_bytes: 0,
            compact_header_target_bytes: 0,
            max_side_transport_templates: 4,
        },
    };
    let discovery =
        crate::discovery::build_discovery_address("RECEIVER", 0, &peer_advertisement).unwrap();
    sender.rx_from_side(&discovery, sender_side).unwrap();
    sender.process_all_queues().unwrap();

    let sources = [
        "SRC_A", "SRC_B", "SRC_C", "SRC_D", "SRC_E", "SRC_F", "SRC_A", "SRC_B", "SRC_C", "SRC_D",
        "SRC_E", "SRC_F",
    ];
    for (index, sender_id) in sources.into_iter().enumerate() {
        let payload: Arc<[u8]> = [index as f32, 0.0, 0.0]
            .into_iter()
            .flat_map(f32::to_le_bytes)
            .collect::<Vec<_>>()
            .into();
        sender
            .tx(Packet::new(
                best_effort_type(),
                &[DataEndpoint::named("SD_CARD")],
                sender_id,
                index as u64 + 1,
                payload,
            )
            .unwrap()
            .with_nonce(index as u16 + 1))
            .unwrap();
        sender.process_all_queues().unwrap();
        receiver.process_all_queues().unwrap();
    }

    let receiver_stats = receiver.export_runtime_stats();
    let receiver_side = receiver_stats
        .sides
        .iter()
        .find(|side| side.side_name == "mismatched-link")
        .expect("mismatched receiver side stats");
    let received_values = receiver_side
        .data_types
        .iter()
        .find(|item| item.data_type == best_effort_type())
        .expect("received GPS data stats");
    assert_eq!(received_values.rx_packets, sources.len() as u64 + 6);
    assert_eq!(receiver_side.side_transport_rx_template_count, 4);
    let stats = sender.export_runtime_stats();
    let side = stats
        .sides
        .iter()
        .find(|side| side.side_name == "mismatched-link")
        .expect("mismatched sender side stats");
    assert_eq!(side.side_transport_tx_template_count, 4);
}

#[test]
fn compact_side_recovers_when_initial_full_template_is_lost() {
    crate::tests::ensure_common_test_schema();
    let delivered = Arc::new(AtomicUsize::new(0));
    let delivered_c = delivered.clone();
    let receiver = Arc::new(Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(
            DataEndpoint::named("SD_CARD"),
            move |_pkt: &Packet| {
                delivered_c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )]),
        zero_clock(),
    ));
    let receiver_side_id = Arc::new(Mutex::new(None));
    let receiver_side_id_c = receiver_side_id.clone();
    let receiver_c = receiver.clone();
    let transmitted = Arc::new(AtomicUsize::new(0));
    let transmitted_c = transmitted.clone();

    let sender = Router::new_with_clock(RouterConfig::default(), zero_clock());
    sender.add_side_packed_with_options(
        "lossy-link",
        move |bytes: &[u8]| {
            if transmitted_c.fetch_add(1, Ordering::SeqCst) == 0 {
                return Ok(());
            }
            let side = receiver_side_id_c
                .lock()
                .unwrap()
                .expect("receiver side id");
            receiver_c.rx_packed_from_side(bytes, side)
        },
        RouterSideOptions {
            header_template_enabled: true,
            max_side_transport_templates: 2,
            ..RouterSideOptions::default()
        },
    );
    let rx_side = receiver.add_side_packed_with_options(
        "lossy-link",
        |_bytes| Ok(()),
        RouterSideOptions {
            header_template_enabled: true,
            max_side_transport_templates: 2,
            ..RouterSideOptions::default()
        },
    );
    *receiver_side_id.lock().unwrap() = Some(rx_side);

    for index in 0..11u16 {
        let pkt = Packet::from_f32_slice(
            best_effort_type(),
            &[index as f32, 0.0, 0.0],
            &[DataEndpoint::named("SD_CARD")],
            u64::from(index),
        )
        .unwrap()
        .with_nonce(index + 1);
        sender.tx(pkt).unwrap();
    }

    assert_eq!(transmitted.load(Ordering::SeqCst), 11);
    assert_eq!(delivered.load(Ordering::SeqCst), 2);
    let stats = sender.export_runtime_stats();
    let side = stats
        .sides
        .iter()
        .find(|side| side.side_name == "lossy-link")
        .expect("lossy sender side stats");
    assert_eq!(side.side_transport_full_frames, 2);
    assert_eq!(side.side_transport_compact_frames, 9);
}

#[cfg(feature = "discovery")]
#[test]
fn topology_change_resynchronizes_a_missing_compact_template_immediately() {
    use crate::discovery::build_discovery_announce;

    crate::tests::ensure_common_test_schema();
    // This test drops best-effort data to exercise compact-template recovery.
    // Reliable frames are self-describing and tested separately.
    let template_type = crate::config::register_data_type_with_description(
        "TEMPLATE_RESET_DATA",
        "best-effort template recovery fixture",
        crate::MessageElement::Static(
            3,
            crate::MessageDataType::Float32,
            crate::MessageClass::Data,
        ),
        &[DataEndpoint::named("SD_CARD")],
        crate::ReliableMode::None,
        1,
    )
    .unwrap();
    let delivered = Arc::new(AtomicUsize::new(0));
    let delivered_c = delivered.clone();
    let receiver = Arc::new(Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(
            DataEndpoint::named("SD_CARD"),
            move |_pkt: &Packet| {
                delivered_c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )])
        .with_sender("RECEIVER"),
        zero_clock(),
    ));
    let receiver_side_id = Arc::new(Mutex::new(None));
    let receiver_side_id_c = receiver_side_id.clone();
    let receiver_c = receiver.clone();
    let transmitted = Arc::new(AtomicUsize::new(0));
    let transmitted_c = transmitted.clone();

    let sender =
        Router::new_with_clock(RouterConfig::default().with_sender("SENDER"), zero_clock());
    let lossy = sender.add_side_packed_with_options(
        "lossy-link",
        move |bytes: &[u8]| {
            if transmitted_c.fetch_add(1, Ordering::SeqCst) == 0 {
                return Ok(());
            }
            let side = receiver_side_id_c
                .lock()
                .unwrap()
                .expect("receiver side id");
            receiver_c.rx_packed_from_side(bytes, side)
        },
        RouterSideOptions {
            header_template_enabled: true,
            ..RouterSideOptions::default()
        },
    );
    let ingress = sender.add_side_packet("new-peer", |_pkt| Ok(()));
    let rx_side = receiver.add_side_packed_with_options(
        "lossy-link",
        |_bytes| Ok(()),
        RouterSideOptions {
            header_template_enabled: true,
            ..RouterSideOptions::default()
        },
    );
    *receiver_side_id.lock().unwrap() = Some(rx_side);

    sender
        .rx_from_side(
            &build_discovery_announce("STORAGE_NODE", 0, &[DataEndpoint::named("SD_CARD")])
                .unwrap(),
            lossy,
        )
        .unwrap();

    let packet = |nonce| {
        Packet::from_f32_slice(
            template_type,
            &[nonce as f32, 0.0, 0.0],
            &[DataEndpoint::named("SD_CARD")],
            u64::from(nonce),
        )
        .unwrap()
        .with_nonce(nonce)
    };
    sender.tx(packet(1)).unwrap(); // Full template is lost.
    sender.tx(packet(2)).unwrap(); // Compact frame cannot be decoded.
    assert_eq!(delivered.load(Ordering::SeqCst), 0);

    sender
        .rx_from_side(
            &build_discovery_announce("NEW_PEER", 2, &[DataEndpoint::named("RADIO")]).unwrap(),
            ingress,
        )
        .unwrap();
    sender.tx(packet(3)).unwrap();
    receiver.process_all_queues().unwrap();

    assert_eq!(transmitted.load(Ordering::SeqCst), 3);
    let stats = sender.export_runtime_stats();
    let side = stats
        .sides
        .iter()
        .find(|side| side.side_name == "lossy-link")
        .expect("lossy sender side stats");
    assert_eq!(side.side_transport_full_frames, 2);
    assert_eq!(side.side_transport_compact_frames, 1);
    let received = receiver.export_runtime_stats();
    let received_gps = received.sides[0]
        .data_types
        .iter()
        .find(|item| item.data_type == template_type)
        .expect("post-topology-change full frame must decode as GPS_DATA");
    assert_eq!(received_gps.rx_packets, 1);
}

#[test]
fn compact_header_target_misses_are_counted() {
    crate::tests::ensure_common_test_schema();
    let receiver = Arc::new(Router::new_with_clock(
        RouterConfig::default(),
        zero_clock(),
    ));
    let receiver_side_id = Arc::new(Mutex::new(None));
    let receiver_side_id_c = receiver_side_id.clone();
    let receiver_c = receiver.clone();

    let sender = Router::new_with_clock(RouterConfig::default(), zero_clock());
    sender.add_side_packed_with_options(
        "tight-target",
        move |bytes: &[u8]| {
            let side = receiver_side_id_c
                .lock()
                .unwrap()
                .expect("receiver side id");
            receiver_c.rx_packed_from_side(bytes, side)
        },
        RouterSideOptions {
            header_template_enabled: true,
            compact_header_target_bytes: 1,
            ..RouterSideOptions::default()
        },
    );
    let rx_side = receiver.add_side_packed_with_options(
        "tight-target",
        |_bytes| Ok(()),
        RouterSideOptions {
            header_template_enabled: true,
            ..RouterSideOptions::default()
        },
    );
    *receiver_side_id.lock().unwrap() = Some(rx_side);

    for (value, nonce) in [(1.0, 11), (2.0, 12)] {
        let pkt = Packet::from_f32_slice(
            best_effort_type(),
            &[value, 0.0, 0.0],
            &[DataEndpoint::named("SD_CARD")],
            nonce as u64,
        )
        .unwrap()
        .with_nonce(nonce);
        sender.tx(pkt).unwrap();
    }

    let stats = sender.export_runtime_stats();
    let side = stats
        .sides
        .iter()
        .find(|side| side.side_name == "tight-target")
        .expect("tight target side stats");
    assert_eq!(side.side_transport_compact_frames, 1);
    assert_eq!(side.side_transport_compact_target_misses, 1);
}

#[test]
fn packed_side_chunking_reassembles_for_fixed_size_links() {
    crate::tests::ensure_common_test_schema();
    let delivered = Arc::new(AtomicUsize::new(0));
    let delivered_c = delivered.clone();
    let receiver = Arc::new(Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(
            DataEndpoint::named("SD_CARD"),
            move |_pkt: &Packet| {
                delivered_c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )]),
        zero_clock(),
    ));
    let receiver_side_id = Arc::new(Mutex::new(None));
    let receiver_side_id_c = receiver_side_id.clone();
    let chunk_count = Arc::new(AtomicUsize::new(0));
    let chunk_count_c = chunk_count.clone();
    let max_seen = Arc::new(AtomicUsize::new(0));
    let max_seen_c = max_seen.clone();
    let receiver_c = receiver.clone();
    let sender = Router::new_with_clock(RouterConfig::default(), zero_clock());
    let max_frame_bytes = 48usize;

    sender.add_side_packed_small_packets(
        "fixed-link",
        move |bytes: &[u8]| {
            chunk_count_c.fetch_add(1, Ordering::SeqCst);
            let mut current = max_seen_c.load(Ordering::SeqCst);
            while bytes.len() > current
                && max_seen_c
                    .compare_exchange(current, bytes.len(), Ordering::SeqCst, Ordering::SeqCst)
                    .is_err()
            {
                current = max_seen_c.load(Ordering::SeqCst);
            }
            let side = receiver_side_id_c
                .lock()
                .unwrap()
                .expect("receiver side id");
            receiver_c.rx_packed_from_side(bytes, side)
        },
        max_frame_bytes,
    );
    let rx_side = receiver.add_side_packed_with_options(
        "fixed-link",
        |_bytes| Ok(()),
        RouterSideOptions {
            header_template_enabled: true,
            max_frame_bytes,
            ..RouterSideOptions::default()
        },
    );
    *receiver_side_id.lock().unwrap() = Some(rx_side);

    let payload = vec![b'X'; 180];
    let pkt = Packet::new(
        DataType::TelemetryError,
        &[DataEndpoint::named("SD_CARD")],
        "CHUNK_SRC",
        55,
        Arc::<[u8]>::from(payload),
    )
    .unwrap()
    .with_nonce(21);

    sender.tx(pkt).unwrap();

    assert_eq!(delivered.load(Ordering::SeqCst), 1);
    assert!(chunk_count.load(Ordering::SeqCst) > 1);
    assert!(max_seen.load(Ordering::SeqCst) <= max_frame_bytes);
}

// -----------------------------------------------------------------------
// Relay dedupe tests
// -----------------------------------------------------------------------

/// For a single relay side, repeatedly injecting the *same* packed
/// frame should fan out exactly once to other sides.
#[test]
fn relay_deduplicates_identical_frames_per_side() {
    crate::tests::ensure_common_test_schema();
    let relay = Relay::new(zero_clock());

    let tx_count_b = Arc::new(AtomicUsize::new(0));
    let tx_count_c = Arc::new(AtomicUsize::new(0));

    let tx_b_c = tx_count_b.clone();
    let tx_b = move |bytes: &[u8]| -> TelemetryResult<()> {
        assert!(!bytes.is_empty());
        if packed_frame_type(bytes) == Some(best_effort_type()) {
            tx_b_c.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    };

    let tx_c_c = tx_count_c.clone();
    let tx_c = move |bytes: &[u8]| -> TelemetryResult<()> {
        assert!(!bytes.is_empty());
        if packed_frame_type(bytes) == Some(best_effort_type()) {
            tx_c_c.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    };

    let id_src = relay.add_side_packed("SRC", |_b| Ok(()));
    let side_b = relay.add_side_packed("B", tx_b);
    let side_c = relay.add_side_packed("C", tx_c);
    relay
        .set_source_route_mode(Some(id_src), crate::RouteSelectionMode::Fanout)
        .unwrap();
    advertise_side(&relay, side_b, "SIDE_B");
    advertise_side(&relay, side_c, "SIDE_C");
    relay.process_all_queues_with_timeout(0).unwrap();

    let frame = wire_for_value(1);

    for _ in 0..5 {
        relay
            .rx_packed_from_side(id_src, frame.as_ref())
            .expect("rx_packed_from_side failed");
    }

    relay
        .process_all_queues_with_timeout(0)
        .expect("process_all_queues_with_timeout failed");

    let forwarded_b = tx_count_b.load(Ordering::SeqCst);
    let forwarded_c = tx_count_c.load(Ordering::SeqCst);
    assert_eq!(
        forwarded_b + forwarded_c,
        2,
        "deduplicated ingress should emit exactly one application frame per selected side"
    );
    assert_eq!(forwarded_b, 1);
    assert_eq!(forwarded_c, 1);
}

/// Even when time advances, identical frames from the same side should
/// still be deduped (no time-based expiry).
#[test]
fn relay_dedup_persists_across_time_advance() {
    let now_ms = Arc::new(AtomicU64::new(0));
    let clock_now = now_ms.clone();
    let clock: Box<dyn Clock + Send + Sync> = Box::new(move || clock_now.load(Ordering::SeqCst));
    let relay = Relay::new(clock);

    let tx_count = Arc::new(AtomicUsize::new(0));
    let txc = tx_count.clone();

    let id_src = relay.add_side_packed("SRC", |_b| Ok(()));
    let dst = relay.add_side_packed("DST", move |bytes: &[u8]| -> TelemetryResult<()> {
        assert!(!bytes.is_empty());
        if packed_frame_type(bytes) == Some(best_effort_type()) {
            txc.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    });
    advertise_side(&relay, dst, "DST_SIDE");
    relay.process_all_queues_with_timeout(0).unwrap();

    let frame = wire_for_value(1);

    relay
        .rx_packed_from_side(id_src, frame.as_ref())
        .expect("first rx_packed_from_side failed");
    relay
        .process_all_queues_with_timeout(0)
        .expect("first drain failed");

    now_ms.store(1_000, Ordering::SeqCst);

    relay
        .rx_packed_from_side(id_src, frame.as_ref())
        .expect("second rx_packed_from_side failed");
    relay
        .process_all_queues_with_timeout(0)
        .expect("second drain failed");

    assert_eq!(
        tx_count.load(Ordering::SeqCst),
        1,
        "identical frame from same side should still be deduped after time advance"
    );
}

/// Two different frames from the same side must both be relayed.
#[test]
fn relay_does_not_dedupe_different_frames_from_same_side() {
    let relay = Relay::new(zero_clock());

    let tx_count = Arc::new(AtomicUsize::new(0));
    let txc = tx_count.clone();

    let id_src = relay.add_side_packed("SRC", |_b| Ok(()));
    let dst = relay.add_side_packed("DST", move |bytes: &[u8]| -> TelemetryResult<()> {
        assert!(!bytes.is_empty());
        if packed_frame_type(bytes) == Some(best_effort_type()) {
            txc.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    });
    advertise_side(&relay, dst, "DST_SIDE");
    relay.process_all_queues_with_timeout(0).unwrap();

    let frame_a = wire_for_value(1);
    let frame_b = wire_for_value(2);

    relay
        .rx_packed_from_side(id_src, frame_a.as_ref())
        .expect("rx_packed_from_side A failed");
    relay
        .rx_packed_from_side(id_src, frame_b.as_ref())
        .expect("rx_packed_from_side B failed");

    relay
        .process_all_queues_with_timeout(0)
        .expect("drain failed");

    assert_eq!(
        tx_count.load(Ordering::SeqCst),
        2,
        "relay must not dedupe different frames from the same side"
    );
}
