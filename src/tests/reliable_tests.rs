
use crate::config::{
    DataEndpoint, DataType, register_data_type_with_description, register_endpoint_with_description,
};
use crate::router::{Clock, EndpointHandler, Router, RouterConfig, RouterSideOptions};
use crate::tests::packed_frame_type;
use crate::tests::timeout_tests::StepClock;
use crate::{
    MessageClass, MessageDataType, MessageElement, ReliableMode, TelemetryResult, packet::Packet,
    wire_format,
};

use std::sync::Once;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

fn zero_clock() -> Box<dyn Clock + Send + Sync> {
    Box::new(|| 0u64)
}

fn ensure_reliable_test_schema() {
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        let radio = DataEndpoint::try_named("RADIO").unwrap_or_else(|| {
            register_endpoint_with_description("RADIO", "test radio endpoint", false)
                .expect("register RADIO")
        });
        let sd_card = DataEndpoint::try_named("SD_CARD").unwrap_or_else(|| {
            register_endpoint_with_description("SD_CARD", "test sd endpoint", false)
                .expect("register SD_CARD")
        });
        if DataType::try_named("RELIABLE_TEST_DATA").is_none() {
            register_data_type_with_description(
                "RELIABLE_TEST_DATA",
                "test reliable data type",
                MessageElement::Static(3, MessageDataType::Float32, MessageClass::Data),
                &[radio, sd_card],
                ReliableMode::Ordered,
                1,
            )
            .expect("register RELIABLE_TEST_DATA");
        }
    });
}

#[test]
fn reliable_retransmit_delivers_once() {
    ensure_reliable_test_schema();
    let rx_hits = Arc::new(AtomicUsize::new(0));
    let rx_hits_c = rx_hits.clone();
    let handler = EndpointHandler::new_packet_handler(
        DataEndpoint::named("SD_CARD"),
        move |_pkt: &Packet| {
            rx_hits_c.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    );

    let sender = Arc::new(Router::new_with_clock(
        RouterConfig::new(Vec::new()).with_reliable_enabled(true),
        StepClock::new_box(0, 250),
    ));

    let receiver = Arc::new(Router::new_with_clock(
        RouterConfig::new(vec![handler]).with_reliable_enabled(true),
        zero_clock(),
    ));

    let sender_side_id: Arc<Mutex<Option<usize>>> = Arc::new(Mutex::new(None));
    let receiver_side_id: Arc<Mutex<Option<usize>>> = Arc::new(Mutex::new(None));

    let sender_for_ack = sender.clone();
    let sender_side_id_c = sender_side_id.clone();
    let receiver_side = receiver.add_side_packed_with_options(
        "TO_SENDER",
        move |bytes: &[u8]| {
            if let Some(side_id) = *sender_side_id_c.lock().unwrap() {
                sender_for_ack.rx_packed_from_side(bytes, side_id)?;
            }
            Ok(())
        },
        RouterSideOptions {
            reliable_enabled: true,
            link_local_enabled: false,
            ..RouterSideOptions::default()
        },
    );
    *receiver_side_id.lock().unwrap() = Some(receiver_side);

    let drop_first = Arc::new(AtomicBool::new(true));
    let receiver_for_tx = receiver.clone();
    let drop_first_tx = drop_first.clone();
    let receiver_side_id_c = receiver_side_id.clone();
    let tx = move |bytes: &[u8]| -> TelemetryResult<()> {
        if drop_first_tx.swap(false, Ordering::SeqCst) {
            return Ok(());
        }
        if let Some(side_id) = *receiver_side_id_c.lock().unwrap() {
            receiver_for_tx.rx_packed_from_side(bytes, side_id)?;
        }
        Ok(())
    };

    let sender_side = sender.add_side_packed_with_options(
        "TO_RECEIVER",
        tx,
        RouterSideOptions {
            reliable_enabled: true,
            link_local_enabled: false,
            ..RouterSideOptions::default()
        },
    );
    *sender_side_id.lock().unwrap() = Some(sender_side);

    let pkt = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0_f32, 2.0, 3.0],
        &[DataEndpoint::named("SD_CARD")],
        0,
    )
    .unwrap();

    sender.tx(pkt).unwrap();

    for _ in 0..3 {
        sender.process_tx_queue_with_timeout(0).unwrap();
    }

    assert_eq!(rx_hits.load(Ordering::SeqCst), 1);
}

#[test]
fn immediate_rx_from_side_emits_reliable_ack_without_queue_drain() {
    ensure_reliable_test_schema();

    let sent_frames: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let sent_frames_c = sent_frames.clone();
    let sender = Router::new_with_clock(
        RouterConfig::default().with_reliable_enabled(true),
        zero_clock(),
    );
    sender.add_side_packed_with_options(
        "to_receiver",
        move |bytes: &[u8]| {
            sent_frames_c.lock().unwrap().push(bytes.to_vec());
            Ok(())
        },
        RouterSideOptions {
            reliable_enabled: true,
            ..RouterSideOptions::default()
        },
    );

    let pkt = Packet::from_f32_slice(
        DataType::named("RELIABLE_TEST_DATA"),
        &[1.0_f32, 2.0, 3.0],
        &[DataEndpoint::named("RADIO")],
        7,
    )
    .unwrap();
    sender.tx(pkt).unwrap();
    let frame = sent_frames.lock().unwrap().first().cloned().unwrap();

    let controls: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let controls_c = controls.clone();
    let receiver = Router::new_with_clock(
        RouterConfig::default().with_reliable_enabled(true),
        zero_clock(),
    );
    let receiver_side = receiver.add_side_packed_with_options(
        "to_sender",
        move |bytes: &[u8]| {
            controls_c.lock().unwrap().push(bytes.to_vec());
            Ok(())
        },
        RouterSideOptions {
            reliable_enabled: true,
            ..RouterSideOptions::default()
        },
    );

    receiver.rx_packed_from_side(&frame, receiver_side).unwrap();

    let controls = controls.lock().unwrap().clone();
    assert!(
        controls.iter().any(|bytes| {
            wire_format::peek_envelope(bytes.as_slice())
                .map(|env| env.ty == DataType::ReliableAck)
                .unwrap_or(false)
        }),
        "reliable ack should be emitted immediately on direct rx"
    );
}

#[test]
fn direct_tx_handler_failure_emits_error_without_queue_drain() {
    ensure_reliable_test_schema();

    let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_c = seen.clone();
    let handler = EndpointHandler::new_packet_handler(DataEndpoint::named("SD_CARD"), |_pkt| {
        Err(crate::TelemetryError::Io("boom"))
    });
    let router = Router::new_with_clock(RouterConfig::new(vec![handler]), zero_clock());
    router.add_side_packed("observer", move |bytes| {
        seen_c.lock().unwrap().push(bytes.to_vec());
        Ok(())
    });

    let pkt = Packet::from_f32_slice(
        DataType::named("RELIABLE_TEST_DATA"),
        &[9.0_f32, 8.0, 7.0],
        &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")],
        11,
    )
    .unwrap();

    router.rx(&pkt).unwrap();

    let seen = seen.lock().unwrap().clone();
    assert!(
        seen.iter().any(|bytes| {
            wire_format::peek_envelope(bytes.as_slice())
                .map(|env| env.ty == DataType::TelemetryError)
                .unwrap_or(false)
        }),
        "telemetry error should be emitted immediately on direct tx failure"
    );
    assert_eq!(router.debug_queue_lengths().1, 0);
}

#[test]
fn concurrent_side_tx_busy_is_queued_for_retry() {
    let tx_hits = Arc::new(AtomicUsize::new(0));
    let tx_hits_c = tx_hits.clone();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let release_rx = Arc::new(Mutex::new(release_rx));
    let release_rx_c = release_rx.clone();

    let router = Arc::new(Router::new_with_clock(
        RouterConfig::default(),
        zero_clock(),
    ));
    router.add_side_packed("BUS", move |bytes| -> TelemetryResult<()> {
        if packed_frame_type(bytes) != Some(DataType::named("BATTERY_STATUS")) {
            return Ok(());
        }
        let hit = tx_hits_c.fetch_add(1, Ordering::SeqCst);
        if hit == 0 {
            entered_tx.send(()).unwrap();
            release_rx_c.lock().unwrap().recv().unwrap();
        }
        Ok(())
    });

    let first = Packet::from_f32_slice(
        DataType::named("BATTERY_STATUS"),
        &[1.0_f32, 2.0],
        &[DataEndpoint::named("RADIO")],
        1,
    )
    .unwrap();
    let second = Packet::from_f32_slice(
        DataType::named("BATTERY_STATUS"),
        &[3.0_f32, 4.0],
        &[DataEndpoint::named("RADIO")],
        2,
    )
    .unwrap();

    let router_for_first = router.clone();
    let first_handle = thread::spawn(move || router_for_first.tx(first));
    entered_rx.recv().unwrap();

    router.tx(second).unwrap();
    assert_eq!(
        tx_hits.load(Ordering::SeqCst),
        1,
        "second TX should be queued while the side callback is busy"
    );

    release_tx.send(()).unwrap();
    first_handle.join().unwrap().unwrap();
    router.process_tx_queue().unwrap();
    assert_eq!(
        tx_hits.load(Ordering::SeqCst),
        2,
        "queued TX should flush after the side callback becomes available"
    );
}

#[test]
fn partial_ack_is_emitted_and_still_allows_requested_replay() {
    let sent_frames: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let sent_frames_c = sent_frames.clone();
    let sender = Router::new_with_clock(
        RouterConfig::default().with_reliable_enabled(true),
        zero_clock(),
    );
    let sender_side = sender.add_side_packed_with_options(
        "to_receiver",
        move |bytes: &[u8]| {
            sent_frames_c.lock().unwrap().push(bytes.to_vec());
            Ok(())
        },
        RouterSideOptions {
            reliable_enabled: true,
            ..RouterSideOptions::default()
        },
    );

    let pkt1 = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0_f32, 0.0, 0.0],
        &[DataEndpoint::named("RADIO")],
        1,
    )
    .unwrap();
    let pkt2 = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[2.0_f32, 0.0, 0.0],
        &[DataEndpoint::named("RADIO")],
        2,
    )
    .unwrap();
    sender.tx(pkt1).unwrap();
    sender.tx(pkt2).unwrap();

    let frames = sent_frames.lock().unwrap().clone();
    assert_eq!(frames.len(), 2);

    let receiver_controls: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let receiver_controls_c = receiver_controls.clone();
    let receiver = Router::new_with_clock(
        RouterConfig::default().with_reliable_enabled(true),
        zero_clock(),
    );
    let receiver_side = receiver.add_side_packed_with_options(
        "to_sender",
        move |bytes: &[u8]| {
            receiver_controls_c.lock().unwrap().push(bytes.to_vec());
            Ok(())
        },
        RouterSideOptions {
            reliable_enabled: true,
            ..RouterSideOptions::default()
        },
    );

    receiver
        .rx_packed_from_side(&frames[1], receiver_side)
        .unwrap();
    receiver.process_tx_queue().unwrap();
    let controls = receiver_controls.lock().unwrap().clone();
    assert!(controls.iter().any(|frame| {
        wire_format::peek_envelope(frame)
            .map(|env| env.ty == DataType::ReliablePartialAck)
            .unwrap_or(false)
    }));
    assert!(controls.iter().any(|frame| {
        wire_format::peek_envelope(frame)
            .map(|env| env.ty == DataType::ReliablePacketRequest)
            .unwrap_or(false)
    }));

    let ack1 = Packet::new(
        DataType::ReliableAck,
        &crate::message_meta(DataType::ReliableAck).endpoints,
        "RX",
        0,
        crate::router::encode_slice_le(&[DataType::named("GPS_DATA").as_u32(), 1]),
    )
    .unwrap();
    sender.rx_from_side(&ack1, sender_side).unwrap();
    for control in controls.iter().filter(|frame| {
        wire_format::peek_envelope(frame)
            .map(|env| env.ty == DataType::ReliablePartialAck)
            .unwrap_or(false)
    }) {
        sender.rx_packed_from_side(control, sender_side).unwrap();
    }

    sent_frames.lock().unwrap().clear();
    let request2 = Packet::new(
        DataType::ReliablePacketRequest,
        &crate::message_meta(DataType::ReliablePacketRequest).endpoints,
        "RX",
        0,
        crate::router::encode_slice_le(&[DataType::named("GPS_DATA").as_u32(), 2]),
    )
    .unwrap();
    sender.rx_from_side(&request2, sender_side).unwrap();
    sender.process_tx_queue_with_timeout(0).unwrap();
    assert!(
        sent_frames
            .lock()
            .unwrap()
            .iter()
            .any(|frame| wire_format::peek_frame_info(frame)
                .ok()
                .and_then(|info| info.reliable.map(|hdr| hdr.seq == 2))
                .unwrap_or(false)),
        "requested packet should still retransmit"
    );
}

#[test]
fn lost_request_after_partial_ack_resumes_bounded_retransmission() {
    ensure_reliable_test_schema();
    struct ManualClock(Arc<std::sync::atomic::AtomicU64>);
    impl crate::router::Clock for ManualClock {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    let now = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let sent_frames: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let sent_frames_c = sent_frames.clone();
    let sender = Router::new_with_clock(
        RouterConfig::default().with_reliable_enabled(true),
        Box::new(ManualClock(now.clone())),
    );
    let side = sender.add_side_packed_with_options(
        "uplink",
        move |bytes| {
            sent_frames_c.lock().unwrap().push(bytes.to_vec());
            Ok(())
        },
        RouterSideOptions {
            reliable_enabled: true,
            ..RouterSideOptions::default()
        },
    );
    sender
        .tx(Packet::from_f32_slice(
            DataType::named("RELIABLE_TEST_DATA"),
            &[1.0, 2.0, 3.0],
            &[DataEndpoint::named("RADIO")],
            1,
        )
        .unwrap())
        .unwrap();
    assert_eq!(sent_frames.lock().unwrap().len(), 1);

    let partial = Packet::new(
        DataType::ReliablePartialAck,
        &crate::message_meta(DataType::ReliablePartialAck).endpoints,
        "RX",
        1,
        crate::router::encode_slice_le(&[DataType::named("RELIABLE_TEST_DATA").as_u32(), 1]),
    )
    .unwrap();
    sender.rx_from_side(&partial, side).unwrap();
    let reliable_data_frames = || {
        sent_frames
            .lock()
            .unwrap()
            .iter()
            .filter(|frame| {
                wire_format::peek_envelope(frame)
                    .map(|env| env.ty == DataType::named("RELIABLE_TEST_DATA"))
                    .unwrap_or(false)
            })
            .count()
    };
    let frames_after_partial_ack = reliable_data_frames();

    now.store(crate::config::RELIABLE_RETRANSMIT_MS + 1, Ordering::SeqCst);
    sender.process_all_queues().unwrap();
    assert_eq!(
        reliable_data_frames(),
        frames_after_partial_ack,
        "partial ACK grants one interval for the explicit packet request"
    );

    now.store(
        2 * crate::config::RELIABLE_RETRANSMIT_MS + 2,
        Ordering::SeqCst,
    );
    sender.process_all_queues().unwrap();
    assert_eq!(
        reliable_data_frames(),
        frames_after_partial_ack + 1,
        "a lost packet request must not pin reliable history forever"
    );
}

#[test]
fn reliable_ordered_delivers_in_order() {
    ensure_reliable_test_schema();
    let delivered: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
    let delivered_c = delivered.clone();
    let handler = EndpointHandler::new_packed_handler(
        DataEndpoint::named("SD_CARD"),
        move |bytes: &[u8]| -> TelemetryResult<()> {
            let frame = wire_format::peek_frame_info(bytes)?;
            if frame.envelope.ty == DataType::named("RELIABLE_TEST_DATA")
                && let Some(hdr) = frame.reliable
                && (hdr.flags & wire_format::RELIABLE_FLAG_ACK_ONLY) == 0
            {
                delivered_c.lock().unwrap().push(hdr.seq);
            }
            Ok(())
        },
    );

    let router = Router::new_with_clock(
        RouterConfig::new(vec![handler]).with_reliable_enabled(true),
        zero_clock(),
    );

    let side = router.add_side_packed_with_options(
        "SRC",
        |_b| Ok(()),
        RouterSideOptions {
            reliable_enabled: true,
            link_local_enabled: false,
            ..RouterSideOptions::default()
        },
    );

    let pkt1 = Packet::from_f32_slice(
        DataType::named("RELIABLE_TEST_DATA"),
        &[1.0_f32, 2.0, 3.0],
        &[DataEndpoint::named("SD_CARD")],
        0,
    )
    .unwrap();
    let pkt2 = Packet::from_f32_slice(
        DataType::named("RELIABLE_TEST_DATA"),
        &[4.0_f32, 5.0, 6.0],
        &[DataEndpoint::named("SD_CARD")],
        0,
    )
    .unwrap();

    let seq1 = wire_format::pack_packet_with_reliable(
        &pkt1,
        wire_format::ReliableHeader {
            flags: 0,
            seq: 1,
            ack: 0,
        },
    );
    let seq2 = wire_format::pack_packet_with_reliable(
        &pkt2,
        wire_format::ReliableHeader {
            flags: 0,
            seq: 2,
            ack: 0,
        },
    );

    // Out-of-order: seq2 arrives first, then seq1, then seq2 retransmit.
    router.rx_packed_from_side(seq2.as_ref(), side).unwrap();
    router.rx_packed_from_side(seq1.as_ref(), side).unwrap();
    router.rx_packed_from_side(seq2.as_ref(), side).unwrap();

    let delivered = delivered.lock().unwrap().clone();
    assert_eq!(
        delivered,
        vec![1, 2],
        "ordered reliable delivery must reorder"
    );
}

#[test]
fn reliable_sender_does_not_block_while_waiting_for_ack() {
    let sent: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
    let sent_c = sent.clone();

    let router = Router::new_with_clock(
        RouterConfig::new(Vec::new()).with_reliable_enabled(true),
        zero_clock(),
    );

    router.add_side_packed_with_options(
        "DST",
        move |bytes: &[u8]| -> TelemetryResult<()> {
            let frame = wire_format::peek_frame_info(bytes)?;
            if frame.envelope.ty == DataType::named("GPS_DATA")
                && let Some(hdr) = frame.reliable
            {
                sent_c.lock().unwrap().push(hdr.seq);
            }
            Ok(())
        },
        RouterSideOptions {
            reliable_enabled: true,
            link_local_enabled: false,
            ..RouterSideOptions::default()
        },
    );

    let pkt1 = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0_f32, 2.0, 3.0],
        &[DataEndpoint::named("SD_CARD")],
        0,
    )
    .unwrap();
    let pkt2 = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[4.0_f32, 5.0, 6.0],
        &[DataEndpoint::named("SD_CARD")],
        1,
    )
    .unwrap();

    router.tx(pkt1).unwrap();
    router.tx(pkt2).unwrap();
    router.process_tx_queue_with_timeout(0).unwrap();

    assert_eq!(*sent.lock().unwrap(), vec![1, 2]);
}

#[test]
fn reliable_disabled_skips_ack() {
    let rx_hits = Arc::new(AtomicUsize::new(0));
    let rx_hits_c = rx_hits.clone();
    let handler = EndpointHandler::new_packet_handler(
        DataEndpoint::named("SD_CARD"),
        move |_pkt: &Packet| {
            rx_hits_c.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    );

    let ack_count = Arc::new(AtomicUsize::new(0));
    let ack_count_c = ack_count.clone();
    let rx_direct = move |_bytes: &[u8]| -> TelemetryResult<()> {
        ack_count_c.fetch_add(1, Ordering::SeqCst);
        Ok(())
    };

    let receiver = Arc::new(Router::new_with_clock(
        RouterConfig::new(vec![handler]).with_reliable_enabled(false),
        zero_clock(),
    ));
    receiver.add_side_packed("ACK", rx_direct);

    let rx_for_tx = receiver.clone();
    let tx = move |bytes: &[u8]| -> TelemetryResult<()> {
        rx_for_tx.rx_packed_from_side(bytes, 0)?;
        Ok(())
    };

    let sender = Router::new_with_clock(
        RouterConfig::new(Vec::new()).with_reliable_enabled(false),
        zero_clock(),
    );
    sender.add_side_packed("TO_RECEIVER", tx);

    let pkt = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[4.0_f32, 5.0, 6.0],
        &[DataEndpoint::named("SD_CARD")],
        0,
    )
    .unwrap();

    sender.tx(pkt).unwrap();

    assert_eq!(rx_hits.load(Ordering::SeqCst), 1);
    assert_eq!(ack_count.load(Ordering::SeqCst), 0);
}
