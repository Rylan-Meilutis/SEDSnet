use crate::config::{DataEndpoint, DataType, RELIABLE_RETRANSMIT_MS};
use crate::discovery::build_discovery_announce;
use crate::relay::{Relay, RelaySideOptions};
use crate::router::Clock;
use crate::tests::packed_frame_type;
use crate::tests::timeout_tests::StepClock;
use crate::{TelemetryResult, packet::Packet, wire_format};

use std::sync::{Arc, Mutex};

fn zero_clock() -> Box<dyn Clock + Send + Sync> {
    Box::new(|| 0u64)
}

fn advertise_side(relay: &Relay, side: usize) {
    let pkt = build_discovery_announce("DST_SIDE", 0, &[DataEndpoint::named("SD_CARD")]).unwrap();
    relay.rx_from_side(side, pkt).unwrap();
}

#[test]
fn relay_reliable_seq_advances_with_ack() {
    let relay = Arc::new(Relay::new(zero_clock()));

    relay.add_side_packed_with_options(
        "SRC",
        |_b| Ok(()),
        RelaySideOptions {
            reliable_enabled: true,
            link_local_enabled: false,
            ..RelaySideOptions::default()
        },
    );

    let sent: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let sent_c = sent.clone();
    let relay_c = relay.clone();
    let dst = relay.add_side_packed_with_options(
        "DST",
        move |bytes: &[u8]| -> TelemetryResult<()> {
            sent_c.lock().unwrap().push(bytes.to_vec());

            let frame = wire_format::peek_frame_info(bytes)?;
            if let Some(hdr) = frame.reliable {
                let ack_bytes =
                    wire_format::pack_reliable_ack("DST", frame.envelope.ty, 0, hdr.seq);
                relay_c.rx_packed_from_side(1, ack_bytes.as_ref())?;
            }
            Ok(())
        },
        RelaySideOptions {
            reliable_enabled: true,
            link_local_enabled: false,
            ..RelaySideOptions::default()
        },
    );
    advertise_side(&relay, dst);
    relay.process_all_queues_with_timeout(0).unwrap();

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
        0,
    )
    .unwrap();

    relay.rx_from_side(0, pkt1).unwrap();
    relay.rx_from_side(0, pkt2).unwrap();
    relay.process_all_queues_with_timeout(0).unwrap();
    relay.process_all_queues_with_timeout(0).unwrap();

    let sent = sent.lock().unwrap();
    let gps_sent: Vec<_> = sent
        .iter()
        .filter(|bytes| packed_frame_type(bytes.as_slice()) == Some(DataType::named("GPS_DATA")))
        .collect();
    assert!(
        gps_sent.len() >= 2,
        "expected at least 2 forwarded GPS frames"
    );

    let f1 = wire_format::peek_frame_info(gps_sent[0]).unwrap();
    let f2 = wire_format::peek_frame_info(gps_sent[1]).unwrap();
    let h1 = f1.reliable.expect("frame 1 missing reliable header");
    let h2 = f2.reliable.expect("frame 2 missing reliable header");
    assert_eq!(h1.seq, 1);
    assert_eq!(h2.seq, 2);
    assert_eq!(h1.flags & wire_format::RELIABLE_FLAG_UNSEQUENCED, 0);
    assert_eq!(h2.flags & wire_format::RELIABLE_FLAG_UNSEQUENCED, 0);
}

#[test]
fn relay_reliable_retransmit_across_chain_preserves_order() {
    crate::tests::ensure_common_test_schema();
    let reliable_ty = {
        use crate::config::register_data_type_with_description;
        use crate::{MessageClass, MessageDataType, MessageElement, ReliableMode};
        let radio = DataEndpoint::named("RADIO");
        let sd_card = DataEndpoint::named("SD_CARD");
        DataType::try_named("RELAY_CHAIN_RELIABLE_DATA").unwrap_or_else(|| {
            register_data_type_with_description(
                "RELAY_CHAIN_RELIABLE_DATA",
                "ordered reliable relay-chain regression test type",
                MessageElement::Static(3, MessageDataType::Float32, MessageClass::Data),
                &[radio, sd_card],
                ReliableMode::Ordered,
                1,
            )
            .expect("register RELAY_CHAIN_RELIABLE_DATA")
        })
    };
    let relay1 = Arc::new(Relay::new(StepClock::new_box(
        0,
        RELIABLE_RETRANSMIT_MS + 1,
    )));
    let relay2 = Arc::new(Relay::new(zero_clock()));

    relay1.add_side_packed_with_options(
        "SRC",
        |_b| Ok(()),
        RelaySideOptions {
            reliable_enabled: true,
            link_local_enabled: false,
            ..RelaySideOptions::default()
        },
    );

    // Link: relay1 -> relay2 (drop first seq=1 data frame to force retransmit)
    let drop_first = Arc::new(Mutex::new(true));
    let drop_first_c = drop_first.clone();
    let relay2_rx = relay2.clone();
    let link_sent: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
    let link_sent_c = link_sent.clone();
    let relay1_mid = relay1.add_side_packed_with_options(
        "MID",
        move |bytes: &[u8]| -> TelemetryResult<()> {
            let frame = wire_format::peek_frame_info(bytes)?;
            if let Some(hdr) = frame.reliable
                && (hdr.flags & wire_format::RELIABLE_FLAG_ACK_ONLY) == 0
                && frame.envelope.ty == reliable_ty
            {
                link_sent_c.lock().unwrap().push(hdr.seq);
                if hdr.seq == 1 && *drop_first_c.lock().unwrap() {
                    *drop_first_c.lock().unwrap() = false;
                    return Ok(());
                }
            }
            relay2_rx.rx_packed_from_side(0, bytes)
        },
        RelaySideOptions {
            reliable_enabled: true,
            link_local_enabled: false,
            ..RelaySideOptions::default()
        },
    );

    // Link: relay2 -> relay1 (ACKs and reverse traffic)
    let relay1_rx = relay1.clone();
    let _relay2_mid = relay2.add_side_packed_with_options(
        "MID",
        move |bytes: &[u8]| -> TelemetryResult<()> { relay1_rx.rx_packed_from_side(1, bytes) },
        RelaySideOptions {
            reliable_enabled: true,
            link_local_enabled: false,
            ..RelaySideOptions::default()
        },
    );

    // Destination capture on relay2
    let delivered: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
    let delivered_c = delivered.clone();
    let relay2_for_ack = relay2.clone();
    let relay1_for_ack = relay1.clone();
    let relay2_dst_id: Arc<Mutex<Option<usize>>> = Arc::new(Mutex::new(None));
    let relay2_dst_id_c = relay2_dst_id.clone();
    let relay2_dst = relay2.add_side_packed_with_options(
        "DST",
        move |bytes: &[u8]| -> TelemetryResult<()> {
            let frame = wire_format::peek_frame_info(bytes)?;
            if let Some(hdr) = frame.reliable
                && (hdr.flags & wire_format::RELIABLE_FLAG_ACK_ONLY) == 0
            {
                delivered_c.lock().unwrap().push(hdr.seq);
                let ack_bytes =
                    wire_format::pack_reliable_ack("DST", frame.envelope.ty, 0, hdr.seq);
                if let Some(dst_id) = *relay2_dst_id_c.lock().unwrap() {
                    relay2_for_ack.rx_packed_from_side(dst_id, ack_bytes.as_ref())?;
                }
                relay1_for_ack.rx_packed_from_side(relay1_mid, ack_bytes.as_ref())?;
            }
            Ok(())
        },
        RelaySideOptions {
            reliable_enabled: true,
            link_local_enabled: false,
            ..RelaySideOptions::default()
        },
    );
    *relay2_dst_id.lock().unwrap() = Some(relay2_dst);

    let pkt1 = Packet::from_f32_slice(
        reliable_ty,
        &[1.0_f32, 2.0, 3.0],
        &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")],
        0,
    )
    .unwrap();
    let pkt2 = Packet::from_f32_slice(
        reliable_ty,
        &[4.0_f32, 5.0, 6.0],
        &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")],
        0,
    )
    .unwrap();

    relay1.rx_from_side(0, pkt1).unwrap();
    relay1.rx_from_side(0, pkt2).unwrap();

    for _ in 0..10 {
        relay1.process_all_queues_with_timeout(0).unwrap();
        relay2.process_all_queues_with_timeout(0).unwrap();
        if delivered.lock().unwrap().len() >= 2 {
            break;
        }
    }

    let delivered = delivered.lock().unwrap().clone();
    let mut first_seen = Vec::new();
    for seq in delivered {
        if !first_seen.contains(&seq) {
            first_seen.push(seq);
        }
    }
    assert!(
        first_seen.as_slice().starts_with(&[1, 2]),
        "destination must observe the ordered sequence before any later retransmits: {first_seen:?}"
    );

    let link_sent = link_sent.lock().unwrap().clone();
    let seq1_count = link_sent.iter().filter(|&&s| s == 1).count();
    assert!(
        seq1_count >= 2,
        "expected seq1 to be retransmitted across the relay chain"
    );
}

#[test]
fn relay_reliable_reorders_out_of_order_frames() {
    let relay = Arc::new(Relay::new(zero_clock()));

    relay.add_side_packed_with_options(
        "SRC",
        |_b| Ok(()),
        RelaySideOptions {
            reliable_enabled: true,
            link_local_enabled: false,
            ..RelaySideOptions::default()
        },
    );

    let delivered: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
    let delivered_c = delivered.clone();
    let relay_for_ack = relay.clone();
    let dst = relay.add_side_packed_with_options(
        "DST",
        move |bytes: &[u8]| -> TelemetryResult<()> {
            let frame = wire_format::peek_frame_info(bytes)?;
            if frame.envelope.ty == DataType::named("GPS_DATA")
                && let Some(hdr) = frame.reliable
                && (hdr.flags & wire_format::RELIABLE_FLAG_ACK_ONLY) == 0
            {
                delivered_c.lock().unwrap().push(hdr.seq);
                let ack_bytes =
                    wire_format::pack_reliable_ack("DST", frame.envelope.ty, 0, hdr.seq);
                relay_for_ack.rx_packed_from_side(1, ack_bytes.as_ref())?;
            }
            Ok(())
        },
        RelaySideOptions {
            reliable_enabled: true,
            link_local_enabled: false,
            ..RelaySideOptions::default()
        },
    );
    advertise_side(&relay, dst);
    relay.process_all_queues_with_timeout(0).unwrap();

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
    relay.rx_packed_from_side(0, seq2.as_ref()).unwrap();
    relay.rx_packed_from_side(0, seq1.as_ref()).unwrap();
    relay.rx_packed_from_side(0, seq2.as_ref()).unwrap();

    relay.process_all_queues_with_timeout(0).unwrap();

    let delivered = delivered.lock().unwrap().clone();
    assert_eq!(
        delivered,
        vec![1, 2],
        "out-of-order frames must be reordered"
    );
}

#[test]
fn relay_reliable_sender_does_not_block_while_waiting_for_ack() {
    let relay = Arc::new(Relay::new(zero_clock()));

    relay.add_side_packed_with_options(
        "SRC",
        |_b| Ok(()),
        RelaySideOptions {
            reliable_enabled: true,
            link_local_enabled: false,
            ..RelaySideOptions::default()
        },
    );

    let sent: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
    let sent_c = sent.clone();
    relay.add_side_packed_with_options(
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
        RelaySideOptions {
            reliable_enabled: true,
            link_local_enabled: false,
            ..RelaySideOptions::default()
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

    relay.rx_from_side(0, pkt1).unwrap();
    relay.rx_from_side(0, pkt2).unwrap();
    relay.process_all_queues_with_timeout(0).unwrap();

    assert_eq!(*sent.lock().unwrap(), vec![1, 2]);
}
