use super::*;

#[test]
fn relay_chunk_identity_and_loss_are_bounded() {
    crate::tests::ensure_common_test_schema();
    let relay = Relay::new(Box::new(|| 0));
    let side = relay.add_side_packed_with_options("CAN", |_| Ok(()), RelaySideOptions::default());
    // Relay full frames include a leading one-byte template ID.
    let a = Relay::wrap_side_transport_frame(SIDE_TRANSPORT_KIND_FULL, &[1; 181]);
    let b = Relay::wrap_side_transport_frame(SIDE_TRANSPORT_KIND_FULL, &[2; 181]);
    let first = relay
        .split_side_transport_frame(side, a.clone(), 128)
        .unwrap();
    let repeat = relay.split_side_transport_frame(side, a, 128).unwrap();
    let second = relay.split_side_transport_frame(side, b, 128).unwrap();
    assert_eq!(&first[0][4..8], &repeat[0][4..8]);
    assert_ne!(&first[0][4..8], &second[0][4..8]);
    assert!(
        relay
            .decode_side_transport_frame(side, &first[0])
            .unwrap()
            .is_none()
    );
    let mut decoded = None;
    for frame in second {
        decoded = relay.decode_side_transport_frame(side, &frame).unwrap();
    }
    assert_eq!(decoded.unwrap().as_ref(), &[2; 180]);
    for i in 0..1000u32 {
        let mut data = vec![0; 180];
        data[..4].copy_from_slice(&i.to_le_bytes());
        let frame = Relay::wrap_side_transport_frame(SIDE_TRANSPORT_KIND_FULL, &data);
        let chunks = relay.split_side_transport_frame(side, frame, 128).unwrap();
        relay.decode_side_transport_frame(side, &chunks[0]).unwrap();
        assert!(relay.state.lock().side_transport[&side].rx_chunks.len() <= 4);
    }
}

#[test]
fn unacknowledged_topology_does_not_silence_relay_liveness() {
    use std::sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    };
    crate::tests::ensure_common_test_schema();
    let now = Arc::new(AtomicU64::new(0));
    let clock = now.clone();
    let emitted = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let output = emitted.clone();
    let relay = Relay::new(Box::new(move || clock.load(Ordering::Relaxed)));
    let side = relay.add_side_packed_with_options(
        "CAN",
        move |frame| {
            output.lock().unwrap().push(frame.to_vec());
            Ok(())
        },
        RelaySideOptions {
            reliable_enabled: true,
            ..Default::default()
        },
    );
    relay.announce_discovery().unwrap();
    relay.process_tx_queue().unwrap();
    assert!(
        relay
            .state
            .lock()
            .reliable_tx
            .iter()
            .any(|((s, ty), tx)| *s == side
                && *ty == crate::DataType::DiscoveryTopology.as_u32()
                && !tx.sent.is_empty())
    );
    emitted.lock().unwrap().clear();
    for ms in (1_000..=60_000).step_by(1_000) {
        now.store(ms, Ordering::Relaxed);
        relay.poll_discovery().unwrap();
        // Hold the baseline ACK outstanding; drain only new advertisements.
        while let Some((src, dst, handler, opts, item)) = relay.pop_ready_tx_item() {
            relay.send_tx_item(src, dst, handler, opts, item).unwrap();
        }
    }
    let frames = emitted.lock().unwrap();
    let types: Vec<_> = frames
        .iter()
        .map(|frame| wire_format::peek_envelope(frame).unwrap().ty)
        .collect();
    let pings = types
        .iter()
        .filter(|ty| **ty == crate::DataType::DiscoveryAnnounce)
        .count();
    assert!(
        (3..=5).contains(&pings),
        "keepalives must continue at a bounded rate despite a lost topology ACK; got {pings}"
    );
    assert!(
        types
            .iter()
            .all(|ty| *ty != crate::DataType::DiscoveryTopology)
    );
}

#[test]
fn zero_template_capacity_does_not_retain_timestamp_entries() {
    crate::tests::ensure_common_test_schema();
    let ty = crate::config::register_data_type_with_description(
        "RELAY_ZERO_TEMPLATE_CAPACITY",
        "",
        crate::MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[crate::DataEndpoint::named("RADIO")],
        crate::ReliableMode::None,
        1,
    )
    .unwrap();
    let tx = Relay::new(Box::new(|| 0));
    let rx = Relay::new(Box::new(|| 0));
    let opts = RelaySideOptions {
        max_side_transport_templates: 0,
        ..RelaySideOptions::default().with_small_packet_transport(0)
    };
    let a = tx.add_side_packed_with_options("wire", |_| Ok(()), opts);
    let b = rx.add_side_packed_with_options("wire", |_| Ok(()), opts);
    for index in 0..32 {
        let packet = Packet::new(
            ty,
            &[crate::DataEndpoint::named("RADIO")],
            &format!("PEER{index}"),
            index,
            Arc::<[u8]>::from([0u8]),
        )
        .unwrap();
        let raw = wire_format::pack_packet(&packet);
        let frames = tx
            .encode_side_transport_frames(a, opts, raw.clone())
            .unwrap();
        assert_eq!(
            rx.decode_side_transport_frame(b, &frames[0]).unwrap(),
            Some(raw)
        );
    }
    let st = tx.state.lock();
    assert!(st.side_transport[&a].tx_template_ids.is_empty());
    assert!(
        st.side_transport[&a].tx_last_timestamps.is_empty(),
        "disabled compression must not leak one timestamp entry per header"
    );
    drop(st);
    let st = rx.state.lock();
    assert_eq!(st.side_transport[&b].rx_template_count(), 0);
    assert!(
        st.side_transport[&b].rx_last_timestamps.is_empty(),
        "zero-capacity RX must not retain timestamps without templates"
    );
}

#[test]
fn reliable_control_survives_a_missing_compact_dictionary() {
    crate::tests::ensure_common_test_schema();
    let status = crate::config::register_data_type_with_description(
        "RELAY_RELIABLE_HEADER_RECOVERY",
        "ordered status header recovery",
        crate::MessageElement::Static(2, crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[crate::DataEndpoint::named("RADIO")],
        crate::ReliableMode::Ordered,
        200,
    )
    .unwrap();
    for ty in [
        crate::DataType::ReliableAck,
        crate::DataType::ReliablePartialAck,
        crate::DataType::ReliablePacketRequest,
        status,
    ] {
        let tx = Relay::new(Box::new(|| 0));
        let rx = Relay::new(Box::new(|| 0));
        let opts = RelaySideOptions::default().with_small_packet_transport(0);
        let a = tx.add_side_packed_with_options("wire", |_| Ok(()), opts);
        let b = rx.add_side_packed_with_options("wire", |_| Ok(()), opts);
        let packet = Packet::new(
            ty,
            crate::message_meta(ty).endpoints_ref(),
            "GS",
            100,
            Arc::<[u8]>::from(vec![0u8; crate::get_needed_message_size(ty)]),
        )
        .unwrap();
        let raw = wire_format::pack_packet(&packet);
        tx.encode_side_transport_frames(a, opts, raw.clone())
            .unwrap();
        // Lose the initial header (or restart the receiver), then send control.
        let frames = tx
            .encode_side_transport_frames(a, opts, raw.clone())
            .unwrap();
        assert_eq!(
            rx.decode_side_transport_frame(b, &frames[0]).unwrap(),
            Some(raw),
            "reliability control cannot depend on a possibly lost template"
        );
        assert!(
            tx.state.lock().side_transport[&a]
                .tx_template_ids
                .is_empty(),
            "self-describing reliable frames must not retain unused TX templates"
        );
        assert_eq!(
            rx.state.lock().side_transport[&b].rx_template_count(),
            0,
            "self-describing reliable frames must not consume the RX dictionary"
        );
    }
}

#[test]
fn restarting_peer_refreshes_relay_application_headers_without_erasing_rx() {
    crate::tests::ensure_common_test_schema();
    let ty = crate::config::register_data_type_with_description(
        "RELAY_RESTART_BEST_EFFORT",
        "",
        crate::MessageElement::Static(12, crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[crate::DataEndpoint::named("RADIO")],
        crate::ReliableMode::None,
        1,
    )
    .unwrap();
    for schema_request in [false, true] {
        let tx = Relay::new(Box::new(|| 100));
        let opts = RelaySideOptions::default().with_small_packet_transport(0);
        let side = tx.add_side_packed_with_options("uart", |_| Ok(()), opts);
        let unrelated = tx.add_side_packed_with_options("radio", |_| Ok(()), opts);
        let packet = Packet::new(
            ty,
            &[crate::DataEndpoint::named("RADIO")],
            "AB",
            50,
            Arc::<[u8]>::from([0u8; 12]),
        )
        .unwrap();
        let raw = wire_format::pack_packet(&packet);
        let initial = tx
            .encode_side_transport_frames(side, opts, raw.clone())
            .unwrap();
        tx.decode_side_transport_frame(side, &initial[0])
            .unwrap()
            .unwrap();
        tx.encode_side_transport_frames(unrelated, opts, raw.clone())
            .unwrap();
        let request = if schema_request {
            discovery::build_discovery_schema_request("GS", 2)
        } else {
            discovery::build_discovery_topology_request("GS", 2)
        }
        .unwrap();
        tx.learn_discovery_item(side, &RelayItem::Packet(Arc::new(request)))
            .unwrap();
        let restarted = Relay::new(Box::new(|| 100));
        let rx = restarted.add_side_packed_with_options("uart", |_| Ok(()), opts);
        let frames = tx
            .encode_side_transport_frames(side, opts, raw.clone())
            .unwrap();
        assert!(
            restarted
                .decode_side_transport_frame(rx, &frames[0])
                .unwrap()
                .is_some()
        );
        assert_eq!(tx.state.lock().side_transport[&side].rx_template_count(), 1);
        let frames = tx
            .encode_side_transport_frames(unrelated, opts, raw)
            .unwrap();
        let empty = Relay::new(Box::new(|| 100));
        let rx = empty.add_side_packed_with_options("uart", |_| Ok(()), opts);
        assert!(matches!(
            empty.decode_side_transport_frame(rx, &frames[0]),
            Err(TelemetryError::Unpack("unknown side compact template"))
        ));
    }
}
