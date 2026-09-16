use super::*;

#[test]
fn zero_template_capacity_does_not_retain_timestamp_entries() {
    crate::tests::ensure_common_test_schema();
    let ty = crate::config::register_data_type_with_description(
        "ROUTER_ZERO_TEMPLATE_CAPACITY", "",
        crate::MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[crate::DataEndpoint::named("RADIO")], crate::ReliableMode::None, 1).unwrap();
    let tx = Router::new(RouterConfig::default());
    let rx = Router::new(RouterConfig::default());
    let opts = RouterSideOptions {
        max_side_transport_templates: 0,
        ..RouterSideOptions::default().with_small_packet_transport(0)
    };
    let a = tx.add_side_packed_with_options("wire", |_| Ok(()), opts);
    let b = rx.add_side_packed_with_options("wire", |_| Ok(()), opts);
    for index in 0..32 {
        let packet = Packet::new(ty, &[crate::DataEndpoint::named("RADIO")],
            &format!("PEER{index}"), index, Arc::<[u8]>::from([0u8])).unwrap();
        let raw = wire_format::pack_packet(&packet);
        let frames = tx.encode_side_transport_frames(a, opts, raw.clone()).unwrap();
        assert_eq!(rx.decode_side_transport_frame(b, &frames[0]).unwrap(), Some(raw));
    }
    let st = tx.state.lock();
    assert!(st.side_transport[&a].tx_template_ids.is_empty());
    assert!(st.side_transport[&a].tx_last_timestamps.is_empty(),
        "disabled compression must not leak one timestamp entry per header");
    drop(st);
    let st = rx.state.lock();
    assert_eq!(st.side_transport[&b].rx_template_count(), 0);
    assert!(st.side_transport[&b].rx_last_timestamps.is_empty(),
        "zero-capacity RX must not retain timestamps without templates");
}

#[test]
fn reliable_control_survives_a_missing_compact_dictionary() {
    crate::tests::ensure_common_test_schema();
    let status = crate::config::register_data_type_with_description(
        "ROUTER_RELIABLE_HEADER_RECOVERY", "ordered status header recovery",
        crate::MessageElement::Static(2, crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[crate::DataEndpoint::named("RADIO")], crate::ReliableMode::Ordered, 200).unwrap();
    for ty in [crate::DataType::ReliableAck, crate::DataType::ReliablePartialAck, crate::DataType::ReliablePacketRequest, status] {
        let tx = Router::new(RouterConfig::default());
        let rx = Router::new(RouterConfig::default());
        let opts = RouterSideOptions::default().with_small_packet_transport(0);
        let a = tx.add_side_packed_with_options("wire", |_| Ok(()), opts);
        let b = rx.add_side_packed_with_options("wire", |_| Ok(()), opts);
        let packet = Packet::new(ty, crate::message_meta(ty).endpoints_ref(),
            "GS", 100, Arc::<[u8]>::from(vec![0u8; crate::get_needed_message_size(ty)])).unwrap();
        let raw = wire_format::pack_packet(&packet);
        tx.encode_side_transport_frames(a, opts, raw.clone()).unwrap();
        // Lose the initial header (or restart the receiver), then send control.
        let frames = tx.encode_side_transport_frames(a, opts, raw.clone()).unwrap();
        assert_eq!(rx.decode_side_transport_frame(b, &frames[0]).unwrap(), Some(raw),
            "reliability control cannot depend on a possibly lost template");
        assert!(tx.state.lock().side_transport[&a].tx_template_ids.is_empty(),
            "self-describing reliable frames must not retain unused TX templates");
        assert_eq!(rx.state.lock().side_transport[&b].rx_template_count(), 0,
            "self-describing reliable frames must not consume the RX dictionary");
    }
}

#[test]
fn restarting_peer_discovery_request_refreshes_next_application_header() {
    for schema_request in [false, true] {
        check_restarting_peer_header(schema_request);
    }
}

fn check_restarting_peer_header(schema_request: bool) {
    crate::tests::ensure_common_test_schema();
    let ty = crate::DataType::try_named("ROUTER_RESTART_BEST_EFFORT").unwrap_or_else(||
        crate::config::register_data_type_with_description("ROUTER_RESTART_BEST_EFFORT", "",
            crate::MessageElement::Static(12, crate::MessageDataType::UInt8, crate::MessageClass::Data),
            &[crate::DataEndpoint::named("RADIO")], crate::ReliableMode::None, 1).unwrap());
    let tx = Router::new_with_clock(
        RouterConfig::new([]).with_sender("GB"), Box::new(|| 100u64));
    let opts = RouterSideOptions::default().with_small_packet_transport(0);
    let side = tx.add_side_packed_with_options("uart", |_| Ok(()), opts);
    let unrelated = tx.add_side_packed_with_options("radio", |_| Ok(()), opts);
    let endpoint = DataEndpoint::named("RADIO");
    tx.rx_from_side(&discovery::build_discovery_announce("GS", 1, &[endpoint]).unwrap(), side).unwrap();
    let packet = Packet::new(ty, &[endpoint], "AB", 50,
        Arc::<[u8]>::from([0u8; 12])).unwrap();
    // The peer knew this template before its process restarted.
    let initial = tx.encode_side_transport_frames(side, opts, wire_format::pack_packet(&packet)).unwrap();
    tx.decode_side_transport_frame(side, &initial[0]).unwrap().unwrap();
    tx.encode_side_transport_frames(unrelated, opts, wire_format::pack_packet(&packet)).unwrap();
    let restarted = Router::new(RouterConfig::default());
    let rx_side = restarted.add_side_packed_with_options("uart", |_| Ok(()), opts);
    let request = if schema_request {
        discovery::build_discovery_schema_request("GS", 2)
    } else {
        discovery::build_discovery_topology_request("GS", 2)
    }.unwrap();
    tx.rx_from_side(&request, side).unwrap();
    let frames = tx.encode_side_transport_frames(side, opts, wire_format::pack_packet(&packet)).unwrap();
    assert!(restarted.decode_side_transport_frame(rx_side, &frames[0]).unwrap().is_some(),
        "a peer requesting discovery must receive a self-describing application header immediately");
    assert_eq!(tx.state.lock().side_transport[&side].rx_template_count(), 1,
        "incoming dictionaries must survive a transmit refresh");
    let unrelated_frames = tx.encode_side_transport_frames(unrelated, opts, wire_format::pack_packet(&packet)).unwrap();
    let empty = Router::new(RouterConfig::default());
    let empty_side = empty.add_side_packed_with_options("wire", |_| Ok(()), opts);
    assert!(empty.decode_side_transport_frame(empty_side, &unrelated_frames[0]).unwrap().is_none(),
        "unrelated links must keep their existing compact dictionary");
}

#[test]
fn reliable_missing_route_is_an_error_and_same_packet_can_retry_after_discovery() {
    crate::tests::ensure_common_test_schema();
    let destination = DataEndpoint::named("RADIO");
    let ty = crate::config::register_data_type_with_description(
        "NO_ROUTE_RETRY_TEST", "reliable route recovery",
        MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[destination], crate::ReliableMode::Ordered, 200).unwrap();
    let received = Arc::new(core::sync::atomic::AtomicU32::new(0));
    let received_cb = received.clone();
    let router = Router::new(RouterConfig::default());
    let side = router.add_side_packet("can", move |_| {
        received_cb.fetch_add(1, Ordering::Relaxed); Ok(())
    });
    router.rx_from_side(&discovery::build_discovery_announce(
        "PEER", 1, &[DataEndpoint::named("SD_CARD")]).unwrap(), side).unwrap();
    let packet = Packet::new(ty, &[destination], "VB", 42,
        Arc::from([1u8].as_slice())).unwrap();
    assert!(router.tx(packet.clone()).is_err(),
        "a missing remote route must not masquerade as successful delivery");
    assert_eq!(received.load(Ordering::Relaxed), 0);
    router.rx_from_side(&discovery::build_discovery_announce(
        "PEER", 2, &[destination]).unwrap(), side).unwrap();
    router.tx(packet).unwrap();
    assert_eq!(received.load(Ordering::Relaxed), 1,
        "failed submission must not poison duplicate tracking");
}

#[test]
fn discovery_refresh_survives_a_missed_transport_template() {
    crate::tests::ensure_common_test_schema();
    let tx = Router::new(RouterConfig::default());
    let rx = Router::new(RouterConfig::default());
    let opts = RouterSideOptions::default().with_small_packet_transport(512);
    let tx_side = tx.add_side_packed_with_options("can", |_| Ok(()), opts);
    let rx_side = rx.add_side_packed_with_options("can", |_| Ok(()), opts);
    for timestamp in [1000, 6000] {
        let packet = discovery::build_discovery_announce("GB", timestamp, &[]).unwrap();
        let frames = tx.encode_side_transport_frames(
            tx_side, opts, wire_format::pack_packet(&packet)).unwrap();
        if timestamp == 1000 { continue; }
        let decoded = rx.decode_side_transport_frame(rx_side, &frames[0]).unwrap();
        assert!(decoded.is_some(), "discovery must bootstrap without a dictionary");
    }
}

#[test]
fn compact_loss_must_not_change_packet_identity() {
    crate::tests::ensure_common_test_schema();
    let tx = Router::new_with_clock(RouterConfig::new([]).with_sender("VB"), Box::new(|| 0u64));
    let rx = Router::new_with_clock(RouterConfig::new([]).with_sender("GS"), Box::new(|| 0u64));
    let opts = RouterSideOptions::default().with_small_packet_transport(0);
    let a = tx.add_side_packed_with_options("wire", |_| Ok(()), opts);
    let b = rx.add_side_packed_with_options("wire", |_| Ok(()), opts);
    for (index, timestamp) in [10000, 10010, 10020].into_iter().enumerate() {
        let pkt = Packet::new(
            DataType::named("GPS_DATA"),
            &[DataEndpoint::named("RADIO")],
            "VB",
            timestamp,
            Arc::<[u8]>::from([0u8; 12]),
        )
        .unwrap();
        let raw = wire_format::pack_packet(&pkt);
        let frames = tx
            .encode_side_transport_frames(a, opts, raw.clone())
            .unwrap();
        assert_eq!(frames.len(), 1);
        if index == 1 {
            continue;
        } // One valid datagram is lost in transit.
        let received = rx
            .decode_side_transport_frame(b, &frames[0])
            .unwrap()
            .unwrap();
        assert_eq!(
            wire_format::unpack_packet(&received).unwrap().timestamp(),
            timestamp
        );
        assert_eq!(
            received, raw,
            "loss must not silently rewrite a later packet"
        );
    }
}

#[test]
fn generated_ack_keeps_original_sender_after_return_cache_eviction() {
    check_ack_return_identity("AB");
}

#[test]
fn compact_sender_ack_returns_after_cache_eviction() {
    check_ack_return_identity(&format!("@addr:{}", sender_address_u32("AB")));
}

fn check_ack_return_identity(original_sender: &str) {
    crate::tests::ensure_common_test_schema();
    let router = Router::new_with_clock(
        RouterConfig::new([])
            .with_sender("GS")
            .with_reliable_enabled(true),
        Box::new(|| 0u64),
    );
    let sent = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
    let output = sent.clone();
    let side = router.add_side_packed_with_options(
        "CAN",
        move |bytes| {
            output.lock().unwrap().push(bytes.to_vec());
            Ok(())
        },
        RouterSideOptions::default(),
    );
    let endpoint = DataEndpoint::named("RADIO");
    router
        .rx_from_side(
            &discovery::build_discovery_announce("AB", 0, &[endpoint]).unwrap(),
            side,
        )
        .unwrap();
    router.process_all_queues().unwrap();
    sent.lock().unwrap().clear();
    let packet = Packet::new(
        DataType::named("GPS_DATA"),
        &[endpoint],
        original_sender,
        1,
        Arc::<[u8]>::from([0u8; 12]),
    )
    .unwrap();
    router.note_reliable_return_route(side, packet.packet_id());
    router.queue_end_to_end_reliable_ack(&packet, true).unwrap();
    for index in 0..runtime_reliable_max_return_routes().max(1) {
        router.note_reliable_return_route(side, packet.packet_id().wrapping_add(index as u64 + 1));
    }
    assert!(
        !router
            .state
            .lock()
            .reliable_return_routes
            .contains_key(&packet.packet_id())
    );
    router.process_all_queues().unwrap();
    let frames = sent.lock().unwrap();
    let acks: Vec<_> = frames
        .iter()
        .filter_map(|bytes| wire_format::unpack_packet(bytes).ok())
        .filter(Router::is_end_to_end_ack_packet)
        .collect();
    assert_eq!(
        acks.len(),
        1,
        "ACK must return to AB even after its per-packet return route is evicted"
    );
    assert_eq!(
        Router::end_to_end_ack_sender_hash(&acks[0]),
        Some(Router::sender_hash("GS"))
    );
    assert_eq!(
        acks[0].wire_target_senders().get(1),
        Some(&Router::sender_hash("AB"))
    );
}
