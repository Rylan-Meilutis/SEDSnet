use super::*;

#[test]
fn relay_chunk_identity_and_loss_are_bounded() {
    crate::tests::ensure_common_test_schema();
    let relay = Relay::new(Box::new(|| 0));
    let side = relay.add_side_packed_with_options("CAN", |_| Ok(()), RelaySideOptions::default());
    // Relay full frames include a leading one-byte template ID.
    let a = wrap_side_transport_frame(SIDE_TRANSPORT_KIND_FULL, &[1; 181]);
    let b = wrap_side_transport_frame(SIDE_TRANSPORT_KIND_FULL, &[2; 181]);
    let first = relay
        .split_side_transport_frame(side, a.clone(), 128)
        .unwrap()
        .collect::<Vec<_>>();
    let repeat = relay
        .split_side_transport_frame(side, a, 128)
        .unwrap()
        .collect::<Vec<_>>();
    let second = relay
        .split_side_transport_frame(side, b, 128)
        .unwrap()
        .collect::<Vec<_>>();
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
        let frame = wrap_side_transport_frame(SIDE_TRANSPORT_KIND_FULL, &data);
        let chunks = relay
            .split_side_transport_frame(side, frame, 128)
            .unwrap()
            .collect::<Vec<_>>();
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
            .encode_side_transport_frames(a, opts, crate::shared_bytes::convert(raw.clone()))
            .unwrap()
            .collect::<Vec<_>>();
        assert_eq!(
            rx.decode_side_transport_frame(b, &frames[0]).unwrap(),
            Some(crate::shared_bytes::convert(raw))
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
        let _ = tx
            .encode_side_transport_frames(a, opts, crate::shared_bytes::convert(raw.clone()))
            .unwrap();
        // Lose the initial header (or restart the receiver), then send control.
        let frames = tx
            .encode_side_transport_frames(a, opts, crate::shared_bytes::convert(raw.clone()))
            .unwrap()
            .collect::<Vec<_>>();
        assert_eq!(
            rx.decode_side_transport_frame(b, &frames[0]).unwrap(),
            Some(crate::shared_bytes::convert(raw)),
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
            .encode_side_transport_frames(side, opts, crate::shared_bytes::convert(raw.clone()))
            .unwrap()
            .collect::<Vec<_>>();
        tx.decode_side_transport_frame(side, &initial[0])
            .unwrap()
            .unwrap();
        let _ = tx
            .encode_side_transport_frames(
                unrelated,
                opts,
                crate::shared_bytes::convert(raw.clone()),
            )
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
            .encode_side_transport_frames(side, opts, crate::shared_bytes::convert(raw.clone()))
            .unwrap()
            .collect::<Vec<_>>();
        assert!(
            restarted
                .decode_side_transport_frame(rx, &frames[0])
                .unwrap()
                .is_some()
        );
        assert_eq!(tx.state.lock().side_transport[&side].rx_template_count(), 1);
        let frames = tx
            .encode_side_transport_frames(unrelated, opts, crate::shared_bytes::convert(raw))
            .unwrap()
            .collect::<Vec<_>>();
        let empty = Relay::new(Box::new(|| 100));
        let rx = empty.add_side_packed_with_options("uart", |_| Ok(()), opts);
        assert!(matches!(
            empty.decode_side_transport_frame(rx, &frames[0]),
            Err(TelemetryError::Unpack("unknown side compact template"))
        ));
    }
}

#[test]
fn queue_service_expires_incomplete_transfers_without_new_fragments() {
    crate::tests::ensure_common_test_schema();
    let now = Arc::new(core::sync::atomic::AtomicU64::new(0));
    let clock = now.clone();
    let router = Relay::new(Box::new(move || {
        clock.load(core::sync::atomic::Ordering::Relaxed)
    }));
    let side = router.add_side_packed("CAN", |_| Ok(()));
    let retained = Arc::<[u8]>::from([42; 128]);
    let witness = Arc::downgrade(&retained);
    router
        .state
        .lock()
        .side_transport
        .get_mut(&side)
        .unwrap()
        .rx_chunks
        .insert(
            7,
            SideChunkAssembly {
                last_seen_ms: 0,
                total: 2,
                received: [(0, crate::shared_bytes::convert(retained))]
                    .into_iter()
                    .collect(),
            },
        );
    now.store(2000, core::sync::atomic::Ordering::Relaxed);
    router.process_tx_queue_with_timeout(1).unwrap();
    assert!(witness.upgrade().is_some(), "live transfer expired early");
    extern "C" fn deny_new_work(_: usize, _: usize) -> bool {
        false
    }
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            crate::memory_admission::set_probe(None);
        }
    }
    let _reset = Reset;
    crate::memory_admission::set_probe(Some(deny_new_work));
    now.store(2001, core::sync::atomic::Ordering::Relaxed);
    router.process_tx_queue_with_timeout(1).unwrap();
    assert!(
        witness.upgrade().is_none(),
        "abandoned transfer pinned its payload without new ingress"
    );
    assert!(
        router.state.lock().side_transport[&side]
            .rx_chunks
            .is_empty()
    );
}

#[test]
fn wrapped_acks_use_reserved_headroom_during_memory_pressure() {
    extern "C" fn only_control(additional: usize, largest: usize) -> bool {
        additional <= 512 && largest <= 160
    }
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            crate::memory_admission::set_probe(None);
        }
    }
    let rx = Relay::new(Box::new(|| 0));
    let opts = RelaySideOptions::default().with_small_packet_transport(0);
    let b = rx.add_side_packed_with_options("wire", |_| Ok(()), opts);
    let packet = Packet::new(
        crate::DataType::ReliableAck,
        &[crate::DataEndpoint::Discovery],
        "GS",
        100,
        Arc::<[u8]>::from([0; 8]),
    )
    .unwrap();
    let raw = wire_format::pack_packet(&packet);
    // Current senders use canonical ACKs; older peers can still wrap them.
    let mut body = vec![1];
    body.extend_from_slice(&raw);
    let full = wrap_side_transport_frame(SIDE_TRANSPORT_KIND_FULL, &body);
    let (_, _, flags, size, timestamp, nonce, reliable, payload) =
        extract_side_header_template(&raw).unwrap();
    let mut body = vec![flags, 1];
    write_uleb128_local(size, &mut body);
    write_uleb128_local(timestamp, &mut body);
    if flags & SIDE_TRANSPORT_FLAG_PACKET_NONCE != 0 {
        write_uleb128_local(u64::from(nonce), &mut body);
    }
    if let Some((seq, ack)) = reliable {
        write_uleb128_local(u64::from(seq), &mut body);
        write_uleb128_local(u64::from(ack), &mut body);
    }
    body.extend_from_slice(payload);
    let compact = wrap_side_transport_frame(SIDE_TRANSPORT_KIND_COMPACT, &body);
    let ordinary = Packet::new(
        crate::DataType::DiscoverySchema,
        &[crate::DataEndpoint::Discovery],
        "GS",
        101,
        Arc::<[u8]>::from([1; 32]),
    )
    .unwrap();
    let ordinary = wire_format::pack_packet(&ordinary);
    let _reset = Reset;
    crate::memory_admission::set_probe(Some(only_control));
    assert!(
        rx.decode_side_transport_frame(b, &ordinary).is_err(),
        "ordinary ingress must remain refused"
    );
    for wire in [raw.as_ref(), full.as_ref(), compact.as_ref()] {
        let decoded = rx.decode_side_transport_frame(b, wire).unwrap().unwrap();
        assert_eq!(decoded, raw);
        let packet = wire_format::unpack_packet(&decoded).unwrap();
        assert_eq!(packet.data_type(), crate::DataType::ReliableAck);
    }
}

#[test]
fn short_budget_still_dispatches_retained_relay_tx() {
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    crate::tests::ensure_common_test_schema();
    let time = Arc::new(AtomicU64::new(0));
    let clock = time.clone();
    let relay = Relay::new(Box::new(move || clock.fetch_add(1, Ordering::Relaxed)));
    let sent = Arc::new(AtomicUsize::new(0));
    let count = sent.clone();
    let ty = crate::DataType::named("GPS_DATA");
    let side = relay.add_side_packed("output", move |wire| {
        if wire_format::peek_routing_envelope(wire).is_ok_and(|env| env.ty == ty) {
            count.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    });
    let packet = Packet::new(
        ty,
        &[crate::DataEndpoint::named("RADIO")],
        "GS",
        1,
        Arc::<[u8]>::from([0; 12]),
    )
    .unwrap();
    relay
        .state
        .lock()
        .push_tx(RelayTxItem {
            src: None,
            dst: side,
            data: RelayItem::Packet(Arc::new(packet)),
            priority: 255,
        })
        .unwrap();
    relay.process_all_queues_with_timeout(1).unwrap();
    assert_eq!(
        sent.load(Ordering::Relaxed),
        1,
        "RX budget boundary must not starve retained TX"
    );
}

#[test]
fn malformed_discovery_preserves_retained_relay_routes() {
    crate::tests::ensure_common_test_schema();
    let relay = Relay::new(Box::new(|| 1));
    let side = relay.add_side_packed("CAN", |_| Ok(()));
    let mut route = DiscoverySideState::default();
    route.announcers.insert(
        "VB".into(),
        DiscoverySenderState {
            last_seen_ms: 1,
            advertised_reachable: vec![crate::DataEndpoint::named("RADIO")],
            ..Default::default()
        },
    );
    relay
        .state
        .lock()
        .discovery_routes
        .insert(side, route.clone());
    let packet = Packet::new(
        crate::DataType::DiscoveryTimeSyncSources,
        &[crate::DataEndpoint::Discovery],
        "VB",
        1,
        Arc::<[u8]>::from([0xff; 4]),
    )
    .unwrap();
    assert!(
        relay
            .learn_discovery_item(side, &RelayItem::Packet(Arc::new(packet)))
            .is_err()
    );
    assert_eq!(relay.state.lock().discovery_routes[&side], route);
}

#[test]
fn discovery_growth_drops_telemetry_before_live_routes() {
    crate::tests::ensure_common_test_schema();
    let relay = Relay::new(Box::new(|| 1));
    let side = relay.add_side_packed("CAN", |_| Ok(()));
    let endpoint = crate::DataEndpoint::named("RADIO");
    let mut route = DiscoverySideState {
        reachable: vec![endpoint],
        ..Default::default()
    };
    for name in ["AB", "VB"] {
        route.announcers.insert(
            name.into(),
            DiscoverySenderState {
                last_seen_ms: 1,
                reachable: vec![endpoint],
                advertised_reachable: vec![endpoint],
                ..Default::default()
            },
        );
    }
    let mut st = relay.state.lock();
    st.discovery_routes.insert(side, route.clone());
    st.push_tx(RelayTxItem {
        src: None,
        dst: side,
        data: RelayItem::Packed(crate::shared_bytes::convert(Arc::<[u8]>::from([0; 512]))),
        priority: 1,
    })
    .unwrap();
    st.push_tx(RelayTxItem {
        src: None,
        dst: side,
        data: RelayItem::Packed(crate::shared_bytes::convert(Arc::<[u8]>::from([0; 32]))),
        priority: 255,
    })
    .unwrap();
    st.memory.max_queue_budget = st.shared_queue_bytes_used();
    // Simulate new discovery metadata arriving while the shared queue is full.
    st.discovery_routes
        .get_mut(&side)
        .unwrap()
        .reachable_timesync_sources
        .push("x".repeat(128));
    let expected = st.discovery_routes[&side].clone();
    st.fit_discovery_budget();
    assert_eq!(
        st.discovery_routes.get(&side),
        Some(&expected),
        "a telemetry backlog erased AB and VB routes"
    );
    assert!(st.shared_queue_bytes_used() <= st.memory.max_queue_budget);
    assert_eq!(st.tx_queue.len(), 1);
    assert_eq!(
        st.tx_queue.lowest_priority(|item| item.priority),
        Some(255),
        "discard low-priority telemetry before control"
    );
}

#[test]
fn incoming_relay_packet_cannot_evict_the_only_live_route() {
    crate::tests::ensure_common_test_schema();
    let relay = Relay::new(Box::new(|| 1));
    let side = relay.add_side_packed("CAN", |_| Ok(()));
    let endpoint = crate::DataEndpoint::named("RADIO");
    let mut route = DiscoverySideState {
        reachable: vec![endpoint],
        ..Default::default()
    };
    for name in ["AB", "VB"] {
        route.announcers.insert(
            name.into(),
            DiscoverySenderState {
                last_seen_ms: 1,
                reachable: vec![endpoint],
                advertised_reachable: vec![endpoint],
                ..Default::default()
            },
        );
    }
    let mut st = relay.state.lock();
    st.discovery_routes.insert(side, route.clone());
    st.memory.max_queue_budget = st.shared_queue_bytes_used() + 64;
    assert!(st.make_shared_queue_room(128, RelayQueueKind::Tx).is_err());
    assert_eq!(st.discovery_routes.get(&side), Some(&route));
}

#[test]
fn known_discovery_survives_snapshot_memory_pressure() {
    crate::tests::ensure_common_test_schema();
    let now = Arc::new(core::sync::atomic::AtomicU64::new(1));
    let clock = now.clone();
    let node = Relay::new_with_config(
        RelayConfig::default().with_sender("GB"),
        Box::new(move || clock.load(core::sync::atomic::Ordering::Relaxed)),
    );
    let sent = Arc::new(std::sync::Mutex::new(Vec::new()));
    let output = sent.clone();
    let side = node.add_side_packet("CAN", move |pkt| {
        output.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let endpoint = crate::DataEndpoint::named("RADIO");
    let ad = discovery::AddressAdvertisement {
        hostname: "AB".into(),
        address: 42,
        requested_address: 42,
        mode: discovery::ADDRESS_MODE_REQUESTED,
        state: discovery::ADDRESS_STATE_REQUEST,
        birth_ms: 1,
        owner_hash: 42,
        reachable_endpoints: vec![endpoint],
        reachable_network_variables: vec![],
        reachable_timesync_sources: vec![],
        link_capabilities: RelaySideOptions::default().link_capabilities(),
    };
    let baseline = discovery::build_discovery_address("AB", 1, &ad).unwrap();
    node.learn_discovery_item(side, &RelayItem::Packet(Arc::new(baseline)))
        .unwrap();
    {
        let mut st = node.state.lock();
        let peer = st
            .discovery_routes
            .get_mut(&side)
            .unwrap()
            .announcers
            .get_mut("AB")
            .unwrap();
        peer.has_full_topology = true;
        peer.has_schema = true;
        let throttle = st.discovery_side_throttle.entry(side).or_default();
        throttle.has_sent_full = true;
        throttle.next_ping_ms = 0;
    }
    extern "C" fn only_small_work(additional: usize, _: usize) -> bool {
        additional <= 4096
    }
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            crate::memory_admission::set_probe(None);
        }
    }
    let _reset = Reset;
    crate::memory_admission::set_probe(Some(only_small_work));
    for ms in (5_000..=300_000).step_by(5_000) {
        now.store(ms, core::sync::atomic::Ordering::Relaxed);
        let repeated = discovery::build_discovery_address("AB", ms, &ad).unwrap();
        node.learn_discovery_item(side, &RelayItem::Packet(Arc::new(repeated)))
            .unwrap();
        let ping = discovery::build_discovery_announce("AB", ms, &[]).unwrap();
        node.learn_discovery_item(side, &RelayItem::Packet(Arc::new(ping)))
            .unwrap();
        node.queue_discovery_announce(false, true).unwrap();
        node.process_tx_queue().unwrap();
        let st = node.state.lock();
        let peer = &st.discovery_routes[&side].announcers["AB"];
        assert_eq!(peer.last_seen_ms, ms);
        assert_eq!(peer.advertised_reachable, vec![endpoint]);
    }
    let packets = sent.lock().unwrap();
    let pings = packets
        .iter()
        .filter(|pkt| pkt.data_type() == crate::DataType::DiscoveryAnnounce)
        .count();
    assert!(
        (20..=60).contains(&pings),
        "keepalives must be bounded but outlive the 30-second route TTL: {pings}"
    );
    assert!(
        packets
            .iter()
            .all(|pkt| pkt.data_type() == crate::DataType::DiscoveryAnnounce)
    );
    drop(packets);
    let before = node.state.lock().discovery_routes[&side].clone();
    let unknown = discovery::build_discovery_announce("UNKNOWN", 300_001, &[]).unwrap();
    assert!(
        node.learn_discovery_item(side, &RelayItem::Packet(Arc::new(unknown)))
            .is_err()
    );
    let mut changed = ad.clone();
    changed
        .reachable_endpoints
        .push(crate::DataEndpoint::named("SD_CARD"));
    let update = discovery::build_discovery_address("AB", 300_001, &changed).unwrap();
    assert!(
        node.learn_discovery_item(side, &RelayItem::Packet(Arc::new(update)))
            .is_err()
    );
    assert_eq!(
        node.state.lock().discovery_routes[&side],
        before,
        "pressure liveness must not admit new peers or changed endpoint claims"
    );
    now.store(
        300_000 + discovery::DISCOVERY_ROUTE_TTL_MS + 1,
        core::sync::atomic::Ordering::Relaxed,
    );
    let mut st = node.state.lock();
    Relay::prune_discovery_routes_locked(&mut st, now.load(core::sync::atomic::Ordering::Relaxed));
    assert!(
        !st.discovery_routes.contains_key(&side),
        "a silent peer must still expire"
    );
}
