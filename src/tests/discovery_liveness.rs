use super::*;
use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
};

#[test]
fn lost_chunk_cannot_poison_later_frames_from_same_router() {
    crate::tests::ensure_common_test_schema();
    let rf = Router::new_with_clock(RouterConfig::new([]).with_sender("RF"), Box::new(|| 0));
    let fc = Router::new_with_clock(RouterConfig::new([]).with_sender("FC"), Box::new(|| 0));
    let side = fc.add_side_packed_with_options("CAN", |_| Ok(()), RouterSideOptions::default());
    let first = wrap_side_transport_frame(SIDE_TRANSPORT_KIND_FULL, &[1; 180]);
    let second = wrap_side_transport_frame(SIDE_TRANSPORT_KIND_FULL, &[2; 180]);
    // CRC including the appended CRC has a constant residue: it is NOT an ID.
    assert_eq!(
        crate::side_transport::crc32_bytes(&first),
        crate::side_transport::crc32_bytes(&second)
    );
    let a = rf
        .split_side_transport_frame(0, first, 128)
        .unwrap()
        .collect::<Vec<_>>();
    let b = rf
        .split_side_transport_frame(0, second, 128)
        .unwrap()
        .collect::<Vec<_>>();
    assert_ne!(
        &a[0][4..8],
        &b[0][4..8],
        "different packets need different transfer IDs"
    );
    assert!(
        fc.decode_side_transport_frame(side, &a[0])
            .unwrap()
            .is_none()
    );
    // Drop A's tail; all of B must still be decodable.
    let mut result = None;
    for frame in b {
        result = fc.decode_side_transport_frame(side, &frame).unwrap();
    }
    assert_eq!(result.unwrap().as_ref(), &[2; 180]);
}

#[test]
fn incomplete_side_transfers_stay_bounded_under_repeated_loss() {
    crate::tests::ensure_common_test_schema();
    let router = Router::new_with_clock(RouterConfig::new([]).with_sender("RF"), Box::new(|| 0));
    let side = router.add_side_packed_with_options("CAN", |_| Ok(()), RouterSideOptions::default());
    for i in 0..1000u32 {
        let mut data = vec![0; 180];
        data[..4].copy_from_slice(&i.to_le_bytes());
        let frame = wrap_side_transport_frame(SIDE_TRANSPORT_KIND_FULL, &data);
        let chunks = router
            .split_side_transport_frame(side, frame, 128)
            .unwrap()
            .collect::<Vec<_>>();
        assert!(
            router
                .decode_side_transport_frame(side, &chunks[0])
                .unwrap()
                .is_none()
        );
        assert!(router.state.lock().side_transport[&side].rx_chunks.len() <= 4);
    }
}

#[test]
fn unacknowledged_topology_does_not_silence_discovery_liveness() {
    crate::tests::ensure_common_test_schema();
    let now = Arc::new(AtomicU64::new(0));
    let clock = now.clone();
    let emitted = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let output = emitted.clone();
    let rf = Router::new_with_clock(
        RouterConfig::new([]).with_sender("RF"),
        Box::new(move || clock.load(Ordering::Relaxed)),
    );
    let side = rf.add_side_packed_with_options(
        "CAN",
        move |packet| {
            output.lock().unwrap().push(packet.to_vec());
            Ok(())
        },
        RouterSideOptions {
            reliable_enabled: true,
            ..Default::default()
        },
    );
    rf.announce_discovery().unwrap();
    rf.process_tx_queue().unwrap();
    // Deliberately withhold the hop ACK for a transmitted topology baseline.
    assert!(
        rf.state
            .lock()
            .reliable_tx
            .iter()
            .any(|((s, ty), tx)| *s == side
                && *ty == DataType::DiscoveryTopology.as_u32()
                && !tx.sent.is_empty())
    );
    emitted.lock().unwrap().clear();
    let fc_clock = now.clone();
    let fc = Router::new_with_clock(
        RouterConfig::new([]).with_sender("FC"),
        Box::new(move || fc_clock.load(Ordering::Relaxed)),
    );
    let endpoint = DataEndpoint::named("RADIO");
    let sensor_type = crate::config::register_data_type_with_description(
        "DISCOVERY_LIVENESS_SENSOR",
        "live sensor across RF",
        MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[endpoint],
        crate::ReliableMode::None,
        1,
    )
    .unwrap();
    let sensor_count = Arc::new(AtomicU64::new(0));
    let sent = sensor_count.clone();
    let ingress = fc.add_side_packet("CAN", move |packet| {
        if packet.data_type() == sensor_type {
            sent.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    });
    fc.rx_from_side(
        &discovery::build_discovery_topology(
            "RF",
            0,
            &[
                TopologyBoardNode {
                    sender_id: "RF".into(),
                    reachable_endpoints: vec![],
                    reachable_timesync_sources: vec![],
                    connections: vec!["GS".into()],
                },
                TopologyBoardNode {
                    sender_id: "GS".into(),
                    reachable_endpoints: vec![endpoint],
                    reachable_timesync_sources: vec![],
                    connections: vec!["RF".into()],
                },
            ],
        )
        .unwrap(),
        ingress,
    )
    .unwrap();
    let mut delivered = 0;
    for ms in (1_000..=60_000).step_by(1_000) {
        now.store(ms, Ordering::Relaxed);
        rf.poll_discovery().unwrap();
        // Drain newly queued advertisements without running timeout/retry
        // maintenance: keep the original pending ACK outstanding throughout.
        loop {
            let queued =
                Router::pop_transmit_queue_locked(&mut rf.state.lock(), rf.clock.now_ms(), false);
            let Some(queued) = queued else {
                break;
            };
            rf.dispatch_queued_item(queued).unwrap();
        }
        let frames = emitted.lock().unwrap();
        for frame in &frames[delivered..] {
            let packet = crate::wire_format::unpack_packet(frame).unwrap();
            fc.rx_from_side(&packet, ingress).unwrap();
        }
        delivered = frames.len();
        drop(frames);
        // PB continues to announce on the same CAN segment but is not a
        // GroundStation subscriber. Its liveness must not hide loss of RF.
        fc.rx_from_side(
            &discovery::build_discovery_announce("PB", ms, &[]).unwrap(),
            ingress,
        )
        .unwrap();
        assert!(
            fc.export_topology()
                .routes
                .iter()
                .any(|route| route.reachable_endpoints.contains(&endpoint)),
            "FC must retain GS reachability while RF keepalives continue at {ms} ms"
        );
        let before = sensor_count.load(Ordering::Relaxed);
        fc.log(sensor_type, &[1u8]).unwrap();
        assert_eq!(
            sensor_count.load(Ordering::Relaxed),
            before + 1,
            "FC must actually transmit each sensor packet, not just return success at {ms} ms"
        );
    }
    let frames = emitted.lock().unwrap();
    let types: Vec<_> = frames
        .iter()
        .map(|p| crate::wire_format::peek_envelope(p).unwrap().ty)
        .collect();
    let pings: Vec<_> = types
        .iter()
        .filter(|ty| **ty == DataType::DiscoveryAnnounce)
        .collect();
    assert!(
        pings.len() >= 3,
        "a lost topology ACK must not suppress bounded keepalives for an entire route TTL"
    );
    assert!(
        pings.len() <= 5,
        "keepalives must not run at the firmware polling rate"
    );
    assert!(
        types.iter().all(|ty| *ty != DataType::DiscoveryTopology),
        "do not retransmit full topology just to refresh liveness"
    );
    let expired = 60_000 + DISCOVERY_ROUTE_TTL_MS + 1;
    now.store(expired, Ordering::Relaxed);
    fc.rx_from_side(
        &discovery::build_discovery_announce("PB", expired, &[]).unwrap(),
        ingress,
    )
    .unwrap();
    assert!(
        !fc.export_topology()
            .routes
            .iter()
            .any(|route| route.reachable_endpoints.contains(&endpoint)),
        "a genuinely silent RF must still expire even with PB present"
    );
}

#[test]
fn queue_service_expires_incomplete_transfers_without_new_fragments() {
    crate::tests::ensure_common_test_schema();
    let now = Arc::new(AtomicU64::new(0));
    let clock = now.clone();
    let router = Router::new_with_clock(
        RouterConfig::new([]),
        Box::new(move || clock.load(Ordering::Relaxed)),
    );
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
                received_count: 1,
                received: vec![Some(crate::shared_bytes::convert(retained)), None],
            },
        );
    router
        .state
        .lock()
        .side_transport
        .get_mut(&side)
        .unwrap()
        .refresh_rx_chunk_bytes();
    now.store(2000, Ordering::Relaxed);
    router.dispatch_tx_queue_with_timeout(1).unwrap();
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
    now.store(2001, Ordering::Relaxed);
    router.dispatch_tx_queue_with_timeout(1).unwrap();
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
fn discovery_growth_drops_telemetry_before_live_routes() {
    crate::tests::ensure_common_test_schema();
    let router = Router::new_with_clock(RouterConfig::new([]), Box::new(|| 1));
    let side = router.add_side_packed("CAN", |_| Ok(()));
    let endpoint = crate::DataEndpoint::named("RADIO");
    let mut route = DiscoverySideState {
        reachable: vec![endpoint],
        ..Default::default()
    };
    for name in ["AB", "VB"] {
        route.announcers.insert(
            name.into(),
            Box::new(DiscoverySenderState {
                last_seen_ms: 1,
                reachable: vec![endpoint],
                advertised_reachable: vec![endpoint],
                ..Default::default()
            }),
        );
    }
    let mut st = router.state.lock();
    st.discovery_routes.insert(side, route.clone());
    st.push_transmit(TxQueued {
        disposable: TX_DISPOSABLE,
        item: RouterTxItem::ToSide {
            src: None,
            dst: side,
            data: RouterItem::Packed(crate::shared_bytes::convert(Arc::<[u8]>::from([0; 512]))),
        },
        ignore_local: true,
        priority: 1,
        delivery_state: QueuedDelivery::Untracked,
        accepted_type: 0,
        deferred_since_ms: 0,
        retry_after_ms: 0,
    })
    .unwrap();
    st.push_transmit(TxQueued {
        disposable: TX_DISPOSABLE,
        item: RouterTxItem::ToSide {
            src: None,
            dst: side,
            data: RouterItem::Packed(crate::shared_bytes::convert(Arc::<[u8]>::from([0; 32]))),
        },
        ignore_local: true,
        priority: 255,
        delivery_state: QueuedDelivery::Untracked,
        accepted_type: 0,
        deferred_since_ms: 0,
        retry_after_ms: 0,
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
    assert_eq!(st.transmit_queue.len(), 1);
    assert_eq!(
        st.transmit_queue.lowest_priority(|item| item.priority),
        Some(255),
        "discard low-priority telemetry before control"
    );
}

#[test]
fn known_discovery_survives_snapshot_memory_pressure() {
    crate::tests::ensure_common_test_schema();
    let now = Arc::new(core::sync::atomic::AtomicU64::new(1));
    let clock = now.clone();
    let node = Router::new_with_clock(
        RouterConfig::new([]).with_sender("GB"),
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
        link_capabilities: RouterSideOptions::default().link_capabilities(),
    };
    let baseline = discovery::build_discovery_address("AB", 1, &ad).unwrap();
    node.learn_discovery_packet(&baseline, Some(side), true)
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
        throttle.set_has_sent_full(true);
        throttle.next_ping_ms = 0;
    }
    extern "C" fn only_small_work(additional: usize, _: usize) -> bool {
        additional < 2048
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
        // A restart request invalidates the TX baseline. A refused full reply
        // must not disable small liveness traffic for the rest of the run.
        if ms == 150_000 {
            node.state
                .lock()
                .discovery_side_throttle
                .entry(side)
                .or_default()
                .set_has_sent_full(false);
        }
        let repeated = discovery::build_discovery_address("AB", ms, &ad).unwrap();
        node.learn_discovery_packet(&repeated, Some(side), true)
            .unwrap();
        let ping = discovery::build_discovery_announce("AB", ms, &[]).unwrap();
        node.learn_discovery_packet(&ping, Some(side), true)
            .unwrap();
        node.queue_discovery_announce(false, true).unwrap();
        node.process_tx_queue().unwrap();
        let st = node.state.lock();
        let peer = &st.discovery_routes[&side].announcers["AB"];
        assert_eq!(peer.last_seen_ms, ms);
        assert_eq!(peer.advertised_reachable, vec![endpoint]);
    }
    let packets = sent.lock().unwrap();
    assert!(
        packets
            .last()
            .is_some_and(|packet| packet.timestamp() >= 295_000),
        "a refused restart baseline must not permanently stop keepalives"
    );
    let pings = packets
        .iter()
        .filter(|pkt| {
            matches!(
                pkt.data_type(),
                crate::DataType::DiscoveryAnnounce | crate::DataType::DiscoveryAddress
            )
        })
        .count();
    assert!(
        (20..=60).contains(&pings),
        "keepalives must be bounded but outlive the 30-second route TTL: {pings}"
    );
    assert!(packets.iter().all(|pkt| matches!(
        pkt.data_type(),
        crate::DataType::DiscoveryAnnounce | crate::DataType::DiscoveryAddress
    )));
    drop(packets);
    let before = node.state.lock().discovery_routes[&side].clone();
    let unknown = discovery::build_discovery_announce("UNKNOWN", 300_001, &[]).unwrap();
    assert!(
        node.learn_discovery_packet(&unknown, Some(side), true)
            .is_err()
    );
    let mut changed = ad.clone();
    changed
        .reachable_endpoints
        .push(crate::DataEndpoint::named("SD_CARD"));
    let update = discovery::build_discovery_address("AB", 300_001, &changed).unwrap();
    assert!(
        node.learn_discovery_packet(&update, Some(side), true)
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
    Router::prune_discovery_routes_locked(&mut st, now.load(core::sync::atomic::Ordering::Relaxed));
    assert!(
        !st.discovery_routes.contains_key(&side),
        "a silent peer must still expire"
    );
}

#[test]
fn compact_address_and_topology_bootstrap_fit_bounded_headroom() {
    crate::tests::ensure_common_test_schema();
    extern "C" fn summaries_only(additional: usize, _: usize) -> bool {
        additional < 8192
    }
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            crate::memory_admission::set_probe(None);
        }
    }
    let node = Router::new_with_clock(RouterConfig::new([]).with_sender("GB"), Box::new(|| 1));
    let sent = Arc::new(std::sync::Mutex::new(Vec::new()));
    let output = sent.clone();
    let side = node.add_side_packet("CAN", |_| Ok(()));
    let _upstream = node.add_side_packet("UART", move |packet| {
        output.lock().unwrap().push(packet.clone());
        Ok(())
    });
    let _reset = Reset;
    crate::memory_admission::set_probe(Some(summaries_only));
    for (i, name) in ["AB", "VB", "DAQ"].into_iter().enumerate() {
        let ad = discovery::AddressAdvertisement {
            hostname: name.into(),
            address: 42 + i as u32,
            requested_address: 42 + i as u32,
            mode: discovery::ADDRESS_MODE_REQUESTED,
            state: discovery::ADDRESS_STATE_REQUEST,
            birth_ms: 1,
            owner_hash: 42 + i as u64,
            reachable_endpoints: vec![crate::DataEndpoint::named("RADIO")],
            reachable_network_variables: vec![],
            reachable_timesync_sources: vec![],
            link_capabilities: RouterSideOptions::default().link_capabilities(),
        };
        let packet = discovery::build_discovery_address(name, 1, &ad).unwrap();
        node.learn_discovery_packet(&packet, Some(side), true)
            .unwrap();
        let st = node.state.lock();
        assert!(st.discovery_routes[&side].announcers.contains_key(name));
    }
    assert_eq!(
        node.state.lock().discovery_routes[&side].announcers.len(),
        3
    );
    node.queue_discovery_announce(false, true).unwrap();
    node.process_tx_queue().unwrap();
    let packets = sent.lock().unwrap();
    let summary = packets
        .iter()
        .find(|packet| packet.data_type() == crate::DataType::DiscoveryAddress)
        .expect("compact reachability must reach GroundStation without a full snapshot");
    assert!(
        discovery::decode_discovery_address(summary)
            .unwrap()
            .reachable_endpoints
            .contains(&crate::DataEndpoint::named("RADIO"))
    );
    let topology = packets
        .iter()
        .find(|packet| packet.data_type() == crate::DataType::DiscoveryTopology)
        .expect("a schema-free topology must fit the bounded recovery headroom");
    let boards = discovery::decode_discovery_topology(topology).unwrap();
    for name in ["AB", "VB", "DAQ", "GB"] {
        assert!(
            boards.iter().any(|board| board.sender_id == name),
            "missing {name}"
        );
    }
    drop(packets);
    let unknown = discovery::build_discovery_announce("UNKNOWN", 1, &[]).unwrap();
    assert!(
        node.learn_discovery_packet(&unknown, Some(side), true)
            .is_err(),
        "full discovery admission remains guarded"
    );
}

#[test]
fn chunked_schema_resumes_after_transport_backpressure() {
    crate::tests::ensure_common_test_schema();
    for packed_input in [false, true] {
        let allowance = Arc::new(core::sync::atomic::AtomicUsize::new(0));
        let callback_allowance = allowance.clone();
        let accepted = Arc::new(std::sync::Mutex::new(Vec::new()));
        let callback_accepted = accepted.clone();
        let node = Router::new_with_clock(RouterConfig::new([]).with_sender("GB"), Box::new(|| 1));
        let side = node.add_side_packed_with_options(
            "bounded CAN",
            move |bytes| {
                if callback_allowance
                    .try_update(
                        core::sync::atomic::Ordering::Relaxed,
                        core::sync::atomic::Ordering::Relaxed,
                        |left| left.checked_sub(1),
                    )
                    .is_err()
                {
                    return Err(crate::TelemetryError::Io("CAN queue full"));
                }
                callback_accepted
                    .lock()
                    .unwrap()
                    .push(Arc::<[u8]>::from(bytes));
                Ok(())
            },
            RouterSideOptions::default().with_small_packet_transport(128),
        );
        let packet = crate::packet::Packet::new(
            crate::DataType::DiscoverySchema,
            &[crate::DataEndpoint::Discovery],
            "GB",
            100,
            Arc::from((0..3600).map(|i| (i % 251) as u8).collect::<Vec<_>>()),
        )
        .unwrap();
        let raw = crate::wire_format::pack_packet(&packet);
        let expected = crate::side_transport::SideTransportFrames::split(
            crate::shared_bytes::convert(raw.clone()),
            128,
            b"GB",
        )
        .unwrap()
        .collect::<Vec<_>>();
        let item = if packed_input {
            RouterItem::Packed(crate::shared_bytes::convert(raw))
        } else {
            RouterItem::Packet(packet)
        };
        let handler = node.state.lock().sides[side]
            .as_ref()
            .unwrap()
            .tx_handler
            .clone();
        let mut complete = false;
        for _ in 0..100 {
            allowance.store(1, core::sync::atomic::Ordering::Relaxed);
            match node.call_side_tx_handler(side, &handler, &item, false) {
                Ok(()) => {
                    complete = true;
                    break;
                }
                Err(crate::TelemetryError::Io(_)) => {}
                other => panic!("unexpected chunk dispatch result: {other:?}"),
            }
        }
        assert!(
            complete,
            "partial acceptance must complete instead of replaying chunk zero forever"
        );
        let received = accepted.lock().unwrap();
        assert_eq!(
            received
                .iter()
                .map(|frame| frame.as_ref())
                .collect::<Vec<_>>(),
            expected
                .iter()
                .map(|frame| frame.as_ref())
                .collect::<Vec<_>>(),
            "every accepted chunk is sent once, in order, with one transfer identity"
        );
    }
}

#[test]
fn new_peer_and_schema_cannot_evict_existing_routes() {
    crate::tests::ensure_common_test_schema();
    let node = Router::new_with_clock(RouterConfig::new([]).with_sender("GB"), Box::new(|| 1));
    let side = node.add_side_packet("CAN", |_| Ok(()));
    let ad = discovery::AddressAdvertisement {
        hostname: "AB".into(),
        address: 42,
        requested_address: 42,
        mode: discovery::ADDRESS_MODE_REQUESTED,
        state: discovery::ADDRESS_STATE_REQUEST,
        birth_ms: 1,
        owner_hash: 42,
        reachable_endpoints: vec![crate::DataEndpoint::named("RADIO")],
        reachable_network_variables: vec![],
        reachable_timesync_sources: vec![],
        link_capabilities: RouterSideOptions::default().link_capabilities(),
    };
    let packet = discovery::build_discovery_address("AB", 1, &ad).unwrap();
    node.learn_discovery_packet(&packet, Some(side), true)
        .unwrap();
    let before = {
        let mut st = node.state.lock();
        st.memory.max_queue_budget = st.shared_queue_bytes_used() + 64;
        st.discovery_routes[&side].clone()
    };
    let mut new_peer = ad.clone();
    new_peer.hostname = "VB".into();
    new_peer.address = 43;
    new_peer.requested_address = 43;
    new_peer.owner_hash = 43;
    let packet = discovery::build_discovery_address("VB", 2, &new_peer).unwrap();
    assert!(
        node.learn_discovery_packet(&packet, Some(side), true)
            .is_err()
    );
    assert_eq!(node.state.lock().discovery_routes[&side], before);
    let schema_before = crate::config::schema_bytes_used();
    let schema = crate::config::OwnedRuntimeSchemaSnapshot {
        endpoints: vec![crate::config::OwnedEndpointDefinition {
            id: crate::DataEndpoint(8888),
            name: "PROTECTED_ROUTE_PRESSURE_ENDPOINT".into(),
            description: "x".repeat(4096),
            link_local_only: false,
        }],
        types: vec![],
    };
    let packet =
        discovery::build_discovery_schema_from_owned_snapshot("NEW_BOARD", 3, schema).unwrap();
    assert!(
        node.learn_discovery_packet(&packet, Some(side), true)
            .is_err()
    );
    assert_eq!(
        crate::config::schema_bytes_used(),
        schema_before,
        "a refused schema must leave the registry unchanged"
    );
    let st = node.state.lock();
    assert_eq!(st.discovery_routes[&side], before);
    assert!(st.shared_queue_bytes_used() <= st.memory.max_queue_budget);
}

#[test]
fn schema_reclaims_queued_data_before_refusing_update() {
    crate::tests::ensure_common_test_schema();
    let node = Router::new_with_clock(RouterConfig::new([]).with_sender("GB"), Box::new(|| 1));
    let side = node.add_side_packet("CAN", |_| Ok(()));
    {
        let mut st = node.state.lock();
        st.push_transmit(TxQueued {
            disposable: TX_DISPOSABLE,
            item: RouterTxItem::ToSide {
                src: None,
                dst: side,
                data: RouterItem::Packed(crate::shared_bytes::convert(Arc::<[u8]>::from(vec![
                    0;
                    2048
                ]))),
            },
            ignore_local: true,
            priority: 254,
            delivery_state: QueuedDelivery::Untracked,
            accepted_type: 0,
            deferred_since_ms: 0,
            retry_after_ms: 0,
        })
        .unwrap();
        st.memory.max_queue_budget = st.shared_queue_bytes_used();
    }
    let schema = crate::config::OwnedRuntimeSchemaSnapshot {
        endpoints: vec![crate::config::OwnedEndpointDefinition {
            id: crate::DataEndpoint(8890),
            name: "SCHEMA_RECLAIM_router".into(),
            description: "x".repeat(512),
            link_local_only: false,
        }],
        types: vec![],
    };
    let packet =
        discovery::build_discovery_schema_from_owned_snapshot("NEW_BOARD", 3, schema).unwrap();
    node.learn_discovery_packet(&packet, Some(side), true)
        .unwrap();
    let st = node.state.lock();
    assert!(
        st.transmit_queue.is_empty(),
        "queued data must give way to the new schema"
    );
    assert!(st.shared_queue_bytes_used() <= st.memory.max_queue_budget);
    assert_eq!(
        crate::DataEndpoint::try_from_u32(8890),
        Some(crate::DataEndpoint(8890))
    );
    drop(st);
    crate::config::remove_endpoint(crate::DataEndpoint(8890)).unwrap();
}

#[test]
fn keepalive_fits_reserved_control_headroom() {
    crate::tests::ensure_common_test_schema();
    let node = Router::new_with_clock(RouterConfig::new([]).with_sender("GB"), Box::new(|| 5000));
    let sent = Arc::new(core::sync::atomic::AtomicUsize::new(0));
    let output = sent.clone();
    let side = node.add_side_packet("UART", move |pkt| {
        if pkt.data_type() == crate::DataType::DiscoveryAnnounce && pkt.payload().is_empty() {
            output.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
        Ok(())
    });
    node.state
        .lock()
        .discovery_side_throttle
        .entry(side)
        .or_default()
        .set_has_sent_full(true);
    extern "C" fn control_only(additional: usize, _: usize) -> bool {
        additional <= 512
    }
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            crate::memory_admission::set_probe(None);
        }
    }
    let _reset = Reset;
    crate::memory_admission::set_probe(Some(control_only));
    node.queue_discovery_announce(false, true).unwrap();
    node.process_tx_queue().unwrap();
    assert_eq!(sent.load(core::sync::atomic::Ordering::Relaxed), 1);
    node.queue_discovery_announce(false, true).unwrap();
    node.process_tx_queue().unwrap();
    assert_eq!(
        sent.load(core::sync::atomic::Ordering::Relaxed),
        1,
        "keepalives were not rate limited"
    );
}

#[test]
fn discovery_snapshot_reclaims_telemetry_but_preserves_commands_and_acks() {
    crate::tests::ensure_common_test_schema();
    static REFUSALS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
    extern "C" fn scratch_after_reclaim(additional: usize, _: usize) -> bool {
        additional < 2048 || REFUSALS.fetch_add(1, core::sync::atomic::Ordering::SeqCst) >= 2
    }
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            crate::memory_admission::set_probe(None);
        }
    }
    let node = Router::new_with_clock(RouterConfig::new([]).with_sender("GB"), Box::new(|| 1));
    let side = node.add_side_packet("CAN", |_| Ok(()));
    for priority in [1, 2, 200, 254, 255] {
        node.state
            .lock()
            .push_transmit(TxQueued {
                disposable: TX_DISPOSABLE,
                item: RouterTxItem::ToSide {
                    src: None,
                    dst: side,
                    data: RouterItem::Packed(crate::shared_bytes::convert(Arc::<[u8]>::from(
                        [0; 32],
                    ))),
                },
                ignore_local: true,
                priority,
                delivery_state: QueuedDelivery::Untracked,
                accepted_type: 0,
                deferred_since_ms: 0,
                retry_after_ms: 0,
            })
            .unwrap();
    }
    REFUSALS.store(0, core::sync::atomic::Ordering::SeqCst);
    let _reset = Reset;
    crate::memory_admission::set_probe(Some(scratch_after_reclaim));
    node.queue_discovery_announce(false, true).unwrap();
    let st = node.state.lock();
    assert_eq!(
        st.transmit_queue.lowest_priority(|item| item.priority),
        Some(200)
    );
    for priority in [200, 254] {
        assert_eq!(
            st.transmit_queue
                .iter()
                .filter(|item| item.priority == priority)
                .count(),
            1
        );
    }
    assert!(
        st.transmit_queue.iter().any(|item| matches!(
            &item.item, RouterTxItem::ToSide { data: RouterItem::Packet(pkt), .. }
                if pkt.data_type() == DataType::DiscoveryAddress
        )),
        "scratch refusal left a late-joining valve without a return-route baseline"
    );
}

#[test]
fn stable_network_sends_liveness_without_periodic_route_or_schema_refresh() {
    crate::tests::ensure_common_test_schema();
    let now = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let clock = now.clone();
    let output = Arc::new(std::sync::Mutex::new(Vec::<Packet>::new()));
    let sent = output.clone();
    let node = Router::new_with_clock(
        RouterConfig::new([]).with_sender("STABLE"),
        Box::new(move || clock.load(std::sync::atomic::Ordering::Relaxed)),
    );
    let stable = node.add_side_packet("stable", move |pkt| {
        sent.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let baseline = discovery::build_discovery_topology(
        "PEER",
        0,
        &[discovery::TopologyBoardNode {
            sender_id: "PEER".into(),
            reachable_endpoints: vec![crate::DataEndpoint::named("RADIO")],
            reachable_timesync_sources: vec![],
            connections: vec!["STABLE".into()],
        }],
    )
    .unwrap();
    let schema = discovery::build_discovery_schema("PEER", 0).unwrap();
    node.rx_from_side(&baseline, stable).unwrap();
    node.rx_from_side(&schema, stable).unwrap();

    node.announce_discovery().unwrap();
    node.process_tx_queue().unwrap();
    output.lock().unwrap().clear();
    for ms in (1_000..=300_000).step_by(1_000) {
        now.store(ms, std::sync::atomic::Ordering::Relaxed);
        if ms % 10_000 == 0 {
            let alive = discovery::build_discovery_announce("PEER", ms, &[]).unwrap();
            node.rx_from_side(&alive, stable).unwrap();
        }
        node.poll_discovery().unwrap();
        node.process_tx_queue().unwrap();
    }
    let frames = output.lock().unwrap();
    assert!(
        (14..=20).contains(&frames.len()),
        "expected bounded liveness only: {}",
        frames.len()
    );
    assert!(
        frames
            .iter()
            .all(|pkt| pkt.data_type() == crate::DataType::DiscoveryAnnounce
                && pkt.payload().is_empty()),
        "unchanged routes must not be broadcast again, even after 120 seconds"
    );
    drop(frames);
    let new_side = node.add_side_packet("new_link", |_| Ok(()));
    let newcomer =
        discovery::build_discovery_announce("NEW", 300_000, &[crate::DataEndpoint::named("RADIO")])
            .unwrap();
    node.rx_from_side(&newcomer, new_side).unwrap();
    node.poll_discovery().unwrap();
    node.process_tx_queue().unwrap();
    assert!(
        output
            .lock()
            .unwrap()
            .iter()
            .any(|pkt| pkt.data_type() == crate::DataType::DiscoveryTopology),
        "adding a link must still advertise changed topology"
    );
}

#[test]
fn ordinary_native_and_packed_traffic_renew_only_the_matching_peer() {
    crate::tests::ensure_common_test_schema();
    let now = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let clock = now.clone();
    let node = Router::new_with_clock(
        RouterConfig::new([]).with_sender("GS"),
        Box::new(move || clock.load(std::sync::atomic::Ordering::Relaxed)),
    );
    let side = node.add_side_packet("CAN", |_| Ok(()));
    for name in ["LIVE", "SILENT"] {
        let pkt =
            discovery::build_discovery_announce(name, 0, &[crate::DataEndpoint::named("RADIO")])
                .unwrap();
        node.learn_discovery_packet(&pkt, Some(side), true).unwrap();
    }
    let ty = crate::DataType::named("GPS_DATA");
    for i in 1..=18 {
        now.store(i * 10_000, std::sync::atomic::Ordering::Relaxed);
        let packet = Packet::new(
            ty,
            &[crate::DataEndpoint::named("RADIO")],
            "LIVE",
            i * 10_000,
            vec![0; 12].into(),
        )
        .unwrap();
        if i % 2 == 0 {
            node.rx_from_side(&packet, side).unwrap();
        } else {
            node.rx_packed_from_side(&crate::wire_format::pack_packet(&packet), side)
                .unwrap();
        }
        node.poll_discovery().unwrap();
        let st = node.state.lock();
        let route = st
            .discovery_routes
            .get(&side)
            .expect("active ingress retained");
        assert_eq!(route.announcers["LIVE"].last_seen_ms, i * 10_000);
        if i >= 4 {
            assert!(
                !route.announcers.contains_key("SILENT"),
                "one peer's traffic cannot renew another peer"
            );
        }
    }
    now.store(211_000, std::sync::atomic::Ordering::Relaxed);
    node.poll_discovery().unwrap();
    assert!(
        !node
            .state
            .lock()
            .discovery_routes
            .get(&side)
            .is_some_and(|r| r.announcers.contains_key("LIVE")),
        "actual silence must expire the route"
    );
}

#[test]
fn delayed_liveness_send_does_not_cause_an_immediate_refresh_burst() {
    crate::tests::ensure_common_test_schema();
    let now = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let clock = now.clone();
    let count = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let sent = count.clone();
    let node = Router::new_with_clock(
        RouterConfig::new([]).with_sender("LATE"),
        Box::new(move || clock.load(std::sync::atomic::Ordering::Relaxed)),
    );
    node.add_side_packet("busy", move |pkt| {
        if pkt.data_type() == crate::DataType::DiscoveryAnnounce {
            sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(())
    });
    node.announce_discovery().unwrap();
    node.process_tx_queue().unwrap();
    now.store(20_000, std::sync::atomic::Ordering::Relaxed);
    node.poll_discovery().unwrap();
    now.store(30_000, std::sync::atomic::Ordering::Relaxed);
    node.process_tx_queue().unwrap();
    assert_eq!(count.load(std::sync::atomic::Ordering::Relaxed), 1);
    now.store(35_000, std::sync::atomic::Ordering::Relaxed);
    node.poll_discovery().unwrap();
    node.process_tx_queue().unwrap();
    assert_eq!(
        count.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "queued timestamp is not the successful transmission time"
    );
    now.store(45_000, std::sync::atomic::Ordering::Relaxed);
    node.poll_discovery().unwrap();
    node.process_tx_queue().unwrap();
    assert_eq!(count.load(std::sync::atomic::Ordering::Relaxed), 2);
}

#[test]
fn compact_frames_refresh_live_peer_at_ingress_without_dispatch() {
    crate::tests::ensure_common_test_schema();
    let ty = crate::config::register_data_type_with_description(
        "COMPACT_LIVENESS_ROUTER_TEST",
        "compact ingress test",
        crate::MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[crate::DataEndpoint::named("RADIO")],
        crate::ReliableMode::None,
        0,
    )
    .unwrap();
    struct RemoveTestType(crate::DataType);
    impl Drop for RemoveTestType {
        fn drop(&mut self) {
            let _ = crate::config::remove_data_type(self.0);
        }
    }
    let _remove_type = RemoveTestType(ty);
    let now = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let clock = now.clone();
    let node = Router::new_with_clock(
        RouterConfig::new([]).with_sender("GS"),
        Box::new(move || clock.load(std::sync::atomic::Ordering::Relaxed)),
    );
    let source = Router::new_with_clock(RouterConfig::new([]).with_sender("LIVE"), Box::new(|| 0));
    let opts = RouterSideOptions {
        header_template_enabled: true,
        max_frame_bytes: 0,
        ..Default::default()
    };
    let side = node.add_side_packed_with_options("CAN", |_| Ok(()), opts.clone());
    let tx = source.add_side_packed_with_options("CAN", |_| Ok(()), opts.clone());
    let announcement =
        discovery::build_discovery_announce("LIVE", 0, &[crate::DataEndpoint::named("RADIO")])
            .unwrap();
    node.learn_discovery_packet(&announcement, Some(side), true)
        .unwrap();
    let mut compact = 0;
    let mut last_compact = None;
    for i in 1..=600 {
        now.store(i * 100, std::sync::atomic::Ordering::Relaxed);
        let pkt = Packet::new(
            ty,
            &[crate::DataEndpoint::named("RADIO")],
            "LIVE",
            i * 100,
            vec![0; 1].into(),
        )
        .unwrap();
        let raw = crate::shared_bytes::convert(wire_format::pack_packet(&pkt));
        let frames = source
            .encode_side_transport_frames(tx, opts.clone(), raw)
            .unwrap();
        for frame in frames {
            let (kind, _) = parse_side_transport_wrapper(&frame)
                .unwrap()
                .expect("header templates enabled");
            if kind == SIDE_TRANSPORT_KIND_COMPACT {
                compact += 1;
                last_compact = Some(frame.clone());
            }
            node.decode_side_transport_frame(side, &frame).unwrap();
        }
        assert_eq!(
            node.state.lock().discovery_routes[&side].announcers["LIVE"].last_seen_ms,
            i * 100,
            "compact data must count even if forwarding bypasses the normal RX dispatcher"
        );
    }
    assert!(
        compact > 500,
        "fixture must exercise actual compact frames: {compact}"
    );
    let last = last_compact.expect("compact fixture");
    now.store(61_000, std::sync::atomic::Ordering::Relaxed);
    let mut corrupt = last.to_vec();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(node.decode_side_transport_frame(side, &corrupt).is_err());
    assert_eq!(
        node.state.lock().discovery_routes[&side].announcers["LIVE"].last_seen_ms,
        60_000,
        "bad CRC is not liveness"
    );
    extern "C" fn refuse_payload(_: usize, _: usize) -> bool {
        false
    }
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            crate::memory_admission::set_probe(None);
        }
    }
    let _reset = Reset;
    crate::memory_admission::set_probe(Some(refuse_payload));
    assert!(node.decode_side_transport_frame(side, &last).is_err());
    assert_eq!(
        node.state.lock().discovery_routes[&side].announcers["LIVE"].last_seen_ms,
        61_000,
        "allocation refusal must not turn a live known peer into a stale route"
    );
}

#[test]
fn stable_noop_poll_does_not_reserve_scratch_or_shed_data() {
    crate::tests::ensure_common_test_schema();
    let now = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let clock = now.clone();
    let node = Router::new_with_clock(
        RouterConfig::new([]).with_sender("QUIET"),
        Box::new(move || clock.load(std::sync::atomic::Ordering::Relaxed)),
    );
    node.add_side_packet("quiet", |_| Ok(()));
    node.announce_discovery().unwrap();
    node.process_tx_queue().unwrap();
    static CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    extern "C" fn count_and_refuse(_: usize, _: usize) -> bool {
        CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        false
    }
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            crate::memory_admission::set_probe(None);
        }
    }
    let _reset = Reset;
    CALLS.store(0, std::sync::atomic::Ordering::Relaxed);
    crate::memory_admission::set_probe(Some(count_and_refuse));
    for ms in 1_000..10_000 {
        now.store(ms, std::sync::atomic::Ordering::Relaxed);
        assert!(
            !node.poll_discovery().unwrap(),
            "no metadata is due before liveness deadline"
        );
    }
    assert_eq!(
        CALLS.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "a no-op must not reserve snapshot memory or evict queued traffic"
    );
}
