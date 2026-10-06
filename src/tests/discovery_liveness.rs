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
            let queued = Router::pop_transmit_queue_locked(&mut rf.state.lock());
            let Some(queued) = queued else {
                break;
            };
            rf.tx_item_impl(queued.item, queued.ignore_local, true)
                .unwrap();
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
                received: [(0, crate::shared_bytes::convert(retained))]
                    .into_iter()
                    .collect(),
            },
        );
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
            DiscoverySenderState {
                last_seen_ms: 1,
                reachable: vec![endpoint],
                advertised_reachable: vec![endpoint],
                ..Default::default()
            },
        );
    }
    let mut st = router.state.lock();
    st.discovery_routes.insert(side, route.clone());
    st.push_transmit(TxQueued {
        item: RouterTxItem::ToSide {
            src: None,
            dst: side,
            data: RouterItem::Packed(crate::shared_bytes::convert(Arc::<[u8]>::from([0; 512]))),
        },
        ignore_local: true,
        priority: 1,
    })
    .unwrap();
    st.push_transmit(TxQueued {
        item: RouterTxItem::ToSide {
            src: None,
            dst: side,
            data: RouterItem::Packed(crate::shared_bytes::convert(Arc::<[u8]>::from([0; 32]))),
        },
        ignore_local: true,
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
