//! Regression coverage for bounded, peer-scoped missing-catalog recovery.
use super::*;
use core::sync::atomic::{AtomicU64, Ordering};

fn capture_node(
    name: &str,
    clock: Arc<AtomicU64>,
) -> (Router, RouterSideId, Arc<RouterMutex<Vec<Packet>>>) {
    let node = Router::new_with_clock(
        RouterConfig::new([]).with_sender(name),
        Box::new(move || clock.load(Ordering::Relaxed)),
    );
    let sent = Arc::new(RouterMutex::new(Vec::new()));
    let capture = sent.clone();
    let side = node.add_side_packet("shared-medium", move |packet| {
        capture.lock().push(packet.clone());
        Ok(())
    });
    (node, side, sent)
}
fn peers(node: &Router, side: RouterSideId) -> serde_json::Value {
    let st = node.state.lock();
    serde_json::Value::Array(st.discovery_routes[&side].announcers.iter().map(|(name,p)| serde_json::json!({"name":name,"has_schema":p.has_schema,"full_topology":p.has_full_topology,"last_seen_ms":p.last_seen_ms})).collect())
}
#[test]
fn scoped_query_recovers_missing_peer_without_repeating_complete_known_catalog() {
    crate::tests::ensure_common_test_schema();
    let clock = Arc::new(AtomicU64::new(1000));
    let (receiver, side, receiver_sent) = capture_node("RECOVERING_NODE", clock.clone());
    let (known, known_side, known_sent) = capture_node("KNOWN_PEER", clock.clone());
    let (missing, missing_side, missing_sent) = capture_node("MISSING_PEER", clock.clone());
    {
        // Exact precondition under audit: topology already admitted, one catalog absent.
        // This does not seed has_schema or pretend a catalog was received.
        let mut st = receiver.state.lock();
        for name in ["KNOWN_PEER", "MISSING_PEER"] {
            st.discovery_routes
                .entry(side)
                .or_default()
                .announcers
                .insert(
                    name.into(),
                    Box::new(DiscoverySenderState {
                        advertised_address: Some(sender_address_u32(name)),
                        has_full_topology: true,
                        last_seen_ms: 1000,
                        ..DiscoverySenderState::default()
                    }),
                );
        }
        st.discovery_side_throttle
            .entry(side)
            .or_default()
            .next_schema_request_ms = 1000;
    }
    let mut trace = Vec::new();
    let mut seen_requests = 0;
    let mut known_catalog_count = 0;
    let mut missing_catalog = None;

    for now in [1000u64, 6000, 11000, 16000] {
        clock.store(now, Ordering::Relaxed);
        {
            let mut st = receiver.state.lock();
            for peer in st
                .discovery_routes
                .get_mut(&side)
                .unwrap()
                .announcers
                .values_mut()
            {
                peer.last_seen_ms = now;
            }
        }
        // Full, valid same-known-peer catalog is successfully learned each round.
        let catalog = discovery::build_discovery_schema("KNOWN_PEER", now).unwrap();
        let wire = wire_format::pack_packet(&catalog);
        receiver.rx_packed_from_side(&wire, side).unwrap();
        assert!(receiver.state.lock().discovery_routes[&side].announcers["KNOWN_PEER"].has_schema);
        assert!(
            !receiver.state.lock().discovery_routes[&side].announcers["MISSING_PEER"].has_schema
        );
        receiver.poll_discovery_announce().unwrap();
        receiver.drain_queues_with_timeout(0).unwrap();
        let queries: Vec<_> = receiver_sent
            .lock()
            .iter()
            .filter(|p| p.data_type() == DataType::DiscoverySchemaRequest)
            .cloned()
            .collect();
        assert_eq!(
            queries.len(),
            seen_requests + 1,
            "one still-missing live peer must continue to recover"
        );
        let query = queries.last().unwrap().clone();
        seen_requests = queries.len();
        let targets =
            discovery::schema_request_targets(query.payload()).expect("automatic query is scoped");
        assert_eq!(targets, sender_address_u32("MISSING_PEER").to_le_bytes());
        let query_wire = wire_format::pack_packet(&query);
        let actual = wire_format::unpack_packet(&query_wire).unwrap();
        assert_eq!(actual.payload(), query.payload());
        let known_before = known_sent.lock().len();
        let missing_before = missing_sent.lock().len();
        // Actual public Router ingress/response path, not a mocked responder.
        known.rx_packed_from_side(&query_wire, known_side).unwrap();
        known.drain_queues_with_timeout(0).unwrap();
        missing
            .rx_packed_from_side(&query_wire, missing_side)
            .unwrap();
        missing.drain_queues_with_timeout(0).unwrap();
        let known_replies: Vec<_> = known_sent.lock()[known_before..]
            .iter()
            .filter(|p| p.data_type() == DataType::DiscoverySchema)
            .cloned()
            .collect();
        let missing_replies: Vec<_> = missing_sent.lock()[missing_before..]
            .iter()
            .filter(|p| p.data_type() == DataType::DiscoverySchema)
            .cloned()
            .collect();
        assert!(
            known_replies.is_empty(),
            "already-known peer must leave this request unanswered"
        );
        known_catalog_count += known_replies.len();
        assert_eq!(
            missing_replies.len(),
            1,
            "scoped missing peer still answers its legitimate recovery"
        );
        missing_catalog = Some(missing_replies[0].clone()); // deliberately lost, not delivered
        trace.push(serde_json::json!({"time_ms":now,"request_id":query.packet_id(),"request_wire_len":query_wire.len(),"request_payload_len":query.payload().len(),"request_frozen_targets":query.wire_target_senders(),"known_reply_count":known_replies.len(),"missing_reply_count":missing_replies.len(),"request_reliable":format!("{:?}",message_meta(query.data_type()).reliable),"request_priority":sedsnet_priority(query.data_type()),"peers":peers(&receiver,side)}));
    }
    assert_eq!(known_catalog_count, 0);
    // Receiving the OTHER peer's real catalog is what closes the retry condition.
    clock.store(17000, Ordering::Relaxed);
    receiver
        .rx_packed_from_side(&wire_format::pack_packet(&missing_catalog.unwrap()), side)
        .unwrap();
    assert!(receiver.state.lock().discovery_routes[&side].announcers["MISSING_PEER"].has_schema);
    clock.store(21000, Ordering::Relaxed);
    receiver.poll_discovery_announce().unwrap();
    receiver.drain_queues_with_timeout(0).unwrap();
    assert_eq!(
        receiver_sent
            .lock()
            .iter()
            .filter(|p| p.data_type() == DataType::DiscoverySchemaRequest)
            .count(),
        4
    );
    let report = serde_json::json!({"observations":trace,"final_peers":peers(&receiver,side),"requests_after_missing_catalog_delivery":0,"scope":"Actual Router scoped auto-query ingress and target-filtered response. Two full-topology announcers privately seeded as explicit precondition; no physical throughput or all-ownerACK amplification claimed."});
    if let Ok(path) = std::env::var("SEDS_SCHEMA_RECOVERY_AUDIT_OUTPUT") {
        std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    }
    println!(
        "SCHEMA_RECOVERY_AUDIT {}",
        serde_json::json!({"requests":4,"unneeded_known_catalogs":0,"stopped_after_missing_peer_catalog":true})
    );
}
fn sedsnet_priority(ty: DataType) -> u8 {
    crate::transport_priority(ty)
}

fn seed_missing(node: &Router, side: RouterSideId, addresses: &[u32], now: u64) {
    let mut st = node.state.lock();
    for (i, address) in addresses.iter().enumerate() {
        st.discovery_routes
            .entry(side)
            .or_default()
            .announcers
            .insert(
                format!("PEER_{i}"),
                Box::new(DiscoverySenderState {
                    advertised_address: Some(*address),
                    has_full_topology: true,
                    last_seen_ms: now,
                    ..DiscoverySenderState::default()
                }),
            );
    }
    st.discovery_side_throttle
        .entry(side)
        .or_default()
        .next_schema_request_ms = now;
}
fn query_with_body(body: &[u8], now: u64) -> Packet {
    Packet::new(
        DataType::DiscoverySchemaRequest,
        &[DataEndpoint::Discovery],
        "RECOVERING_NODE",
        now,
        Arc::<[u8]>::from(body),
    )
    .unwrap()
}
#[test]
fn scoped_rotation_covers_more_than_eight_and_legacy_builder_stays_empty() {
    crate::tests::ensure_common_test_schema();
    let clock = Arc::new(AtomicU64::new(1000));
    let (node, side, sent) = capture_node("OBSERVER", clock.clone());
    seed_missing(&node, side, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], 1000);
    let mut selected = Vec::new();
    for now in [1000, 6000, 11000] {
        clock.store(now, Ordering::Relaxed);
        node.poll_discovery_announce().unwrap();
        node.drain_queues_with_timeout(0).unwrap();
        let all = sent.lock();
        let query = all
            .iter()
            .rev()
            .find(|p| p.data_type() == DataType::DiscoverySchemaRequest)
            .unwrap();
        let targets = scope_addresses(discovery::schema_request_targets(query.payload()).unwrap());
        assert_eq!(targets.len(), 8);
        selected.push(targets);
        drop(all);
        if now == 1000 {
            for idle in [1001, 2000, 5999] {
                clock.store(idle, Ordering::Relaxed);
                node.poll_discovery_announce().unwrap();
                node.drain_queues_with_timeout(0).unwrap();
                assert_eq!(
                    sent.lock()
                        .iter()
                        .filter(|p| p.data_type() == DataType::DiscoverySchemaRequest)
                        .count(),
                    1
                );
                let state = node.state.lock();
                let throttle = &state.discovery_side_throttle[&side];
                assert_eq!(throttle.next_schema_request_ms, 6000);
                assert_eq!(throttle.schema_request_cursor, 8);
            }
        }
    }
    assert_eq!(selected[0], vec![1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(selected[1], vec![9, 10, 11, 1, 2, 3, 4, 5]);
    assert_eq!(selected[2], vec![6, 7, 8, 9, 10, 11, 1, 2]);
    assert!(
        discovery::build_discovery_schema_request("OPERATOR", 1)
            .unwrap()
            .payload()
            .is_empty()
    );
    node.request_schema().unwrap();
    node.drain_queues_with_timeout(0).unwrap();
    assert!(
        sent.lock()
            .iter()
            .rev()
            .find(|p| p.data_type() == DataType::DiscoverySchemaRequest)
            .unwrap()
            .payload()
            .is_empty()
    );
}
#[test]
fn scoped_response_matches_current_assigned_and_legacy_address_after_reassignment() {
    crate::tests::ensure_common_test_schema();
    let clock = Arc::new(AtomicU64::new(1000));
    let (node, side, sent) = capture_node("RESPONDER", clock.clone());
    node.set_address_assignment(AddressAssignmentMode::Static(0x1234))
        .unwrap();
    let query =
        discovery::build_scoped_discovery_schema_request("RECOVERING_NODE", 1000, &[0x1234])
            .unwrap();
    node.rx_packed_from_side(&wire_format::pack_packet(&query), side)
        .unwrap();
    node.drain_queues_with_timeout(0).unwrap();
    assert_eq!(
        sent.lock()
            .iter()
            .filter(|p| p.data_type() == DataType::DiscoverySchema)
            .count(),
        1
    );
    node.set_address_assignment(AddressAssignmentMode::Static(0x5678))
        .unwrap();
    sent.lock().clear();
    clock.store(2000, Ordering::Relaxed);
    let old = discovery::build_scoped_discovery_schema_request("RECOVERING_NODE", 2000, &[0x1234])
        .unwrap();
    node.rx_packed_from_side(&wire_format::pack_packet(&old), side)
        .unwrap();
    node.drain_queues_with_timeout(0).unwrap();
    assert!(
        !sent
            .lock()
            .iter()
            .any(|p| p.data_type() == DataType::DiscoverySchema)
    );
    for (at, address) in [(3000, 0x5678), (4000, sender_address_u32("RESPONDER"))] {
        clock.store(at, Ordering::Relaxed);
        let q = discovery::build_scoped_discovery_schema_request("RECOVERING_NODE", at, &[address])
            .unwrap();
        node.rx_packed_from_side(&wire_format::pack_packet(&q), side)
            .unwrap();
        node.drain_queues_with_timeout(0).unwrap();
        assert!(
            sent.lock()
                .iter()
                .any(|p| p.data_type() == DataType::DiscoverySchema)
        );
        sent.lock().clear();
    }
}
#[test]
fn malformed_unknown_and_empty_scope_keep_legacy_response_semantics() {
    crate::tests::ensure_common_test_schema();
    let mut cases = vec![
        vec![],
        b"legacy opaque".to_vec(),
        b"SRQ\x02\x01\x01\0\0\0".to_vec(),
        b"SRQ\x01\0".to_vec(),
        b"SRQ\x01\x01\0\0\0\0".to_vec(),
        b"SRQ\x01\x02\x01\0\0\0\x01\0\0\0".to_vec(),
        b"SRQ\x01\x01\x01".to_vec(),
    ];
    let mut too_many = b"SRQ\x01\x09".to_vec();
    for v in 1u32..=9 {
        too_many.extend(v.to_le_bytes());
    }
    cases.push(too_many);
    for (i, body) in cases.iter().enumerate() {
        assert!(discovery::schema_request_targets(body).is_none());
        let (node, side, sent) = capture_node("RESPONDER", Arc::new(AtomicU64::new(1000)));
        let p = query_with_body(body, i as u64);
        node.rx_packed_from_side(&wire_format::pack_packet(&p), side)
            .unwrap();
        node.drain_queues_with_timeout(0).unwrap();
        assert_eq!(
            sent.lock()
                .iter()
                .filter(|p| p.data_type() == DataType::DiscoverySchema)
                .count(),
            1,
            "case{i}"
        );
    }
}
#[test]
fn excluded_scope_does_not_cancel_pending_or_owned_catalog() {
    crate::tests::ensure_common_test_schema();
    let (node, side, _) = capture_node("RESPONDER", Arc::new(AtomicU64::new(1000)));
    let broad = discovery::build_discovery_schema_request("RECOVERING_NODE", 1).unwrap();
    node.learn_discovery_packet(&broad, Some(side), true)
        .unwrap();
    {
        let mut st = node.state.lock();
        st.discovery_side_throttle
            .get_mut(&side)
            .unwrap()
            .set_schema_response_pending(true);
    }
    let before = {
        let st = node.state.lock();
        let t = &st.discovery_side_throttle[&side];
        assert!(t.schema_response_active());
        (
            t.schema_response_active(),
            t.schema_response_pending(),
            t.schema_response_phase,
            t.schema_response_packet_id,
            st.transmit_queue.len(),
        )
    };
    let assigned = node.current_address();
    let target = if assigned != 0x9999 && sender_address_u32("RESPONDER") != 0x9999 {
        0x9999
    } else {
        0x8888
    };
    let excluded =
        discovery::build_scoped_discovery_schema_request("OTHER_RECOVERER", 2, &[target]).unwrap();
    node.learn_discovery_packet(&excluded, Some(side), true)
        .unwrap();
    let after = {
        let st = node.state.lock();
        let t = &st.discovery_side_throttle[&side];
        (
            t.schema_response_active(),
            t.schema_response_pending(),
            t.schema_response_phase,
            t.schema_response_packet_id,
            st.transmit_queue.len(),
        )
    };
    assert_eq!(before, after);
}
#[test]
fn refused_query_keeps_rotation_cursor_and_original_retry_cadence() {
    crate::tests::ensure_common_test_schema();
    let now = Arc::new(AtomicU64::new(1000));
    let clock = now.clone();
    let memory = RuntimeMemoryConfig::new(1024 * 1024, 16, size_of::<TxQueued>(), 1.0).unwrap();
    let node = Router::new_with_clock(
        RouterConfig::new([])
            .with_sender("OBSERVER")
            .with_memory_config(memory)
            .unwrap(),
        Box::new(move || clock.load(Ordering::Relaxed)),
    );
    let side = node.add_side_packet("bus", |_| Ok(()));
    seed_missing(&node, side, &[1, 2, 3, 4, 5, 6, 7, 8, 9], 1000);
    let ack = Packet::new(
        DataType::ReliableAck,
        &[DataEndpoint::Discovery],
        "OWNER",
        0,
        Arc::<[u8]>::from(42u64.to_le_bytes()),
    )
    .unwrap();
    node.state
        .lock()
        .push_transmit(TxQueued {
            disposable: TX_DISPOSABLE,
            item: RouterTxItem::ToSide {
                src: None,
                dst: side,
                data: RouterItem::Packet(ack),
            },
            ignore_local: true,
            priority: 255,
            delivery_state: QueuedDelivery::Untracked,
            accepted_type: 0,
            deferred_since_ms: 0,
            retry_after_ms: 0,
        })
        .unwrap();
    assert!(node.poll_discovery_announce().is_err());
    {
        let st = node.state.lock();
        let t = &st.discovery_side_throttle[&side];
        assert_eq!(t.schema_request_cursor, 0);
        assert_eq!(t.next_schema_request_ms, 6000);
    }
    node.clear_tx_queue();
    now.store(6000, Ordering::Relaxed);
    node.poll_discovery_announce().unwrap();
    assert_eq!(
        node.state.lock().discovery_side_throttle[&side].schema_request_cursor,
        8
    );
}

#[test]
fn stale_missing_peer_is_removed_and_restarted_topology_requests_again() {
    crate::tests::ensure_common_test_schema();
    let clock = Arc::new(AtomicU64::new(1000));
    let (node, side, sent) = capture_node("OBSERVER", clock.clone());
    seed_missing(&node, side, &[sender_address_u32("PEER_0")], 1000);
    clock.store(1001 + DISCOVERY_ROUTE_TTL_MS, Ordering::Relaxed);
    node.poll_discovery_announce().unwrap();
    node.drain_queues_with_timeout(0).unwrap();
    assert!(
        !node
            .state
            .lock()
            .discovery_routes
            .get(&side)
            .is_some_and(|r| r.announcers.contains_key("PEER_0"))
    );
    assert!(
        !sent
            .lock()
            .iter()
            .any(|p| p.data_type() == DataType::DiscoverySchemaRequest)
    );
    let now = 1002 + DISCOVERY_ROUTE_TTL_MS;
    clock.store(now, Ordering::Relaxed);
    let topology = discovery::build_discovery_topology(
        "PEER_0",
        now,
        &[discovery::TopologyBoardNode {
            sender_id: "PEER_0".into(),
            reachable_endpoints: vec![],
            reachable_timesync_sources: vec![],
            connections: vec![],
        }],
    )
    .unwrap();
    node.rx_packed_from_side(&wire_format::pack_packet(&topology), side)
        .unwrap();
    {
        let mut st = node.state.lock();
        let peer = st
            .discovery_routes
            .get(&side)
            .unwrap()
            .announcers
            .values()
            .next()
            .unwrap();
        assert!(peer.has_full_topology);
        assert!(!peer.has_schema);
        st.discovery_side_throttle
            .entry(side)
            .or_default()
            .next_schema_request_ms = now;
    }
    node.poll_discovery_announce().unwrap();
    node.drain_queues_with_timeout(0).unwrap();
    let last = sent
        .lock()
        .iter()
        .rev()
        .find(|p| p.data_type() == DataType::DiscoverySchemaRequest)
        .cloned()
        .unwrap();
    assert!(
        scope_addresses(discovery::schema_request_targets(last.payload()).unwrap())
            .contains(&sender_address_u32("PEER_0"))
    );
}

#[test]
fn scoped_request_reassembles_before_response_on_small_sdt_transport() {
    crate::tests::ensure_common_test_schema();
    let clock = Arc::new(AtomicU64::new(1000));
    let source = Router::new_with_clock(
        RouterConfig::new([]).with_sender("SOURCE"),
        Box::new(|| 1000),
    );
    let frames = Arc::new(RouterMutex::new(Vec::new()));
    let output = frames.clone();
    let side = source.add_side_packed_with_options(
        "small",
        move |b| {
            output.lock().push(b.to_vec());
            Ok(())
        },
        RouterSideOptions::default().with_small_packet_transport(32),
    );
    let (target, target_side, replies) = capture_node("TARGET", clock);
    let mut addresses = [1, 2, 3, 4, 5, 6, 7, 8];
    addresses[0] = target.current_address();
    let request =
        discovery::build_scoped_discovery_schema_request("SOURCE", 1000, &addresses).unwrap();
    source
        .send_reliable_to_side(side, RouterItem::Packet(request), false)
        .unwrap();
    let captured = frames.lock().clone();
    assert!(captured.len() > 1);
    assert!(captured.iter().all(|b| b.len() <= 32));
    for frame in &captured[..captured.len() - 1] {
        target.rx_packed_from_side(frame, target_side).unwrap();
        target.drain_queues_with_timeout(0).unwrap();
        assert!(
            !replies
                .lock()
                .iter()
                .any(|p| p.data_type() == DataType::DiscoverySchema)
        );
    }
    target
        .rx_packed_from_side(captured.last().unwrap(), target_side)
        .unwrap();
    target.drain_queues_with_timeout(0).unwrap();
    assert_eq!(
        replies
            .lock()
            .iter()
            .filter(|p| p.data_type() == DataType::DiscoverySchema)
            .count(),
        1
    );
}

#[test]
fn zero_source_alias_keeps_legacy_recovery_without_poisoning_other_peers() {
    crate::tests::ensure_common_test_schema();
    let clock = Arc::new(AtomicU64::new(1000));
    let (node, side, sent) = capture_node("OBSERVER", clock.clone());
    // Address advertisements reject zero, but valid topology's compact sender
    // can be @addr:0. Exercise actual wire ingress, not just invented private state.
    let topology = discovery::build_discovery_topology(
        "@addr:0",
        1000,
        &[discovery::TopologyBoardNode {
            sender_id: "@addr:0".into(),
            reachable_endpoints: vec![],
            reachable_timesync_sources: vec![],
            connections: vec![],
        }],
    )
    .unwrap();
    node.rx_packed_from_side(&wire_format::pack_packet(&topology), side)
        .unwrap();
    assert!(
        node.state.lock().discovery_routes[&side]
            .announcers
            .contains_key("@addr:0")
    );
    seed_missing(&node, side, &[0x1234], 1000);
    node.poll_discovery_announce().unwrap();
    node.drain_queues_with_timeout(0).unwrap();
    assert!(
        sent.lock()
            .iter()
            .rev()
            .find(|p| p.data_type() == DataType::DiscoverySchemaRequest)
            .unwrap()
            .payload()
            .is_empty(),
        "one unaddressable peer must preserve the old broad query, not fail all recovery"
    );
    assert_eq!(
        node.state.lock().discovery_side_throttle[&side].schema_request_cursor,
        0
    );
    let schema = discovery::build_discovery_schema("@addr:0", 1001).unwrap();
    node.rx_packed_from_side(&wire_format::pack_packet(&schema), side)
        .unwrap();
    clock.store(6000, Ordering::Relaxed);
    node.poll_discovery_announce().unwrap();
    node.drain_queues_with_timeout(0).unwrap();
    let last = sent
        .lock()
        .iter()
        .rev()
        .find(|p| p.data_type() == DataType::DiscoverySchemaRequest)
        .cloned()
        .unwrap();
    assert_eq!(
        discovery::schema_request_targets(last.payload()).unwrap(),
        0x1234u32.to_le_bytes()
    );
}

#[test]
fn finite_192_byte_shared_medium_completes_missing_catalog_without_known_reply() {
    use core::sync::atomic::AtomicUsize;
    crate::tests::ensure_common_test_schema();
    for legacy in [false, true] {
        let now = Arc::new(AtomicU64::new(1000));
        let credit = Arc::new(AtomicUsize::new(192));
        let accepted = Arc::new(RouterMutex::new(Vec::<(usize, u64, Vec<u8>)>::new()));
        let history = Arc::new(RouterMutex::new(Vec::<(usize, u64, usize, u8)>::new()));
        let mut nodes = Vec::new();
        let mut sides = Vec::new();
        for (index, name) in ["OBSERVER", "KNOWN_PEER", "MISSING_PEER"]
            .into_iter()
            .enumerate()
        {
            let clock = now.clone();
            let node = Router::new_with_clock(
                RouterConfig::new([]).with_sender(name),
                Box::new(move || clock.load(Ordering::Relaxed)),
            );
            let c = credit.clone();
            let bus = accepted.clone();
            let at = now.clone();
            let record = history.clone();
            let side = node.add_side_packed_with_priority_and_options(
                "shared",
                move |bytes, priority| {
                    assert!(bytes.len() <= 192);
                    let mut available = c.load(Ordering::Relaxed);
                    loop {
                        let Some(remaining) = available.checked_sub(bytes.len()) else {
                            return Err(TelemetryError::Io("side tx busy"));
                        };
                        match c.compare_exchange_weak(
                            available,
                            remaining,
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                        ) {
                            Ok(_) => break,
                            Err(next) => available = next,
                        }
                    }
                    record
                        .lock()
                        .push((index, at.load(Ordering::Relaxed), bytes.len(), priority));
                    bus.lock()
                        .push((index, at.load(Ordering::Relaxed), bytes.to_vec()));
                    Ok(())
                },
                RouterSideOptions::default().with_small_packet_transport(192),
            );
            nodes.push(node);
            sides.push(side);
        }
        {
            let mut st = nodes[0].state.lock();
            for (i, name) in [(1, "KNOWN_PEER"), (2, "MISSING_PEER")] {
                st.discovery_routes
                    .entry(sides[0])
                    .or_default()
                    .announcers
                    .insert(
                        name.into(),
                        Box::new(DiscoverySenderState {
                            advertised_address: Some(nodes[i].current_address()),
                            has_full_topology: true,
                            last_seen_ms: 1000,
                            ..DiscoverySenderState::default()
                        }),
                    );
            }
            st.discovery_side_throttle
                .entry(sides[0])
                .or_default()
                .next_schema_request_ms = 1000;
        }
        let initial = discovery::build_discovery_schema("KNOWN_PEER", 1000).unwrap();
        nodes[0]
            .learn_discovery_packet(&initial, Some(sides[0]), true)
            .unwrap();
        if legacy {
            let query = discovery::build_discovery_schema_request("OBSERVER", 1000).unwrap();
            nodes[0]
                .emit_internal_tx(
                    RouterTxItem::ToSide {
                        src: None,
                        dst: sides[0],
                        data: RouterItem::Packet(query),
                    },
                    true,
                    true,
                )
                .unwrap();
        } else {
            nodes[0].poll_discovery_announce().unwrap();
        }
        let mut completed = None;
        // Explicit deterministic finite budget:192 actual SDK bytes each150ms,
        // shared by all three senders; no carry/loan. Atomic link callbacks,
        // not a claim of modem packetization/physical500ms/Bay equivalence.
        for tick in (1000..=31000u64).step_by(150) {
            now.store(tick, Ordering::Relaxed);
            credit.store(192, Ordering::Relaxed);
            for _ in 0..12 {
                for node in &nodes {
                    node.drain_queues_with_timeout(0).unwrap();
                }
                let wire = core::mem::take(&mut *accepted.lock());
                if wire.is_empty() {
                    break;
                }
                for (from, _at, bytes) in wire {
                    for (to, node) in nodes.iter().enumerate() {
                        if to != from {
                            node.rx_packed_queue_from_side(&bytes, sides[to]).unwrap();
                        }
                    }
                }
            }
            if nodes[0].state.lock().discovery_routes[&sides[0]].announcers["MISSING_PEER"]
                .has_schema
            {
                completed = Some(tick);
                // Let the old broadcast control's other catalog finish too.
                if !nodes.iter().any(|node| node.has_queued_work()) {
                    break;
                }
            }
        }
        assert!(
            completed.is_some(),
            "legitimate missing catalog must fully assemble on finite192B medium"
        );
        let known_generations = nodes[1].state.lock().schema_response_sequence;
        if legacy {
            assert!(
                known_generations > 0,
                "old emptyrequest control must actually create redundant known catalog"
            );
        } else {
            assert_eq!(
                known_generations, 0,
                "validscope must not startknowncataloggeneration"
            );
        }
        let rows = history.lock();
        assert!(rows.iter().any(|&(from, _, _, _)| from == 2));
        assert!(rows.iter().all(|&(_, _, len, _)| len <= 192));
        for time in rows.iter().map(|v| v.1) {
            assert!(
                rows.iter()
                    .filter(|v| v.1 == time)
                    .map(|v| v.2)
                    .sum::<usize>()
                    <= 192
            );
        }
        println!(
            "FINITE_SCHEMA_RECOVERY {}",
            serde_json::json!({"legacy_empty_control":legacy,"missing_catalog_complete_ms":completed,"known_schema_generation_sequence":known_generations,"frames":rows.len(),"actual_bytes":rows.iter().map(|v|v.2).sum::<usize>(),"max_frame_bytes":192,"shared_bytes_per_150ms":192,"all_accepted_frames":&*rows})
        );
    }
}

#[test]
fn excluded_router_and_relay_still_forward_scoped_request_to_downstream_target() {
    crate::tests::ensure_common_test_schema();
    for relay_role in [false, true] {
        let (downstream, down_side, replies) =
            capture_node("DOWNSTREAM", Arc::new(AtomicU64::new(1000)));
        downstream
            .set_address_assignment(AddressAssignmentMode::Static(0x2222))
            .unwrap();
        let captured = Arc::new(RouterMutex::new(Vec::<Vec<u8>>::new()));
        let output = captured.clone();
        let request =
            discovery::build_scoped_discovery_schema_request("RECOVERER", 1000, &[0x2222]).unwrap();
        let wire = wire_format::pack_packet(&request);
        if relay_role {
            let transit = crate::relay::Relay::new_with_config(
                crate::relay::RelayConfig::new().with_sender("TRANSIT"),
                Box::new(|| 1000),
            );
            let source = transit.add_side_packed("upstream", |_| Ok(()));
            transit.add_side_packed("downstream", move |b| {
                output.lock().push(b.to_vec());
                Ok(())
            });
            transit.rx_packed_from_side(source, &wire).unwrap();
            transit.drain_queues_with_timeout(0).unwrap();
        } else {
            let transit = Router::new_with_clock(
                RouterConfig::new([]).with_sender("TRANSIT"),
                Box::new(|| 1000),
            );
            let source = transit.add_side_packed("upstream", |_| Ok(()));
            transit.add_side_packed("downstream", move |b| {
                output.lock().push(b.to_vec());
                Ok(())
            });
            transit.rx_packed_from_side(&wire, source).unwrap();
            transit.drain_queues_with_timeout(0).unwrap();
            assert_eq!(transit.state.lock().schema_response_sequence, 0);
        }
        let forwarded: Vec<_> = captured
            .lock()
            .iter()
            .map(|b| wire_format::unpack_packet(b).unwrap())
            .collect();
        assert_eq!(
            forwarded
                .iter()
                .filter(|p| p.data_type() == DataType::DiscoverySchemaRequest)
                .count(),
            1,
            "relay_role={relay_role}"
        );
        assert!(
            !forwarded
                .iter()
                .any(|p| p.data_type() == DataType::DiscoverySchema)
        );
        let query = forwarded
            .iter()
            .find(|p| p.data_type() == DataType::DiscoverySchemaRequest)
            .unwrap();
        assert_eq!(query.payload(), request.payload());
        downstream
            .rx_packed_from_side(&wire_format::pack_packet(query), down_side)
            .unwrap();
        downstream.drain_queues_with_timeout(0).unwrap();
        assert_eq!(
            replies
                .lock()
                .iter()
                .filter(|p| p.data_type() == DataType::DiscoverySchema)
                .count(),
            1
        );
    }
}

fn scope_addresses(bytes: &[u8]) -> Vec<u32> {
    (0..bytes.len() / 4)
        .map(|i| u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap()))
        .collect()
}

#[test]
fn throttle_boolean_flags_preserve_all_combinations_and_independent_state() {
    let getters: [fn(&DiscoverySideThrottleState) -> bool; 5] = [
        DiscoverySideThrottleState::schema_response_active,
        DiscoverySideThrottleState::schema_response_started,
        DiscoverySideThrottleState::schema_response_pending,
        DiscoverySideThrottleState::pending_incremental,
        DiscoverySideThrottleState::has_sent_full,
    ];
    let setters: [fn(&mut DiscoverySideThrottleState, bool); 5] = [
        DiscoverySideThrottleState::set_schema_response_active,
        DiscoverySideThrottleState::set_schema_response_started,
        DiscoverySideThrottleState::set_schema_response_pending,
        DiscoverySideThrottleState::set_pending_incremental,
        DiscoverySideThrottleState::set_has_sent_full,
    ];
    assert_eq!(DiscoverySideThrottleState::default().flags, 0);
    for reserved in [0, 0xe0] {
        for combination in 0u8..32 {
            let mut state = DiscoverySideThrottleState {
                flags: reserved,
                schema_request_cursor: 0x12345678,
                schema_response_phase: SchemaResponsePhase::Owned,
                incremental_retries_remaining: 7,
                next_schema_request_ms: 6000,
                next_schema_response_ms: 9000,
                ..Default::default()
            };
            for (i, set) in setters.iter().enumerate() {
                set(&mut state, combination & (1 << i) != 0);
            }
            assert_eq!(state.flags, reserved | combination);
            assert_eq!(state.clone().flags, state.flags);
            for (index, set) in setters.iter().enumerate() {
                for value in [false, true] {
                    let mut copy = state.clone();
                    set(&mut copy, value);
                    let expected = if value {
                        reserved | combination | (1 << index)
                    } else {
                        (reserved | combination) & !(1 << index)
                    };
                    assert_eq!(copy.flags, expected);
                    for (bit, get) in getters.iter().enumerate() {
                        assert_eq!(get(&copy), expected & (1 << bit) != 0);
                    }
                    assert_eq!(copy.schema_request_cursor, 0x12345678);
                    assert_eq!(copy.schema_response_phase, SchemaResponsePhase::Owned);
                    assert_eq!(copy.incremental_retries_remaining, 7);
                    assert_eq!(copy.next_schema_request_ms, 6000);
                    assert_eq!(copy.next_schema_response_ms, 9000);
                }
            }
        }
    }
}
