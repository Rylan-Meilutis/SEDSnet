use super::*;
use core::sync::atomic::{AtomicU64, Ordering};

fn fixture() -> (Router, usize, usize, Arc<AtomicU64>) {
    crate::tests::ensure_common_test_schema();
    let time = Arc::new(AtomicU64::new(1000));
    let read = time.clone();
    let node = Router::new_with_clock(
        RouterConfig::new([]).with_sender("bridge-under-test"),
        Box::new(move || read.load(Ordering::Relaxed)),
    );
    let a = node.add_side_packed("shared-can", |_| Ok(()));
    let b = node.add_side_packed("uplink", |_| Ok(()));
    node.clear_queues();
    route(&node, a, "DAQ");
    route(&node, a, "VB");
    (node, a, b, time)
}
fn route(node: &Router, side: usize, name: &str) {
    let now = node.clock.now_ms();
    let mut st = node.state.lock();
    let entry = st.discovery_routes.entry(side).or_default();
    entry.announcers.insert(
        name.into(),
        Box::new(DiscoverySenderState {
            last_seen_ms: now,
            advertised_address: Some(sender_address_u32(name)),
            ..Default::default()
        }),
    );
    Router::recompute_discovery_side_state(entry);
}
fn wire(targets: &[&str], reliable: Option<wire_format::ReliableHeader>) -> Arc<[u8]> {
    let ty = DataType::try_named("BATTERY_STATUS").unwrap();
    let packet = Packet::new(
        ty,
        &[DataEndpoint::try_named("SD_CARD").unwrap()],
        "VB",
        1000,
        Arc::from([0u8; 8]),
    )
    .unwrap();
    wire_format::pack_packet_with_wire_contract(
        &packet,
        reliable,
        Some(crate::message_meta(ty).element),
        &targets
            .iter()
            .map(|s| Router::sender_hash(s))
            .collect::<Vec<_>>(),
    )
    .unwrap()
}
#[test]
fn overheard_frozen_holder_keeps_liveness_without_copy_or_rx_queue_slot() {
    let (node, a, _, time) = fixture();
    let bytes = wire(&["DAQ"], None);
    time.store(2000, Ordering::Relaxed);
    assert!(
        node.decode_side_transport_frame(a, &bytes)
            .unwrap()
            .is_none()
    );
    node.rx_packed_queue_from_side(&bytes, a).unwrap();
    let st = node.state.lock();
    assert_eq!(st.received_queue.len(), 0);
    assert_eq!(st.discovery_routes[&a].announcers["VB"].last_seen_ms, 2000);
    assert!(st.reliable_return_routes.is_empty());
}
#[test]
fn unknown_mixed_local_or_alternate_holders_keep_normal_receive() {
    let (node, a, b, _) = fixture();
    for targets in [
        &["unknown"][..],
        &["DAQ", "unknown"][..],
        &["bridge-under-test"][..],
    ] {
        assert!(
            node.decode_side_transport_frame(a, &wire(targets, None))
                .unwrap()
                .is_some()
        );
    }
    route(&node, b, "DAQ");
    assert!(
        node.decode_side_transport_frame(a, &wire(&["DAQ"], None))
            .unwrap()
            .is_some()
    );
}
#[test]
fn stale_routes_managed_values_and_explicit_policy_keep_normal_receive() {
    let (node, a, b, time) = fixture();
    let bytes = wire(&["DAQ"], None);
    time.store(1000 + DISCOVERY_ROUTE_TTL_MS + 1, Ordering::Relaxed);
    assert!(
        node.decode_side_transport_frame(a, &bytes)
            .unwrap()
            .is_some()
    );
    route(&node, a, "DAQ");
    let ty = DataType::try_named("BATTERY_STATUS").unwrap();
    node.state
        .lock()
        .local_services
        .as_mut()
        .unwrap()
        .managed_variable_types
        .insert(ty.as_u32());
    assert!(
        node.decode_side_transport_frame(a, &bytes)
            .unwrap()
            .is_some()
    );
    node.state
        .lock()
        .local_services
        .as_mut()
        .unwrap()
        .managed_variable_types
        .clear();
    node.state.lock().route_overrides.insert((Some(a), b), true);
    assert!(
        node.decode_side_transport_frame(a, &bytes)
            .unwrap()
            .is_some()
    );
}
#[test]
fn hop_reliability_and_corrupt_frames_are_not_silently_consumed() {
    let (node, a, _, _) = fixture();
    let bytes = wire(
        &["DAQ"],
        Some(wire_format::ReliableHeader {
            seq: 1,
            ack: 0,
            flags: 0,
        }),
    );
    assert!(
        node.decode_side_transport_frame(a, &bytes)
            .unwrap()
            .is_some()
    );
    let mut corrupt = wire(&["DAQ"], None).to_vec();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert!(wire_format::peek_routing_frame_info(&corrupt).is_err());
    // Canonical ingress defers malformed application CRC rejection to normal
    // dispatch. The optimization must not consume it as a valid overheard frame.
    assert_eq!(
        node.decode_side_transport_frame(a, &corrupt)
            .unwrap()
            .unwrap()
            .as_ref(),
        corrupt
    );
}

#[test]
fn runtime_added_schema_and_unsequenced_reliable_data_remain_dynamic() {
    let (node, a, _, _) = fixture();
    let element = crate::MessageElement::Static(
        1,
        crate::MessageDataType::Float32,
        crate::MessageClass::Data,
    );
    let ty = crate::config::register_data_type_with_description(
        "INGRESS_RUNTIME_PRESSURE_PROBE",
        "runtime-only schema",
        element,
        &[DataEndpoint::try_named("SD_CARD").unwrap()],
        crate::ReliableMode::Unordered,
        1,
    )
    .unwrap();
    let packet = Packet::new(
        ty,
        &[DataEndpoint::try_named("SD_CARD").unwrap()],
        "VB",
        1000,
        Arc::from([0u8; 4]),
    )
    .unwrap();
    let bytes = wire_format::pack_packet_with_wire_contract(
        &packet,
        Some(wire_format::ReliableHeader {
            seq: 0,
            ack: 0,
            flags: wire_format::RELIABLE_FLAG_UNSEQUENCED,
        }),
        Some(element),
        &[Router::sender_hash("DAQ")],
    )
    .unwrap();
    assert!(
        node.decode_side_transport_frame(a, &bytes)
            .unwrap()
            .is_none()
    );
    crate::config::remove_data_type(ty).unwrap();
    assert!(
        node.decode_side_transport_frame(a, &bytes)
            .unwrap()
            .is_some()
    );
}

#[test]
fn known_discovery_checks_crc_once_and_preserves_liveness_and_rejection() {
    let (node, side, _, time) = fixture();
    let boards = vec![TopologyBoardNode {
        sender_id: "DAQ".into(),
        reachable_endpoints: vec![DataEndpoint::named("SD_CARD")],
        reachable_timesync_sources: vec![],
        connections: vec![],
    }];
    {
        let mut state = node.state.lock();
        let route = state.discovery_routes.get_mut(&side).unwrap();
        route.announcers.get_mut("DAQ").unwrap().topology_boards = Arc::new(boards.clone());
        Router::recompute_discovery_side_state(route);
    }
    let packet = discovery::build_discovery_topology("DAQ", 2000, &boards).unwrap();
    let bytes = wire_format::pack_packet(&packet);
    time.store(2000, Ordering::Relaxed);
    let before = wire_format::crc_verification_count();
    assert!(
        node.decode_side_transport_frame(side, &bytes)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        wire_format::crc_verification_count() - before,
        1,
        "known discovery must not hash the same frame again for liveness"
    );
    assert_eq!(
        node.state.lock().discovery_routes[&side].announcers["DAQ"].last_seen_ms,
        2000
    );
    let mut corrupt = bytes.to_vec();
    let index = corrupt.len() - 1;
    corrupt[index] ^= 1;
    time.store(3000, Ordering::Relaxed);
    assert!(node.decode_side_transport_frame(side, &corrupt).is_err());
    assert_eq!(
        node.state.lock().discovery_routes[&side].announcers["DAQ"].last_seen_ms,
        2000,
        "corrupt discovery cannot keep a route alive"
    );
}
