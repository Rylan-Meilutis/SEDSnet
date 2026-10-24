use super::*;
use std::sync::Mutex;
#[test]
fn packed_forwarding_and_reliable_replay_follow_side_capabilities() {
    crate::tests::ensure_common_test_schema();
    let endpoint = crate::DataEndpoint::named("RADIO");
    let ty = crate::config::register_data_type(
        "RELAY_CODEC_REPLAY",
        crate::MessageElement::Dynamic(crate::MessageDataType::Binary, crate::MessageClass::Data),
        &[endpoint],
        crate::ReliableMode::Unordered,
        10,
    )
    .unwrap();
    let packet = Packet::new(ty, &[endpoint], "SOURCE", 123, Arc::from(vec![b'A'; 4096])).unwrap();
    let packed = wire_format::pack_packet(&packet);
    assert_ne!(packed[0] & 1, 0);
    let output = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let capture = output.clone();
    let relay = Relay::new(Box::new(|| 100));
    let options = RelaySideOptions {
        reliable_enabled: true,
        ..RelaySideOptions::default()
    };
    let side = relay.add_side_packed_with_options(
        "wire",
        move |bytes| {
            capture.lock().unwrap().push(bytes.to_vec());
            Ok(())
        },
        options,
    );
    // Unknown peer: forwarding must transcode without knowing the dynamic schema.
    relay
        .send_reliable_to_side(
            side,
            RelayItem::Packed(crate::shared_bytes::convert(packed.clone())),
        )
        .unwrap();
    assert_eq!(output.lock().unwrap().last().unwrap()[0] & 1, 0);
    let retained = {
        let state = relay.state.lock();
        state.reliable_tx[&(side, ty.as_u32())]
            .sent
            .values()
            .next()
            .unwrap()
            .bytes
            .clone()
    };
    assert_eq!(retained[0] & 1, 0);
    let mut caps = RelaySideOptions::default().link_capabilities();
    caps.flags |= discovery::LINK_CAPABILITY_PAYLOAD_COMPRESSION;
    let ad = discovery::build_discovery_address(
        "PEER",
        100,
        &discovery::AddressAdvertisement {
            hostname: "PEER".into(),
            address: crate::packet::sender_address_u32("PEER"),
            requested_address: 0,
            mode: discovery::ADDRESS_MODE_STATIC,
            state: discovery::ADDRESS_STATE_APPROVED,
            birth_ms: 1,
            owner_hash: 3,
            reachable_endpoints: vec![endpoint],
            reachable_network_variables: vec![],
            reachable_timesync_sources: vec![],
            link_capabilities: caps,
        },
    )
    .unwrap();
    relay.rx_from_side(side, ad).unwrap();
    relay.process_rx_queue().unwrap();
    assert!(
        relay.state.lock().side_transport[&side]
            .payload_codec
            .allowed(100)
    );
    let handler = relay.state.lock().sides[side]
        .as_ref()
        .unwrap()
        .tx_handler
        .clone();
    relay
        .call_tx_handler(side, &handler, &RelayItem::Packed(retained.clone()))
        .unwrap();
    assert_ne!(output.lock().unwrap().last().unwrap()[0] & 1, 0);
    caps.flags &= !discovery::LINK_CAPABILITY_PAYLOAD_COMPRESSION;
    relay
        .rx_from_side(
            side,
            discovery::build_discovery_link_capabilities("PEER", 100, caps).unwrap(),
        )
        .unwrap();
    relay.process_rx_queue().unwrap();
    relay
        .call_tx_handler(side, &handler, &RelayItem::Packed(retained.clone()))
        .unwrap();
    assert_eq!(output.lock().unwrap().last().unwrap()[0] & 1, 0);
    let frames = output.lock().unwrap();
    let last = frames.last().unwrap();
    assert_eq!(
        wire_format::peek_routing_frame_info(last).unwrap().reliable,
        wire_format::peek_routing_frame_info(retained.as_ref())
            .unwrap()
            .reliable
    );
}

#[test]
fn optional_codec_ledger_is_reclaimed_before_relay_route_admission() {
    crate::tests::ensure_common_test_schema();
    let relay = Relay::new(Box::new(|| 100));
    let side = relay.add_side_packed("wire", |_| Ok(()));
    let mut caps = RelaySideOptions::default().link_capabilities();
    caps.flags |= discovery::LINK_CAPABILITY_PAYLOAD_COMPRESSION;
    for index in 0..32 {
        let name = alloc::format!("RELAY_CODEC_PEER_{index:03}");
        let packet = discovery::build_discovery_address(
            &name,
            100,
            &discovery::AddressAdvertisement {
                hostname: name.clone(),
                address: crate::packet::sender_address_u32(&name),
                requested_address: 0,
                mode: discovery::ADDRESS_MODE_STATIC,
                state: discovery::ADDRESS_STATE_APPROVED,
                birth_ms: 1,
                owner_hash: index + 1,
                reachable_endpoints: vec![crate::DataEndpoint::named("RADIO")],
                reachable_network_variables: vec![],
                reachable_timesync_sources: vec![],
                link_capabilities: caps,
            },
        )
        .unwrap();
        relay
            .learn_discovery_item(side, &RelayItem::Packet(Arc::new(packet)))
            .unwrap();
    }
    let mut state = relay.state.lock();
    let before = state.discovery_routes[&side].clone();
    let mut updated = before.clone();
    let template = updated.announcers.values().next().unwrap().clone();
    updated
        .announcers
        .insert("NEW_RELAY_REQUIRED_PEER".into(), template);
    let growth = RelayInner::discovery_route_byte_cost(&updated)
        - RelayInner::discovery_route_byte_cost(&before);
    let cached = state.side_transport[&side].payload_codec.heap_bytes();
    assert!(cached > growth);
    let used = state.shared_queue_bytes_used();
    state.memory.max_queue_budget = used - cached + growth + 1;
    assert!(used + growth > state.memory.max_queue_budget);
    state.commit_discovery_route(side, updated.clone()).unwrap();
    assert_eq!(state.discovery_routes[&side], updated);
    assert_eq!(state.side_transport[&side].payload_codec.heap_bytes(), 0);
    assert!(!state.side_transport[&side].payload_codec.allowed(100));
    assert!(!state.reclaim_codec_metadata());
    assert!(state.shared_queue_bytes_used() <= state.memory.max_queue_budget);
}
