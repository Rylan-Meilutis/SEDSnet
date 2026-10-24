//! Red regressions for transport-owned payload compression; standalone encoding stays explicit.
use super::*;
use std::sync::Mutex;
const PROPOSED_PAYLOAD_CODEC_CAPABILITY: u32 = 0x40;

fn data_packet() -> Packet {
    crate::tests::ensure_common_test_schema();
    let endpoint = DataEndpoint::named("RADIO");
    let ty = crate::config::register_data_type(
        "LINK_CODEC_NEGOTIATION_DATA",
        crate::MessageElement::Dynamic(crate::MessageDataType::Binary, crate::MessageClass::Data),
        &[endpoint],
        crate::ReliableMode::None,
        10,
    )
    .unwrap();
    Packet::new(ty, &[endpoint], "HOST", 123, Arc::from(vec![b'A'; 4096])).unwrap()
}
fn fixture(peers: &[(&str, Option<bool>)]) -> (Router, RouterSideId, Arc<Mutex<Vec<Vec<u8>>>>) {
    let output = Arc::new(Mutex::new(Vec::new()));
    let capture = output.clone();
    let node = Router::new_with_clock(RouterConfig::new([]).with_sender("HOST"), Box::new(|| 100));
    let side = node.add_side_packed_with_options(
        "shared",
        move |frame| {
            capture.lock().unwrap().push(frame.to_vec());
            Ok(())
        },
        RouterSideOptions::default(),
    );
    for (name, support) in peers {
        let packet = if let Some(supported) = support {
            let mut caps = RouterSideOptions::default().link_capabilities();
            caps.flags &= !PROPOSED_PAYLOAD_CODEC_CAPABILITY;
            if *supported {
                caps.flags |= PROPOSED_PAYLOAD_CODEC_CAPABILITY;
            }
            discovery::build_discovery_address(
                name,
                100,
                &discovery::AddressAdvertisement {
                    hostname: (*name).into(),
                    address: sender_address_u32(name),
                    requested_address: 0,
                    mode: discovery::ADDRESS_MODE_STATIC,
                    state: discovery::ADDRESS_STATE_APPROVED,
                    birth_ms: 1,
                    owner_hash: sender_address_u32(name) as u64,
                    reachable_endpoints: vec![DataEndpoint::named("RADIO")],
                    reachable_network_variables: vec![],
                    reachable_timesync_sources: vec![],
                    link_capabilities: caps,
                },
            )
            .unwrap()
        } else {
            discovery::build_discovery_announce(name, 100, &[DataEndpoint::named("RADIO")]).unwrap()
        };
        node.rx_from_side(&packet, side).unwrap();
    }
    output.lock().unwrap().clear();
    (node, side, output)
}
fn emit(node: &Router, side: RouterSideId, item: &RouterItem) {
    let handler = node.state.lock().sides[side]
        .as_ref()
        .unwrap()
        .tx_handler
        .clone();
    node.call_side_tx_handler(side, &handler, item, false)
        .unwrap();
}
fn is_compressed(output: &Arc<Mutex<Vec<Vec<u8>>>>) -> bool {
    let frames = output.lock().unwrap();
    assert!(!frames.is_empty());
    frames.last().unwrap()[0] & 1 != 0
}
#[test]
fn unknown_or_legacy_peer_requires_decodable_plain_payload_for_packet_and_packed_inputs() {
    let packet = data_packet();
    let standalone = crate::wire_format::pack_packet(&packet);
    assert_ne!(
        standalone[0] & 1,
        0,
        "standalone auto-compression is an intentional API"
    );
    for peers in [vec![], vec![("LEGACY", None)], vec![("MCU", Some(false))]] {
        for packed in [false, true] {
            let (node, side, output) = fixture(&peers);
            let item = if packed {
                RouterItem::Packed(crate::shared_bytes::convert(standalone.clone()))
            } else {
                RouterItem::Packet(packet.clone())
            };
            emit(&node, side, &item);
            assert!(
                !is_compressed(&output),
                "transport emitted optional codec to {peers:?}; packed={packed}"
            );
        }
    }
}
#[test]
fn one_capable_announcer_cannot_enable_compression_for_an_entire_shared_bus() {
    let packet = data_packet();
    for peers in [
        vec![("A_MCU", Some(false)), ("Z_HOST", Some(true))],
        vec![("A_HOST", Some(true)), ("Z_MCU", Some(false))],
        vec![("A_LEGACY", None), ("Z_HOST", Some(true))],
    ] {
        let (node, side, output) = fixture(&peers);
        emit(&node, side, &RouterItem::Packet(packet.clone()));
        assert!(
            !is_compressed(&output),
            "last/matching peer is not a side-wide permission: {peers:?}"
        );
    }
}
#[test]
fn warm_prepacked_data_must_follow_a_receiver_capability_downgrade() {
    let packet = data_packet();
    let item = RouterItem::Packed(crate::shared_bytes::convert(
        crate::wire_format::pack_packet(&packet),
    ));
    let (node, side, output) = fixture(&[("PEER", Some(true))]);
    emit(&node, side, &item);
    assert!(is_compressed(&output));
    let mut caps = RouterSideOptions::default().link_capabilities();
    caps.flags &= !PROPOSED_PAYLOAD_CODEC_CAPABILITY;
    node.rx_from_side(
        &discovery::build_discovery_link_capabilities("PEER", 100, caps).unwrap(),
        side,
    )
    .unwrap();
    emit(&node, side, &item);
    assert!(
        !is_compressed(&output),
        "queued/shared bytes cannot freeze a stale codec choice"
    );
}

#[test]
fn reliable_replay_retains_raw_canonical_data_and_preserves_sequence_on_downgrade() {
    for (suffix, mode) in [
        ("ORDERED", crate::ReliableMode::Ordered),
        ("UNORDERED", crate::ReliableMode::Unordered),
    ] {
        crate::tests::ensure_common_test_schema();
        let endpoint = DataEndpoint::named("RADIO");
        let ty = crate::config::register_data_type(
            &format!("CODEC_REPLAY_{suffix}"),
            crate::MessageElement::Dynamic(
                crate::MessageDataType::Binary,
                crate::MessageClass::Data,
            ),
            &[endpoint],
            mode,
            10,
        )
        .unwrap();
        let packet =
            Packet::new(ty, &[endpoint], "HOST", 123, Arc::from(vec![b'A'; 4096])).unwrap();
        let packed = crate::wire_format::pack_packet(&packet);
        assert_ne!(packed[0] & 1, 0);
        let (node, side, output) = fixture(&[("PEER", Some(true))]);
        node.state.lock().sides[side]
            .as_mut()
            .unwrap()
            .opts
            .reliable_enabled = true;
        node.send_reliable_to_side(
            side,
            RouterItem::Packed(crate::shared_bytes::convert(packed)),
            false,
        )
        .unwrap();
        assert!(is_compressed(&output));
        let retained = {
            let state = node.state.lock();
            state.reliable_tx[&(side, ty.as_u32())]
                .sent
                .values()
                .next()
                .unwrap()
                .bytes
                .clone()
        };
        assert_eq!(
            retained[0] & 1,
            0,
            "replay cache must not retain a transient codec choice"
        );
        let before = wire_format::peek_routing_frame_info(retained.as_ref()).unwrap();
        let mut caps = RouterSideOptions::default().link_capabilities();
        caps.flags &= !PROPOSED_PAYLOAD_CODEC_CAPABILITY;
        node.rx_from_side(
            &discovery::build_discovery_link_capabilities("PEER", 100, caps).unwrap(),
            side,
        )
        .unwrap();
        emit(&node, side, &RouterItem::Packed(retained.clone()));
        assert!(!is_compressed(&output));
        let frames = output.lock().unwrap();
        let last = frames.last().unwrap();
        let after = wire_format::peek_routing_frame_info(last).unwrap();
        assert_eq!(before.reliable, after.reliable);
        assert_eq!(
            crate::wire_format::unpack_packet(last).unwrap().payload(),
            packet.payload()
        );
    }
}

#[cfg(feature = "cryptography")]
#[test]
fn newly_sealed_router_payload_has_raw_inner_and_opaque_downgrade_is_explicit() {
    let packet = data_packet();
    let sealed_node = Router::new_with_clock(
        RouterConfig::default()
            .with_e2e_encryption(RouterE2eEncryptionMode::ForceAll)
            .with_e2e_key_id(0xC0DEC),
        Box::new(|| 100),
    );
    crate::crypto::register_software_key(0xC0DEC, b"0123456789abcdef0123456789abcdef").unwrap();
    let sealed = sealed_node.pack_packet_for_router(&packet, None).unwrap();
    assert_ne!(sealed[0] & 0x10, 0);
    assert_eq!(sealed[0] & 1, 0);
    let (node, side, output) = fixture(&[]);
    emit(&node, side, &RouterItem::Packed(sealed.clone()));
    assert!(!is_compressed(&output));
    let mut incompatible = sealed.as_ref().to_vec();
    incompatible[0] |= 1;
    // Opaque encrypted frames cannot be transcoded by a keyless forwarder.
    let before = output.lock().unwrap().len();
    let handler = node.state.lock().sides[side]
        .as_ref()
        .unwrap()
        .tx_handler
        .clone();
    assert!(
        node.call_side_tx_handler(
            side,
            &handler,
            &RouterItem::Packed(crate::shared_bytes::convert(Arc::<[u8]>::from(
                incompatible
            ))),
            false
        )
        .is_err()
    );
    assert_eq!(output.lock().unwrap().len(), before);
}

#[test]
fn required_downgrade_reserves_expanded_queue_credit_before_handler_dispatch() {
    let packet = data_packet();
    let bytes = crate::wire_format::pack_packet(&packet);
    let node = Arc::new(Router::new_with_clock(
        RouterConfig::new([]).with_sender("HOST"),
        Box::new(|| 100),
    ));
    let weak = Arc::downgrade(&node);
    let competing = packet.clone();
    let called = Arc::new(core::sync::atomic::AtomicBool::new(false));
    let callback_called = called.clone();
    let side = node.add_side_packed("unknown", move |_| {
        let owner = weak.upgrade().unwrap();
        let mut state = owner.state.lock();
        assert!(state.codec_reserved_bytes > 0);
        let queued = state.push_transmit(TxQueued {
            disposable: true,
            item: RouterTxItem::Broadcast(RouterItem::Packet(competing.clone())),
            ignore_local: true,
            priority: 10,
            delivery_state: QueuedDelivery::Untracked,
            accepted_type: 0,
            deferred_since_ms: 0,
            retry_after_ms: 0,
        });
        assert!(
            queued.is_err(),
            "callback spent retained owner's reserved expansion credit"
        );
        callback_called.store(true, core::sync::atomic::Ordering::Relaxed);
        Err(TelemetryError::Io("side tx busy"))
    });
    let mut item = RouterItem::Packed(crate::shared_bytes::convert(bytes.clone()));
    let needed = wire_format::decoded_frame_upper_bound(bytes.as_ref()).unwrap()
        + size_of::<crate::SharedBytes>()
        + size_of::<bool>()
        + size_of::<u8>()
        + size_of::<u64>();
    let baseline = node.state.lock().shared_queue_bytes_used();
    node.state.lock().memory.max_queue_budget = baseline + needed - 1;
    assert!(node.prepare_queued_payload(side, &mut item).is_err());
    assert!(matches!(&item,RouterItem::Packed(bytes) if bytes[0]&1!=0));
    assert_eq!(node.state.lock().codec_reserved_bytes, 0);
    node.state.lock().memory.max_queue_budget = baseline + needed + 64;
    let (result, mut reservation) = node.send_queued_to_side(side, &mut item, false);
    assert!(result.is_err());
    assert!(called.load(core::sync::atomic::Ordering::Relaxed));
    assert!(reservation.is_some());
    assert!(matches!(&item,RouterItem::Packed(bytes) if bytes[0]&1==0));
    {
        let state = node.state.lock();
        assert_eq!(state.codec_reserved_bytes, needed);
        assert!(state.shared_queue_bytes_used() <= state.memory.max_queue_budget);
    }
    node.retry_codec_owner(
        RouterTxItem::ToSide {
            src: None,
            dst: side,
            data: item,
        },
        true,
        &mut reservation,
    )
    .unwrap();
    let state = node.state.lock();
    assert_eq!(state.codec_reserved_bytes, 0);
    assert_eq!(state.transmit_queue.len(), 1);
    assert!(state.shared_queue_bytes_used() <= state.memory.max_queue_budget);
}

#[test]
fn optional_codec_ledger_is_discarded_before_required_route_admission() {
    let names: Vec<_> = (0..32)
        .map(|index| format!("CODEC_PEER_{index:03}"))
        .collect();
    let peers: Vec<_> = names
        .iter()
        .map(|name| (name.as_str(), Some(true)))
        .collect();
    let (node, side, _) = fixture(&peers);
    let mut state = node.state.lock();
    let before = state.discovery_routes[&side].clone();
    let mut updated = before.clone();
    let template = updated.announcers.values().next().unwrap().clone();
    updated
        .announcers
        .insert("NEW_REQUIRED_PEER".into(), template);
    let growth = RouterInner::discovery_route_byte_cost(side, &updated)
        - RouterInner::discovery_route_byte_cost(side, &before);
    let cached = state.side_transport[&side].payload_codec.heap_bytes();
    assert!(cached > growth);
    let used = state.shared_queue_bytes_used();
    state.memory.max_queue_budget = used - cached + growth + 1;
    assert!(used + growth > state.memory.max_queue_budget);
    state.commit_discovery_route(side, updated.clone()).unwrap();
    assert_eq!(state.discovery_routes[&side], updated);
    assert_eq!(state.side_transport[&side].payload_codec.heap_bytes(), 0);
    assert!(!state.side_transport[&side].payload_codec.allowed(100));
    assert!(
        !state.reclaim_codec_metadata(),
        "one cache eviction was sufficient"
    );
    assert!(state.shared_queue_bytes_used() <= state.memory.max_queue_budget);
}

#[test]
fn optional_codec_ledger_cannot_block_required_runtime_schema_growth() {
    let names: Vec<_> = (0..32)
        .map(|index| format!("SCHEMA_PEER_{index:03}"))
        .collect();
    let peers: Vec<_> = names
        .iter()
        .map(|name| (name.as_str(), Some(true)))
        .collect();
    let (node, side, _) = fixture(&peers);
    let snapshot = crate::config::OwnedRuntimeSchemaSnapshot {
        endpoints: vec![crate::config::OwnedEndpointDefinition {
            id: DataEndpoint(987_321),
            name: "CODEC_PRIORITY_SCHEMA_GROWTH".into(),
            description: "details".repeat(32),
            link_local_only: false,
        }],
        types: vec![],
    };
    let growth = crate::config::owned_schema_byte_cost(&snapshot);
    let packet =
        discovery::build_discovery_schema_from_owned_snapshot("SOURCE", 100, snapshot).unwrap();
    let before = {
        let mut state = node.state.lock();
        let cached = state.side_transport[&side].payload_codec.heap_bytes();
        assert!(cached > growth);
        let used = state.shared_queue_bytes_used();
        state.memory.max_queue_budget = used - cached + growth + 1;
        assert!(used + growth > state.memory.max_queue_budget);
        state.discovery_routes[&side].clone()
    };
    node.learn_discovery_packet(&packet, Some(side), false)
        .unwrap();
    let state = node.state.lock();
    assert_eq!(state.discovery_routes[&side], before);
    assert_eq!(state.side_transport[&side].payload_codec.heap_bytes(), 0);
    assert!(!state.side_transport[&side].payload_codec.allowed(100));
    assert!(state.shared_queue_bytes_used() <= state.memory.max_queue_budget);
}

#[test]
fn required_schema_workspace_retries_only_after_positive_codec_reclaim() {
    let (node, side, output) = fixture(&[("KNOWN_CAPABLE", Some(true))]);
    let before = node.state.lock().discovery_routes[&side].clone();
    let cached = node.state.lock().side_transport[&side]
        .payload_codec
        .heap_bytes();
    assert!(cached > 0);
    let malformed: TelemetryResult<u32> =
        node.decode_required_schema(|| Err(TelemetryError::Unpack("malformed catalog")));
    assert!(malformed.is_err());
    assert_eq!(
        node.state.lock().side_transport[&side]
            .payload_codec
            .heap_bytes(),
        cached
    );
    let mut attempts = 0;
    let decoded = node
        .decode_required_schema(|| {
            attempts += 1;
            if node.state.lock().side_transport[&side]
                .payload_codec
                .heap_bytes()
                != 0
            {
                Err(TelemetryError::Io("memory pressure"))
            } else {
                Ok(17)
            }
        })
        .unwrap();
    assert_eq!(decoded, 17);
    assert_eq!(attempts, 2);
    let state = node.state.lock();
    assert_eq!(state.discovery_routes[&side], before);
    assert!(!state.side_transport[&side].payload_codec.allowed(100));
    assert!(
        output.lock().unwrap().is_empty(),
        "cache reclamation broadcast discovery traffic"
    );
}
