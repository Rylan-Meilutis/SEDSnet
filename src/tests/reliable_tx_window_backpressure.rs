use super::*;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
#[test]
fn accepted_queued_reliable_packet_waits_for_window_credit_without_repeating_local_handler() {
    for ordered in [false, true] {
        for packed in [false, true] {
            for route_churn in [false, true] {
                check_window_credit(ordered, packed, route_churn);
            }
        }
    }
}
fn check_window_credit(ordered: bool, packed: bool, route_churn: bool) {
    crate::tests::ensure_common_test_schema();
    let remote = crate::config::register_endpoint_with_description(
        &format!("WINDOW_REMOTE_{ordered}_{packed}"),
        "",
        false,
    )
    .unwrap();
    let local = crate::config::register_endpoint_with_description(
        &format!("WINDOW_LOCAL_{ordered}_{packed}"),
        "",
        false,
    )
    .unwrap();
    let ty = crate::config::register_data_type_with_description(
        &format!("WINDOW_ACCEPTED_BATCH_{ordered}_{packed}"),
        "",
        MessageElement::Static(44, crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[remote, local],
        if ordered {
            crate::ReliableMode::Ordered
        } else {
            crate::ReliableMode::Unordered
        },
        0,
    )
    .unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = hits.clone();
    let time = Arc::new(AtomicU64::new(1000));
    let clock = time.clone();
    let node = Router::new_with_clock(
        RouterConfig::new([EndpointHandler::new_packet_handler(local, move |_| {
            seen.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })])
        .with_sender("publisher"),
        Box::new(move || clock.load(Ordering::Relaxed)),
    );
    let wanted = Arc::new(AtomicU64::new(0));
    let wanted_wire = wanted.clone();
    let output = Arc::new(std::sync::Mutex::new(Vec::new()));
    let out = output.clone();
    let side = node.add_side_packed("CAN", move |bytes| {
        if wire_format::peek_routing_envelope(bytes).is_ok_and(|env| env.ty == ty)
            && wire_format::packet_id_from_wire(bytes)
                .is_ok_and(|id| id == wanted_wire.load(Ordering::Relaxed))
        {
            out.lock().unwrap().push(bytes.to_vec());
        }
        Ok(())
    });
    node.clear_queues();
    let owner = Router::sender_hash("sink");
    {
        let mut st = node.state.lock();
        let route = st.discovery_routes.entry(side).or_default();
        route.announcers.insert(
            "sink".into(),
            DiscoverySenderState {
                last_seen_ms: 1000,
                advertised_address: Some(sender_address_u32("sink")),
                reachable: vec![remote],
                advertised_reachable: vec![remote],
                topology_boards: Arc::new(vec![TopologyBoardNode {
                    sender_id: "sink".into(),
                    reachable_endpoints: vec![remote],
                    reachable_timesync_sources: vec![],
                    connections: vec![],
                }]),
                has_full_topology: true,
                has_schema: true,
                ..Default::default()
            },
        );
        Router::recompute_discovery_side_state(route);
    }
    let mut predecessors = Vec::new();
    for n in 0..runtime_reliable_max_end_to_end_pending().max(1) {
        let packet = Packet::new_with_wire_contract(
            ty,
            &[remote, local],
            "publisher",
            n as u64 + 1,
            u16::try_from(n + 1).unwrap(),
            Arc::<[u8]>::from([1u8; 44]),
            None,
            Arc::from([owner]),
        )
        .unwrap();
        predecessors.push(packet.packet_id());
        node.register_end_to_end_reliable_tx(
            &RouterItem::Packet(packet),
            Some(BTreeMap::from([(owner, side)])),
        )
        .unwrap();
    }
    assert_eq!(
        node.state.lock().end_to_end_reliable_tx.len(),
        runtime_reliable_max_end_to_end_pending().max(1)
    );
    // The frozen retry must keep the canonical logical identity even when
    // callers supplied duplicate endpoints in a different order.
    let packet = Packet::new(
        ty,
        &[local, remote, local],
        "publisher",
        10000,
        Arc::<[u8]>::from([42u8; 44]),
    )
    .unwrap();
    let id = packet.packet_id();
    wanted.store(id, Ordering::Relaxed);
    assert!(
        node.should_route_remote(&RouterItem::Packet(packet.clone()), None)
            .unwrap()
    );
    if packed {
        node.tx_packed_queue(wire_format::pack_packet(&packet))
            .unwrap();
    } else {
        node.tx_queue(packet).unwrap();
    }
    node.process_tx_queue().expect(
        "accepted queued data must wait for an ACK, not be lost when the reliable window is full",
    );
    assert_eq!(hits.load(Ordering::Relaxed), 1);
    assert!(output.lock().unwrap().is_empty());
    assert_eq!(node.state.lock().transmit_queue.len(), 1);
    assert!(!node.state.lock().recent_rx.contains(&id));
    if route_churn {
        let mut state = node.state.lock();
        let route = state.discovery_routes.get_mut(&side).unwrap();
        let mut newcomer = route.announcers.get("sink").unwrap().clone();
        newcomer.advertised_address = Some(sender_address_u32("new_sink"));
        newcomer.topology_boards = Arc::new(vec![TopologyBoardNode {
            sender_id: "new_sink".into(),
            reachable_endpoints: vec![remote],
            reachable_timesync_sources: vec![],
            connections: vec![],
        }]);
        route.announcers.insert("new_sink".into(), newcomer);
        Router::recompute_discovery_side_state(route);
    }
    let release = |oldest: u64| {
        let ack = Packet::new_with_wire_contract(
            DataType::ReliableAck,
            message_meta(DataType::ReliableAck).endpoints_ref(),
            "E2EACK:sink",
            1000,
            1,
            Arc::<[u8]>::from(oldest.to_le_bytes()),
            None,
            Arc::from([owner, Router::sender_hash("publisher")]),
        )
        .unwrap();
        node.rx_from_side(&ack, side).unwrap();
        time.store(1002, Ordering::Relaxed);
        node.process_tx_queue().unwrap();
    };
    release(predecessors[0]);
    if ordered {
        assert!(
            output.lock().unwrap().is_empty(),
            "ordered tail must wait for every earlier unconfirmed packet"
        );
        for &oldest in &predecessors[1..] {
            release(oldest);
        }
    }
    assert_eq!(
        hits.load(Ordering::Relaxed),
        1,
        "retry cannot reapply a local actuator or variable handler"
    );
    {
        let state = node.state.lock();
        let pending = &state
            .end_to_end_reliable_tx
            .get(&id)
            .unwrap()
            .pending_destinations;
        assert_eq!(
            pending.keys().copied().collect::<Vec<_>>(),
            vec![owner],
            "route discovery must not add receipt owners outside the frozen wire cohort"
        );
    }
    let frames = output.lock().unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(wire_format::packet_id_from_wire(&frames[0]).unwrap(), id);
    assert!(
        node.state.lock().end_to_end_reliable_tx.contains_key(&id),
        "ordered={ordered} packed={packed}; pending={:?}",
        node.state
            .lock()
            .end_to_end_reliable_tx
            .keys()
            .collect::<Vec<_>>()
    );
}

#[test]
fn accepted_hop_reliable_queue_waits_for_ack_credit() {
    for ordered in [false, true] {
        for packed in [false, true] {
            crate::tests::ensure_common_test_schema();
            let ep = crate::config::register_endpoint_with_description(
                &format!("HOP_WINDOW_{ordered}_{packed}"),
                "",
                false,
            )
            .unwrap();
            let ty = crate::config::register_data_type_with_description(
                &format!("HOP_BATCH_{ordered}_{packed}"),
                "",
                MessageElement::Static(
                    44,
                    crate::MessageDataType::UInt8,
                    crate::MessageClass::Data,
                ),
                &[ep],
                if ordered {
                    crate::ReliableMode::Ordered
                } else {
                    crate::ReliableMode::Unordered
                },
                0,
            )
            .unwrap();
            let time = Arc::new(AtomicU64::new(1000));
            let clock = time.clone();
            let hits = Arc::new(AtomicUsize::new(0));
            let local = hits.clone();
            let node = Router::new_with_clock(
                RouterConfig::new([EndpointHandler::new_packet_handler(ep, move |_| {
                    local.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                })]),
                Box::new(move || clock.load(Ordering::Relaxed)),
            );
            let wanted = Arc::new(AtomicU64::new(0));
            let wanted_wire = wanted.clone();
            let frames = Arc::new(std::sync::Mutex::new(Vec::new()));
            let output = frames.clone();
            let side = node.add_side_packed_with_options(
                "CAN",
                move |bytes| {
                    if wire_format::packet_id_from_wire(bytes)
                        .is_ok_and(|id| id == wanted_wire.load(Ordering::Relaxed))
                    {
                        output.lock().unwrap().push(bytes.to_vec());
                    }
                    Ok(())
                },
                RouterSideOptions {
                    reliable_enabled: true,
                    header_template_enabled: false,
                    ..Default::default()
                },
            );
            node.clear_queues();
            for n in 0..runtime_reliable_max_pending() {
                let packet = Packet::new(
                    ty,
                    &[ep],
                    "source",
                    n as u64 + 1,
                    Arc::<[u8]>::from([1u8; 44]),
                )
                .unwrap();
                node.send_reliable_to_side(side, RouterItem::Packet(packet), false)
                    .unwrap();
            }
            let packet =
                Packet::new(ty, &[ep], "source", 10000, Arc::<[u8]>::from([42u8; 44])).unwrap();
            let id = packet.packet_id();
            wanted.store(id, Ordering::Relaxed);
            let data = if packed {
                RouterItem::Packed(crate::shared_bytes::convert(wire_format::pack_packet(
                    &packet,
                )))
            } else {
                RouterItem::Packet(packet)
            };
            node.tx_queue_item_with_flags(
                RouterTxItem::ToSide {
                    src: None,
                    dst: side,
                    data,
                },
                false,
            )
            .unwrap();
            node.process_tx_queue()
                .expect("hop history pressure must preserve an accepted queue item");
            assert!(frames.lock().unwrap().is_empty());
            assert_eq!(hits.load(Ordering::Relaxed), 1);
            assert_eq!(node.state.lock().transmit_queue.len(), 1);
            node.rx_packed_queue_from_side(
                &wire_format::pack_reliable_ack("sink", ty, 1000, 1),
                side,
            )
            .unwrap();
            time.store(1002, Ordering::Relaxed);
            node.process_tx_queue().unwrap();
            assert_eq!(frames.lock().unwrap().len(), 1);
            assert_eq!(hits.load(Ordering::Relaxed), 1);
            assert_eq!(
                node.state.lock().reliable_tx[&(side, ty.as_u32())]
                    .sent
                    .len(),
                runtime_reliable_max_pending()
            );
        }
    }
}

#[test]
fn attaching_a_contract_preserves_an_existing_packet_or_packed_cohort() {
    crate::tests::ensure_common_test_schema();
    let ep = DataEndpoint::named("RADIO");
    let ty = DataType::named("GPS_DATA");
    let owner = Router::sender_hash("original_owner");
    let shape =
        MessageElement::Static(12, crate::MessageDataType::UInt8, crate::MessageClass::Data);
    let packet = Packet::new_with_wire_contract(
        ty,
        &[ep],
        "publisher",
        1000,
        1,
        Arc::<[u8]>::from([0u8; 12]),
        Some(shape),
        Arc::from([owner]),
    )
    .unwrap();
    let id = packet.packet_id();
    let router = Router::new(RouterConfig::new([]));
    for packed in [false, true] {
        let item = if packed {
            RouterItem::Packed(crate::shared_bytes::convert(wire_format::pack_packet(
                &packet,
            )))
        } else {
            RouterItem::Packet(packet.clone())
        };
        let RouterItem::Packed(bytes) = router
            .attach_wire_contract_to_item(item, &[Router::sender_hash("new_owner")])
            .unwrap()
        else {
            panic!("expected canonical wire");
        };
        assert_eq!(
            wire_format::peek_routing_envelope(&bytes)
                .unwrap()
                .target_senders()
                .collect::<Vec<_>>(),
            vec![owner]
        );
        assert_eq!(wire_format::packet_id_from_wire(&bytes).unwrap(), id);
        assert_eq!(
            wire_format::peek_routing_envelope(&bytes)
                .unwrap()
                .wire_shape,
            Some(shape)
        );
    }
}
