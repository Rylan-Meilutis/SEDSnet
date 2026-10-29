use super::*;

fn hop_node() -> (Router, RouterSideId, DataType) {
    crate::tests::ensure_common_test_schema();
    let node = Router::new_with_clock(RouterConfig::new([]), Box::new(|| 1000));
    let side = node.add_side_packed_with_options(
        "CAN",
        |_| Ok(()),
        RouterSideOptions {
            reliable_enabled: true,
            ..RouterSideOptions::default()
        },
    );
    node.clear_queues();
    let ty = DataType::named("GPS_DATA");
    let packet =
        Packet::from_f32_slice(ty, &[1.0, 2.0, 3.0], &[DataEndpoint::named("RADIO")], 1).unwrap();
    node.send_reliable_to_side(side, RouterItem::Packet(packet), false)
        .unwrap();
    assert!(
        node.state.lock().reliable_tx[&Router::reliable_key(side, ty)]
            .sent
            .contains_key(&1)
    );
    (node, side, ty)
}

#[test]
fn refused_router_hop_replay_does_not_pin_queued_flag() {
    let (node, side, ty) = hop_node();
    node.state.lock().transmit_queue = BoundedDeque::new(1, 1, 1.0);
    assert!(node.queue_reliable_retransmit(side, ty, 1, true).is_err());
    assert!(
        !node.state.lock().reliable_tx[&Router::reliable_key(side, ty)].sent[&1].queued,
        "a refused retry owns no queue entry and must remain eligible for retry"
    );
    node.state.lock().transmit_queue = BoundedDeque::new(4096, 512, 1.25);
    node.queue_reliable_retransmit(side, ty, 1, true).unwrap();
    assert_eq!(node.state.lock().transmit_queue.len(), 1);
}

#[test]
fn evicted_router_hop_replay_does_not_pin_queued_flag() {
    let (node, side, ty) = hop_node();
    node.queue_reliable_retransmit(side, ty, 1, true).unwrap();
    {
        let mut state = node.state.lock();
        assert!(state.pop_shared_queue_item(RouterQueueKind::Transmit));
        assert!(
            !state.reliable_tx[&Router::reliable_key(side, ty)].sent[&1].queued,
            "shared-budget eviction must release the retry marker, not its retained payload"
        );
        assert!(
            state.reliable_tx[&Router::reliable_key(side, ty)]
                .sent
                .contains_key(&1)
        );
    }
    node.queue_reliable_retransmit(side, ty, 1, true).unwrap();
    assert_eq!(node.state.lock().transmit_queue.len(), 1);
}

fn end_to_end_node() -> (Router, u64) {
    crate::tests::ensure_common_test_schema();
    let node = Router::new_with_clock(RouterConfig::new([]), Box::new(|| 1000));
    node.clear_queues();
    let packet = Packet::new_with_wire_contract(
        DataType::named("GPS_DATA"),
        &[DataEndpoint::named("RADIO")],
        "publisher",
        1,
        1,
        Arc::<[u8]>::from([0; 12]),
        None,
        Arc::from([1u64]),
    )
    .unwrap();
    let id = packet.packet_id();
    node.register_end_to_end_reliable_tx(
        &RouterItem::Packet(packet),
        Some(BTreeMap::from([(1, 0)])),
    )
    .unwrap();
    (node, id)
}

#[test]
fn evicted_end_to_end_replay_does_not_pin_queued_flag() {
    let (node, id) = end_to_end_node();
    node.queue_end_to_end_reliable_retransmit(id).unwrap();
    {
        let mut state = node.state.lock();
        assert!(state.pop_shared_queue_item(RouterQueueKind::Transmit));
        assert!(
            !state.end_to_end_reliable_tx[&id].queued,
            "retained delivery must recover after its control marker was evicted"
        );
    }
    node.queue_end_to_end_reliable_retransmit(id).unwrap();
    assert_eq!(node.state.lock().transmit_queue.len(), 1);
}

#[test]
fn ring_slot_eviction_releases_end_to_end_replay_marker() {
    let (node, id) = end_to_end_node();
    node.state.lock().transmit_queue = BoundedDeque::new(512, 1, 1.0);
    node.queue_end_to_end_reliable_retransmit(id).unwrap();
    let ack = Packet::new(
        DataType::ReliableAck,
        message_meta(DataType::ReliableAck).endpoints_ref(),
        "E2EACK:peer",
        1,
        Arc::<[u8]>::from([0; 8]),
    )
    .unwrap();
    let mut state = node.state.lock();
    state
        .push_transmit(TxQueued {
            disposable: TX_DISPOSABLE,
            item: RouterTxItem::ToSide {
                src: None,
                dst: 0,
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
    assert!(
        !state.end_to_end_reliable_tx[&id].queued,
        "fixed ring capacity may evict a replay even when the shared byte budget has room"
    );
}

#[test]
fn evicted_timer_marker_does_not_spend_retry_budget_on_every_poll() {
    let (node, id) = end_to_end_node();
    node.state
        .lock()
        .end_to_end_reliable_tx
        .get_mut(&id)
        .unwrap()
        .last_send_ms = 0;
    node.queue_end_to_end_reliable_retransmit(id).unwrap();
    for _ in 0..32 {
        node.state
            .lock()
            .pop_shared_queue_item(RouterQueueKind::Transmit);
        node.process_end_to_end_reliable_timeouts().unwrap();
    }
    let state = node.state.lock();
    assert!(
        state.end_to_end_reliable_tx.contains_key(&id),
        "queue eviction is not repeated wire delivery failure"
    );
    assert_eq!(
        state.end_to_end_reliable_tx[&id].retries, 0,
        "a successful marker reservation starts one retry interval even if subsequently evicted"
    );
}

#[test]
fn clearing_router_replays_releases_reservations_without_losing_retained_delivery() {
    for all in [false, true] {
        let (node, id) = end_to_end_node();
        node.queue_end_to_end_reliable_retransmit(id).unwrap();
        if all {
            node.clear_queues()
        } else {
            node.clear_tx_queue()
        }
        assert!(node.state.lock().transmit_queue.is_empty());
        assert!(!node.state.lock().end_to_end_reliable_tx[&id].queued);
        node.queue_end_to_end_reliable_retransmit(id).unwrap();
        assert_eq!(node.state.lock().transmit_queue.len(), 1);
    }
}
#[test]
fn disabled_router_egress_does_not_pin_a_removed_retry_marker() {
    let (node, side, ty) = hop_node();
    node.queue_reliable_retransmit(side, ty, 1, true).unwrap();
    node.set_side_egress_enabled(side, false).unwrap();
    assert!(!node.state.lock().reliable_tx[&Router::reliable_key(side, ty)].sent[&1].queued);
    node.set_side_egress_enabled(side, true).unwrap();
    node.queue_reliable_retransmit(side, ty, 1, true).unwrap();
    assert_eq!(node.state.lock().transmit_queue.len(), 1);
}

#[test]
fn accepted_original_contract_survives_control_eviction_before_first_dispatch() {
    crate::tests::ensure_common_test_schema();
    for packed in [false, true] {
        let node = Router::new_with_clock(RouterConfig::new([]), Box::new(|| 1000));
        node.clear_queues();
        node.state.lock().transmit_queue = BoundedDeque::new(512, 1, 1.0);
        let packet = Packet::new_with_wire_contract(
            DataType::named("GPS_DATA"),
            &[DataEndpoint::named("RADIO")],
            "publisher",
            1,
            1,
            Arc::<[u8]>::from([0; 12]),
            None,
            Arc::from([1u64]),
        )
        .unwrap();
        let id = packet.packet_id();
        if packed {
            node.tx_packed_queue(wire_format::pack_packet(&packet))
                .unwrap();
        } else {
            node.tx_queue(packet).unwrap();
        }
        let ack = Packet::new(
            DataType::ReliableAck,
            message_meta(DataType::ReliableAck).endpoints_ref(),
            "E2EACK:peer",
            1,
            Arc::<[u8]>::from([0; 8]),
        )
        .unwrap();
        let control_result = node.tx_queue_item_with_priority(
            RouterTxItem::ToSide {
                src: None,
                dst: 0,
                data: RouterItem::Packet(ack),
            },
            true,
            255,
        );
        // A control may be backpressured if the only slot owns reliable data.
        let _ = control_result;
        let state = node.state.lock();
        let still_queued = state.transmit_queue.iter().any(|q| match &q.item {
            RouterTxItem::Broadcast(d) | RouterTxItem::ToSide { data: d, .. } => {
                Router::get_hash(d) == id
            }
            _ => false,
        });
        assert!(
            still_queued || state.end_to_end_reliable_tx.contains_key(&id),
            "accepted original must remain owned until delivery; packed={packed}"
        );
    }
}

#[test]
fn control_admission_reclaims_best_effort_before_an_accepted_reliable_original() {
    crate::tests::ensure_common_test_schema();
    for packed in [false, true] {
        let node = Router::new_with_clock(RouterConfig::new([]), Box::new(|| 1000));
        node.clear_queues();
        node.state.lock().transmit_queue = BoundedDeque::new(1024, 2 * size_of::<TxQueued>(), 1.0);
        let original = Packet::new_with_wire_contract(
            DataType::named("GPS_DATA"),
            &[DataEndpoint::named("RADIO")],
            "publisher",
            1,
            1,
            Arc::<[u8]>::from([0; 12]),
            None,
            Arc::from([1u64]),
        )
        .unwrap();
        let id = original.packet_id();
        if packed {
            node.tx_packed_queue(wire_format::pack_packet(&original))
                .unwrap();
        } else {
            node.tx_queue(original).unwrap();
        }
        let disposable = Packet::from_f32_slice(
            DataType::named("BAROMETER_DATA"),
            &[1.0, 2.0, 3.0],
            &[DataEndpoint::named("RADIO")],
            2,
        )
        .unwrap();
        // Place disposable work ahead of the reliable original, so choosing
        // the queue tail would discard the only owner of accepted data.
        node.tx_queue_item_with_priority(
            RouterTxItem::Broadcast(RouterItem::Packet(disposable)),
            true,
            200,
        )
        .unwrap();
        let ack = Packet::new(
            DataType::ReliableAck,
            message_meta(DataType::ReliableAck).endpoints_ref(),
            "E2EACK:peer",
            3,
            Arc::<[u8]>::from([0; 8]),
        )
        .unwrap();
        node.tx_queue_item_with_priority(
            RouterTxItem::ToSide {
                src: None,
                dst: 0,
                data: RouterItem::Packet(ack),
            },
            true,
            255,
        )
        .unwrap();
        let state = node.state.lock();
        assert_eq!(state.transmit_queue.len(), 2);
        assert!(state.transmit_queue.iter().any(|q| matches!(&q.item,
            RouterTxItem::Broadcast(data) if Router::get_hash(data)==id)));
    }
}

#[test]
fn shared_budget_backpressures_instead_of_discarding_the_only_reliable_owner() {
    crate::tests::ensure_common_test_schema();
    let node = Router::new_with_clock(RouterConfig::new([]), Box::new(|| 1000));
    node.clear_queues();
    let original = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0, 2.0, 3.0],
        &[DataEndpoint::named("RADIO")],
        1,
    )
    .unwrap();
    let id = original.packet_id();
    node.tx_queue(original).unwrap();
    let mut state = node.state.lock();
    state.memory.max_queue_budget = state.shared_queue_bytes_used();
    assert!(state.make_shared_queue_room(1, 255, None).is_err());
    assert_eq!(state.transmit_queue.len(), 1);
    assert!(matches!(&state.transmit_queue.iter().next().unwrap().item,
        RouterTxItem::Broadcast(data) if Router::get_hash(data)==id));
    assert!(state.shared_queue_bytes_used() <= state.memory.max_queue_budget);
}
