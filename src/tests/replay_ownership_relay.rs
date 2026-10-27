use super::*;
fn hop_node() -> (Relay, RelaySideId, crate::DataType) {
    crate::tests::ensure_common_test_schema();
    let node = Relay::new(Box::new(|| 1000u64));
    let side = node.add_side_packed_with_options(
        "CAN",
        |_| Ok(()),
        RelaySideOptions {
            reliable_enabled: true,
            ..RelaySideOptions::default()
        },
    );
    node.clear_queues();
    let ty = crate::DataType::named("GPS_DATA");
    let packet = Packet::from_f32_slice(
        ty,
        &[1.0, 2.0, 3.0],
        &[crate::DataEndpoint::named("RADIO")],
        1,
    )
    .unwrap();
    node.core
        .send_reliable_to_side(side, RouterItem::Packet(packet), true)
        .unwrap();
    assert!(
        node.state.lock().reliable_tx[&Router::reliable_key(side, ty)]
            .sent
            .contains_key(&1)
    );
    (node, side, ty)
}
fn assert_replay_marker(node: &Relay, side: RelaySideId, ty: crate::DataType) {
    let state = node.state.lock();
    assert_eq!(state.transmit_queue.len(), 1);
    let marker = state.transmit_queue.iter().next().unwrap();
    assert!(
        matches!(&marker.item, RouterTxItem::ReliableReplay { dst, ty: found, seq: 1, bytes }
        if *dst == side && *found == ty && bytes == &state.reliable_tx[&Router::reliable_key(side, ty)].sent[&1].bytes)
    );
    assert!(state.reliable_tx[&Router::reliable_key(side, ty)].sent[&1].queued);
}
#[test]
fn refused_relay_hop_replay_does_not_pin_queued_flag() {
    let (node, side, ty) = hop_node();
    node.state.lock().transmit_queue = BoundedDeque::new(1, 1, 1.0);
    assert!(node.queue_reliable_retransmit(side, ty, 1, true).is_err());
    assert!(!node.state.lock().reliable_tx[&Router::reliable_key(side, ty)].sent[&1].queued);
    node.state.lock().transmit_queue = BoundedDeque::new(4096, 512, 1.25);
    node.queue_reliable_retransmit(side, ty, 1, true).unwrap();
    assert_replay_marker(&node, side, ty);
}
#[test]
fn evicted_relay_hop_replay_does_not_pin_queued_flag() {
    let (node, side, ty) = hop_node();
    node.queue_reliable_retransmit(side, ty, 1, true).unwrap();
    {
        let mut state = node.state.lock();
        assert!(state.pop_shared_queue_item(RouterQueueKind::Transmit));
        assert!(!state.reliable_tx[&Router::reliable_key(side, ty)].sent[&1].queued);
        assert!(
            state.reliable_tx[&Router::reliable_key(side, ty)]
                .sent
                .contains_key(&1)
        );
    }
    node.queue_reliable_retransmit(side, ty, 1, true).unwrap();
    assert_replay_marker(&node, side, ty);
}

#[test]
fn clearing_relay_replays_releases_reservations_without_losing_retained_delivery() {
    for all in [false, true] {
        let (node, side, ty) = hop_node();
        node.queue_reliable_retransmit(side, ty, 1, true).unwrap();
        if all {
            node.clear_queues()
        } else {
            node.clear_tx_queue()
        }
        assert!(node.state.lock().transmit_queue.is_empty());
        assert!(!node.state.lock().reliable_tx[&Router::reliable_key(side, ty)].sent[&1].queued);
        node.queue_reliable_retransmit(side, ty, 1, true).unwrap();
        assert_replay_marker(&node, side, ty);
    }
}
#[test]
fn disabled_relay_egress_does_not_pin_a_removed_retry_marker() {
    let (node, side, ty) = hop_node();
    node.queue_reliable_retransmit(side, ty, 1, true).unwrap();
    node.set_side_egress_enabled(side, false).unwrap();
    assert!(!node.state.lock().reliable_tx[&Router::reliable_key(side, ty)].sent[&1].queued);
    node.set_side_egress_enabled(side, true).unwrap();
    node.queue_reliable_retransmit(side, ty, 1, true).unwrap();
    assert_replay_marker(&node, side, ty);
}
