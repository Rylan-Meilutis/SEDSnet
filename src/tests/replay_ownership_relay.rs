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
    node.send_reliable_to_side(side, RelayItem::Packet(Arc::new(packet)))
        .unwrap();
    assert!(
        node.state.lock().reliable_tx[&Relay::reliable_key(side, ty)]
            .sent
            .contains_key(&1)
    );
    (node, side, ty)
}
#[test]
fn refused_relay_hop_replay_does_not_pin_queued_flag() {
    let (node, side, ty) = hop_node();
    node.state.lock().replay_queue = BoundedDeque::new(1, 1, 1.0);
    assert!(node.queue_reliable_retransmit(side, ty, 1).is_err());
    assert!(!node.state.lock().reliable_tx[&Relay::reliable_key(side, ty)].sent[&1].queued);
    node.state.lock().replay_queue = BoundedDeque::new(4096, 512, 1.25);
    node.queue_reliable_retransmit(side, ty, 1).unwrap();
    assert_eq!(node.state.lock().replay_queue.len(), 1);
}
#[test]
fn evicted_relay_hop_replay_does_not_pin_queued_flag() {
    let (node, side, ty) = hop_node();
    node.queue_reliable_retransmit(side, ty, 1).unwrap();
    {
        let mut state = node.state.lock();
        assert!(state.pop_lowest_packet_queue_item(256));
        assert!(!state.reliable_tx[&Relay::reliable_key(side, ty)].sent[&1].queued);
        assert!(
            state.reliable_tx[&Relay::reliable_key(side, ty)]
                .sent
                .contains_key(&1)
        );
    }
    node.queue_reliable_retransmit(side, ty, 1).unwrap();
    assert_eq!(node.state.lock().replay_queue.len(), 1);
}

#[test]
fn clearing_relay_replays_releases_reservations_without_losing_retained_delivery() {
    for all in [false, true] {
        let (node, side, ty) = hop_node();
        node.queue_reliable_retransmit(side, ty, 1).unwrap();
        if all {
            node.clear_queues()
        } else {
            node.clear_tx_queue()
        }
        assert!(node.state.lock().replay_queue.is_empty());
        assert!(!node.state.lock().reliable_tx[&Relay::reliable_key(side, ty)].sent[&1].queued);
        node.queue_reliable_retransmit(side, ty, 1).unwrap();
        assert_eq!(node.state.lock().replay_queue.len(), 1);
    }
}
#[test]
fn disabled_relay_egress_does_not_pin_a_removed_retry_marker() {
    let (node, side, ty) = hop_node();
    node.queue_reliable_retransmit(side, ty, 1).unwrap();
    node.set_side_egress_enabled(side, false).unwrap();
    assert!(!node.state.lock().reliable_tx[&Relay::reliable_key(side, ty)].sent[&1].queued);
    node.set_side_egress_enabled(side, true).unwrap();
    node.queue_reliable_retransmit(side, ty, 1).unwrap();
    assert_eq!(node.state.lock().replay_queue.len(), 1);
}
