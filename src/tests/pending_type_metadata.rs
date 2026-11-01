use super::*;

fn retained(send_stop: bool) -> (Router, DataType, DataType, u64) {
    let ep = crate::config::register_endpoint("PENDING_TYPE_LEAF", false).unwrap();
    let ty = crate::config::register_data_type_with_description(
        "PENDING_TYPE_BULK",
        "",
        MessageElement::Dynamic(crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[ep],
        crate::ReliableMode::Ordered,
        16,
    )
    .unwrap();
    let stop = crate::config::register_data_type_with_description(
        "PENDING_TYPE_STOP",
        "",
        MessageElement::Dynamic(crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[ep],
        crate::ReliableMode::Unordered,
        200,
    )
    .unwrap();
    let bulk = ty;
    let ty = if send_stop { stop } else { bulk };
    let unrelated = if send_stop { bulk } else { stop };
    let router = Router::new(RouterConfig::new([]).with_sender("host"));
    let side = router.add_side_packed("busy-bulk", move |wire| {
        if wire_format::peek_frame_info(wire).is_ok_and(|frame| frame.envelope.ty == ty) {
            return Err(TelemetryError::Io("test busy"));
        }
        Ok(())
    });
    router
        .rx_from_side(
            &crate::discovery::build_discovery_announce("leaf", 123, &[ep]).unwrap(),
            side,
        )
        .unwrap();
    router.process_all_queues_with_timeout(0).unwrap();
    let packet =
        Packet::new_with_nonce(ty, &[ep], "host", 100, 77, Arc::from(vec![0x53; 1024])).unwrap();
    let id = packet.packet_id();
    router
        .tx_packed_queue(wire_format::pack_packet(&packet))
        .unwrap();
    assert!(
        !router.has_pending_reliable_tx_type(unrelated),
        "initial typed queue is exact"
    );
    let _ = router.process_all_queues_with_timeout(0);
    {
        let state = router.state.lock();
        assert!(state.transmit_queue.is_empty());
        assert_eq!(state.end_to_end_reliable_tx.len(), 1);
        let owner = state.end_to_end_reliable_tx.get(&id).unwrap();
        assert!(matches!(&owner.data, RouterItem::Packed(_)));
        assert_eq!(
            owner
                .pending_destinations
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            vec![Router::sender_hash("leaf")]
        );
    }
    (router, ty, unrelated, id)
}
#[test]
fn retained_packed_owner_has_exact_logical_type_without_materialization() {
    let (router, ty, stop, _) = retained(false);
    assert!(router.has_pending_reliable_tx_type(ty));
    assert!(
        !router.has_pending_reliable_tx_type(stop),
        "known unrelated Packed E2E owner must not masquerade as Stop"
    );
}
#[test]
fn cached_e2e_replay_unknown_metadata_and_active_guard_remain_conservative() {
    let (router, ty, stop, id) = retained(false);
    router
        .tx_queue_item_for_retry(RouterTxItem::EndToEndReplay { packet_id: id }, true)
        .unwrap();
    assert!(router.has_pending_reliable_tx_type(ty));
    assert!(!router.has_pending_reliable_tx_type(stop));
    router
        .state
        .lock()
        .end_to_end_reliable_tx
        .get_mut(&id)
        .unwrap()
        .pending_type = 0;
    assert!(
        router.has_pending_reliable_tx_type(stop),
        "unknown owner metadata fails closed even with a replay marker"
    );
    let fallback = router.export_reliable_pending_stats();
    assert_eq!(fallback.len(), 1);
    assert_eq!((fallback[0].packet_id, fallback[0].data_type), (id, ty));
    router
        .state
        .lock()
        .end_to_end_reliable_tx
        .get_mut(&id)
        .unwrap()
        .pending_type = ty.as_u32();
    router
        .active_queued_tx
        .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
    assert!(
        router.has_pending_reliable_tx_type(stop),
        "conservative in-progress dispatch contract unchanged"
    );
    router
        .active_queued_tx
        .fetch_sub(1, core::sync::atomic::Ordering::AcqRel);
    assert!(!router.has_pending_reliable_tx_type(stop));
}
#[test]
fn cached_type_native_record_growth_is_fully_charged() {
    #[allow(dead_code)]
    struct Before {
        completion_epoch: u64,
        ordered_type: Option<u32>,
        waiting_for_predecessor: bool,
        data: RouterItem,
        pending_destinations: BTreeMap<u64, RouterSideId>,
        tracked_destinations: bool,
        last_send_ms: u64,
        retries: u32,
        queued: bool,
    }
    let before = size_of::<Before>();
    let after = size_of::<EndToEndReliableSent>();
    eprintln!("PENDING_TYPE_LAYOUT: native before={before} after={after} cache_std_only=true");
    assert!(after <= before + PENDING_TYPE_METADATA_BYTES);
    let (router, _, _, id) = retained(false);
    let mut state = router.state.lock();
    let charged = state.protected_metadata_bytes_used();
    let owner = state.end_to_end_reliable_tx.remove(&id).unwrap();
    let released = charged - state.protected_metadata_bytes_used();
    assert_eq!(
        released,
        PENDING_TYPE_METADATA_BYTES + usize::from(owner.completion_epoch != 0) * size_of::<u64>()
    );
    state.end_to_end_reliable_tx.insert(id, owner);
    eprintln!(
        "PENDING_TYPE_ACCOUNTING: owner_growth={} per_owner_cache_charge={PENDING_TYPE_METADATA_BYTES}",
        after - before
    );
}

#[test]
fn retained_packed_stop_owner_is_not_hidden() {
    let (router, stop, other, id) = retained(true);
    assert!(router.has_pending_reliable_tx_type(stop));
    assert!(!router.has_pending_reliable_tx_type(other));
    assert_eq!(
        router.state.lock().end_to_end_reliable_tx[&id].pending_type,
        stop.as_u32()
    );
}
#[test]
fn incremental_cache_budget_is_reserved_transactionally_and_released_on_receipt() {
    let (router, ty, _, id) = retained(false);
    let (data, destinations, side, original_budget) = {
        let mut state = router.state.lock();
        let owner = state.end_to_end_reliable_tx.remove(&id).unwrap();
        let side = *owner.pending_destinations.values().next().unwrap();
        let original = state.memory.max_queue_budget;
        (owner.data, owner.pending_destinations, side, original)
    };
    let before = {
        let mut state = router.state.lock();
        let used = state.shared_queue_bytes_used();
        state.memory.max_queue_budget = used + PENDING_TYPE_METADATA_BYTES - 1;
        state.protected_metadata_bytes_used()
    };
    assert!(
        router
            .register_end_to_end_reliable_tx(&data, Some(destinations.clone()))
            .is_err()
    );
    {
        let state = router.state.lock();
        assert!(state.end_to_end_reliable_tx.is_empty());
        assert!(state.transmit_queue.is_empty());
        assert_eq!(state.protected_metadata_bytes_used(), before);
    }
    router.state.lock().memory.max_queue_budget += 1;
    assert!(
        router
            .register_end_to_end_reliable_tx(&data, Some(destinations))
            .unwrap()
    );
    let accepted = router.state.lock().protected_metadata_bytes_used();
    assert_eq!(accepted - before, PENDING_TYPE_METADATA_BYTES);
    assert!(router.has_pending_reliable_tx_type(ty));
    router.state.lock().memory.max_queue_budget = original_budget;
    let owner = Router::sender_hash("leaf");
    let ack = Packet::new_with_wire_contract(
        DataType::ReliableAck,
        message_meta(DataType::ReliableAck).endpoints_ref(),
        "leaf",
        101,
        78,
        Arc::from(id.to_le_bytes()),
        None,
        Arc::from([owner]),
    )
    .unwrap();
    router.rx_from_side(&ack, side).unwrap();
    router.process_all_queues_with_timeout(0).unwrap();
    let state = router.state.lock();
    assert!(state.end_to_end_reliable_tx.is_empty());
    assert!(state.transmit_queue.is_empty());
    assert_eq!(
        accepted - state.protected_metadata_bytes_used(),
        PENDING_TYPE_METADATA_BYTES
    );
    eprintln!(
        "PENDING_TYPE_BUDGET: refused_cache_budget=7 accepted_cache_budget=8 released_cache_charge={PENDING_TYPE_METADATA_BYTES} exact_id={id}"
    );
}
