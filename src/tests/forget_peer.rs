use super::*;

/// An application that has decided a peer is out of range (an RRLS that took
/// over from a primary it can no longer hear) retires it at once: a frame
/// owed to it and to a reachable owner completes on the reachable owner's
/// receipt, and one owed only to it completes now, instead of both waiting
/// for the full retry span on a peer that can never answer.
#[test]
fn forgetting_a_peer_retires_it_from_pending_frames() {
    crate::tests::ensure_common_test_schema();
    let endpoint = DataEndpoint::named("RADIO");
    let ty = crate::config::register_data_type_with_description(
        "FORGET_PEER_WRITE",
        "",
        crate::MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[endpoint],
        crate::ReliableMode::Unordered,
        16,
    )
    .unwrap();
    let node = Router::new_with_clock(RouterConfig::new([]).with_sender("RRLS"), Box::new(|| 1000));
    let radio = node.add_side_packed("radio", |_| Ok(()));
    node.clear_queues();
    let (rf, gs) = (Router::sender_hash("RF"), Router::sender_hash("GS"));
    let frame = |timestamp: u64, owners: &[u64]| {
        let packet = Packet::new(ty, &[endpoint], "RRLS", timestamp, Arc::<[u8]>::from([1u8])).unwrap();
        let item = RouterItem::Packed(crate::shared_bytes::convert(wire_format::pack_packet(&packet)));
        let id = Router::get_hash(&item);
        node.register_end_to_end_reliable_tx(
            &item,
            Some(owners.iter().map(|owner| (*owner, radio)).collect::<OrdMap<_, _>>()),
        )
        .unwrap();
        id
    };
    let both = frame(1, &[rf, gs]);
    let gs_only = frame(2, &[gs]);
    let rf_only = frame(3, &[rf]);

    assert_eq!(node.forget_peer("GS").unwrap(), 2);
    {
        let st = node.state.lock();
        assert_eq!(
            st.end_to_end_reliable_tx[&both].pending_destinations.keys().copied().collect::<Vec<_>>(),
            vec![rf],
            "still owed to the reachable owner"
        );
        assert!(!st.end_to_end_reliable_tx.contains_key(&gs_only), "owed to no one else: complete");
        assert_eq!(st.end_to_end_reliable_tx[&rf_only].pending_destinations.len(), 1, "untouched");
    }
    let receipt = Packet::new_with_wire_contract(
        DataType::ReliableAck,
        message_meta(DataType::ReliableAck).endpoints_ref(),
        "E2EACK:RF",
        2,
        3,
        Arc::<[u8]>::from(both.to_le_bytes()),
        None,
        Arc::from([rf, Router::sender_hash("RRLS")]),
    )
    .unwrap();
    node.handle_internal_reliable_packet(&receipt, Some(radio), true).unwrap();
    assert!(
        !node.state.lock().end_to_end_reliable_tx.contains_key(&both),
        "the reachable owner's receipt completes it"
    );
    assert_eq!(node.forget_peer("GS").unwrap(), 0, "nothing left to retire");
}

/// Forgetting a peer never completes an ABORT or another urgent frame (as
/// complete_reliable never does): one owed only to the forgotten peer stays
/// pending and retries out its span; one also owed to a reachable owner
/// still drops the forgotten peer and waits for that owner's receipt.
#[test]
fn forgetting_a_peer_never_completes_an_abort_or_urgent_frame() {
    crate::tests::ensure_common_test_schema();
    let endpoint = DataEndpoint::named("RADIO");
    let register = |name: &str| {
        crate::config::register_data_type_with_description(
            name,
            "",
            crate::MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
            &[endpoint],
            crate::ReliableMode::Unordered,
            16,
        )
        .unwrap()
    };
    // The same ABORT definition router_managed_refresh registers (the type
    // registry is process-wide).
    let abort_ep = crate::config::register_endpoint("GENERIC_REFRESH_CHURN_ENDPOINT", false).unwrap();
    let abort = crate::config::register_data_type_with_description(
        "ABORT",
        "Diagnostic application Stop ownership",
        crate::MessageElement::Dynamic(crate::MessageDataType::String, crate::MessageClass::Error),
        &[abort_ep],
        crate::ReliableMode::Unordered,
        0,
    )
    .unwrap();
    let urgent = register("FORGET_PEER_URGENT");
    assert!(crate::set_type_scheduling_class(urgent, -1));
    let node = Router::new_with_clock(RouterConfig::new([]).with_sender("RRLS"), Box::new(|| 1000));
    let radio = node.add_side_packed("radio", |_| Ok(()));
    node.clear_queues();
    let (rf, gs) = (Router::sender_hash("RF"), Router::sender_hash("GS"));
    let frame = |ty: DataType, timestamp: u64, owners: &[u64]| {
        let ep = if ty == abort { abort_ep } else { endpoint };
        let packet = Packet::new(ty, &[ep], "RRLS", timestamp, Arc::<[u8]>::from(*b"K")).unwrap();
        let item = RouterItem::Packed(crate::shared_bytes::convert(wire_format::pack_packet(&packet)));
        let id = Router::get_hash(&item);
        node.register_end_to_end_reliable_tx(
            &item,
            Some(owners.iter().map(|owner| (*owner, radio)).collect::<OrdMap<_, _>>()),
        )
        .unwrap();
        id
    };
    let abort_gs_only = frame(abort, 1, &[gs]);
    let urgent_gs_only = frame(urgent, 2, &[gs]);
    let abort_both = frame(abort, 3, &[rf, gs]);
    assert_eq!(node.forget_peer("GS").unwrap(), 1, "only the frame a reachable owner still owes");
    let st = node.state.lock();
    assert_eq!(
        st.end_to_end_reliable_tx[&abort_gs_only].pending_destinations.keys().copied().collect::<Vec<_>>(),
        vec![gs],
        "an ABORT owed to no one else is never completed by forget_peer"
    );
    assert!(st.end_to_end_reliable_tx.contains_key(&urgent_gs_only), "nor an urgent frame");
    assert_eq!(
        st.end_to_end_reliable_tx[&abort_both].pending_destinations.keys().copied().collect::<Vec<_>>(),
        vec![rf],
        "an ABORT still owed to a reachable owner waits for its receipt"
    );
    drop(st);
    assert!(crate::set_type_scheduling_class(urgent, 0));
}
