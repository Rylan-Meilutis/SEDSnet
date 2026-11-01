use super::*;
fn schema() -> (DataEndpoint, DataType, DataType) {
    let ep = crate::config::register_endpoint("TOSIDE_INSPECTION_METADATA", false).unwrap();
    let bulk = crate::config::register_data_type_with_description(
        "TOSIDE_INSPECTION_BULK",
        "",
        MessageElement::Dynamic(crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[ep],
        crate::ReliableMode::Ordered,
        16,
    )
    .unwrap();
    let stop = crate::config::register_data_type_with_description(
        "TOSIDE_INSPECTION_STOP",
        "",
        MessageElement::Dynamic(crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[ep],
        crate::ReliableMode::Unordered,
        240,
    )
    .unwrap();
    (ep, bulk, stop)
}
fn queue(node: &Router, data: RouterItem, provided: u32) {
    let dst = node.add_side_packed("held-for-inspection", |_| Ok(()));
    node.state
        .lock()
        .push_transmit(TxQueued {
            disposable: 0,
            item: RouterTxItem::ToSide {
                src: None,
                dst,
                data,
            },
            ignore_local: true,
            priority: 16,
            delivery_state: QueuedDelivery::Untracked,
            accepted_type: provided,
            deferred_since_ms: 0,
            retry_after_ms: 0,
        })
        .unwrap();
}
#[test]
fn toside_known_bulk_and_stop_keep_untracked_semantics() {
    let (ep, bulk, stop) = schema();
    for ty in [bulk, stop] {
        let node = Router::new(RouterConfig::new([]).with_sender("inspection-host"));
        let packet = Packet::new(ty, &[ep], "inspection-source", 1, Arc::from([1u8])).unwrap();
        queue(
            &node,
            RouterItem::Packed(crate::shared_bytes::convert(wire_format::pack_packet(
                &packet,
            ))),
            0,
        );
        assert_eq!(node.has_pending_reliable_tx_type(stop), ty == stop);
        let mut state = node.state.lock();
        let entry = state
            .transmit_queue
            .iter()
            .find(|q| matches!(q.item, RouterTxItem::ToSide { .. }))
            .unwrap();
        assert_eq!(entry.accepted_type, ty.as_u32());
        assert_eq!(entry.delivery_state, QueuedDelivery::Untracked);
        assert_eq!(RouterInner::reliable_original_type(entry), None);
        assert_eq!(RouterInner::ordered_original_type(entry), None);
        state.cancel_accepted_type(ty.as_u32());
        assert!(
            state
                .transmit_queue
                .iter()
                .any(|q| matches!(q.item, RouterTxItem::ToSide { .. })),
            "cancel of app original must not cancel side work"
        );
    }
}
#[test]
fn toside_malformed_unknown_and_explicit_provenance_stay_conservative() {
    let (_, bulk, stop) = schema();
    for raw in [vec![], vec![0, 0, 0x80], vec![0xff; 32]] {
        let node = Router::new(RouterConfig::new([]));
        queue(
            &node,
            RouterItem::Packed(crate::shared_bytes::convert(Arc::<[u8]>::from(raw))),
            0,
        );
        assert!(node.has_pending_reliable_tx_type(stop));
        assert!(node.has_pending_reliable_tx_type(bulk));
    }
    let node = Router::new(RouterConfig::new([]));
    queue(
        &node,
        RouterItem::Packed(crate::shared_bytes::convert(Arc::<[u8]>::from(&b""[..]))),
        stop.as_u32(),
    );
    assert!(node.has_pending_reliable_tx_type(stop));
    assert!(!node.has_pending_reliable_tx_type(bulk));
    assert!(
        node.state
            .lock()
            .transmit_queue
            .iter()
            .filter(|q| matches!(q.item, RouterTxItem::ToSide { .. }))
            .all(|q| q.accepted_type == stop.as_u32())
    );
}
#[test]
fn toside_reuse_has_zero_layout_growth_extra_field_has_a_cost() {
    #[allow(dead_code)]
    struct ExtraInspectionField {
        disposable: u8,
        item: RouterTxItem,
        ignore_local: bool,
        priority: u8,
        delivery_state: QueuedDelivery,
        accepted_type: u32,
        inspection_type: u32,
        deferred_since_ms: u64,
        retry_after_ms: u64,
    }
    let current = size_of::<TxQueued>();
    let extra = size_of::<ExtraInspectionField>();
    assert_eq!(
        current,
        size_of::<(RouterTxItem, bool, u8, QueuedDelivery, u32, u64, u64)>()
    );
    eprintln!(
        "TOSIDE_METADATA_LAYOUT: reused_existing={current} extra_u32_record={extra} candidate_growth=0 alternative_growth={}",
        extra - current
    );
}
