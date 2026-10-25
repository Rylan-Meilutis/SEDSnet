use super::*;
use core::sync::atomic::{AtomicU64,Ordering};

#[test]
fn generic_retry_at_high_uptime_starts_its_own_deferral_clock() {
    crate::tests::ensure_common_test_schema();
    let ep=crate::config::register_endpoint("GENERIC_RETRY_REMOTE",false).unwrap();
    let ty=crate::config::register_data_type_with_description("GENERIC_RETRY_ORDERED","",
        MessageElement::Static(2,crate::MessageDataType::UInt8,crate::MessageClass::Data),
        &[ep],crate::ReliableMode::Ordered,255).unwrap();
    let now=Arc::new(AtomicU64::new(123_456_789));let clock=now.clone();
    let node=Router::new_with_clock(RouterConfig::new([]).with_sender("VB"),
        Box::new(move||clock.load(Ordering::Relaxed)));
    node.clear_queues();
    let packet=Packet::new(ty,&[ep],"VB",1,Arc::<[u8]>::from([0,0])).unwrap();
    node.tx_queue_item_for_retry(RouterTxItem::Broadcast(RouterItem::Packet(packet)),true).unwrap();
    now.fetch_add(1,Ordering::Relaxed);
    node.process_tx_queue().unwrap();
    let st=node.state.lock();let retry=st.transmit_queue.iter().next().unwrap();
    assert_eq!(retry.delivery_state,QueuedDelivery::DeferredOrdered);
    assert_eq!(retry.deferred_since_ms,123_456_790);
}

#[test]
fn queue_metadata_growth_respects_target_alignment() {
    let alignment = core::mem::align_of::<TxQueued>();
    // Freeze the intended field budget independently of Rust's tuple ordering.
    let metadata_bytes = 24usize;
    let expected = (size_of::<RouterTxItem>() + metadata_bytes)
        .div_ceil(alignment) * alignment;
    assert_eq!(size_of::<TxQueued>(), expected);
    assert_eq!(size_of::<TxQueued>(),
        size_of::<(RouterTxItem, bool, u8, QueuedDelivery, u32, u64, u64)>());
    let legacy = size_of::<(RouterTxItem, bool, u8, u64)>();
    let legacy_metadata = (size_of::<bool>() + size_of::<u8>() + size_of::<u64>())
        .div_ceil(alignment) * alignment;
    assert_eq!(legacy, size_of::<RouterTxItem>() + legacy_metadata);
    let aligned_metadata = metadata_bytes.div_ceil(alignment) * alignment;
    assert_eq!(size_of::<TxQueued>() - legacy, aligned_metadata - legacy_metadata);
    println!("TxQueued={} legacy={} alignment={} RouterInner={}",
        size_of::<TxQueued>(), legacy, alignment, size_of::<RouterInner>());
}

#[test]
fn additive_schema_priority_merge_keeps_accepted_ordered_band() {
    crate::tests::ensure_common_test_schema();
    let ep=crate::config::register_endpoint("PRIORITY_MERGE_REMOTE",false).unwrap();
    let ty=crate::config::register_data_type_with_description("PRIORITY_MERGE_ORDERED","",
        MessageElement::Static(44,crate::MessageDataType::UInt8,crate::MessageClass::Data),
        &[ep],crate::ReliableMode::Ordered,20).unwrap();
    let node=Router::new_with_clock(RouterConfig::new([]).with_sender("SOURCE"),Box::new(||1000));
    node.clear_queues();
    node.log_queue(ty,&[0u8;44]).unwrap();
    let mut snapshot=crate::config::export_schema();
    snapshot.endpoints.clear();
    snapshot.types.retain(|definition|definition.id==ty);
    snapshot.types[0].priority=200;
    let _ = crate::config::merge_owned_schema_snapshot(snapshot);
    assert_eq!(crate::message_priority(ty),200);
    node.log_queue(ty,&[1u8;44]).unwrap();
    {
        let st=node.state.lock();
        let packets:Vec<_>=st.transmit_queue.iter().filter(|item|item.accepted_type==ty.as_u32()).collect();
        assert_eq!(packets.len(),2);
        assert_eq!(packets.iter().map(|p|p.priority).collect::<Vec<_>>(),vec![20,20]);
        assert!(matches!(&packets[0].item,RouterTxItem::Broadcast(RouterItem::Packet(p)) if p.payload()[0]==0));
        assert!(matches!(&packets[1].item,RouterTxItem::Broadcast(RouterItem::Packet(p)) if p.payload()[0]==1));
    }
    node.clear_tx_queue();
    node.log_queue(ty,&[2u8;44]).unwrap();
    assert_eq!(node.state.lock().transmit_queue.iter().find(|item|item.accepted_type==ty.as_u32()).unwrap().priority,200);
}
