//! Pure code-generation equivalence; synthetic row placement is NOT a wire-delivery proof.
use super::*;
fn owner(phase: FirstHopOffer, payload: &[u8]) -> ReliableSent {
    ReliableSent { bytes: crate::SharedBytes::from(payload), offer_stamp: 1000,
        first_offer: phase, retries: 0, queued: false, partial_acked: false }
}
fn node() -> Router {
    crate::tests::ensure_common_test_schema();
    Router::new_with_clock(RouterConfig::new([]).with_sender("CODEGEN_RECEIVER"),Box::new(||1000))
}
#[test]
fn byte_fold_matches_original_empty_mixed_keys_and_phases() {
    let node=node();
    let mut state=node.state.lock();
    assert_eq!(state.first_offer_bytes_used(),0);
    for side in [9,2] {
        let mut sent=OrdMap::new();
        for (seq,phase,len) in [(u32::MAX,FirstHopOffer::AckedActive,31),(1,FirstHopOffer::Complete,5),
            (17,FirstHopOffer::Pending,0),(8,FirstHopOffer::Active,11)] {
            sent.insert(seq,owner(phase,&vec![7;len]));
        }
        state.reliable_tx.insert(Router::reliable_key(side,DataType::DiscoverySchema),ReliableTxState {
            next_seq:0,sent_order:VecDeque::new(),sent });
    }
    let old=state.reliable_tx.values().flat_map(|stream|stream.sent.values())
        .filter(|sent|sent.first_offer.pending()).fold(0usize,|total,sent|
            total.saturating_add(sent.bytes.len()).saturating_add(size_of::<ReliableSent>()+3*size_of::<usize>()));
    assert_eq!(state.first_offer_bytes_used(),old);
    assert_eq!(old,2*(31+11+3*(size_of::<ReliableSent>()+3*size_of::<usize>())));
}
#[test]
fn saturation_operation_order_extremes_match_original_fold() {
    // No impossible MAX-sized allocation/owner is fabricated. This is the
    // exact pure arithmetic comparison for lengths unreachable in this fixture.
    for lengths in [vec![],vec![usize::MAX],vec![usize::MAX-1,2],vec![0,1,usize::MAX,0]] {
        let charge=size_of::<ReliableSent>()+3*size_of::<usize>();
        let old=lengths.iter().fold(0usize,|n,len|n.saturating_add(*len).saturating_add(charge));
        let mut new=0usize;
        for len in lengths { new=new.saturating_add(len).saturating_add(charge); }
        assert_eq!(new,old);
    }
}
#[test]
fn actual_receipt_scan_matches_ordered_cursor_max_and_exact_phase_owner() {
    let node=node();let side=7;let ty=DataType::DiscoverySchema;let key=Router::reliable_key(side,ty);
    let packet=discovery::build_discovery_schema("CODEGEN_PUBLISHER",1001).unwrap();
    let pid=packet.packet_id();let publisher=Router::sender_hash("CODEGEN_PUBLISHER");
    let wire=wire_format::pack_packet_with_reliable(&packet,wire_format::ReliableHeader{flags:0,seq:1,ack:0});
    let other=discovery::build_discovery_schema("CODEGEN_OTHER",1001).unwrap();
    let otherwire=wire_format::pack_packet_with_reliable(&other,wire_format::ReliableHeader{flags:0,seq:2,ack:0});
    let retained=crate::SharedBytes::from(wire.as_ref());
    let mut sent=OrdMap::new();
    for (seq,phase,bytes) in [(u32::MAX,FirstHopOffer::Complete,retained.clone()),
        (8,FirstHopOffer::Complete,crate::SharedBytes::from(otherwire.as_ref())),
        (1,FirstHopOffer::Pending,retained.clone())] {
        let mut row=owner(phase,&[]);row.bytes=bytes;sent.insert(seq,row);
    }
    // The old filter/min-by-key oracle visits8,thenMAX; Pending1 is excluded.
    let mut cursor=None;
    for expected in [Some(8),Some(u32::MAX),None] {
        let next=sent.iter().filter(|(seq,row)|cursor.is_none_or(|last|**seq>last)
            &&(!row.first_offer.pending()||row.first_offer.active())).min_by_key(|(seq,_)|**seq).map(|(seq,_)|*seq);
        assert_eq!(next,expected);cursor=next.or(cursor);
    }
    node.state.lock().reliable_tx.insert(key,ReliableTxState{next_seq:0,sent_order:VecDeque::from([1,8,u32::MAX]),sent});
    assert!(!node.retire_bound_control_hop_type(side,ty,publisher,other.packet_id()).unwrap());
    assert!(node.retire_bound_control_hop_type(side,ty,publisher,pid).unwrap());
    {
        let mut state=node.state.lock();let stream=state.reliable_tx.get_mut(&key).unwrap();
        assert_eq!(stream.sent.keys().copied().collect::<Vec<_>>(),vec![1,8]);
        assert_eq!(stream.sent_order,VecDeque::from([1,8]));
        assert!(crate::shared_bytes::same_owner(&stream.sent[&1].bytes,&retained));
        stream.sent.get_mut(&1).unwrap().first_offer=FirstHopOffer::Active;
    }
    assert!(node.retire_bound_control_hop_type(side,ty,publisher,pid).unwrap());
    let state=node.state.lock();let stream=&state.reliable_tx[&key];
    assert_eq!(stream.sent[&1].first_offer,FirstHopOffer::AckedActive);
    assert_eq!(stream.sent.len(),2,"active owner only records tentative ACK");
}
