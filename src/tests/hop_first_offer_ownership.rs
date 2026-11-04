//! Real refusal-before-accept ownership: no invented wire/clock or handler ACK.
use super::*;
use std::sync::{Mutex,atomic::{AtomicBool,AtomicU64,AtomicUsize,Ordering}};
#[test]
fn actual_hop_owner_layout() {println!("ACTUAL_HOP_OWNER_LAYOUT size={} align={}",size_of::<ReliableSent>(),core::mem::align_of::<ReliableSent>());}
fn application(name:&str)->(DataType,DataEndpoint) {let ep=crate::config::register_endpoint_with_description(&format!("{name}_EP"),"app-owned",false).unwrap();let ty=crate::config::register_data_type_with_description(name,"owned ordered message",MessageElement::Static(1,crate::MessageDataType::UInt32,crate::MessageClass::Data),&[ep],crate::ReliableMode::Ordered,80).unwrap();(ty,ep)}
#[test]
fn first_refusal_retries_same_original_sequence_without_wire_acceptance_claim() {
    crate::tests::ensure_common_test_schema();let(ty,ep)=application("FIRST_OFFER_BUSY");let now=Arc::new(AtomicU64::new(1000));let c=now.clone();let node=Router::new_with_clock(RouterConfig::new([]).with_sender("FIRST_PUBLISHER"),Box::new(move||c.load(Ordering::SeqCst)));
    let busy=Arc::new(AtomicBool::new(true));let reject=busy.clone();let wire=Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));let out=wire.clone();let attempts=Arc::new(AtomicUsize::new(0));let calls=attempts.clone();let side=node.add_side_packed_with_options("bounded",move|b| {
        if wire_format::peek_frame_info(b).is_ok_and(|f|f.envelope.ty==ty) {calls.fetch_add(1,Ordering::SeqCst);if reject.load(Ordering::SeqCst){return Err(TelemetryError::Io("side tx busy"))}out.lock().unwrap().push(b.to_vec());}Ok(())
    },RouterSideOptions{reliable_enabled:true,..Default::default()});node.clear_queues();let packet=Packet::new(ty,&[ep],"FIRST_PUBLISHER",1001,Arc::<[u8]>::from(7u32.to_le_bytes())).unwrap();let original=packet.packet_id();let mut admitted=false;
    let first=node.send_reliable_to_side_with_progress(side,RouterItem::Packet(packet.clone()),false,&mut admitted);assert!(!admitted);assert!(wire.lock().unwrap().is_empty());
    if first.is_ok() {
        // LocalOk is valid only if the SDK now actually owns the exact frame.
        assert_eq!(node.state.lock().reliable_tx[&Router::reliable_key(side,ty)].sent.len(),1);
        let before=attempts.load(Ordering::SeqCst);node.send_reliable_to_side(side,RouterItem::Packet(packet.clone()),false).unwrap();assert_eq!(attempts.load(Ordering::SeqCst),before,"same pending original must not allocate/offer another owner");
        busy.store(false,Ordering::SeqCst);now.fetch_add(crate::config::RELIABLE_RETRANSMIT_MS+1,Ordering::SeqCst);node.process_all_queues().unwrap();
    } else {
        assert!(matches!(first,Err(TelemetryError::Io("side tx busy"))));busy.store(false,Ordering::SeqCst);node.send_reliable_to_side(side,RouterItem::Packet(packet),false).unwrap();
    }
    let accepted=wire.lock().unwrap();assert!(!accepted.is_empty());for bytes in accepted.iter() {let frame=wire_format::peek_frame_info(bytes).unwrap();assert_eq!(frame.reliable.unwrap().seq,1,"a refusal cannot leave an unfillable hop sequence hole");assert_eq!(wire_format::packet_id_from_wire(bytes).unwrap(),original);assert_eq!(frame.envelope.timestamp_ms,1001);}
}
type PendingNode = (Arc<Router>,RouterSideId,DataType,DataEndpoint,Arc<AtomicU64>,Arc<AtomicBool>,Arc<Mutex<Vec<Vec<u8>>>>);
fn pending_node(name: &str) -> PendingNode {
    crate::tests::ensure_common_test_schema();
    let (ty,ep)=application(name);let now=Arc::new(AtomicU64::new(1000));let c=now.clone();
    let node=Arc::new(Router::new_with_clock(RouterConfig::new([]).with_sender("PENDING_PUBLISHER"),Box::new(move||c.load(Ordering::SeqCst))));
    let busy=Arc::new(AtomicBool::new(true));let b=busy.clone();let wire=Arc::new(Mutex::new(Vec::new()));let w=wire.clone();
    let side=node.add_side_packed_with_options("pending",move|bytes| {
        if wire_format::peek_frame_info(bytes).is_ok_and(|f| f.envelope.ty==ty) {
            if b.load(Ordering::SeqCst) {return Err(TelemetryError::Io("side tx busy"))}
            w.lock().unwrap().push(bytes.to_vec());
        }Ok(())
    },RouterSideOptions{reliable_enabled:true,..Default::default()});node.clear_queues();(node,side,ty,ep,now,busy,wire)
}
fn packet(ty:DataType,ep:DataEndpoint,value:u32) -> Packet {
    Packet::new(ty,&[ep],"PENDING_PUBLISHER",1001,Arc::<[u8]>::from(value.to_le_bytes())).unwrap()
}
#[test]
fn forced_filter_collision_different_payload_never_coalesces() {
    let (node,side,ty,ep,_,_,_)=pending_node("PENDING_COLLISION");
    let first=packet(ty,ep,1);let second=packet(ty,ep,2);
    node.send_reliable_to_side(side,RouterItem::Packet(first),false).unwrap();
    // Deliberately collide ONLY the non-authoritative filter, not the immutable owner.
    node.state.lock().reliable_tx.get_mut(&Router::reliable_key(side,ty)).unwrap().sent.get_mut(&1).unwrap().offer_stamp=second.packet_id();
    node.send_reliable_to_side(side,RouterItem::Packet(second.clone()),false).unwrap();
    let state=node.state.lock();let stream=&state.reliable_tx[&Router::reliable_key(side,ty)];
    assert_eq!(stream.next_seq,3);assert_eq!(stream.sent.len(),2);
    assert_ne!(stream.sent[&1].bytes.as_ref(),stream.sent[&2].bytes.as_ref());
    assert_eq!(wire_format::packet_id_from_wire(stream.sent[&2].bytes.as_ref()).unwrap(),second.packet_id());
}
#[test]
fn same_pid_different_frozen_recipients_never_coalesces() {
    crate::tests::ensure_common_test_schema();let ep=crate::config::register_endpoint_with_description("PENDING_RECIP_EP","test",false).unwrap();
    let ty=crate::config::register_data_type_with_description("PENDING_RECIP","test",MessageElement::Static(1,crate::MessageDataType::UInt32,crate::MessageClass::Data),&[ep],crate::ReliableMode::Unordered,80).unwrap();
    let node=Router::new_with_clock(RouterConfig::new([]).with_sender("PENDING_PUBLISHER"),Box::new(||1000));
    let side=node.add_side_packed_with_options("pending",move|bytes| {if wire_format::peek_frame_info(bytes).is_ok_and(|f|f.envelope.ty==ty){Err(TelemetryError::Io("side tx busy"))}else{Ok(())}},RouterSideOptions{reliable_enabled:true,..Default::default()});node.clear_queues();
    let build=|owner|Packet::new_with_wire_contract(ty,&[ep],"PENDING_PUBLISHER",1001,0,Arc::<[u8]>::from(9u32.to_le_bytes()),None,Arc::<[u64]>::from([owner])).unwrap();
    let a=build(100);let b=build(200);assert_eq!(a.packet_id(),b.packet_id(),"frozen recipients are deliberately outside original PID");
    node.send_reliable_to_side(side,RouterItem::Packet(a),false).unwrap();node.send_reliable_to_side(side,RouterItem::Packet(b),false).unwrap();
    let state=node.state.lock();let stream=&state.reliable_tx[&Router::reliable_key(side,ty)];assert_eq!(stream.sent.len(),2);assert_ne!(stream.sent[&1].bytes.as_ref(),stream.sent[&2].bytes.as_ref());
}
#[test]
fn busy_and_refused_replay_admission_do_not_spend_retry_budget_or_timestamp_key() {
    let (node,side,ty,ep,now,busy,wire)=pending_node("PENDING_ATTEMPTS");let p=packet(ty,ep,3);let key=p.packet_id();
    node.send_reliable_to_side(side,RouterItem::Packet(p),false).unwrap();
    for _ in 0..12 {now.fetch_add(1000,Ordering::SeqCst);node.process_all_queues().unwrap();let st=node.state.lock();let sent=&st.reliable_tx[&Router::reliable_key(side,ty)].sent[&1];assert!(sent.first_offer.pending());assert_eq!(sent.offer_stamp,key);assert_eq!(sent.retries,0);}
    busy.store(false,Ordering::SeqCst);now.fetch_add(crate::config::RELIABLE_RETRANSMIT_MS+1,Ordering::SeqCst);node.process_all_queues().unwrap();assert!(!wire.lock().unwrap().is_empty());
    let st=node.state.lock();let sent=&st.reliable_tx[&Router::reliable_key(side,ty)].sent[&1];assert!(!sent.first_offer.pending());assert_eq!(sent.retries,0);assert_eq!(sent.offer_stamp,now.load(Ordering::SeqCst));
}
#[test]
fn memory_refusal_has_no_callback_or_sequence_commit() {
    let (node,side,ty,ep,_,_,wire)=pending_node("PENDING_MEMORY");node.state.lock().memory.max_queue_budget=0;
    let result=node.send_reliable_to_side(side,RouterItem::Packet(packet(ty,ep,4)),false);
    assert!(matches!(result,Err(TelemetryError::Io("memory pressure"))));assert!(wire.lock().unwrap().is_empty());assert!(!node.state.lock().reliable_tx.contains_key(&Router::reliable_key(side,ty)));
}
#[test]
fn side_retirement_cannot_resurrect_retained_pending_owner() {
    let (node,side,ty,ep,now,busy,wire)=pending_node("PENDING_ABA");node.send_reliable_to_side(side,RouterItem::Packet(packet(ty,ep,5)),false).unwrap();
    node.remove_side(side).unwrap();busy.store(false,Ordering::SeqCst);
    let accepted=Arc::new(AtomicUsize::new(0));let a=accepted.clone();let reused=node.add_side_packed_with_options("replacement",move|_|{a.fetch_add(1,Ordering::SeqCst);Ok(())},RouterSideOptions{reliable_enabled:true,..Default::default()});assert_eq!(reused,side);node.clear_queues();
    now.fetch_add(1000,Ordering::SeqCst);node.process_reliable_timeouts().unwrap();assert!(wire.lock().unwrap().is_empty());assert_eq!(accepted.load(Ordering::SeqCst),0);assert!(!node.state.lock().reliable_tx.contains_key(&Router::reliable_key(side,ty)));
}
#[test]
fn concurrent_and_reentrant_producers_cannot_rollback_or_consume_sequences() {
    crate::tests::ensure_common_test_schema();let(ty,ep)=application("PENDING_CONCURRENT");
    let node=Arc::new(Router::new_with_clock(RouterConfig::new([]).with_sender("PENDING_PUBLISHER"),Box::new(||1000)));
    let entered=Arc::new(std::sync::Barrier::new(2));let release=Arc::new(std::sync::Barrier::new(2));let e=entered.clone();let r=release.clone();let weak=Arc::downgrade(&node);let sid=Arc::new(AtomicUsize::new(usize::MAX));let s=sid.clone();let reentrant=Arc::new(AtomicBool::new(false));let re=reentrant.clone();
    let side=node.add_side_packed_with_options("concurrent",move|wire| {
        if wire_format::peek_frame_info(wire).is_ok_and(|f|f.envelope.ty==ty) {
            let n=weak.upgrade().unwrap();assert!(matches!(n.send_reliable_to_side(s.load(Ordering::SeqCst),RouterItem::Packet(packet(ty,ep,99)),false),Err(TelemetryError::Io("side tx busy"))));re.store(true,Ordering::SeqCst);
            assert!(matches!(n.remove_side(s.load(Ordering::SeqCst)),Err(TelemetryError::Io("side tx busy"))));
            e.wait();r.wait();return Err(TelemetryError::Io("side tx busy"));
        }Ok(())
    },RouterSideOptions{reliable_enabled:true,..Default::default()});sid.store(side,Ordering::SeqCst);node.clear_queues();
    let worker=node.clone();let t=std::thread::spawn(move||worker.send_reliable_to_side(side,RouterItem::Packet(packet(ty,ep,1)),false));entered.wait();
    assert!(matches!(node.send_reliable_to_side(side,RouterItem::Packet(packet(ty,ep,2)),false),Err(TelemetryError::Io("side tx busy"))));
    node.process_reliable_timeouts().unwrap();{let st=node.state.lock();let stream=&st.reliable_tx[&Router::reliable_key(side,ty)];assert_eq!(stream.next_seq,2);assert_eq!(stream.sent.len(),1);assert!(stream.sent[&1].queued);assert_eq!(stream.sent[&1].retries,0);}
    release.wait();assert!(t.join().unwrap().is_ok());assert!(reentrant.load(Ordering::SeqCst));let st=node.state.lock();assert_eq!(st.reliable_tx[&Router::reliable_key(side,ty)].next_seq,2);
}
#[test]
fn public_inline_ack_before_callback_return_retires_exact_committed_owner() {
    crate::tests::ensure_common_test_schema();let(ty,ep)=application("PENDING_INLINE_ACK");
    let node=Arc::new(Router::new_with_clock(RouterConfig::new([]).with_sender("PENDING_PUBLISHER"),Box::new(||1000)));
    let peer=Arc::new(Router::new_with_clock(RouterConfig::new([]).with_sender("REAL_ACK_PEER"),Box::new(||1000)));
    let weak=Arc::downgrade(&node);let ack_peer=peer.clone();let side_value=Arc::new(AtomicUsize::new(usize::MAX));let sid=side_value.clone();
    let side=node.add_side_packed_with_options("inline",move|wire| {
        if let Ok(frame)=wire_format::peek_frame_info(wire) && frame.envelope.ty==ty {
            let n=weak.upgrade().unwrap();let s=sid.load(Ordering::SeqCst);let seq=frame.reliable.unwrap().seq;
            {let state=n.state.lock();let stream=&state.reliable_tx[&Router::reliable_key(s,ty)];assert!(stream.sent[&seq].first_offer.pending());}
            let ack=ack_peer.reliable_control_packet(DataType::ReliableAck,ty,seq).unwrap();
            n.rx_packed_from_side(&wire_format::pack_packet(&ack),s).unwrap();
            n.process_rx_queue().unwrap(); // actual concurrent/reentrant queue servicing before callback returns
            assert_eq!(n.state.lock().reliable_tx[&Router::reliable_key(s,ty)].sent.len(),1,"inline public RX must defer while callback owns side");
        }Ok(())
    },RouterSideOptions{reliable_enabled:true,..Default::default()});side_value.store(side,Ordering::SeqCst);node.clear_queues();
    node.send_reliable_to_side(side,RouterItem::Packet(packet(ty,ep,1)),false).unwrap();node.process_rx_queue().unwrap();
    let state=node.state.lock();let stream=&state.reliable_tx[&Router::reliable_key(side,ty)];assert!(stream.sent.is_empty());assert_eq!(stream.next_seq,2);
}
#[test]
fn fragmented_partial_offer_resumes_same_canonical_owner_without_repeating_prefix() {
    crate::tests::ensure_common_test_schema();let ep=crate::config::register_endpoint_with_description("PENDING_FRAGMENT_EP","test",false).unwrap();let ty=crate::config::register_data_type_with_description("PENDING_FRAGMENT","test",MessageElement::Static(64,crate::MessageDataType::UInt32,crate::MessageClass::Data),&[ep],crate::ReliableMode::Ordered,80).unwrap();
    let now=Arc::new(AtomicU64::new(1000));let c=now.clone();let node=Router::new_with_clock(RouterConfig::new([]).with_sender("FRAGMENT_PUBLISHER"),Box::new(move||c.load(Ordering::SeqCst)));
    let busy=Arc::new(AtomicBool::new(true));let b=busy.clone();let accepted=Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));let out=accepted.clone();
    let side=node.add_side_packed_with_options("fragmented",move|wire| {
        let mut frames=out.lock().unwrap();if !frames.is_empty()&&b.load(Ordering::SeqCst){return Err(TelemetryError::Io("side tx busy"))}frames.push(wire.to_vec());Ok(())
    },RouterSideOptions{reliable_enabled:true,max_frame_bytes:96,..Default::default()});node.clear_queues();
    let p=Packet::new(ty,&[ep],"FRAGMENT_PUBLISHER",1001,Arc::<[u8]>::from([4u8;256])).unwrap();let original=p.packet_id();let mut admitted=false;
    node.send_reliable_to_side_with_progress(side,RouterItem::Packet(p),false,&mut admitted).unwrap();assert!(admitted,"prefix really accepted");assert_eq!(accepted.lock().unwrap().len(),1);
    let original_owner=node.state.lock().reliable_tx[&Router::reliable_key(side,ty)].sent[&1].bytes.clone();assert_eq!(wire_format::packet_id_from_wire(original_owner.as_ref()).unwrap(),original);
    busy.store(false,Ordering::SeqCst);now.fetch_add(201,Ordering::SeqCst);node.process_all_queues().unwrap();let frames=accepted.lock().unwrap();assert!(frames.len()>1);assert!(frames[1..].iter().all(|frame|frame!=&frames[0]),"accepted prefix is not retransmitted on first-offer resume");
    let seen=Arc::new(Mutex::new(Vec::<Packet>::new()));let received=seen.clone();let receiver=Router::new_with_clock(RouterConfig::new([EndpointHandler::new_packet_handler(ep,move|p|{received.lock().unwrap().push(p.clone());Ok(())})]).with_sender("FRAGMENT_PEER"),Box::new(||1201));let rs=receiver.add_side_packed("source",|_|Ok(()));receiver.clear_queues();for frame in frames.iter(){receiver.rx_packed_from_side(frame,rs).unwrap();}receiver.process_all_queues().unwrap();assert_eq!(seen.lock().unwrap().len(),1);assert_eq!(seen.lock().unwrap()[0].packet_id(),original);
}
#[test]
fn replay_queue_refusal_retains_original_pending_owner_without_spending_attempt() {
    let (node,side,ty,ep,now,_,_)=pending_node("PENDING_QUEUE_REFUSAL");let p=packet(ty,ep,7);let id=p.packet_id();node.send_reliable_to_side(side,RouterItem::Packet(p),false).unwrap();
    let original_budget=node.state.lock().memory.max_queue_budget;node.state.lock().memory.max_queue_budget=0;
    for _ in 0..3 {now.fetch_add(1000,Ordering::SeqCst);let result=node.process_reliable_timeouts();assert!(matches!(result,Err(TelemetryError::PacketTooLarge("Item exceeds maximum shared queue budget"))),"actual zero-budget replay admission must refuse: {result:?}");let state=node.state.lock();let sent=&state.reliable_tx[&Router::reliable_key(side,ty)].sent[&1];assert!(sent.first_offer.pending());assert_eq!(sent.offer_stamp,id);assert_eq!(sent.retries,0);assert!(!sent.queued);}
    node.state.lock().memory.max_queue_budget=original_budget;
}
#[test]
fn permanent_failure_after_commit_fails_ordered_stream_without_reusing_sequence() {
    crate::tests::ensure_common_test_schema();let(ty,ep)=application("PENDING_PERMANENT");let node=Router::new_with_clock(RouterConfig::new([]).with_sender("PENDING_PUBLISHER"),Box::new(||1000));let calls=Arc::new(AtomicUsize::new(0));let c=calls.clone();let side=node.add_side_packed_with_options("failed",move|bytes|{if wire_format::peek_frame_info(bytes).is_ok_and(|f|f.envelope.ty==ty){c.fetch_add(1,Ordering::SeqCst);Err(TelemetryError::Io("permanent driver failure"))}else{Ok(())}},RouterSideOptions{reliable_enabled:true,..Default::default()});node.clear_queues();
    assert!(matches!(node.send_reliable_to_side(side,RouterItem::Packet(packet(ty,ep,1)),false),Err(TelemetryError::Io("permanent driver failure"))));
    let count=calls.load(Ordering::SeqCst);assert!(count>0);{let state=node.state.lock();let stream=&state.reliable_tx[&Router::reliable_key(side,ty)];assert_eq!(stream.next_seq,0);assert!(stream.sent.is_empty());}
    assert!(matches!(node.send_reliable_to_side(side,RouterItem::Packet(packet(ty,ep,2)),false),Err(TelemetryError::HandlerError("ordered hop stream failed"))));assert_eq!(calls.load(Ordering::SeqCst),count);
}
#[cfg(feature="compact-packet-store")]
struct ResetArena;
#[cfg(feature="compact-packet-store")]
impl Drop for ResetArena {fn drop(&mut self){crate::packet_store::set_default_store(None)}}
#[test]
#[cfg(feature="compact-packet-store")]
fn actual_managed_pending_owner_and_exact_comparison_survive_compaction_without_pins() {
    let _reset=ResetArena;let arena=crate::packet_store::PacketStore::new(256*1024,1024,usize::MAX).unwrap();crate::packet_store::set_default_store(Some(arena.clone()));let hole=arena.store(&[0;128]).unwrap();
    let (node,side,ty,ep,now,busy,wire)=pending_node("PENDING_MANAGED");let p=packet(ty,ep,8);node.send_reliable_to_side(side,RouterItem::Packet(p.clone()),false).unwrap();
    {let state=node.state.lock();assert!(matches!(state.reliable_tx[&Router::reliable_key(side,ty)].sent[&1].bytes,crate::small_payload::SmallPayload::Managed(_)));}
    assert_eq!(arena.stats().pinned_bytes,0);node.send_reliable_to_side(side,RouterItem::Packet(p),false).unwrap();assert_eq!(arena.stats().pinned_bytes,0);let before=arena.stats().moves;drop(hole);arena.compact();assert!(arena.stats().moves>before);assert_eq!(arena.stats().pinned_bytes,0);
    busy.store(false,Ordering::SeqCst);now.fetch_add(201,Ordering::SeqCst);node.process_all_queues().unwrap();assert!(!wire.lock().unwrap().is_empty());assert_eq!(arena.stats().pinned_bytes,0);let state=node.state.lock();let stream=&state.reliable_tx[&Router::reliable_key(side,ty)];assert_eq!(stream.sent.len(),1);assert_eq!(stream.next_seq,2);assert!(!stream.sent[&1].first_offer.pending());
}
#[test]
fn ack_before_any_active_offer_cannot_retire_pending_owner() {
    let (node,side,ty,ep,_,_,_)=pending_node("PENDING_UNOFFERED_ACK");node.send_reliable_to_side(side,RouterItem::Packet(packet(ty,ep,1)),false).unwrap();
    let peer=Router::new_with_clock(RouterConfig::new([]).with_sender("ACK_PEER"),Box::new(||1000));let ack=peer.reliable_control_packet(DataType::ReliableAck,ty,1).unwrap();node.rx_packed_from_side(&wire_format::pack_packet(&ack),side).unwrap();node.process_rx_queue().unwrap();
    let state=node.state.lock();let sent=&state.reliable_tx[&Router::reliable_key(side,ty)].sent[&1];assert_eq!(sent.first_offer,FirstHopOffer::Pending);assert_eq!(sent.retries,0);
}
#[test]
fn active_ack_followed_by_callback_busy_cannot_retire_pending_owner() {
    crate::tests::ensure_common_test_schema();let(ty,ep)=application("PENDING_FALSE_ACK");let node=Arc::new(Router::new_with_clock(RouterConfig::new([]).with_sender("PENDING_PUBLISHER"),Box::new(||1000)));let peer=Arc::new(Router::new_with_clock(RouterConfig::new([]).with_sender("ACK_PEER"),Box::new(||1000)));let weak=Arc::downgrade(&node);let sid=Arc::new(AtomicUsize::new(usize::MAX));let s=sid.clone();
    let side=node.add_side_packed_with_options("falseACK",move|wire| {if let Ok(frame)=wire_format::peek_frame_info(wire) && frame.envelope.ty==ty {let n=weak.upgrade().unwrap();let seq=frame.reliable.unwrap().seq;let side=s.load(Ordering::SeqCst);let ack=peer.reliable_control_packet(DataType::ReliableAck,ty,seq).unwrap();n.rx_packed_from_side(&wire_format::pack_packet(&ack),side).unwrap();n.process_rx_queue().unwrap();assert_eq!(n.state.lock().reliable_tx[&Router::reliable_key(side,ty)].sent[&seq].first_offer,FirstHopOffer::AckedActive);return Err(TelemetryError::Io("side tx busy"))}Ok(())},RouterSideOptions{reliable_enabled:true,..Default::default()});sid.store(side,Ordering::SeqCst);node.clear_queues();let mut admitted=false;node.send_reliable_to_side_with_progress(side,RouterItem::Packet(packet(ty,ep,1)),false,&mut admitted).unwrap();assert!(!admitted);let state=node.state.lock();let sent=&state.reliable_tx[&Router::reliable_key(side,ty)].sent[&1];assert_eq!(sent.first_offer,FirstHopOffer::Pending);assert_eq!(sent.retries,0);
}
#[test]
fn exact_bound_receipt_during_active_offer_retires_after_success_at_same_clock() {
    crate::tests::ensure_common_test_schema();let node=Arc::new(Router::new_with_clock(RouterConfig::new([]).with_sender("BOUND_ACTIVE_PUBLISHER"),Box::new(||1000)));let peer=Arc::new(Router::new_with_clock(RouterConfig::new([]).with_sender("BOUND_ACK_PEER"),Box::new(||1000)));let weak=Arc::downgrade(&node);let sid=Arc::new(AtomicUsize::new(usize::MAX));let s=sid.clone();
    let side=node.add_side_packed_with_options("bound-inline",move|wire| {if let Ok(frame)=wire_format::peek_frame_info(wire) && frame.envelope.ty==DataType::DiscoverySchema {let n=weak.upgrade().unwrap();let side=s.load(Ordering::SeqCst);let seq=frame.reliable.unwrap().seq;let id=wire_format::packet_id_from_wire(wire).unwrap();let receipt=peer.build_end_to_end_ack_data(id,Router::sender_hash("BOUND_ACTIVE_PUBLISHER")).unwrap();let bytes=match receipt {RouterItem::Packet(p)=>wire_format::pack_packet(&p),RouterItem::Packed(b)=>Arc::from(b.as_ref())};n.rx_packed_from_side(&bytes,side).unwrap();n.process_rx_queue().unwrap();assert_eq!(n.state.lock().reliable_tx[&Router::reliable_key(side,DataType::DiscoverySchema)].sent[&seq].first_offer,FirstHopOffer::AckedActive);}Ok(())},RouterSideOptions{reliable_enabled:true,..Default::default()});sid.store(side,Ordering::SeqCst);node.clear_queues();let schema=discovery::build_discovery_schema("BOUND_ACTIVE_PUBLISHER",1001).unwrap();node.send_reliable_to_side(side,RouterItem::Packet(schema),false).unwrap();let state=node.state.lock();let stream=&state.reliable_tx[&Router::reliable_key(side,DataType::DiscoverySchema)];assert!(stream.sent.is_empty());assert_eq!(stream.next_seq,2);
}
#[test]
fn ack_removing_completed_row_during_replay_callback_never_resurrects_it() {
    crate::tests::ensure_common_test_schema();let(ty,ep)=application("PENDING_ACK_RETIRE");let now=Arc::new(AtomicU64::new(1000));let c=now.clone();let node=Arc::new(Router::new_with_clock(RouterConfig::new([]).with_sender("PENDING_PUBLISHER"),Box::new(move||c.load(Ordering::SeqCst))));let peer=Arc::new(Router::new_with_clock(RouterConfig::new([]).with_sender("ACK_PEER"),Box::new(||1000)));let weak=Arc::downgrade(&node);let sid=Arc::new(AtomicUsize::new(usize::MAX));let s=sid.clone();let calls=Arc::new(AtomicUsize::new(0));let count=calls.clone();
    let side=node.add_side_packed_with_options("retire-inline",move|wire|{if let Ok(frame)=wire_format::peek_frame_info(wire) && frame.envelope.ty==ty && count.fetch_add(1,Ordering::SeqCst)>0 {let n=weak.upgrade().unwrap();let side=s.load(Ordering::SeqCst);let ack=peer.reliable_control_packet(DataType::ReliableAck,ty,frame.reliable.unwrap().seq).unwrap();n.rx_packed_from_side(&wire_format::pack_packet(&ack),side).unwrap();n.process_rx_queue().unwrap();assert!(n.state.lock().reliable_tx[&Router::reliable_key(side,ty)].sent.is_empty());}Ok(())},RouterSideOptions{reliable_enabled:true,..Default::default()});sid.store(side,Ordering::SeqCst);node.clear_queues();node.send_reliable_to_side(side,RouterItem::Packet(packet(ty,ep,1)),false).unwrap();now.fetch_add(201,Ordering::SeqCst);node.process_all_queues().unwrap();assert_eq!(calls.load(Ordering::SeqCst),2);assert!(node.state.lock().reliable_tx[&Router::reliable_key(side,ty)].sent.is_empty());
}
