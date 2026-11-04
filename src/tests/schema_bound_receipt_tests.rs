//! Actual parser, transport history and finite owner boundary controls.
use super::*;
use std::sync::{Mutex, atomic::{AtomicU64,Ordering}};
type Wire = Arc<Mutex<Vec<Vec<u8>>>>;
fn captured_side(node: &Router,name:&str)->(usize,Wire) {
    let wire=Arc::new(Mutex::new(Vec::new())); let out=wire.clone();
    let side=node.add_side_packed_with_options(name,move |bytes|{out.lock().unwrap().push(bytes.to_vec());Ok(())},
        RouterSideOptions{reliable_enabled:true,link_local_enabled:false,..Default::default()});
    (side,wire)
}
fn source(name:&str)->(Router,usize,Wire) {
    let node=Router::new_with_clock(RouterConfig::new([]).with_sender(name),Box::new(||1000));
    let(side,wire)=captured_side(&node,"receiver");node.clear_queues();wire.lock().unwrap().clear();(node,side,wire)
}
fn receiver()->(Router,usize,Wire,Arc<AtomicU64>) {
    crate::tests::ensure_common_test_schema();
    let now=Arc::new(AtomicU64::new(1000));let clock=now.clone();
    let node=Router::new_with_clock(RouterConfig::default().with_sender("BOUND_RECEIVER"),Box::new(move||clock.load(Ordering::SeqCst)));
    let(side,wire)=captured_side(&node,"shared");
    for sender in ["SCHEMA_A","SCHEMA_B"] {
        node.rx_from_side(&discovery::build_discovery_announce(sender,1000,&[DataEndpoint::Discovery]).unwrap(),side).unwrap();
    }
    assert!(node.side_has_multiple_announcers_locked(&node.state.lock(),side,1000));
    node.clear_queues();wire.lock().unwrap().clear();(node,side,wire,now)
}
fn send_schema(node:&Router,side:usize,out:&Wire,stamp:u64)->(u64,Vec<u8>,u32) {
    let packet=discovery::build_discovery_schema(node.sender_arc().as_ref(),stamp).unwrap();let id=packet.packet_id();
    node.send_reliable_to_side(side,RouterItem::Packet(packet),false).unwrap();
    let bytes=out.lock().unwrap().iter().find(|wire|wire_format::packet_id_from_wire(wire).ok()==Some(id)).unwrap().clone();
    let seq=wire_format::peek_frame_info(&bytes).unwrap().reliable.unwrap().seq;(id,bytes,seq)
}
fn ack(out:&Wire,id:u64)->Vec<u8> {
    out.lock().unwrap().iter().find(|wire|wire_format::unpack_packet(wire).is_ok_and(|p|p.data_type()==DataType::ReliableAck&&p.payload()==id.to_le_bytes()&&p.wire_target_senders().len()==2)).expect("actual bound receipt").clone()
}
fn pending(node:&Router,side:usize)->Vec<u32> {
    node.state.lock().reliable_tx.get(&Router::reliable_key(side,DataType::DiscoverySchema)).map(|s|s.sent.keys().copied().collect()).unwrap_or_default()
}
fn binding(node:&Router,side:usize)->RouterTxHandlerFn {Router::side_ref(&node.state.lock(),side).unwrap().tx_handler.clone()}
fn owned_ack(node:&Router,id:u64,publisher:&str)->RouterItem {node.build_end_to_end_ack_data(id,Router::sender_hash(publisher)).unwrap()}
#[test]
fn two_independent_publishers_same_seq_cannot_retire_each_other() {
    let(receiver,rs,out,_)=receiver();let(a,as_,ao)=source("SCHEMA_A");let(b,bs,bo)=source("SCHEMA_B");
    let(aid,awire,aseq)=send_schema(&a,as_,&ao,1001);let(bid,bwire,bseq)=send_schema(&b,bs,&bo,1001);
    assert_eq!((aseq,bseq),(1,1));assert_ne!(aid,bid);
    receiver.rx_packed_from_side(&awire,rs).unwrap();receiver.process_all_queues().unwrap();let first=ack(&out,aid);
    a.rx_packed_from_side(&first,as_).unwrap();b.rx_packed_from_side(&first,bs).unwrap();
    assert!(pending(&a,as_).is_empty());assert_eq!(pending(&b,bs),vec![1]);
    b.rx_packed_from_side(&first,bs).unwrap();assert_eq!(pending(&b,bs),vec![1]);
    receiver.rx_packed_from_side(&bwire,rs).unwrap();receiver.process_all_queues().unwrap();b.rx_packed_from_side(&ack(&out,bid),bs).unwrap();assert!(pending(&b,bs).is_empty());
}
#[test]
fn invalid_schema_keeps_one_reserved_owner_and_later_good_retry_succeeds() {
    let(receiver,side,out,_)=receiver();
    let malformed=Packet::new(DataType::DiscoverySchema,&[DataEndpoint::Discovery],"SCHEMA_A",1001,Arc::<[u8]>::from([255,7,0])).unwrap();
    let malformed=wire_format::pack_packet_with_reliable(&malformed,wire_format::ReliableHeader{flags:0,seq:1,ack:0});
    assert!(receiver.rx_packed_from_side(&malformed,side).is_err());
    let(token,count)={let state=receiver.state.lock();let row=&state.reliable_rx[&Router::reliable_key(side,DataType::DiscoverySchema)];assert_eq!(row.control_mode,ControlRxMode::Reserved);(row.control_token,state.reliable_rx.len())};
    assert!(out.lock().unwrap().iter().all(|wire|wire_format::unpack_packet(wire).map_or(true,|p|p.wire_target_senders().len()!=2)));
    assert!(receiver.rx_packed_from_side(&malformed,side).is_err());
    assert_eq!(receiver.state.lock().local_admission_sequence,token);
    let(source,ss,sw)=source("SCHEMA_A");let(id,good,_)=send_schema(&source,ss,&sw,1002);
    receiver.rx_packed_from_side(&good,side).unwrap();receiver.process_all_queues().unwrap();ack(&out,id);
    assert!(receiver.rx_packed_from_side(&malformed,side).is_err());
    let state=receiver.state.lock();let row=&state.reliable_rx[&Router::reliable_key(side,DataType::DiscoverySchema)];
    assert_eq!(row.control_mode,ControlRxMode::BoundReceipt);assert_eq!(row.control_token,token);assert_eq!(state.reliable_rx.len(),count);
}
#[test]
fn shared_to_single_is_sticky_and_remove_side_destroys_the_owner() {
    let(receiver,rs,out,now)=receiver();let(sender,ss,sw)=source("SCHEMA_A");
    let(first,wire,_)=send_schema(&sender,ss,&sw,1001);receiver.rx_packed_from_side(&wire,rs).unwrap();receiver.process_all_queues().unwrap();sender.rx_packed_from_side(&ack(&out,first),ss).unwrap();
    let(expected,token)={let st=receiver.state.lock();let row=&st.reliable_rx[&Router::reliable_key(rs,DataType::DiscoverySchema)];(row.expected_seq,row.control_token)};
    now.store(1000+DISCOVERY_ROUTE_TTL_MS+1,Ordering::SeqCst);
    receiver.rx_from_side(&discovery::build_discovery_announce("SCHEMA_A",now.load(Ordering::SeqCst),&[DataEndpoint::Discovery]).unwrap(),rs).unwrap();
    assert!(!receiver.side_has_multiple_announcers_locked(&receiver.state.lock(),rs,now.load(Ordering::SeqCst)));
    let(second,wire,seq)=send_schema(&sender,ss,&sw,1002);assert_eq!(seq,2);
    receiver.rx_packed_from_side(&wire,rs).unwrap();receiver.process_all_queues().unwrap();sender.rx_packed_from_side(&ack(&out,second),ss).unwrap();assert!(pending(&sender,ss).is_empty());
    {let st=receiver.state.lock();let row=&st.reliable_rx[&Router::reliable_key(rs,DataType::DiscoverySchema)];assert_eq!(row.expected_seq,expected);assert_eq!(row.control_token,token);assert_eq!(row.control_mode,ControlRxMode::BoundReceipt);}
    receiver.remove_side(rs).unwrap();assert!(!receiver.state.lock().reliable_rx.contains_key(&Router::reliable_key(rs,DataType::DiscoverySchema)));
    let(new_side,_)=captured_side(&receiver,"replacement");assert_eq!(new_side,rs);
    assert!(!receiver.state.lock().reliable_rx.contains_key(&Router::reliable_key(new_side,DataType::DiscoverySchema)));
}
#[test]
fn valid_max_sequence_does_not_become_a_mode_sentinel() {
    let(receiver,side,out,_)=receiver();let packet=discovery::build_discovery_schema("SCHEMA_A",1003).unwrap();let id=packet.packet_id();
    let wire=wire_format::pack_packet_with_reliable(&packet,wire_format::ReliableHeader{flags:0,seq:u32::MAX,ack:0});
    receiver.rx_packed_from_side(&wire,side).unwrap();receiver.process_all_queues().unwrap();ack(&out,id);
    let state=receiver.state.lock();let row=&state.reliable_rx[&Router::reliable_key(side,DataType::DiscoverySchema)];
    assert_eq!(row.expected_seq,1,"bound protocol never rebases numeric hop window");assert_eq!(row.control_mode,ControlRxMode::BoundReceipt);
    assert_eq!(u32::MAX.wrapping_add(1),0,"zero is an ordinary numeric wrap, not a mode tag");
}
#[test]
fn cold_logical_admission_refusal_never_owns_a_receipt() {
    let(receiver,side,out,_)=receiver();let original_budget={let mut state=receiver.state.lock();let old=state.memory.max_queue_budget;state.memory.max_queue_budget=state.shared_queue_bytes_used();old};
    let binding=binding(&receiver,side);let token=receiver.state.lock().local_admission_sequence;
    assert!(receiver.reserve_bound_control_mode(side,DataType::DiscoverySchema,&binding).is_err());
    assert!(!receiver.state.lock().reliable_rx.contains_key(&Router::reliable_key(side,DataType::DiscoverySchema)));
    assert_eq!(receiver.state.lock().local_admission_sequence,token);assert!(out.lock().unwrap().is_empty());
    receiver.state.lock().memory.max_queue_budget=original_budget;
    receiver.reserve_bound_control_mode(side,DataType::DiscoverySchema,&binding).unwrap();
}
#[test]
fn old_reserved_owner_cannot_commit_after_real_side_remove_readd() {
    let(receiver,side,out,_)=receiver();let old_binding=binding(&receiver,side);let old_token=receiver.reserve_bound_control_mode(side,DataType::DiscoverySchema,&old_binding).unwrap();
    let packet=discovery::build_discovery_schema("SCHEMA_A",1003).unwrap();receiver.learn_discovery_packet(&packet,Some(side),false).unwrap();
    let ack=owned_ack(&receiver,packet.packet_id(),"SCHEMA_A");let priority=Router::router_item_priority(&ack).unwrap();
    receiver.remove_side(side).unwrap();let(new_side,new_out)=captured_side(&receiver,"new actual side");assert_eq!(new_side,side);
    let new_binding=binding(&receiver,new_side);let new_token=receiver.reserve_bound_control_mode(new_side,DataType::DiscoverySchema,&new_binding).unwrap();assert!(new_token>old_token);
    assert!(receiver.commit_bound_control_receipt(side,DataType::DiscoverySchema,old_token,&old_binding,ack,priority).is_err());
    let st=receiver.state.lock();let row=&st.reliable_rx[&Router::reliable_key(side,DataType::DiscoverySchema)];assert_eq!(row.control_token,new_token);assert_eq!(row.control_mode,ControlRxMode::Reserved);
    assert!(out.lock().unwrap().is_empty());assert!(new_out.lock().unwrap().is_empty());
}
#[test]
fn existing_rx_row_layout_and_logical_charge_are_measured() {
    eprintln!("SCHEMA_RX_LAYOUT {}",serde_json::json!({"rx_state":size_of::<ReliableRxState>(),"alignment":core::mem::align_of::<ReliableRxState>(),"mode":size_of::<ControlRxMode>(),"token":size_of::<u64>(),"tag_logical":CONTROL_RX_TAG_LOGICAL_BYTES,"reserved_row_logical":CONTROL_RX_ROW_LOGICAL_BYTES,"pointer":size_of::<usize>()}));
    let(receiver,side,_,_)=receiver();let owner=binding(&receiver,side);let before=receiver.state.lock().reliable_rx_buffered_bytes();
    receiver.reserve_bound_control_mode(side,DataType::DiscoverySchema,&owner).unwrap();
    let after=receiver.state.lock().reliable_rx_buffered_bytes();
    assert!(after>=before+CONTROL_RX_ROW_LOGICAL_BYTES+CONTROL_RX_TAG_LOGICAL_BYTES);
}

#[test]
fn reliable_schema_lost_data_and_receipt_keep_exact_original_until_retirement() {
    use crate::config::RELIABLE_RETRANSMIT_MS;
    let(receiver,rs,out,clock)=receiver();
    let now=clock.clone();
    let sender=Router::new_with_clock(RouterConfig::new([]).with_sender("SCHEMA_A"),Box::new(move||now.load(Ordering::SeqCst)));
    let(ss,sent)=captured_side(&sender,"shared receiver");sender.clear_queues();sent.lock().unwrap().clear();
    let(id,first,seq)=send_schema(&sender,ss,&sent,1001);assert_eq!(seq,1);
    // Drop first DATA; the actual default reliable side must retry the same owner.
    clock.fetch_add(RELIABLE_RETRANSMIT_MS+1,Ordering::SeqCst);sender.process_all_queues().unwrap();
    let attempts=sent.lock().unwrap().iter().filter(|wire|wire_format::packet_id_from_wire(wire).ok()==Some(id)).cloned().collect::<Vec<_>>();assert!(attempts.len()>=2);
    assert!(attempts.iter().all(|wire|wire_format::unpack_packet(wire).unwrap().timestamp()==1001));
    receiver.rx_packed_from_side(attempts.last().unwrap(),rs).unwrap();receiver.process_all_queues().unwrap();let _lost_receipt=ack(&out,id);
    assert_eq!(pending(&sender,ss),vec![1]);
    clock.fetch_add(RELIABLE_RETRANSMIT_MS+1,Ordering::SeqCst);sender.process_all_queues().unwrap();
    receiver.rx_packed_from_side(&first,rs).unwrap();receiver.process_all_queues().unwrap();
    sender.rx_packed_from_side(&ack(&out,id),ss).unwrap();assert!(pending(&sender,ss).is_empty());
    let attempts=sent.lock().unwrap().iter().filter(|wire|wire_format::packet_id_from_wire(wire).ok()==Some(id)).cloned().collect::<Vec<_>>();assert!(attempts.len()>=3);
    assert!(attempts.iter().all(|wire|wire_format::unpack_packet(wire).unwrap().timestamp()==1001&&wire_format::peek_frame_info(wire).unwrap().reliable.unwrap().seq==1));
}
