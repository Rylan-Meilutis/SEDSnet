//! Real advertisements distinguish logical address publishers from physical hop peers.
use super::*;
use std::sync::{Mutex,atomic::{AtomicU64,Ordering}};
type Wire=Arc<Mutex<Vec<Vec<u8>>>>;
fn node(name:&str,clock:&Arc<AtomicU64>)->Router {let now=clock.clone();Router::new_with_clock(RouterConfig::new([]).with_sender(name),Box::new(move||now.load(Ordering::SeqCst)))}
fn side(node:&Router)->(usize,Wire) {let wire=Arc::new(Mutex::new(Vec::new()));let out=wire.clone();let s=node.add_side_packed_with_options("physical test link",move|b|{out.lock().unwrap().push(b.to_vec());Ok(())},RouterSideOptions{reliable_enabled:true,link_local_enabled:true,..Default::default()});(s,wire)}
fn address(name:&str,clock:&Arc<AtomicU64>)->Vec<u8> {let source=node(name,clock);let(_,out)=side(&source);source.announce_discovery().unwrap();source.process_all_queues().unwrap();out.lock().unwrap().iter().find(|wire|wire_format::unpack_packet(wire).is_ok_and(|p|p.data_type()==DataType::DiscoveryAddress)).expect("real producer emits Address17").clone()}
fn announce(node:&Router,s:usize,name:&str,stamp:u64) {node.rx_from_side(&discovery::build_discovery_announce(name,stamp,&[]).unwrap(),s).unwrap();}
fn multiple(node:&Router,s:usize,now:u64)->bool {node.side_has_multiple_announcers_locked(&node.state.lock(),s,now)}
#[test]
fn forwarded_logical_addresses_do_not_disable_point_to_point_ordered_ack() {
    crate::tests::ensure_common_test_schema();let clock=Arc::new(AtomicU64::new(0));let receiver=node("PHYSICAL_LEAF",&clock);let(rs,acks)=side(&receiver);announce(&receiver,rs,"PHYSICAL_BRIDGE",0);
    for name in ["LOGICAL_GS","LOGICAL_VB","LOGICAL_DAQ"] {receiver.rx_packed_from_side(&address(name,&clock),rs).unwrap();}
    assert_eq!(receiver.state.lock().discovery_routes[&rs].announcers.len(),4,"logical routes remain intact");
    assert!(!multiple(&receiver,rs,0),"forwardable Address17 cannot manufacture physical multidrop peers");
    let ep=crate::config::register_endpoint_with_description("PHYSICAL_HOP_APP_EP","test local consumer",false).unwrap();
    let ty=crate::config::register_data_type_with_description("PHYSICAL_HOP_APP","ordinary ordered app",crate::MessageElement::Static(1,crate::MessageDataType::UInt32,crate::MessageClass::Data),&[ep],crate::ReliableMode::Ordered,80).unwrap();
    let source=node("PHYSICAL_BRIDGE",&clock);let(ss,sent)=side(&source);source.clear_queues();sent.lock().unwrap().clear();
    let packet=Packet::new(ty,&[ep],"PHYSICAL_BRIDGE",0,Arc::<[u8]>::from(7u32.to_le_bytes())).unwrap();let id=packet.packet_id();source.send_reliable_to_side(ss,RouterItem::Packet(packet),false).unwrap();
    let wire=sent.lock().unwrap().iter().find(|w|wire_format::packet_id_from_wire(w).ok()==Some(id)).unwrap().clone();receiver.rx_packed_from_side(&wire,rs).unwrap();receiver.process_all_queues().unwrap();
    let ack=acks.lock().unwrap().iter().find(|w|wire_format::unpack_packet(w).is_ok_and(|p|p.data_type()==DataType::ReliableAck&&p.payload().len()==8&&u32::from_le_bytes(p.payload()[..4].try_into().unwrap())==ty.as_u32()&&u32::from_le_bytes(p.payload()[4..].try_into().unwrap())==1&&p.wire_target_senders().is_empty())).expect("actual ordinary hop ACK").clone();source.rx_packed_from_side(&ack,ss).unwrap();
    assert!(source.state.lock().reliable_tx[&Router::reliable_key(ss,ty)].sent.is_empty());
}

#[test]
fn actual_peer_layout() {println!("ACTUAL_PEER_LAYOUT size={} align={}",size_of::<DiscoverySenderState>(),core::mem::align_of::<DiscoverySenderState>());}
#[test]
fn genuine_nonforwardable_peers_and_zero_clock_remain_shared() {
    let clock=Arc::new(AtomicU64::new(0));let receiver=node("TRUE_BUS",&clock);let(s,_)=side(&receiver);
    announce(&receiver,s,"DIRECT_A",0);announce(&receiver,s,"DIRECT_B",0);
    assert!(multiple(&receiver,s,0));
    let st=receiver.state.lock();assert!(st.discovery_routes[&s].announcers.values().all(|p|p.has_hop_local_evidence&&p.last_hop_local_ms==0));
}
#[test]
fn logical_address_flood_cannot_keep_expired_physical_peer_shared() {
    let clock=Arc::new(AtomicU64::new(0));let receiver=node("AGE_LEAF",&clock);let(s,_)=side(&receiver);
    announce(&receiver,s,"AGED_A",0);announce(&receiver,s,"AGED_B",0);assert!(multiple(&receiver,s,0));
    let later=DISCOVERY_ROUTE_TTL_MS+1;clock.store(later,Ordering::SeqCst);
    // Refresh logical reachability through the real Address decoder; never physical age.
    receiver.rx_packed_from_side(&address("AGED_B",&clock),s).unwrap();
    assert!(!multiple(&receiver,s,later));
    {let st=receiver.state.lock();let b=&st.discovery_routes[&s].announcers["AGED_B"];assert_eq!(b.last_seen_ms,later);assert_eq!(b.last_hop_local_ms,0);}
    announce(&receiver,s,"AGED_A",later);assert!(!multiple(&receiver,s,later));
    // Actual retained empty Announce fastpath must renew B's physical witness.
    announce(&receiver,s,"AGED_B",later);assert!(multiple(&receiver,s,later));
}
#[test]
fn validated_topology_full_retained_and_packed_fastpath_renew_same_peer() {
    let clock=Arc::new(AtomicU64::new(0));let receiver=node("TOPO_LEAF",&clock);let(s,_)=side(&receiver);
    let wire=address("TOPO_DIRECT",&clock);let packet=wire_format::unpack_packet(&wire).unwrap();let ad=discovery::decode_discovery_address(&packet).unwrap();receiver.rx_packed_from_side(&wire,s).unwrap();
    assert!(!receiver.state.lock().discovery_routes[&s].announcers["TOPO_DIRECT"].has_hop_local_evidence);
    let boards=[discovery::TopologyBoardNode{sender_id:"TOPO_DIRECT".into(),reachable_endpoints:vec![],reachable_timesync_sources:vec![],connections:vec![]}];
    let topology=discovery::build_discovery_topology("TOPO_DIRECT",0,&boards).unwrap();receiver.rx_from_side(&topology,s).unwrap();
    assert!(receiver.state.lock().discovery_routes[&s].announcers["TOPO_DIRECT"].has_hop_local_evidence);
    clock.store(17,Ordering::SeqCst);let fresh_topology=discovery::build_discovery_topology("TOPO_DIRECT",17,&boards).unwrap();receiver.rx_from_side(&fresh_topology,s).unwrap();assert_eq!(receiver.state.lock().discovery_routes[&s].announcers["TOPO_DIRECT"].last_hop_local_ms,17);
    let compact_source=discovery::build_discovery_topology(&format!("@addr:{}",ad.address),0,&boards).unwrap();let packed=wire_format::pack_packet(&compact_source);
    clock.store(23,Ordering::SeqCst);assert!(receiver.consume_known_packed_topology(s,packed.as_ref()).unwrap());
    let st=receiver.state.lock();let peers=&st.discovery_routes[&s].announcers;assert_eq!(peers.len(),1);assert_eq!(peers["TOPO_DIRECT"].last_hop_local_ms,23);
}
#[test]
fn malformed_crc_schema_and_generic_liveness_cannot_renew_physical_age() {
    let clock=Arc::new(AtomicU64::new(0));let receiver=node("BAD_LEAF",&clock);let(s,_)=side(&receiver);announce(&receiver,s,"DIRECT_VALID",0);clock.store(99,Ordering::SeqCst);
    assert!(Packet::new(DataType::DiscoveryAnnounce,&[DataEndpoint::Discovery],"DIRECT_VALID",99,Arc::<[u8]>::from([255,7,0])).is_err(),"actual constructor rejects malformed announce width before RX");let malformed=Packet::new(DataType::DiscoveryTimeSyncSources,&[DataEndpoint::Discovery],"DIRECT_VALID",99,Arc::<[u8]>::from([1,0,0,0])).unwrap();assert!(receiver.rx_from_side(&malformed,s).is_err());
    let valid=discovery::build_discovery_announce("DIRECT_VALID",99,&[]).unwrap();let mut bad=wire_format::pack_packet(&valid).as_ref().to_vec();*bad.last_mut().unwrap()^=1;let _=receiver.rx_packed_from_side(&bad,s);
    receiver.refresh_peer_liveness(s,sender_address_u32("DIRECT_VALID"));receiver.note_schema_received(s,"DIRECT_VALID");
    let st=receiver.state.lock();let peer=&st.discovery_routes[&s].announcers["DIRECT_VALID"];assert_eq!(peer.last_seen_ms,99);assert_eq!(peer.last_hop_local_ms,0);
}
#[test]
fn physical_clock_wrap_and_numeric_alias_never_use_zero_sentinel() {
    let clock=Arc::new(AtomicU64::new(u64::MAX-5));let receiver=node("WRAP_LEAF",&clock);let(s,_)=side(&receiver);
    announce(&receiver,s,"WRAP_A",0);announce(&receiver,s,"WRAP_B",0);assert!(multiple(&receiver,s,u64::MAX-5));clock.store(3,Ordering::SeqCst);assert!(multiple(&receiver,s,3));
    let later=DISCOVERY_ROUTE_TTL_MS+1;clock.store(later,Ordering::SeqCst);assert!(!multiple(&receiver,s,later));
    receiver.rx_packed_from_side(&address("WRAP_A",&clock),s).unwrap();let wire=address("WRAP_A",&clock);let ad=discovery::decode_discovery_address(&wire_format::unpack_packet(&wire).unwrap()).unwrap();
    announce(&receiver,s,&format!("@addr:{}",ad.address),later);
    let st=receiver.state.lock();let peers=&st.discovery_routes[&s].announcers;assert_eq!(peers.len(),2);assert_eq!(peers["WRAP_A"].last_hop_local_ms,later);assert_eq!(peers["WRAP_B"].last_hop_local_ms,u64::MAX-5);
}
#[test]
fn cold_numeric_hop_witness_survives_actual_address_identity_resolution() {
    let clock=Arc::new(AtomicU64::new(0));let receiver=node("COLD_ALIAS_LEAF",&clock);let(s,_)=side(&receiver);
    let wire=address("COLD_DIRECT",&clock);let ad=discovery::decode_discovery_address(&wire_format::unpack_packet(&wire).unwrap()).unwrap();let numeric=format!("@addr:{}",ad.address);
    announce(&receiver,s,&numeric,0);
    {let st=receiver.state.lock();assert!(st.discovery_routes[&s].announcers[&numeric].has_hop_local_evidence);}
    clock.store(11,Ordering::SeqCst);receiver.rx_packed_from_side(&wire,s).unwrap();
    let st=receiver.state.lock();let peers=&st.discovery_routes[&s].announcers;if let Some(alias)=peers.get(&numeric) {assert!(!alias.has_hop_local_evidence,"logical alias may remain but cannot count twice");assert_eq!(alias.last_hop_local_ms,0);}let peer=&peers["COLD_DIRECT"];assert!(peer.has_hop_local_evidence,"same physical owner proof must survive actual numeric-to-hostname alias resolution");assert_eq!(peer.last_hop_local_ms,0,"logical Address cannot refresh the physical observation");
}

#[test]
fn actual_canonical_hop_refresh_cannot_double_count_one_numeric_owner() {
    let clock=Arc::new(AtomicU64::new(0));let receiver=node("ALIAS_GUARD_LEAF",&clock);let(s,_)=side(&receiver);
    let wire=address("ALIAS_GUARD_DIRECT",&clock);let ad=discovery::decode_discovery_address(&wire_format::unpack_packet(&wire).unwrap()).unwrap();let numeric=format!("@addr:{}",ad.address);
    announce(&receiver,s,&numeric,0);assert!(!multiple(&receiver,s,0));
    clock.store(11,Ordering::SeqCst);receiver.rx_packed_from_side(&wire,s).unwrap();assert!(!multiple(&receiver,s,11));
    clock.store(12,Ordering::SeqCst);announce(&receiver,s,"ALIAS_GUARD_DIRECT",12);
    assert!(!multiple(&receiver,s,12),"same actual numericowner cannot become two physicalpeers after valid canonical advertisement");
    announce(&receiver,s,"DIFFERENT_REAL_DIRECT",12);assert!(multiple(&receiver,s,12),"actual distinct directpeer remains protected");
}
fn cold_alias_with_wrong_source(clock:&Arc<AtomicU64>,name:&str)->(Router,usize,Wire,Vec<u8>,discovery::AddressAdvertisement,String) {
    let receiver=node("MIGRATION_LEAF",clock);let(s,out)=side(&receiver);let wire=address(name,clock);let ad=discovery::decode_discovery_address(&wire_format::unpack_packet(&wire).unwrap()).unwrap();let numeric=format!("@addr:{}",ad.address);announce(&receiver,s,&numeric,0);
    let wrong=discovery::build_discovery_address("DIFFERENT_SOURCE",clock.load(Ordering::SeqCst),&ad).unwrap();receiver.rx_from_side(&wrong,s).unwrap();
    (receiver,s,out,wire,ad,numeric)
}
#[test]
fn wrong_source_does_not_migrate_and_real_address_does_not_extend_ttl() {
    let clock=Arc::new(AtomicU64::new(0));let(receiver,s,_,wire,ad,numeric)=cold_alias_with_wrong_source(&clock,"SOURCE_BOUND_DIRECT");
    {let st=receiver.state.lock();let peers=&st.discovery_routes[&s].announcers;assert!(peers[&numeric].has_hop_local_evidence);assert!(!peers[ad.hostname.as_str()].has_hop_local_evidence);}
    let later=DISCOVERY_ROUTE_TTL_MS+1;clock.store(later,Ordering::SeqCst);receiver.rx_packed_from_side(&wire,s).unwrap();
    let st=receiver.state.lock();let peers=&st.discovery_routes[&s].announcers;assert_eq!(peers[ad.hostname.as_str()].last_hop_local_ms,0);assert!(!peers[ad.hostname.as_str()].has_live_hop_local_evidence(later));if let Some(alias)=peers.get(&numeric){assert!(!alias.has_hop_local_evidence);}
}
#[test]
fn stale_side_owner_cannot_migrate_new_sides_physical_evidence() {
    let clock=Arc::new(AtomicU64::new(0));let receiver=node("ABA_MIGRATION_LEAF",&clock);let(old,_) =side(&receiver);let binding=Router::side_ref(&receiver.state.lock(),old).unwrap().tx_handler.clone();receiver.remove_side(old).unwrap();let(s,_)=side(&receiver);assert_eq!(s,old);
    let wire=address("ABA_DIRECT",&clock);let ad=discovery::decode_discovery_address(&wire_format::unpack_packet(&wire).unwrap()).unwrap();let numeric=format!("@addr:{}",ad.address);announce(&receiver,s,&numeric,0);let wrong=discovery::build_discovery_address("DIFFERENT_SOURCE",0,&ad).unwrap();receiver.rx_from_side(&wrong,s).unwrap();
    let mut st=receiver.state.lock();Router::reconcile_unresolved_hop_alias_locked(&mut st,s,(&ad.hostname,ad.address,ad.owner_hash),ad.address,0,&binding);assert!(st.discovery_routes[&s].announcers[&numeric].has_hop_local_evidence);assert!(!st.discovery_routes[&s].announcers[ad.hostname.as_str()].has_hop_local_evidence);
}
#[test]
fn newer_canonical_observation_survives_old_address_capture() {
    let clock=Arc::new(AtomicU64::new(0));let(receiver,s,_,_,ad,numeric)=cold_alias_with_wrong_source(&clock,"NEWER_DIRECT");clock.store(20,Ordering::SeqCst);announce(&receiver,s,"NEWER_DIRECT",20);
    let binding=Router::side_ref(&receiver.state.lock(),s).unwrap().tx_handler.clone();let mut st=receiver.state.lock();Router::reconcile_unresolved_hop_alias_locked(&mut st,s,(&ad.hostname,ad.address,ad.owner_hash),ad.address,11,&binding);
    let peers=&st.discovery_routes[&s].announcers;assert_eq!(peers["NEWER_DIRECT"].last_hop_local_ms,20);assert!(!peers[&numeric].has_hop_local_evidence);assert_eq!(peers[&numeric].last_hop_local_ms,0);
}
#[test]
fn competing_known_address_owner_keeps_conservative_numeric_guard() {
    let clock=Arc::new(AtomicU64::new(0));let(receiver,s,_,wire,ad,numeric)=cold_alias_with_wrong_source(&clock,"CONTESTED_DIRECT");
    let c=clock.clone();let competitor=Router::new_with_clock(RouterConfig::new([]).with_sender("OTHER_KNOWN_OWNER").with_static_address(ad.address),Box::new(move||c.load(Ordering::SeqCst)));let(_,out)=side(&competitor);competitor.announce_discovery().unwrap();competitor.process_all_queues().unwrap();let other=out.lock().unwrap().iter().find(|w|wire_format::unpack_packet(w).is_ok_and(|p|p.data_type()==DataType::DiscoveryAddress)).unwrap().clone();receiver.rx_packed_from_side(&other,s).unwrap();
    receiver.rx_packed_from_side(&wire,s).unwrap();
    let st=receiver.state.lock();assert!(st.address_book.values().filter(|p|p.address==ad.address).count()>=2,"actual conflicting address ingestion premise");assert!(st.discovery_routes[&s].announcers[&numeric].has_hop_local_evidence);drop(st);
    announce(&receiver,s,"CONTESTED_DIRECT",1);assert!(multiple(&receiver,s,0),"ambiguous same-address alias must not be silently merged");
}
