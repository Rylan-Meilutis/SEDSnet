#![cfg(all(feature = "std", feature = "discovery"))]
use sedsnet::discovery::{build_discovery_topology, TopologyBoardNode, DISCOVERY_ROUTE_TTL_MS};
use sedsnet::router::{Router, RouterConfig};
use std::sync::{Arc, atomic::{AtomicU64, Ordering}};

#[test]
fn stream_data_and_response_cross_gateway_without_leaf_address_advertisement() {
    use sedsnet::router::P2pStreamEventKind;
    use std::{collections::VecDeque, sync::Mutex};
    let gs = Arc::new(Router::new_with_clock(RouterConfig::new([]).with_sender("GS"),Box::new(||0)));
    let gb = Arc::new(Router::new_with_clock(RouterConfig::new([]).with_sender("GB"),Box::new(||0)));
    let ab = Arc::new(Router::new_with_clock(RouterConfig::new([]).with_sender("AB"),Box::new(||0)));
    let frames = (0..4).map(|_| Arc::new(Mutex::new(VecDeque::<Vec<u8>>::new()))).collect::<Vec<_>>();
    let add = |router: &Router, name, i: usize| {
        let queue = frames[i].clone();
        router.add_side_packed(name,move |bytes| { queue.lock().unwrap().push_back(bytes.to_vec()); Ok(()) })
    };
    let gs_side=add(&gs,"gb",0); let gb_gs=add(&gb,"gs",1);
    let gb_ab=add(&gb,"ab",2); let ab_side=add(&ab,"gb",3);
    let node = |sender: &str, connections: Vec<String>| TopologyBoardNode { sender_id:sender.into(),reachable_endpoints:vec![],reachable_timesync_sources:vec![],connections };
    for (router,side,sender,boards) in [
        (&gs,gs_side,"GB",vec![node("GB",vec!["AB".into()])]),
        (&gb,gb_gs,"GS",vec![node("GS",vec![])]),
        (&gb,gb_ab,"AB",vec![node("AB",vec![])]),
        (&ab,ab_side,"GB",vec![node("GB",vec!["GS".into()])]),
    ] { router.rx_from_side(&build_discovery_topology(sender,0,&boards).unwrap(),side).unwrap(); }
    let pump = || {
        for _ in 0..100 {
            for r in [&gs,&gb,&ab] { r.process_all_queues().unwrap(); }
            let mut delivered=false;
            for (i,router,side) in [(0,&gb,gb_gs),(1,&gs,gs_side),(2,&ab,ab_side),(3,&gb,gb_ab)] {
                for _ in 0..1000 {
                    let frame = frames[i].lock().unwrap().pop_front();
                    let Some(frame)=frame else { break; };
                    router.rx_packed_from_side(&frame,side).unwrap(); delivered=true;
                }
            }
            if !delivered { return; }
        }
        panic!("P2P routing did not quiesce");
    };
    pump();
    assert!(!gs.address_book().iter().any(|e|e.hostname.as_ref()=="AB"));
    let replies=Arc::new(Mutex::new(Vec::new())); let events=replies.clone();
    gs.bind_p2p_stream_port(49152,move |event| { events.lock().unwrap().push((event.kind,event.payload.to_vec())); Ok(()) }).unwrap();
    let received=Arc::new(Mutex::new(Vec::new())); let commands=received.clone(); let weak=Arc::downgrade(&ab);
    ab.bind_p2p_stream_port(4510,move |event| {
        if event.kind==P2pStreamEventKind::Data {
            commands.lock().unwrap().push(event.payload.to_vec());
            weak.upgrade().unwrap().send_p2p_stream(event.stream_id,b"state-response")?;
        }
        Ok(())
    }).unwrap();
    let stream=gs.open_p2p_stream_to_hostname("AB",4510,49152).unwrap(); pump();
    assert!(replies.lock().unwrap().iter().any(|(kind,_)|*kind==P2pStreamEventKind::Connected));
    gs.send_p2p_stream(stream,b"ota-chunk").unwrap(); pump();
    assert_eq!(*received.lock().unwrap(),vec![b"ota-chunk".to_vec()]);
    assert!(replies.lock().unwrap().iter().any(|(kind,payload)|*kind==P2pStreamEventKind::Data && payload==b"state-response"));
}

#[test]
fn topology_only_hostname_is_a_valid_stream_target_and_expires() {
    let clock = Arc::new(AtomicU64::new(0));
    let c = clock.clone();
    let router = Router::new_with_clock(RouterConfig::new([]).with_sender("GS"), Box::new(move || c.load(Ordering::Relaxed)));
    let side = router.add_side_packet("gateway", |_| Ok(()));
    let boards = vec![TopologyBoardNode {
        sender_id: "GB".into(), reachable_endpoints: vec![], reachable_timesync_sources: vec![],
        connections: vec!["AB".into(), "VB".into(), "DAQ".into()],
    }];
    router.rx_from_side(&build_discovery_topology("GB", 0, &boards).unwrap(),side).unwrap();
    router.process_all_queues().unwrap();
    assert!(!router.address_book().iter().any(|e| e.hostname.as_ref() == "AB"), "test requires no link-local AB address advertisement");
    for hostname in ["AB","VB","DAQ"] {
        let entry = router.resolve_hostname(hostname).expect("retained downstream topology must resolve by hostname");
        assert_eq!(entry.hostname.as_ref(),hostname);
        assert_eq!(router.resolve_address(entry.address).unwrap().hostname.as_ref(),hostname);
        let stream = router.open_p2p_stream_to_hostname(hostname,4510,49152).expect("topology-only OTA target must allow stream establishment");
        router.close_p2p_stream(stream).unwrap();
    }
    assert!(router.resolve_hostname("UNSEEN").is_none());
    clock.store(DISCOVERY_ROUTE_TTL_MS+1,Ordering::Relaxed);
    assert!(router.resolve_hostname("AB").is_none(), "expired topology must not keep a board online");
}
