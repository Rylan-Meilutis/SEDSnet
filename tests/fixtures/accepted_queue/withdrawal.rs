use sedsnet::{
    MessageClass, MessageDataType, MessageElement, ReliableMode, config,
    discovery::{TopologyBoardNode, build_discovery_topology},
    router::{EndpointHandler, Router, RouterConfig, RouterSideOptions},
    wire_format,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
pub fn run(mode: ReliableMode) {
    let ep = config::register_endpoint("PRESSURE_RECORDER", false).unwrap();
    let ty = config::register_data_type_with_description(
        "PRESSURE_BATCH",
        "",
        MessageElement::Static(1, MessageDataType::UInt32, MessageClass::Data),
        &[ep],
        mode,
        0,
    )
    .unwrap();
    let tick = Arc::new(AtomicU64::new(1000));
    let clock = tick.clone();
    let source = Router::new_with_clock(
        RouterConfig::new([]).with_sender("VB"),
        Box::new(move || clock.load(Ordering::SeqCst)),
    );
    let wire = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let out = wire.clone();
    let opts = RouterSideOptions {
        reliable_enabled: false,
        header_template_enabled: false,
        ..Default::default()
    };
    let side = source.add_side_packed_with_options(
        "CAN",
        move |b| {
            out.lock().unwrap().push(b.to_vec());
            Ok(())
        },
        opts.clone(),
    );
    let effects = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let seen = effects.clone();
    let clock = tick.clone();
    let sink = Router::new_with_clock(
        RouterConfig::new([EndpointHandler::new_packet_handler(ep, move |p| {
            seen.lock().unwrap().push(p.payload().to_vec());
            Ok(())
        })])
        .with_sender("DAQ"),
        Box::new(move || clock.load(Ordering::SeqCst)),
    );
    let receipts = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let out = receipts.clone();
    let sink_side = sink.add_side_packed_with_options(
        "CAN",
        move |b| {
            out.lock().unwrap().push(b.to_vec());
            Ok(())
        },
        opts,
    );
    source.clear_queues();
    sink.clear_queues();
    let announce = |present: bool| {
        let mut nodes = vec![TopologyBoardNode {
            sender_id: "GW".into(),
            reachable_endpoints: vec![],
            reachable_timesync_sources: vec![],
            connections: if present { vec!["DAQ".into()] } else { vec![] },
        }];
        if present {
            nodes.push(TopologyBoardNode {
                sender_id: "DAQ".into(),
                reachable_endpoints: vec![ep],
                reachable_timesync_sources: vec![],
                connections: vec!["GW".into()],
            });
        }
        let p = build_discovery_topology("GW", tick.load(Ordering::SeqCst), &nodes).unwrap();
        source
            .rx_packed_from_side(&wire_format::pack_packet(&p), side)
            .unwrap();
    };
    announce(true);
    source.clear_queues();
    wire.lock().unwrap().clear();
    source.log_queue(ty, &[52u32]).unwrap();
    source.process_all_queues_with_timeout(0).unwrap();
    let pending = source.export_reliable_pending_stats();
    let packet = pending
        .iter()
        .find(|p| p.data_type == ty)
        .expect("actual packed publication must create pending owner")
        .packet_id;
    assert!(
        wire.lock()
            .unwrap()
            .iter()
            .any(|b| wire_format::packet_id_from_wire(b).ok() == Some(packet)),
        "real frozen data never reached transport"
    );
    // Lose the first physical transmission, then receive a real packed bridge
    // snapshot which temporarily no longer lists DAQ. No receipt has arrived.
    wire.lock().unwrap().clear();
    tick.store(1010, Ordering::SeqCst);
    announce(false);
    assert!(
        source
            .export_reliable_pending_stats()
            .iter()
            .any(|p| p.packet_id == packet),
        "route withdrawal retired {mode:?} without a destination ACK"
    );
    tick.store(1020, Ordering::SeqCst);
    announce(true);
    let mut actual_ack = false;
    for _ in 0..30 {
        tick.fetch_add(100, Ordering::SeqCst);
        source.process_all_queues_with_timeout(0).unwrap();
        for b in wire.lock().unwrap().drain(..) {
            sink.rx_packed_from_side(&b, sink_side).unwrap();
        }
        sink.process_all_queues_with_timeout(0).unwrap();
        for b in receipts.lock().unwrap().drain(..) {
            if let Ok(p) = wire_format::unpack_packet(&b)
                && p.data_type() == config::DataType::ReliableAck
                && p.payload() == packet.to_le_bytes()
            {
                actual_ack = true;
            }
            source.rx_packed_from_side(&b, side).unwrap();
        }
        if actual_ack
            && !source
                .export_reliable_pending_stats()
                .iter()
                .any(|p| p.packet_id == packet)
        {
            break;
        }
    }
    assert_eq!(
        *effects.lock().unwrap(),
        vec![52u32.to_le_bytes().to_vec()],
        "must deliver original batch exactly once"
    );
    assert!(actual_ack, "test never delivered a real destination ACK");
    assert!(
        !source
            .export_reliable_pending_stats()
            .iter()
            .any(|p| p.packet_id == packet),
        "real destination ACK did not retire pending"
    );
    // Permanently absent owners must still release bounded retry state.
    source.log_queue(ty, &[56u32]).unwrap();
    source.process_all_queues_with_timeout(0).unwrap();
    let doomed = source
        .export_reliable_pending_stats()
        .iter()
        .find(|p| p.data_type == ty)
        .expect("second pending publication")
        .packet_id;
    wire.lock().unwrap().clear();
    announce(false);
    assert!(
        source
            .export_reliable_pending_stats()
            .iter()
            .any(|p| p.packet_id == doomed)
    );
    let tuning = config::runtime_tuning_config();
    for _ in 0..tuning.reliable_max_retries + 4 {
        tick.fetch_add(
            u64::from(tuning.reliable_retransmit_ms) + 1,
            Ordering::SeqCst,
        );
        let _ = source.process_all_queues_with_timeout(0);
        let _ = source.process_all_queues_with_timeout(0);
        wire.lock().unwrap().clear();
    }
    assert!(
        !source
            .export_reliable_pending_stats()
            .iter()
            .any(|p| p.packet_id == doomed),
        "permanently absent owner exceeded its retry bound"
    );
    assert_eq!(
        effects.lock().unwrap().len(),
        1,
        "absent-owner fixture accidentally delivered data"
    );
    println!("ROUTE_WITHDRAWAL_PASS mode={mode:?} packet={packet} bounded_timeout=true");
}
