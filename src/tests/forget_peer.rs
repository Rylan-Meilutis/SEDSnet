use super::*;

/// Frames in flight: (destination, side, bytes).
type Air = Arc<std::sync::Mutex<Vec<(Arc<Router>, RouterSideId, Vec<u8>)>>>;

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

/// A station that went silent (its discovery leave lost): an Unordered
/// frame the GS acknowledged but the RRLS never did completes for the GS when
/// its retries run out, and the RRLS is retired from the other Unordered
/// frames still pending. It stays owed every Ordered frame (the application
/// re-sends from an Ordered exhaustion and its owners) and every ABORT.
#[test]
fn an_owner_that_missed_every_retry_is_retired_not_the_stream() {
    crate::tests::ensure_common_test_schema();
    let endpoint = DataEndpoint::named("RADIO");
    let ty = crate::config::register_data_type_with_description(
        "SILENT_OWNER_UNORDERED",
        "",
        crate::MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[endpoint],
        crate::ReliableMode::Unordered,
        16,
    )
    .unwrap();
    let ordered = crate::config::register_data_type_with_description(
        "SILENT_OWNER_ORDERED",
        "",
        crate::MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[endpoint],
        crate::ReliableMode::Ordered,
        16,
    )
    .unwrap();
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
    let now = Arc::new(core::sync::atomic::AtomicU64::new(1_000));
    let clock = now.clone();
    let node = Router::new_with_clock(
        RouterConfig::new([]).with_sender("RF"),
        Box::new(move || clock.load(Ordering::SeqCst)),
    );
    let radio = node.add_side_packed("radio", |_| Ok(()));
    node.clear_queues();
    let (gs, rr) = (Router::sender_hash("GS"), Router::sender_hash("RRLS"));
    let frame = |ty: DataType, ep: DataEndpoint, timestamp: u64, owners: &[u64]| {
        let packet = Packet::new(ty, &[ep], "RF", timestamp, Arc::<[u8]>::from(*b"K")).unwrap();
        let item = node.attach_wire_contract_to_item(RouterItem::Packet(packet), owners).unwrap();
        let id = Router::get_hash(&item);
        node.register_end_to_end_reliable_tx(
            &item,
            Some(owners.iter().map(|owner| (*owner, radio)).collect::<OrdMap<_, _>>()),
        )
        .unwrap();
        id
    };
    let head = frame(ty, endpoint, 1, &[gs, rr]);
    // The GS acknowledges the head; the RRLS never answers.
    node.state.lock().end_to_end_reliable_tx.get_mut(&head).unwrap().pending_destinations.remove(&gs);
    let span = runtime_reliable_retransmit_ms() * (u64::from(runtime_reliable_max_retries()) + 2);
    let (mut later, mut ordered_rr, mut abort_rr) = (None, None, None);
    let mut elapsed = 0;
    while node.state.lock().end_to_end_reliable_tx.contains_key(&head) && elapsed < 2 * span {
        if later.is_none() && elapsed >= span / 2 {
            // Sent while the head still retries: another Unordered frame, an
            // Ordered one and an ABORT, each also owed to the RRLS.
            later = Some(frame(ty, endpoint, 2, &[gs, rr]));
            ordered_rr = Some(frame(ordered, endpoint, 3, &[gs, rr]));
            abort_rr = Some(frame(abort, abort_ep, 4, &[gs, rr]));
        }
        now.fetch_add(10, Ordering::SeqCst);
        elapsed += 10;
        let _ = node.process_all_queues_with_timeout(0);
    }
    let st = node.state.lock();
    assert!(!st.end_to_end_reliable_tx.contains_key(&head), "the head completed for the GS");
    let owners = |id: u64| st.end_to_end_reliable_tx[&id].pending_destinations.keys().copied().collect::<Vec<_>>();
    assert_eq!(owners(later.unwrap()), vec![gs], "the silent RRLS is retired from the other Unordered frames");
    let mut both = vec![gs, rr];
    both.sort_unstable();
    assert_eq!(owners(ordered_rr.unwrap()), both, "an Ordered frame keeps every owner");
    assert_eq!(owners(abort_rr.unwrap()), both, "an ABORT keeps every owner");
    drop(st);
    // Counted with the exhaustion counters: the RRLS retired from the head
    // and the later Unordered frame, the head completed only after it.
    let counts = node.export_runtime_stats().reliable.exhausted;
    assert_eq!(
        (
            counts.silent_owner_retired_unordered,
            counts.silent_owner_completed_unordered,
            counts.silent_owner_retired_ordered,
            counts.silent_owner_completed_ordered,
            counts.end_to_end_unordered,
        ),
        (2, 1, 0, 0, 0),
        "{counts:?}"
    );
}

/// RRLS and GS share a radio bus with RF, which relays onto a CAN side where
/// FC is. After the GS is cut and the RRLS forgets it (its takeover), a
/// reliable frame from the RRLS to an FC endpoint must still reach FC through
/// RF and FC's receipt must complete it at the RRLS.
#[test]
fn after_forgetting_the_primary_a_frame_still_reaches_a_board_behind_the_relay() {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
    crate::tests::ensure_common_test_schema();
    let ep = DataEndpoint::named("RADIO");
    let ty = crate::config::register_data_type_with_description(
        "FORGET_RELAY_WRITE",
        "",
        crate::MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[ep],
        crate::ReliableMode::Unordered,
        16,
    )
    .unwrap();
    let now = Arc::new(AtomicU64::new(1_000));
    let clock = |n: &Arc<AtomicU64>| { let n = n.clone(); Box::new(move || n.load(Ordering::Relaxed)) as Box<dyn Clock + Send + Sync> };
    let got = Arc::new(AtomicU32::new(0));
    let g = got.clone();
    let fc = Arc::new(Router::new_with_clock(
        RouterConfig::new([EndpointHandler::new_packet_handler(ep, move |_| { g.fetch_add(1, Ordering::Relaxed); Ok(()) })]).with_sender("FC"),
        clock(&now)));
    let rf = Arc::new(Router::new_with_clock(RouterConfig::new([]).with_sender("RF"), clock(&now)));
    let rrls = Arc::new(Router::new_with_clock(RouterConfig::new([]).with_sender("RRLS"), clock(&now)));
    let gs = Arc::new(Router::new_with_clock(RouterConfig::new([]).with_sender("GS"), clock(&now)));
    // Frames in flight: (destination, side, bytes)
    let air: Air = Arc::new(Mutex::new(Vec::new()));
    let gs_up = Arc::new(AtomicBool::new(true));
    // Side ids: rf 0 radio, 1 can; rrls 0 radio; gs 0 radio; fc 0 can.
    let (a, f, g2, r2) = (air.clone(), fc.clone(), gs.clone(), rrls.clone());
    let up = gs_up.clone();
    rf.add_side_packed("radio", move |b| { let mut q = a.lock().unwrap(); q.push((r2.clone(), 0, b.to_vec())); if up.load(Ordering::Relaxed) { q.push((g2.clone(), 0, b.to_vec())); } Ok(()) });
    let a = air.clone();
    rf.add_side_packed("can", move |b| { a.lock().unwrap().push((f.clone(), 0, b.to_vec())); Ok(()) });
    let (a, rfc, g3) = (air.clone(), rf.clone(), gs.clone());
    let up = gs_up.clone();
    rrls.add_side_packed("radio", move |b| { let mut q = a.lock().unwrap(); q.push((rfc.clone(), 0, b.to_vec())); if up.load(Ordering::Relaxed) { q.push((g3.clone(), 0, b.to_vec())); } Ok(()) });
    let (a, rfc, r3) = (air.clone(), rf.clone(), rrls.clone());
    let up = gs_up.clone();
    gs.add_side_packed("radio", move |b| { if up.load(Ordering::Relaxed) { let mut q = a.lock().unwrap(); q.push((rfc.clone(), 0, b.to_vec())); q.push((r3.clone(), 0, b.to_vec())); } Ok(()) });
    let (a, rfc) = (air.clone(), rf.clone());
    fc.add_side_packed("can", move |b| { a.lock().unwrap().push((rfc.clone(), 1, b.to_vec())); Ok(()) });
    let all = [fc.clone(), rf.clone(), rrls.clone(), gs.clone()];
    let pump = |rounds: usize| {
        for _ in 0..rounds {
            for r in &all { r.process_all_queues().unwrap(); }
            let batch: Vec<_> = air.lock().unwrap().drain(..).collect();
            for (to, side, bytes) in batch { let _ = to.rx_packed_from_side(&bytes, side); }
        }
    };
    for r in &all { r.announce_discovery().unwrap(); }
    pump(20);
    for r in &all { r.announce_discovery().unwrap(); }
    pump(20);
    let send = |ts: u64| {
        rrls.tx(Packet::new(ty, &[ep], "RRLS", ts, Arc::<[u8]>::from([1u8])).unwrap()).unwrap();
        pump(20);
    };
    send(2);
    assert_eq!(got.load(Ordering::Relaxed), 1, "baseline: FC receives through RF");
    assert!(rrls.export_reliable_pending_stats().is_empty(), "baseline: FC's receipt completes it");
    gs_up.store(false, Ordering::Relaxed);
    assert!(rrls.forget_peer("GS").is_ok());
    send(3);
    assert_eq!(got.load(Ordering::Relaxed), 2, "after forgetting the primary FC still receives");
    assert!(rrls.export_reliable_pending_stats().is_empty(), "and its receipt still completes it");
}

/// fullnet C-fix2/Cshort: the primary forgot an idle (listening) RRLS when it
/// went Offline, and later the FC behind RF refused the RRLS's takeover
/// FLIGHT_STATE and FLIGHT_COMMAND (its handler-level refusal counter rose)
/// while RF accepted them. The FC authorizes a station by resolving the
/// frame's compact sender address to its hostname. Does the primary's forget
/// make a board behind the relay lose the RRLS?
#[test]
fn a_board_behind_the_relay_keeps_resolving_a_peer_another_station_forgot() {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};
    crate::tests::ensure_common_test_schema();
    let now = Arc::new(AtomicU64::new(1_000));
    let clock = |n: &Arc<AtomicU64>| { let n = n.clone(); Box::new(move || n.load(Ordering::Relaxed)) as Box<dyn Clock + Send + Sync> };
    let fc = Arc::new(Router::new_with_clock(RouterConfig::new([]).with_sender("FC"), clock(&now)));
    let rf = Arc::new(Router::new_with_clock(RouterConfig::new([]).with_sender("RF"), clock(&now)));
    let rrls = Arc::new(Router::new_with_clock(RouterConfig::new([]).with_sender("RRLS"), clock(&now)));
    let gs = Arc::new(Router::new_with_clock(RouterConfig::new([]).with_sender("GS"), clock(&now)));
    let air: Air = Arc::new(Mutex::new(Vec::new()));
    let radio = [rf.clone(), rrls.clone(), gs.clone()];
    for (me, side) in [(rf.clone(), 0usize), (rrls.clone(), 0), (gs.clone(), 0)] {
        let (a, peers) = (air.clone(), radio.clone());
        let mine = me.clone();
        me.add_side_packed("radio", move |b| {
            let mut q = a.lock().unwrap();
            for p in &peers { if !Arc::ptr_eq(p, &mine) { q.push((p.clone(), 0, b.to_vec())); } }
            Ok(())
        });
        let _ = side;
    }
    let (a, f) = (air.clone(), fc.clone());
    rf.add_side_packed("can", move |b| { a.lock().unwrap().push((f.clone(), 0, b.to_vec())); Ok(()) });
    let (a, r) = (air.clone(), rf.clone());
    fc.add_side_packed("can", move |b| { a.lock().unwrap().push((r.clone(), 1, b.to_vec())); Ok(()) });
    let all = [fc.clone(), rf.clone(), rrls.clone(), gs.clone()];
    let pump = |rounds: usize| {
        for _ in 0..rounds {
            for r in &all { r.process_all_queues().unwrap(); }
            let batch: Vec<_> = air.lock().unwrap().drain(..).collect();
            for (to, side, bytes) in batch { let _ = to.rx_packed_from_side(&bytes, side); }
        }
    };
    for _ in 0..2 {
        for r in &all { r.announce_discovery().unwrap(); }
        pump(20);
    }
    // What the RRLS's frames carry as their source (seen on air: the name's identity).
    let rrls_sender = format!("@addr:{}", crate::packet::sender_address_u32("RRLS"));
    assert!(rf.sender_matches_hostname(&rrls_sender, "RRLS"), "RF resolves the RRLS");
    assert!(fc.sender_matches_hostname(&rrls_sender, "RRLS"), "FC resolves the RRLS through RF");
    // The primary decides the RRLS is out of range and forgets it, then keeps announcing.
    gs.forget_peer("RRLS").unwrap();
    now.fetch_add(1_000, Ordering::Relaxed);
    for r in [&gs, &rf] { r.announce_discovery().unwrap(); }
    pump(20);
    assert!(rf.sender_matches_hostname(&rrls_sender, "RRLS"), "RF still resolves the RRLS");
    assert!(fc.sender_matches_hostname(&rrls_sender, "RRLS"), "FC still resolves the RRLS after the primary forgot it");
}
