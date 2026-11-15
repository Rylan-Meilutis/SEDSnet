use super::*;
use core::sync::atomic::{AtomicU64, Ordering};

/// R2-C (combined round): after an RRLS takeover the primary station came
/// back, announced itself and sent its Abort, yet RF addressed every
/// BOARD_STATE_STATUS (its Abort push and the reply to the station's own
/// readback query) to the RRLS alone for 5.4 s. Two GROUND_STATION hosts
/// share RF's one radio side; a host re-heard after its route aged must be an
/// owner of the next frame queued.
fn fixture() -> (Router, RouterSideId, DataType, DataEndpoint, std::sync::Arc<AtomicU64>) {
    crate::tests::ensure_common_test_schema();
    let ep = crate::config::register_endpoint("RETURNING_OWNER_STATION", false).unwrap();
    let ty = crate::config::register_data_type_with_description(
        "RETURNING_OWNER_STATUS",
        "",
        MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[ep],
        crate::ReliableMode::Unordered,
        16,
    )
    .unwrap();
    let clock = std::sync::Arc::new(AtomicU64::new(1_000));
    let now = clock.clone();
    let rf = Router::new_with_clock(
        RouterConfig::new([]).with_sender("RF"),
        Box::new(move || now.load(Ordering::SeqCst)),
    );
    let radio = rf.add_side_packed("radio", |_| Ok(()));
    (rf, radio, ty, ep, clock)
}
fn announce(rf: &Router, radio: RouterSideId, who: &str, ep: DataEndpoint, at: u64) {
    rf.rx_from_side(&crate::discovery::build_discovery_announce(who, at, &[ep]).unwrap(), radio)
        .unwrap();
    rf.process_all_queues_with_timeout(0).unwrap();
}
fn queue_status(rf: &Router, ty: DataType, ep: DataEndpoint, at: u64) -> Vec<u64> {
    let packet = Packet::new(ty, &[ep], "RF", at, Arc::<[u8]>::from([1u8])).unwrap();
    let id = packet.packet_id();
    rf.tx_packed_queue(wire_format::pack_packet(&packet)).unwrap();
    let _ = rf.process_all_queues_with_timeout(0);
    let st = rf.state.lock();
    st.end_to_end_reliable_tx
        .get(&id)
        .map(|sent| sent.pending_destinations.keys().copied().collect())
        .unwrap_or_default()
}

#[test]
fn a_station_reheard_after_its_route_aged_owns_the_next_frame() {
    let (rf, radio, ty, ep, clock) = fixture();
    let (gs, rrls) = (Router::sender_hash("GS"), Router::sender_hash("RRLS"));
    announce(&rf, radio, "GS", ep, 1_000);
    announce(&rf, radio, "RRLS", ep, 1_000);
    let both = queue_status(&rf, ty, ep, 1_100);
    assert!(both.contains(&gs) && both.contains(&rrls), "both stations own a status: {both:?}");
    // The primary is cut for 45 s while the RRLS keeps announcing.
    for t in (6_000..=46_000).step_by(5_000) {
        clock.store(t, Ordering::SeqCst);
        announce(&rf, radio, "RRLS", ep, t);
    }
    let rrls_only = queue_status(&rf, ty, ep, 46_100);
    assert_eq!(rrls_only, vec![rrls], "the silent primary's route aged out");
    // The primary returns and announces itself.
    clock.store(47_000, Ordering::SeqCst);
    announce(&rf, radio, "GS", ep, 47_000);
    let back = queue_status(&rf, ty, ep, 47_100);
    assert!(back.contains(&gs), "the returning primary owns the next status: {back:?}");
}

/// The R2-C mechanism: the RRLS (full topology) lists the primary as a board
/// with no endpoints while it is cut; the primary returns with an empty
/// keepalive announce. RF counted it as described by the RRLS's topology and
/// never asked for the primary's own, so the primary owned no status until its
/// next full topology (5.4 s). A peer heard again that no topology describes
/// with endpoints is asked for its topology at once (one request per side),
/// and owns the next status once that arrives.
#[test]
fn a_returning_peer_that_no_topology_describes_is_asked_for_its_topology() {
    let sent = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
    let (rf, radio, ty, ep, clock) = {
        crate::tests::ensure_common_test_schema();
        let ep = crate::config::register_endpoint("RETURNING_OWNER_STATION", false).unwrap();
        let ty = crate::config::register_data_type_with_description(
            "RETURNING_OWNER_STATUS", "",
            MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
            &[ep], crate::ReliableMode::Unordered, 16).unwrap();
        let clock = std::sync::Arc::new(AtomicU64::new(1_000));
        let now = clock.clone();
        let rf = Router::new_with_clock(RouterConfig::new([]).with_sender("RF"), Box::new(move || now.load(Ordering::SeqCst)));
        let out = sent.clone();
        let radio = rf.add_side_packed("radio", move |bytes| { out.lock().unwrap().push(bytes.to_vec()); Ok(()) });
        (rf, radio, ty, ep, clock)
    };
    let (gs, rrls) = (Router::sender_hash("GS"), Router::sender_hash("RRLS"));
    let board = |id: &str, eps: &[DataEndpoint], peers: &[&str]| crate::discovery::TopologyBoardNode {
        sender_id: id.to_string(), reachable_endpoints: eps.to_vec(),
        reachable_timesync_sources: Vec::new(), connections: peers.iter().map(|p| p.to_string()).collect() };
    let topology = |rf: &Router, who: &str, at: u64, boards: &[crate::discovery::TopologyBoardNode]| {
        rf.rx_from_side(&crate::discovery::build_discovery_topology(who, at, boards).unwrap(), radio).unwrap();
        rf.process_all_queues_with_timeout(0).unwrap();
    };
    // Cut: the RRLS describes itself and lists the primary with no endpoints.
    clock.store(50_000, Ordering::SeqCst);
    topology(&rf, "RRLS", 50_000, &[board("RRLS", &[ep], &["GS", "RF"]), board("GS", &[], &["RRLS"])]);
    assert_eq!(queue_status(&rf, ty, ep, 50_100), vec![rrls]);
    // The primary returns with an empty keepalive announce.
    clock.store(56_000, Ordering::SeqCst);
    rf.rx_from_side(&crate::discovery::build_discovery_announce("GS", 56_000, &[]).unwrap(), radio).unwrap();
    rf.process_all_queues_with_timeout(0).unwrap();
    sent.lock().unwrap().clear();
    let requested = |sent: &std::sync::Mutex<Vec<Vec<u8>>>| sent.lock().unwrap().iter().any(|b| {
        wire_format::peek_frame_info(b).is_ok_and(|f| f.envelope.ty == DataType::DiscoveryTopologyRequest)
    });
    let mut asked_at = None;
    for t in (56_000..=62_000).step_by(100) {
        clock.store(t, Ordering::SeqCst);
        rf.poll_discovery().unwrap();
        rf.process_all_queues_with_timeout(0).unwrap();
        if requested(&sent) { asked_at = Some(t); break; }
    }
    let asked_at = asked_at.expect("the returning primary is asked for its topology");
    assert!(asked_at - 56_000 <= discovery::DISCOVERY_BASELINE_GRACE_MS, "asked {} ms after it was heard", asked_at - 56_000);
    // Its topology arrives: it owns the next status; a frame already queued keeps its owners.
    let earlier = {
        let packet = Packet::new(ty, &[ep], "RF", asked_at, Arc::<[u8]>::from([1u8])).unwrap();
        let id = packet.packet_id();
        rf.tx_packed_queue(wire_format::pack_packet(&packet)).unwrap();
        let _ = rf.process_all_queues_with_timeout(0);
        id
    };
    topology(&rf, "GS", asked_at + 50, &[board("GS", &[ep], &["RF", "RRLS"])]);
    let next = queue_status(&rf, ty, ep, asked_at + 100);
    assert!(next.contains(&gs) && next.contains(&rrls), "the primary owns the next status: {next:?}");
    let kept: Vec<u64> = rf.state.lock().end_to_end_reliable_tx.get(&earlier)
        .map(|s| s.pending_destinations.keys().copied().collect()).unwrap_or_default();
    assert_eq!(kept, vec![rrls], "a frame already queued keeps its owners");
}

/// A silent, departed owner still ages out as before.
#[test]
fn a_departed_owner_still_ages_out() {
    let (rf, radio, ty, ep, clock) = fixture();
    let (gs, rrls) = (Router::sender_hash("GS"), Router::sender_hash("RRLS"));
    announce(&rf, radio, "GS", ep, 1_000);
    announce(&rf, radio, "RRLS", ep, 1_000);
    for t in (6_000..=36_000).step_by(5_000) {
        clock.store(t, Ordering::SeqCst);
        announce(&rf, radio, "RRLS", ep, t);
        rf.poll_discovery().unwrap();
    }
    let owners = queue_status(&rf, ty, ep, 36_100);
    assert_eq!(owners, vec![rrls], "the silent GS aged out");
    assert!(!owners.contains(&gs));
}

type Sent = std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>;

fn station_fixture() -> (Router, RouterSideId, DataType, DataEndpoint, std::sync::Arc<AtomicU64>, Sent) {
    crate::tests::ensure_common_test_schema();
    let ep = crate::config::register_endpoint("RETURNING_OWNER_STATION", false).unwrap();
    let ty = crate::config::register_data_type_with_description(
        "RETURNING_OWNER_STATUS", "",
        MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[ep], crate::ReliableMode::Unordered, 16).unwrap();
    let clock = std::sync::Arc::new(AtomicU64::new(1_000));
    let now = clock.clone();
    let gs = Router::new_with_clock(RouterConfig::new([]).with_sender("GS"), Box::new(move || now.load(Ordering::SeqCst)));
    let sent = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
    let out = sent.clone();
    let radio = gs.add_side_packed("radio", move |bytes| { out.lock().unwrap().push(bytes.to_vec()); Ok(()) });
    (gs, radio, ty, ep, clock, sent)
}
fn topology_requests(sent: &std::sync::Mutex<Vec<Vec<u8>>>) -> usize {
    sent.lock().unwrap().iter().filter(|b| {
        wire_format::peek_frame_info(b).is_ok_and(|f| f.envelope.ty == DataType::DiscoveryTopologyRequest)
    }).count()
}

/// R3-C: after a 45 s cut (longer than the 30 s route TTL) the station heard
/// RF's data from 350 s but re-learned the AV bay only from RF's next
/// discovery packet (~354.7 s); its topology request was then lost and retried
/// 5 s later, so the operator's ABORT to FC had no route until 361.5 s and
/// PB's latch push was rejected as unverified. Data from a sender that no
/// fresh announcer or topology describes asks that side for topology within
/// the baseline grace; while it stays undescribed the request repeats every
/// DISCOVERY_TOPOLOGY_RETRY_MS (1 s), not 5 s.
#[test]
fn data_from_an_undescribed_sender_asks_for_topology_and_retries_quickly() {
    let (gs, radio, ty, ep, clock, sent) = station_fixture();
    // RF was known, then the cut aged it out.
    gs.rx_from_side(&crate::discovery::build_discovery_announce("RF", 1_000, &[ep]).unwrap(), radio).unwrap();
    gs.process_all_queues_with_timeout(0).unwrap();
    for t in (2_000..=40_000).step_by(1_000) {
        clock.store(t, Ordering::SeqCst);
        gs.poll_discovery().unwrap();
        gs.process_all_queues_with_timeout(0).unwrap();
    }
    sent.lock().unwrap().clear();
    // RF's data is heard again; no discovery packet from it yet.
    let mut asked = Vec::new();
    for t in (40_000..=44_000).step_by(100) {
        clock.store(t, Ordering::SeqCst);
        let data = Packet::new(ty, &[ep], "RF", t, Arc::<[u8]>::from([1u8])).unwrap();
        gs.rx_from_side(&data, radio).unwrap();
        gs.poll_discovery().unwrap();
        gs.process_all_queues_with_timeout(0).unwrap();
        let n = topology_requests(&sent);
        if n > asked.len() { asked.push(t); }
    }
    assert!(!asked.is_empty(), "data from the undescribed RF asks for topology");
    assert!(asked[0] - 40_000 <= discovery::DISCOVERY_BASELINE_GRACE_MS + 100, "first request {} ms after RF was heard", asked[0] - 40_000);
    assert!(asked.len() >= 2 && asked[1] - asked[0] <= discovery::DISCOVERY_TOPOLOGY_RETRY_MS + 100,
            "an unanswered request is repeated within 1 s: {asked:?}");
    // Still undescribed: the retry backs off (1, 2, 4, then 5 s), never storms.
    for t in (44_100..=80_000).step_by(100) {
        clock.store(t, Ordering::SeqCst);
        let data = Packet::new(ty, &[ep], "RF", t, Arc::<[u8]>::from([1u8])).unwrap();
        gs.rx_from_side(&data, radio).unwrap();
        gs.poll_discovery().unwrap();
        gs.process_all_queues_with_timeout(0).unwrap();
        let n = topology_requests(&sent);
        if n > asked.len() { asked.push(t); }
    }
    // A sender that stays undescribed is asked a bounded number of times
    // (backing off 1 s, 2 s), never at the retry floor for the whole outage.
    let gaps: Vec<u64> = asked.windows(2).map(|w| w[1] - w[0]).collect();
    assert!(gaps.iter().all(|g| *g + 100 >= discovery::DISCOVERY_TOPOLOGY_RETRY_MS), "backs off: {gaps:?}");
    assert!(asked.len() <= 4, "no storm over 40 s: {} requests at {asked:?}", asked.len());
    // RF's topology arrives: no further requests.
    let board = crate::discovery::TopologyBoardNode { sender_id: "RF".into(), reachable_endpoints: vec![ep],
        reachable_timesync_sources: Vec::new(), connections: vec!["GS".into()] };
    gs.rx_from_side(&crate::discovery::build_discovery_topology("RF", 80_000, &[board]).unwrap(), radio).unwrap();
    gs.process_all_queues_with_timeout(0).unwrap();
    sent.lock().unwrap().clear();
    for t in (80_100..=86_000).step_by(100) {
        clock.store(t, Ordering::SeqCst);
        let data = Packet::new(ty, &[ep], "RF", t, Arc::<[u8]>::from([1u8])).unwrap();
        gs.rx_from_side(&data, radio).unwrap();
        gs.poll_discovery().unwrap();
        gs.process_all_queues_with_timeout(0).unwrap();
    }
    assert_eq!(topology_requests(&sent), 0, "a described sender asks for nothing");
}

/// Replay of RF's radio receive in R2-C (frames extracted from the radio
/// trace): which owners RF gives a BOARD_STATE_STATUS around the hand-back.
#[test]
#[ignore]
fn replay_r2c_rf_status_owners() {
    let (Ok(fixture), Ok(schema)) = (std::env::var("R2C_RF_RX"), std::env::var("R2C_RF_SCHEMA")) else { return };
    crate::config::register_schema_json_file(&schema).unwrap();
    let frames: Vec<(u64, u8, Vec<u8>)> = {
        let text = std::fs::read_to_string(fixture).unwrap();
        let mut out = Vec::new();
        for row in text.trim_start_matches('[').trim_end_matches(']').split("},") {
            let field = |k: &str| -> String {
                let at = row.find(&format!("\"{k}\":")).unwrap() + k.len() + 3;
                row[at..].trim_start().trim_start_matches('"').split(['"', ',', '}']).next().unwrap().to_string()
            };
            let hex = field("hex");
            let bytes = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
            out.push((field("t").parse().unwrap(), field("kind").parse().unwrap(), bytes));
        }
        out
    };
    let clock = std::sync::Arc::new(AtomicU64::new(frames[0].0));
    let now = clock.clone();
    let rf = Router::new_with_clock(RouterConfig::new([]).with_sender("RF"), Box::new(move || now.load(Ordering::SeqCst)));
    let radio = rf.add_side_packed("radio", |_| Ok(()));
    let status = DataType::named("BOARD_STATE_STATUS");
    let gs_ep = DataEndpoint::named("GROUND_STATION");
    let probes = [356_000u64, 358_000, 359_300, 359_700, 360_500, 361_500, 362_500, 363_500, 364_100, 364_300, 365_000];
    let mut next = 0;
    let names: Vec<(u64, &str)> = ["GS", "RRLS", "FC", "PB", "GB"].iter().map(|n| (Router::sender_hash(n), *n)).collect();
    for (t, kind, bytes) in frames {
        while next < probes.len() && probes[next] <= t {
            clock.store(probes[next], Ordering::SeqCst);
            let packet = Packet::new(status, &[gs_ep], "RF", probes[next], Arc::<[u8]>::from([0u8; 40])).unwrap();
            let id = packet.packet_id();
            let _ = rf.tx_packed_queue(wire_format::pack_packet(&packet));
            let _ = rf.process_all_queues_with_timeout(0);
            let owners: Vec<&str> = rf.state.lock().end_to_end_reliable_tx.get(&id)
                .map(|s| s.pending_destinations.keys().map(|k| names.iter().find(|(h, _)| h == k).map_or("?", |(_, n)| *n)).collect())
                .unwrap_or_default();
            eprintln!("R2C t={} status owners {:?}", probes[next], owners);
            next += 1;
        }
        clock.store(t, Ordering::SeqCst);
        if kind == 5 {
            let _ = rf.rx_packed_from_side(&bytes, radio);
            let _ = rf.process_all_queues_with_timeout(0);
        }
    }
}
