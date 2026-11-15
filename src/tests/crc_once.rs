//! A frame's CRC is verified once, where it enters the router. Queued and
//! retained items are only re-parsed, never re-hashed, on later polls.
use super::*;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

const POLLS: u64 = 25;

struct Node {
    node: Router,
    ingress: RouterSideId,
    egress: RouterSideId,
    time: Arc<AtomicU64>,
    egress_attempts: Arc<AtomicUsize>,
    egress_frames: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    local_hits: Arc<AtomicUsize>,
}

fn sd() -> DataEndpoint {
    DataEndpoint::try_named("SD_CARD").unwrap()
}

/// A bridge with an ingress side, an egress side behind which `sink` owns
/// SD_CARD, and optionally a local SD_CARD handler.
fn bridge(egress_busy: bool, local_handler: bool) -> Node {
    crate::tests::ensure_common_test_schema();
    let time = Arc::new(AtomicU64::new(1000));
    let read = time.clone();
    let local_hits = Arc::new(AtomicUsize::new(0));
    let hits = local_hits.clone();
    let handlers = if local_handler {
        vec![EndpointHandler::new_packet_handler(sd(), move |_| {
            hits.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })]
    } else {
        vec![]
    };
    let node = Router::new_with_clock(
        RouterConfig::new(handlers).with_sender("bridge-under-test"),
        Box::new(move || read.load(Ordering::Relaxed)),
    );
    let egress_attempts = Arc::new(AtomicUsize::new(0));
    let attempts = egress_attempts.clone();
    let egress_frames = Arc::new(std::sync::Mutex::new(Vec::new()));
    let frames = egress_frames.clone();
    let ingress = node.add_side_packed("ingress", |_| Ok(()));
    let egress = node.add_side_packed("egress", move |bytes| {
        attempts.fetch_add(1, Ordering::Relaxed);
        if egress_busy {
            return Err(TelemetryError::Io("side tx busy"));
        }
        frames.lock().unwrap().push(bytes.to_vec());
        Ok(())
    });
    node.clear_queues();
    {
        let mut st = node.state.lock();
        let route = st.discovery_routes.entry(egress).or_default();
        route.announcers.insert(
            "sink".into(),
            Box::new(DiscoverySenderState {
                last_seen_ms: 1000,
                advertised_address: Some(sender_address_u32("sink")),
                reachable: vec![sd()],
                advertised_reachable: vec![sd()],
                topology_boards: Arc::new(vec![TopologyBoardNode {
                    sender_id: "sink".into(),
                    reachable_endpoints: vec![sd()],
                    reachable_timesync_sources: vec![],
                    connections: vec![],
                }]),
                has_full_topology: true,
                has_schema: true,
                ..Default::default()
            }),
        );
        Router::recompute_discovery_side_state(route);
    }
    Node {
        node,
        ingress,
        egress,
        time,
        egress_attempts,
        egress_frames,
        local_hits,
    }
}

fn frame(ty: &str, sender: &str, timestamp: u64) -> Arc<[u8]> {
    let ty = DataType::try_named(ty).unwrap();
    let len = crate::get_needed_message_size(ty);
    let packet = Packet::new(ty, &[sd()], sender, timestamp, Arc::from(vec![0x5A; len])).unwrap();
    wire_format::pack_packet(&packet)
}

fn poll(n: &Node, count: u64) {
    for _ in 0..count {
        n.time.fetch_add(1, Ordering::Relaxed);
        let _ = n.node.periodic(0);
    }
}

fn verifications() -> usize {
    wire_format::crc_verification_count()
}

#[test]
fn queued_relay_frames_are_crc_checked_once_across_polls() {
    const FRAMES: usize = 4;
    let n = bridge(true, false);
    let before = verifications();
    for i in 0..FRAMES {
        n.node
            .rx_packed_queue_from_side(&frame("BATTERY_STATUS", "VB", 2000 + i as u64), n.ingress)
            .unwrap();
    }
    let at_ingress = verifications() - before;
    poll(&n, POLLS);
    assert!(
        n.egress_attempts.load(Ordering::Relaxed) > FRAMES,
        "the busy egress keeps the frames queued and retried"
    );
    assert_eq!(
        (at_ingress, verifications() - before),
        (FRAMES, FRAMES),
        "(after ingress, after {POLLS} polls): one verification per frame"
    );
}

#[test]
fn retained_reliable_frames_are_not_rehashed_while_awaiting_receipts() {
    let n = bridge(false, false);
    let ty = DataType::try_named("GPS_DATA").unwrap();
    let (calls_before, _) = crate::crc32::counters::snapshot();
    let before = verifications();
    for i in 0..3 {
        n.node.log_ts(ty, 2000 + i, &[1.0f32, 2.0, i as f32]).unwrap();
    }
    let built = crate::crc32::counters::snapshot().0 - calls_before;
    assert!(!n.egress_frames.lock().unwrap().is_empty(), "frames were sent");
    assert!(
        !n.node.state.lock().end_to_end_reliable_tx.is_empty(),
        "unacknowledged frames are retained"
    );
    // Stay inside the retransmit interval: nothing new is sent, so nothing
    // new needs a CRC; only retained frames are inspected.
    let (calls_mid, _) = crate::crc32::counters::snapshot();
    for _ in 0..POLLS {
        n.time.fetch_add(1, Ordering::Relaxed);
        let _ = n.node.process_all_queues();
    }
    assert_eq!(
        (verifications() - before, crate::crc32::counters::snapshot().0 - calls_mid),
        (0, 0),
        "(verifications, CRCs while polling): locally built frames ({built} CRCs \
         to build and send) are never re-verified or re-hashed"
    );
}

#[test]
fn delivered_and_forwarded_frame_is_crc_checked_exactly_once() {
    let n = bridge(false, true);
    for queued in [false, true] {
        let bytes = frame("BATTERY_STATUS", "VB", 3000 + u64::from(queued));
        let hits = n.local_hits.load(Ordering::Relaxed);
        let sent = n.egress_frames.lock().unwrap().len();
        let before = verifications();
        if queued {
            n.node.rx_packed_queue_from_side(&bytes, n.ingress).unwrap();
        } else {
            n.node.rx_packed_from_side(&bytes, n.ingress).unwrap();
        }
        poll(&n, POLLS);
        assert_eq!(n.local_hits.load(Ordering::Relaxed), hits + 1, "delivered locally");
        assert!(n.egress_frames.lock().unwrap().len() > sent, "forwarded");
        assert_eq!(verifications() - before, 1, "queued={queued}");
    }
}
