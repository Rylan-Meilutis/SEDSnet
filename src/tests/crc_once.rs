//! A frame's CRC is verified once, where it enters the router. Queued and
//! retained items are only re-parsed, never re-hashed, on later polls.
use super::*;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

const POLLS: u64 = 25;

struct Node {
    node: Router,
    ingress: RouterSideId,
    time: Arc<AtomicU64>,
    egress_attempts: Arc<AtomicUsize>,
    egress_frames: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    local_hits: Arc<AtomicUsize>,
}

fn battery_frames(n: &Node) -> usize {
    let ty = DataType::try_named("BATTERY_STATUS");
    n.egress_frames
        .lock()
        .unwrap()
        .iter()
        .filter(|bytes| wire_format::scheduling_type(bytes) == ty)
        .count()
}

fn sd() -> DataEndpoint {
    DataEndpoint::try_named("SD_CARD").unwrap()
}

fn radio() -> DataEndpoint {
    DataEndpoint::try_named("RADIO").unwrap()
}

/// A bridge with an ingress side, an egress side behind which `sink` owns
/// SD_CARD, and optionally a local RADIO handler.
fn bridge(egress_busy: bool, local_handler: bool) -> Node {
    crate::tests::ensure_common_test_schema();
    let time = Arc::new(AtomicU64::new(1000));
    let read = time.clone();
    let local_hits = Arc::new(AtomicUsize::new(0));
    let hits = local_hits.clone();
    let handlers = if local_handler {
        vec![EndpointHandler::new_packet_handler(radio(), move |_| {
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
        frames.lock().unwrap().push(bytes.to_vec());
        if egress_busy {
            return Err(TelemetryError::Io("side tx busy"));
        }
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
        time,
        egress_attempts,
        egress_frames,
        local_hits,
    }
}

fn frame(ty: &str, sender: &str, timestamp: u64) -> Arc<[u8]> {
    let ty = DataType::try_named(ty).unwrap();
    let len = crate::get_needed_message_size(ty);
    let packet =
        Packet::new(ty, &[sd(), radio()], sender, timestamp, Arc::from(vec![0x5A; len])).unwrap();
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
        battery_frames(&n) > FRAMES,
        "the busy egress keeps the frames queued and retried ({} attempts, {} of them frames)",
        n.egress_attempts.load(Ordering::Relaxed),
        battery_frames(&n)
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
    // Let every new frame go out once.
    for _ in 0..4 {
        n.time.fetch_add(1, Ordering::Relaxed);
        let _ = n.node.process_all_queues();
    }
    let built = crate::crc32::counters::snapshot().0 - calls_before;
    let sent = n.egress_frames.lock().unwrap().len();
    assert!(sent >= 3, "frames were sent");
    assert!(
        !n.node.state.lock().end_to_end_reliable_tx.is_empty(),
        "unacknowledged frames are retained"
    );
    // Stay inside the retransmit interval: nothing new is sent, so nothing
    // needs a CRC; the retained frames are only inspected.
    let (calls_mid, _) = crate::crc32::counters::snapshot();
    for _ in 0..POLLS {
        n.time.fetch_add(1, Ordering::Relaxed);
        let _ = n.node.process_all_queues();
    }
    assert_eq!(n.egress_frames.lock().unwrap().len(), sent, "no retransmission yet");
    assert_eq!(
        (verifications() - before, crate::crc32::counters::snapshot().0 - calls_mid),
        (0, 0),
        "(verifications, CRCs while polling): locally built frames ({built} CRCs \
         to build and send) are never re-verified or re-hashed"
    );
}

#[test]
fn delivered_and_forwarded_frame_is_crc_checked_exactly_once() {
    for queued in [false, true] {
        let n = bridge(false, true);
        let bytes = frame("BATTERY_STATUS", "VB", 3000 + u64::from(queued));
        let hits = n.local_hits.load(Ordering::Relaxed);
        let sent = battery_frames(&n);
        let before = verifications();
        if queued {
            n.node.rx_packed_queue_from_side(&bytes, n.ingress).unwrap();
        } else {
            n.node.rx_packed_from_side(&bytes, n.ingress).unwrap();
        }
        poll(&n, POLLS);
        assert_eq!(n.local_hits.load(Ordering::Relaxed), hits + 1, "delivered locally");
        assert!(battery_frames(&n) > sent, "forwarded, queued={queued}");
        assert_eq!(verifications() - before, 1, "queued={queued}");
    }
}

fn corrupt(frame: &[u8]) -> Vec<u8> {
    let mut bad = frame.to_vec();
    let mid = bad.len() / 2;
    bad[mid] ^= 0x04;
    bad
}

/// Nothing from a corrupted frame may be delivered, forwarded or retained.
fn assert_nothing_admitted(n: &Node, path: &str) {
    poll(n, 5);
    assert_eq!(n.local_hits.load(Ordering::Relaxed), 0, "{path}: delivered");
    assert_eq!(battery_frames(n), 0, "{path}: forwarded");
    let st = n.node.state.lock();
    assert_eq!(st.received_queue.len(), 0, "{path}: queued");
    assert!(
        n.node.isr_rx_queue.as_ref().is_none_or(|q| q.try_lock().is_ok_and(|q| q.is_empty())),
        "{path}: ISR queued"
    );
}

#[test]
fn corrupted_frames_are_rejected_at_every_ingress() {
    crate::tests::ensure_common_test_schema();
    let good = frame("BATTERY_STATUS", "VB", 4000);
    let bad = corrupt(&good);
    assert!(wire_format::peek_frame_info(&bad).is_err());
    // A FULL frame whose canonical part is damaged in transit (its CRC32
    // covers the whole frame; a sender only wraps admitted frames).
    let full = {
        let mut full = crate::side_transport::encode_full_frame(&good, 1, 0, 0).to_vec();
        full[5] ^= 0x40;
        full
    };
    // A corrupted frame split across two valid chunk wrappers.
    let chunks: Vec<Vec<u8>> = {
        let half = bad.len() / 2;
        [&bad[..half], &bad[half..]]
            .iter()
            .enumerate()
            .map(|(index, part)| {
                crate::side_transport::test_chunk_frame(0x0BAD_F00D, index as u16, 2, part)
            })
            .collect()
    };
    let bundle = corrupt(&crate::wire_bundle::pack_bundle(&[&good, &good]).unwrap());
    let wrapper = corrupt(&crate::side_transport::encode_full_frame(&good, 1, 0, 0));

    type Ingress = fn(&Node, &[u8]) -> TelemetryResult<()>;
    let paths: [(&str, &[u8], Ingress); 15] = [
        ("rx_packed", &bad, |n, b| n.node.rx_packed(b)),
        ("rx_packed_queue", &bad, |n, b| n.node.rx_packed_queue(b)),
        ("rx_packed_queue_isr", &bad, |n, b| n.node.rx_packed_queue_isr(b)),
        ("rx_packed_from_side", &bad, |n, b| n.node.rx_packed_from_side(b, n.ingress)),
        ("rx_packed_queue_from_side", &bad, |n, b| {
            n.node.rx_packed_queue_from_side(b, n.ingress)
        }),
        ("rx_packed_queue_from_side_isr", &bad, |n, b| {
            n.node.rx_packed_queue_from_side_isr(b, n.ingress)
        }),
        ("side FULL", &full, |n, b| n.node.rx_packed_from_side(b, n.ingress)),
        ("side FULL queued", &full, |n, b| n.node.rx_packed_queue_from_side(b, n.ingress)),
        ("side wrapper", &wrapper, |n, b| n.node.rx_packed_from_side(b, n.ingress)),
        ("bundle", &bundle, |n, b| n.node.rx_packed_from_side(b, n.ingress)),
        ("bundle queued", &bundle, |n, b| n.node.rx_packed_queue_from_side(b, n.ingress)),
        ("chunks", &chunks[0], |n, b| {
            n.node.rx_packed_from_side(b, n.ingress)?;
            n.node.rx_packed_from_side(&corrupt_chunk_tail(b), n.ingress)
        }),
        ("chunks queued", &chunks[0], |n, b| {
            n.node.rx_packed_queue_from_side(b, n.ingress)?;
            n.node.rx_packed_queue_from_side(&corrupt_chunk_tail(b), n.ingress)
        }),
        ("tx_packed", &bad, |n, b| n.node.tx_packed(Arc::from(b))),
        ("tx_packed_queue", &bad, |n, b| n.node.tx_packed_queue(Arc::from(b))),
    ];
    // The second chunk is looked up by content rather than captured.
    CHUNK_TAIL.with(|tail| *tail.borrow_mut() = chunks[1].clone());
    for (path, bytes, ingress) in paths {
        let n = bridge(false, true);
        let result = ingress(&n, bytes);
        assert!(result.is_err(), "{path}: accepted ({result:?})");
        assert_nothing_admitted(&n, path);
        // The same path still admits the intact frame.
        let n = bridge(false, true);
        let intact: Vec<u8> = match path {
            "side FULL" | "side FULL queued" | "side wrapper" => {
                crate::side_transport::encode_full_frame(&good, 1, 0, 0)
                .to_vec()
            }
            "bundle" | "bundle queued" => crate::wire_bundle::pack_bundle(&[&good]).unwrap(),
            _ if path.starts_with("chunks") => continue,
            _ => good.to_vec(),
        };
        ingress(&n, &intact).unwrap_or_else(|e| panic!("{path}: intact frame refused: {e:?}"));
        poll(&n, 5);
        assert!(
            n.local_hits.load(Ordering::Relaxed) == 1 && battery_frames(&n) == 1,
            "{path}: intact frame went nowhere"
        );
    }
    // Relay ingress goes through the same side decode.
    let relay = crate::relay::Relay::new(Box::new(|| 0u64));
    let a = relay.add_side_packed("a", |_| Ok(()));
    let out = Arc::new(AtomicUsize::new(0));
    let seen = out.clone();
    let battery = DataType::try_named("BATTERY_STATUS");
    relay.add_side_packed("b", move |bytes| {
        if wire_format::scheduling_type(bytes) == battery {
            seen.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    });
    assert!(relay.rx_packed_from_side(a, &bad).is_err());
    let _ = relay.process_all_queues();
    assert_eq!(out.load(Ordering::Relaxed), 0, "relay forwarded a corrupted frame");
    relay.rx_packed_from_side(a, &good).unwrap();
    let _ = relay.process_all_queues();
    assert!(out.load(Ordering::Relaxed) > 0, "relay forwards the intact frame");
}

std::thread_local! {
    static CHUNK_TAIL: core::cell::RefCell<Vec<u8>> = const { core::cell::RefCell::new(Vec::new()) };
}
fn corrupt_chunk_tail(_first: &[u8]) -> Vec<u8> {
    CHUNK_TAIL.with(|tail| tail.borrow().clone())
}
