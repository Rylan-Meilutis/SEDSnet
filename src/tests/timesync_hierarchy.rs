//! Multi-router time sync: UTC quality, hop-by-hop re-serving and loop safety.
use crate::config::{DataEndpoint, DataType};
use crate::packet::Packet;
use crate::router::{Router, RouterConfig, RouterSideId};
use crate::timesync::{
    PartialNetworkTime, TIMESYNC_LEGACY_STRATUM, TIMESYNC_UTC_FLOOR_MS, TimeSyncConfig,
    TimeSyncQuality, TimeSyncRole, TimeSyncTracker, build_timesync_announce_with_sender,
    decode_timesync_quality, encode_timesync_priority, timesync_sender_tag,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const UTC: u64 = 1_793_000_000_000;
type Wire = Arc<Mutex<Vec<Packet>>>;

#[derive(Clone, Debug)]
struct Frame {
    at: u64,
    from: usize,
    to: usize,
    ty: DataType,
    words: Vec<u64>,
}

struct Link {
    a: usize,
    side_a: RouterSideId,
    b: usize,
    side_b: RouterSideId,
    a_to_b: Wire,
    b_to_a: Wire,
    up: bool,
}

struct Net {
    now: Arc<AtomicU64>,
    nodes: Vec<Router>,
    links: Vec<Link>,
    frames: Mutex<Vec<Frame>>,
}

fn cfg(role: TimeSyncRole, priority: u64) -> TimeSyncConfig {
    TimeSyncConfig {
        role,
        priority,
        source_timeout_ms: 5_000,
        announce_interval_ms: 1_000,
        request_interval_ms: 1_000,
        consumer_promotion_enabled: true,
        max_slew_ppm: 50_000,
    }
}

fn consumer() -> TimeSyncConfig {
    cfg(TimeSyncRole::Consumer, 100)
}

impl Net {
    fn new(nodes: &[(&str, TimeSyncConfig)]) -> Self {
        // Monotonic clocks start at five seconds of uptime, like the bench boards.
        let now = Arc::new(AtomicU64::new(5_000_000));
        let nodes = nodes
            .iter()
            .map(|(name, ts)| {
                let read = now.clone();
                Router::new_with_clock(
                    RouterConfig::default()
                        .with_sender(*name)
                        .with_timesync(*ts),
                    Box::new(move || read.load(Ordering::SeqCst)),
                )
            })
            .collect();
        Self {
            now,
            nodes,
            links: Vec::new(),
            frames: Mutex::default(),
        }
    }

    fn link(&mut self, a: usize, b: usize) -> usize {
        let a_to_b: Wire = Arc::default();
        let b_to_a: Wire = Arc::default();
        let tx = a_to_b.clone();
        let side_a = self.nodes[a].add_side_packet(format!("to{b}"), move |pkt| {
            tx.lock().unwrap().push(pkt.clone());
            Ok(())
        });
        let tx = b_to_a.clone();
        let side_b = self.nodes[b].add_side_packet(format!("to{a}"), move |pkt| {
            tx.lock().unwrap().push(pkt.clone());
            Ok(())
        });
        self.links.push(Link {
            a,
            side_a,
            b,
            side_b,
            a_to_b,
            b_to_a,
            up: true,
        });
        self.links.len() - 1
    }

    fn deliver(&self, link: &Link, from: usize, to: usize, side: RouterSideId, wire: &Wire) {
        let packets: Vec<_> = core::mem::take(&mut *wire.lock().unwrap());
        if !link.up {
            return;
        }
        for pkt in packets {
            if matches!(
                pkt.data_type(),
                DataType::TimeSyncAnnounce | DataType::TimeSyncRequest | DataType::TimeSyncResponse
            ) {
                self.frames.lock().unwrap().push(Frame {
                    at: self.now.load(Ordering::SeqCst),
                    from,
                    to,
                    ty: pkt.data_type(),
                    words: pkt.data_as_u64().unwrap(),
                });
            }
            let _ = self.nodes[to].rx_from_side(&pkt, side);
        }
    }

    fn step(&self, ms: u64) {
        for node in &self.nodes {
            node.periodic(0).unwrap();
        }
        for _ in 0..4 {
            for link in &self.links {
                self.deliver(link, link.a, link.b, link.side_b, &link.a_to_b);
                self.deliver(link, link.b, link.a, link.side_a, &link.b_to_a);
            }
            for node in &self.nodes {
                node.drain_queues_with_timeout(0).unwrap();
            }
        }
        self.now.fetch_add(ms, Ordering::SeqCst);
    }

    fn run(&self, total_ms: u64) {
        for _ in 0..total_ms / 50 {
            self.step(50);
        }
    }

    fn mono(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }

    fn error_ms(&self, node: usize) -> u64 {
        self.nodes[node]
            .network_time_ms()
            .map_or(u64::MAX, |t| t.abs_diff(UTC + self.mono()))
    }

    fn set_utc(&self, node: usize) {
        self.nodes[node]
            .set_local_network_time(PartialNetworkTime::from_unix_ms(UTC + self.mono()));
    }

    fn frames_since(&self, at: u64) -> Vec<Frame> {
        self.frames
            .lock()
            .unwrap()
            .iter()
            .filter(|f| f.at >= at)
            .cloned()
            .collect()
    }
}

fn announces(frames: &[Frame], from: usize, to: usize) -> Vec<(TimeSyncQuality, u64)> {
    frames
        .iter()
        .filter(|f| f.ty == DataType::TimeSyncAnnounce && f.from == from && f.to == to)
        .map(|f| (decode_timesync_quality(f.words[0], f.words[1]), f.words[1]))
        .collect()
}

fn count(frames: &[Frame], ty: DataType, from: usize, to: usize) -> usize {
    frames
        .iter()
        .filter(|f| f.ty == ty && f.from == from && f.to == to)
        .count()
}

/// Runs until every listed node reads UTC within `tolerance_ms`, returning the elapsed time.
fn converge(net: &Net, nodes: &[usize], tolerance_ms: u64, limit_ms: u64) -> u64 {
    let start = net.mono();
    while net.mono() - start <= limit_ms {
        if nodes.iter().all(|&n| net.error_ms(n) <= tolerance_ms) {
            return net.mono() - start;
        }
        net.step(50);
    }
    panic!(
        "no convergence within {limit_ms} ms: errors {:?}",
        nodes.iter().map(|&n| net.error_ms(n)).collect::<Vec<_>>()
    );
}

#[test]
fn consumer_behind_relay_steps_from_uptime_to_utc() {
    let mut net = Net::new(&[
        ("GS", cfg(TimeSyncRole::Source, 50)),
        ("GATEWAY", consumer()),
        ("ACTUATOR", consumer()),
    ]);
    let umbilical = net.link(0, 1);
    net.link(1, 2);
    // The ground station has no NTP fix yet, so every board anchors to uptime.
    net.run(3_000);
    assert_eq!(net.nodes[0].network_time_ms(), None);
    for node in 1..3 {
        assert!(net.nodes[node].network_time_ms().unwrap() < TIMESYNC_UTC_FLOOR_MS);
    }
    let fixed = net.mono();
    net.set_utc(0);
    // A 5% slew would need years; only steps can close a 1.79e12 ms gap this quickly.
    assert!(converge(&net, &[0, 1, 2], 2, 3_000) <= 2_000);
    net.run(5_000);
    for node in 0..3 {
        assert!(
            net.error_ms(node) <= 2,
            "node {node} drifted: {}",
            net.error_ms(node)
        );
    }
    let frames = net.frames_since(fixed);
    // Point-to-point: the actuator exchanges with the gateway, never across it.
    assert!(count(&frames, DataType::TimeSyncRequest, 2, 1) > 0);
    assert!(count(&frames, DataType::TimeSyncResponse, 1, 2) > 0);
    let link = &net.links[umbilical];
    assert_eq!((link.a, link.b), (0, 1));
    for f in frames.iter().filter(|f| f.from == 1 && f.to == 0) {
        assert_eq!(
            f.ty,
            DataType::TimeSyncRequest,
            "gateway only requests upstream"
        );
    }
    let downstream = announces(&frames, 1, 2);
    let (last, _) = downstream.last().copied().unwrap();
    assert!(last.anchored);
    assert_eq!(last.stratum, 1);
    assert_eq!(last.priority, 50);
    assert_eq!(last.upstream, timesync_sender_tag("GS"));
    assert!(
        announces(&frames, 2, 1).is_empty(),
        "leaf boards never announce"
    );
}

#[test]
fn utc_propagates_through_two_relays() {
    let mut net = Net::new(&[
        ("GS", cfg(TimeSyncRole::Source, 50)),
        ("GATEWAY", consumer()),
        ("BRIDGE", consumer()),
        ("VALVE", consumer()),
    ]);
    net.link(0, 1);
    net.link(1, 2);
    net.link(2, 3);
    net.run(3_000);
    assert!(net.nodes[3].network_time_ms().unwrap() < TIMESYNC_UTC_FLOOR_MS);
    let fixed = net.mono();
    net.set_utc(0);
    assert!(converge(&net, &[1, 2, 3], 2, 4_000) <= 3_000);
    net.run(3_000);
    assert!(net.error_ms(3) <= 2);
    let frames = net.frames_since(fixed + 2_000);
    let (deep, _) = *announces(&frames, 2, 3).last().unwrap();
    assert!(deep.anchored && deep.stratum == 2 && deep.priority == 50);
    assert_eq!(deep.upstream, timesync_sender_tag("GATEWAY"));
    assert!(frames.iter().all(|f| f.from.abs_diff(f.to) == 1));
    assert!(count(&frames, DataType::TimeSyncResponse, 2, 3) > 0);
}

#[test]
fn utc_source_beats_earlier_uptime_source() {
    let mut net = Net::new(&[
        ("GS", cfg(TimeSyncRole::Source, 50)),
        ("RF", cfg(TimeSyncRole::Source, 1)),
        ("FC", consumer()),
    ]);
    let radio = net.link(0, 1);
    net.link(1, 2);
    net.set_utc(0);
    net.links[radio].up = false;
    // RF has no GPS fix: it leads the vehicle with uptime first.
    net.run(3_000);
    assert!(net.nodes[2].network_time_ms().unwrap() < TIMESYNC_UTC_FLOOR_MS);
    net.links[radio].up = true;
    let joined = net.mono();
    converge(&net, &[0, 1, 2], 2, 3_000);
    net.run(5_000);
    assert_eq!(
        net.error_ms(0),
        0,
        "an uptime source must not drag the UTC source"
    );
    assert!(net.error_ms(2) <= 2);
    let frames = net.frames_since(joined + 3_000);
    // RF still has the better configured priority but follows the anchored GS.
    assert!(announces(&frames, 1, 0).is_empty());
    let (vehicle, _) = *announces(&frames, 1, 2).last().unwrap();
    assert!(vehicle.anchored && vehicle.stratum == 1);
    assert!(count(&frames, DataType::TimeSyncRequest, 1, 0) > 0);

    // The standalone tracker applies the same order regardless of arrival order.
    let mut tracker = TimeSyncTracker::new(cfg(TimeSyncRole::Consumer, 100));
    let uptime = build_timesync_announce_with_sender("RF", 1, 5_000_000).unwrap();
    let utc = build_timesync_announce_with_sender("GS", 50, UTC).unwrap();
    tracker.handle_announce(&uptime, 0).unwrap();
    assert_eq!(tracker.current_source().unwrap().sender, "RF");
    tracker.handle_announce(&utc, 10).unwrap();
    assert_eq!(tracker.current_source().unwrap().sender, "GS");
    let mut source = TimeSyncTracker::new(cfg(TimeSyncRole::Source, 1));
    source.handle_announce(&utc, 10).unwrap();
    assert!(
        !source.should_announce(10, true),
        "unanchored local time yields to UTC"
    );
    source.set_local_time_anchored(true);
    assert!(source.should_announce(10, true));
}

#[test]
fn relays_time_out_to_unanchored_without_a_loop() {
    let mut net = Net::new(&[
        ("GS", cfg(TimeSyncRole::Source, 50)),
        ("R1", consumer()),
        ("R2", consumer()),
    ]);
    let a = net.link(0, 1);
    let b = net.link(0, 2);
    net.link(1, 2);
    net.set_utc(0);
    converge(&net, &[1, 2], 2, 3_000);
    net.run(3_000);
    let lost = net.mono();
    net.links[a].up = false;
    net.links[b].up = false;
    net.run(20_000);
    let frames = net.frames_since(lost);
    for f in frames.iter().filter(|f| f.ty == DataType::TimeSyncAnnounce) {
        let quality = decode_timesync_quality(f.words[0], f.words[1]);
        assert!(quality.stratum <= 2, "stratum counted up: {f:?}");
        if f.at > lost + 5_000 + 2_000 {
            assert!(
                !quality.anchored,
                "relays kept each other alive as UTC: {f:?}"
            );
        }
    }
    // Both relays still agree on a common (holdover) time after the source is gone.
    let r1 = net.nodes[1].network_time_ms().unwrap();
    let r2 = net.nodes[2].network_time_ms().unwrap();
    assert!(r1.abs_diff(r2) <= 50, "relays diverged: {r1} {r2}");

    // The source returns and both relays step back onto its UTC.
    net.links[a].up = true;
    net.links[b].up = true;
    converge(&net, &[1, 2], 2, 3_000);
}

#[test]
fn downstream_announce_naming_this_node_is_never_selected() {
    let now = Arc::new(AtomicU64::new(0));
    let read = now.clone();
    let router = Router::new_with_clock(
        RouterConfig::default()
            .with_sender("RELAY")
            .with_timesync(consumer()),
        Box::new(move || read.load(Ordering::SeqCst)),
    );
    let requests = Arc::new(AtomicU64::new(0));
    let seen = requests.clone();
    let side = router.add_side_packet("bus", move |pkt| {
        if pkt.data_type() == DataType::TimeSyncRequest {
            seen.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    });
    let announce = |sender: &'static str, upstream: &str| {
        let word = encode_timesync_priority(TimeSyncQuality {
            anchored: true,
            stratum: 1,
            priority: 1,
            upstream: timesync_sender_tag(upstream),
        });
        Packet::new(
            DataType::TimeSyncAnnounce,
            &[DataEndpoint::TimeSync],
            sender,
            UTC,
            crate::router::encode_slice_le(&[word, UTC]),
        )
        .unwrap()
    };
    router
        .rx_from_side(&announce("DOWNSTREAM", "RELAY"), side)
        .unwrap();
    router.process_all_queues_with_timeout(0).unwrap();
    assert_eq!(
        requests.load(Ordering::SeqCst),
        0,
        "followed its own follower"
    );
    now.store(10, Ordering::SeqCst);
    router.rx_from_side(&announce("PEER", "GS"), side).unwrap();
    router.process_all_queues_with_timeout(0).unwrap();
    assert_eq!(requests.load(Ordering::SeqCst), 1);
}

#[test]
fn qualified_priority_word_orders_like_its_quality_and_reads_legacy_conservatively() {
    let word = |anchored, stratum, priority| {
        encode_timesync_priority(TimeSyncQuality {
            anchored,
            stratum,
            priority,
            upstream: 7,
        })
    };
    let q = TimeSyncQuality {
        anchored: true,
        stratum: 3,
        priority: 50,
        upstream: 7,
    };
    assert_eq!(decode_timesync_quality(encode_timesync_priority(q), UTC), q);
    // Numeric order seen by older decoders: UTC, then priority, then stratum.
    assert!(word(true, 9, 99) < word(false, 0, 1));
    assert!(word(true, 9, 1) < word(true, 0, 2));
    assert!(word(true, 0, 1) < word(true, 1, 1));
    // An anchored flag never survives a time below the plausibility floor.
    assert!(!decode_timesync_quality(word(true, 0, 1), 5_000_000).anchored);
    let legacy_uptime = decode_timesync_quality(50, 5_000_000);
    assert!(!legacy_uptime.anchored && legacy_uptime.stratum == 0 && legacy_uptime.priority == 50);
    let legacy_utc = decode_timesync_quality(50, UTC);
    assert!(legacy_utc.anchored && legacy_utc.stratum == TIMESYNC_LEGACY_STRATUM);
    assert_eq!(legacy_utc.upstream, 0);
    let clamped = decode_timesync_quality(word(true, 0, u64::MAX), UTC);
    assert_eq!(clamped.priority, (1 << 26) - 1);
}

#[test]
fn legacy_source_is_followed_and_re_served_at_the_next_stratum() {
    let mut net = Net::new(&[("GATEWAY", consumer()), ("VALVE", consumer())]);
    let side = net.nodes[0].add_side_packet("legacy-gs", |_| Ok(()));
    net.link(0, 1);
    for _ in 0..60 {
        let legacy = build_timesync_announce_with_sender("GS", 50, UTC + net.mono()).unwrap();
        net.nodes[0].rx_from_side(&legacy, side).unwrap();
        net.run(100);
    }
    assert!(net.error_ms(1) <= 2);
    let (re_served, _) = *announces(&net.frames_since(0), 0, 1).last().unwrap();
    assert!(re_served.anchored);
    assert_eq!(re_served.stratum, TIMESYNC_LEGACY_STRATUM + 1);
}

#[test]
fn targeted_requests_are_answered_only_by_their_target() {
    let now = Arc::new(AtomicU64::new(0));
    let read = now.clone();
    let router = Router::new_with_clock(
        RouterConfig::default()
            .with_sender("SERVER")
            .with_timesync(cfg(TimeSyncRole::Source, 10)),
        Box::new(move || read.load(Ordering::SeqCst)),
    );
    router.set_local_network_time(PartialNetworkTime::from_unix_ms(UTC));
    let responses = Arc::new(Mutex::new(Vec::new()));
    let seen = responses.clone();
    let side = router.add_side_packet("bus", move |pkt| {
        if pkt.data_type() == DataType::TimeSyncResponse {
            seen.lock().unwrap().push(pkt.data_as_u64()?[0]);
        }
        Ok(())
    });
    let mine = u64::from(timesync_sender_tag("SERVER")) << 32;
    let other = u64::from(timesync_sender_tag("OTHER")) << 32;
    for seq in [other | 1, mine | 2, 3] {
        let req = Packet::new(
            DataType::TimeSyncRequest,
            &[DataEndpoint::TimeSync],
            "CLIENT",
            0,
            crate::router::encode_slice_le(&[seq, 0]),
        )
        .unwrap();
        router.rx_from_side(&req, side).unwrap();
        router.process_all_queues_with_timeout(0).unwrap();
    }
    assert_eq!(*responses.lock().unwrap(), vec![mine | 2, 3]);
}

#[test]
fn hop_by_hop_sync_does_not_add_traffic_to_the_upstream_link() {
    let mut net = Net::new(&[
        ("GS", cfg(TimeSyncRole::Source, 50)),
        ("RF", consumer()),
        ("FC", consumer()),
        ("PB", consumer()),
    ]);
    let radio = net.link(0, 1);
    net.link(1, 2);
    net.link(1, 3);
    net.set_utc(0);
    converge(&net, &[1, 2, 3], 2, 3_000);
    let start = net.mono();
    net.run(10_000);
    let frames = net.frames_since(start);
    let link = &net.links[radio];
    let up: Vec<_> = frames
        .iter()
        .filter(|f| (f.from, f.to) == (link.a, link.b) || (f.from, f.to) == (link.b, link.a))
        .collect();
    // One announce, one request and one response per interval, whatever sits behind RF.
    assert!(
        up.len() <= 3 * 11,
        "radio carried {} time sync frames",
        up.len()
    );
    assert_eq!(count(&frames, DataType::TimeSyncAnnounce, 1, 0), 0);
    assert!(count(&frames, DataType::TimeSyncRequest, 1, 0) <= 11);
    for leaf in [2, 3] {
        assert_eq!(count(&frames, DataType::TimeSyncAnnounce, leaf, 1), 0);
    }
}
