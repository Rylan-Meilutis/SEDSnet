//! Interleaved (v2) time sync over the unchanged request/response frames:
//! transport stamps, legacy peers on both ends, quality reporting and the
//! scheduling bands. Mixed builds against the real 4.3.14 router are covered
//! by the out-of-tree compat harness (workspace `compat-test`).
use crate::config::{DataEndpoint, DataType};
use crate::packet::Packet;
use crate::router::{Clock, Router, RouterConfig, RouterSideId};
use crate::timesync::*;
use crate::timesync_discipline::SyncState;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const UTC_NS: i128 = 1_793_000_000_000_000_000;

/// Node clock: local = true * (1 + skew_ppm), nanosecond resolution.
struct Osc {
    now_ns: Arc<AtomicU64>,
    skew_ppm: i64,
}

impl Clock for Osc {
    fn now_ms(&self) -> u64 {
        self.now_ns() / 1_000_000
    }
    fn now_ns(&self) -> u64 {
        let t = self.now_ns.load(Ordering::SeqCst) as i128;
        (t + t * self.skew_ppm as i128 / 1_000_000) as u64
    }
}

fn cfg(source: bool) -> TimeSyncConfig {
    TimeSyncConfig {
        role: if source { TimeSyncRole::Source } else { TimeSyncRole::Consumer },
        priority: if source { 50 } else { 100 },
        source_timeout_ms: 5_000,
        announce_interval_ms: 1_000,
        request_interval_ms: 1_000,
        consumer_promotion_enabled: true,
        max_slew_ppm: 50_000,
    }
}

type Out = Arc<Mutex<Vec<Vec<u8>>>>;

struct Pair {
    now: Arc<AtomicU64>,
    gs: Router,
    rf: Router,
    gs_side: RouterSideId,
    rf_side: RouterSideId,
    gs_out: Out,
    rf_out: Out,
    /// Frames in flight: (arrival true ns, to_rf, bytes).
    flight: Vec<(u64, bool, Vec<u8>)>,
}

impl Pair {
    fn new(rf_skew_ppm: i64) -> Self {
        let now = Arc::new(AtomicU64::new(5_000_000_000));
        let gs = Router::new_with_clock(
            RouterConfig::default().with_sender("GS").with_timesync(cfg(true)),
            Box::new(Osc { now_ns: now.clone(), skew_ppm: 0 }),
        );
        let rf = Router::new_with_clock(
            RouterConfig::default().with_sender("RF").with_timesync(cfg(false)),
            Box::new(Osc { now_ns: now.clone(), skew_ppm: rf_skew_ppm }),
        );
        let gs_out: Out = Arc::default();
        let rf_out: Out = Arc::default();
        let tx = gs_out.clone();
        let gs_side = gs.add_side_packed("radio", move |b: &[u8]| {
            tx.lock().unwrap().push(b.to_vec());
            Ok(())
        });
        let tx = rf_out.clone();
        let rf_side = rf.add_side_packed("radio", move |b: &[u8]| {
            tx.lock().unwrap().push(b.to_vec());
            Ok(())
        });
        Self { now, gs, rf, gs_side, rf_side, gs_out, rf_out, flight: Vec::new() }
    }

    fn true_ns(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }

    fn set_gs_utc(&self) {
        let t = NetworkTime::from_unix_ns(UTC_NS + self.true_ns() as i128).unwrap();
        self.gs.set_local_network_time(t.into());
    }

    /// Advances 1 ms. GS->RF frames wait `gs_queue_ns` after handoff before
    /// they leave (reported to the GS router as transmit-complete).
    fn step(&mut self, one_way_ns: u64, gs_queue_ns: u64) {
        let t = self.true_ns();
        if t % 1_000_000_000 < 1_000_000 {
            self.set_gs_utc();
        }
        let _ = self.gs.periodic(0);
        let _ = self.rf.periodic(0);
        for b in std::mem::take(&mut *self.gs_out.lock().unwrap()) {
            self.flight.push((t + gs_queue_ns + one_way_ns, true, b));
        }
        for b in std::mem::take(&mut *self.rf_out.lock().unwrap()) {
            self.rf.note_frame_sent(self.rf_side, &b, self.rf_local_ns());
            self.flight.push((t + one_way_ns, false, b));
        }
        // GS transmit-complete stamps when a queued frame leaves.
        for (arrive, to_rf, b) in &self.flight {
            if *to_rf && arrive.saturating_sub(one_way_ns) == t {
                self.gs.note_frame_sent(self.gs_side, b, t);
            }
        }
        let due: Vec<_> = self.flight.iter().filter(|f| f.0 <= t).cloned().collect();
        self.flight.retain(|f| f.0 > t);
        for (_, to_rf, b) in due {
            if to_rf {
                let _ = self.rf.rx_packed_from_side_at(&b, self.rf_side, self.rf_local_ns());
                let _ = self.rf.drain_queues_with_timeout(0);
            } else {
                let _ = self.gs.rx_packed_from_side_at(&b, self.gs_side, t);
                let _ = self.gs.drain_queues_with_timeout(0);
            }
        }
        self.now.fetch_add(1_000_000, Ordering::SeqCst);
    }

    fn rf_local_ns(&self) -> u64 {
        // RF oscillator as configured in `new` (skew applied by its router clock).
        self.rf_clock_ns()
    }

    fn rf_clock_ns(&self) -> u64 {
        // The router exposes no clock accessor; recompute from its error source.
        RF_SKEW.with(|s| {
            let t = self.true_ns() as i128;
            (t + t * s.get() as i128 / 1_000_000) as u64
        })
    }

    fn rf_error_ns(&self) -> i128 {
        self.rf.network_time_ns().unwrap() - (UTC_NS + self.true_ns() as i128)
    }
}

thread_local! {
    static RF_SKEW: std::cell::Cell<i64> = const { std::cell::Cell::new(0) };
}

fn pair(skew_ppm: i64) -> Pair {
    RF_SKEW.with(|s| s.set(skew_ppm));
    Pair::new(skew_ppm)
}

#[test]
fn interleaved_exchange_ignores_a_seven_second_responder_queue() {
    let mut p = pair(8_000);
    // Acquire with a quiet link, then hold every GS frame 7 s in its queue.
    for _ in 0..30_000 {
        p.step(25_000_000, 0);
    }
    for _ in 0..90_000 {
        p.step(25_000_000, 7_000_000_000);
    }
    let err = p.rf_error_ns();
    assert!(err.abs() < 2_000_000, "RF error {err} ns with a 7 s GS queue");
    let st = p.rf.timesync_status().unwrap();
    assert!(st.state.is_synced(), "{st:?}");
    assert!(st.error_bound_ns >= err.unsigned_abs() as u64, "bound {st:?} vs {err}");
    assert!(st.rate_ppb < -7_000_000 && st.rate_ppb > -9_000_000, "rate {}", st.rate_ppb);
}

#[test]
fn frames_keep_their_word_counts_and_flags() {
    let mut p = pair(0);
    let mut seen_v2_request = false;
    let mut seen_v2_response = false;
    for _ in 0..6_000 {
        let gs_frames = p.gs_out.lock().unwrap().clone();
        let rf_frames = p.rf_out.lock().unwrap().clone();
        for b in gs_frames.iter().chain(rf_frames.iter()) {
            let pkt = crate::wire_format::unpack_packet(b).unwrap();
            let words = pkt.data_as_u64().unwrap_or_default();
            match pkt.data_type() {
                DataType::TimeSyncRequest => {
                    assert_eq!(words.len(), TIMESYNC_REQUEST_WORDS);
                    seen_v2_request |= words[0] & TIMESYNC_V2_REQUEST != 0;
                }
                DataType::TimeSyncResponse => {
                    assert_eq!(words.len(), TIMESYNC_RESPONSE_WORDS);
                    seen_v2_response |= words[0] & TIMESYNC_V2_RESPONSE != 0;
                }
                DataType::TimeSyncAnnounce => assert_eq!(words.len(), TIMESYNC_ANNOUNCE_WORDS),
                _ => {}
            }
        }
        p.step(25_000_000, 0);
    }
    assert!(seen_v2_request && seen_v2_response);
}

fn legacy_request(seq: u64, t1: u64) -> Packet {
    Packet::new(
        DataType::TimeSyncRequest,
        &[DataEndpoint::TimeSync],
        "OLD",
        t1,
        crate::router::encode_slice_le(&[seq, t1]),
    )
    .unwrap()
}

#[test]
fn legacy_requester_gets_a_millisecond_answer_with_real_receive_stamp() {
    let p = pair(0);
    for _ in 0..3 {
        p.set_gs_utc();
        let _ = p.gs.periodic(0);
    }
    p.gs_out.lock().unwrap().clear();
    p.gs.rx_from_side(&legacy_request(7, 1234), p.gs_side).unwrap();
    let _ = p.gs.drain_queues_with_timeout(0);
    let frames = p.gs_out.lock().unwrap().clone();
    let resp = frames
        .iter()
        .map(|b| crate::wire_format::unpack_packet(b).unwrap())
        .find(|pkt| pkt.data_type() == DataType::TimeSyncResponse)
        .expect("legacy request answered");
    let w = resp.data_as_u64().unwrap();
    assert_eq!(w[0], 7, "legacy seq echoed without v2 flags");
    assert_eq!(w[1], 1234);
    let utc_ms = ((UTC_NS + p.true_ns() as i128) / 1_000_000) as u64;
    assert!(w[2].abs_diff(utc_ms) <= 1, "t2 is UTC milliseconds: {} vs {utc_ms}", w[2]);
    assert!(w[3] >= w[2]);
}

#[test]
fn legacy_responder_still_disciplines_a_new_requester() {
    // RF (new) follows a GS that answers like 4.3.14: echo seq, t2 = t3 =
    // its processing time in ms, regardless of the v2 flag.
    let now = Arc::new(AtomicU64::new(5_000_000_000));
    RF_SKEW.with(|s| s.set(5_000));
    let rf = Router::new_with_clock(
        RouterConfig::default().with_sender("RF").with_timesync(cfg(false)),
        Box::new(Osc { now_ns: now.clone(), skew_ppm: 5_000 }),
    );
    let out: Arc<Mutex<Vec<Packet>>> = Arc::default();
    let tx = out.clone();
    let side = rf.add_side_packet("radio", move |p: &Packet| {
        tx.lock().unwrap().push(p.clone());
        Ok(())
    });
    let mut pending: Vec<(u64, Packet)> = Vec::new();
    for ms in 0..60_000u64 {
        let t = now.load(Ordering::SeqCst);
        let utc_ms = ((UTC_NS + t as i128) / 1_000_000) as u64;
        if ms % 1_000 == 0 {
            let ann = build_timesync_announce_with_sender("OLDGS", 50, utc_ms).unwrap();
            pending.push((t + 25_000_000, ann));
        }
        let _ = rf.periodic(0);
        for pkt in std::mem::take(&mut *out.lock().unwrap()) {
            if pkt.data_type() == DataType::TimeSyncRequest {
                let w = pkt.data_as_u64().unwrap();
                // Legacy server: answers on arrival + 25 ms.
                let at = t + 25_000_000;
                let ms_then = ((UTC_NS + at as i128) / 1_000_000) as u64;
                let resp = Packet::new(
                    DataType::TimeSyncResponse,
                    &[DataEndpoint::TimeSync],
                    "OLDGS",
                    ms_then,
                    crate::router::encode_slice_le(&[w[0], w[1], ms_then, ms_then]),
                )
                .unwrap();
                pending.push((at + 25_000_000, resp));
            }
        }
        let due: Vec<_> = pending.iter().filter(|(a, _)| *a <= t).cloned().collect();
        pending.retain(|(a, _)| *a > t);
        for (_, pkt) in due {
            let _ = rf.rx_from_side(&pkt, side);
            let _ = rf.drain_queues_with_timeout(0);
        }
        now.fetch_add(1_000_000, Ordering::SeqCst);
    }
    let err = rf.network_time_ns().unwrap() - (UTC_NS + now.load(Ordering::SeqCst) as i128);
    assert!(err.abs() < 3_000_000, "error {err} ns against a legacy responder");
    assert_eq!(rf.timesync_status().unwrap().stratum, TIMESYNC_LEGACY_STRATUM + 1);
}

#[test]
fn quality_moves_from_unsynced_to_locked_and_holds_over() {
    let mut p = pair(-4_000);
    assert_eq!(p.rf.timesync_status().unwrap().state, SyncState::Unsynced);
    for _ in 0..40_000 {
        p.step(25_000_000, 0);
    }
    let st = p.rf.timesync_status().unwrap();
    assert_eq!(st.state, SyncState::Locked, "{st:?}");
    assert_eq!(st.health_byte() & 0x80, 0x80);
    // GS silent for 60 s: holdover on the learned frequency.
    for _ in 0..60_000 {
        let _ = p.rf.periodic(0);
        p.rf_out.lock().unwrap().clear();
        p.now.fetch_add(1_000_000, Ordering::SeqCst);
    }
    let st = p.rf.timesync_status().unwrap();
    let err = p.rf_error_ns();
    assert!(err.abs() < 5_000_000, "holdover error {err}");
    assert!(st.error_bound_ns as i128 >= err.abs(), "{st:?} vs {err}");
}

#[test]
fn urgent_types_outrank_network_control_which_outranks_data() {
    let abort = DataType(0x7A11_0001);
    assert!(!crate::type_is_urgent(abort));
    assert!(crate::set_type_scheduling_class(abort, -1));
    assert_eq!(crate::transport_priority(abort), 255);
    assert_eq!(crate::transport_priority(DataType::TimeSyncRequest), crate::NETWORK_CONTROL_PRIORITY);
    assert_eq!(crate::transport_priority(DataType::TimeSyncAnnounce), 254);
    assert_eq!(crate::transport_priority(DataType::DiscoveryAnnounce), 255);
    assert_eq!(crate::transport_priority(DataType::ReliableAck), 255);
    assert!(crate::set_type_scheduling_class(abort, 1));
    assert!(!crate::type_is_urgent(abort));
}

#[test]
fn utc_reports_ride_in_the_request_cookie_and_never_wrap() {
    let mut p = pair(2_000);
    for _ in 0..30_000 {
        p.step(25_000_000, 0);
    }
    // RF's GPS says the network is 12.345 ms behind UTC, +-20 ms.
    p.rf.set_utc_reference_offset(Some((12_345_000, 20_000_000)));
    let _ = p.gs.take_utc_reference_reports();
    for _ in 0..12_000 {
        p.step(25_000_000, 0);
    }
    let reports = p.gs.take_utc_reference_reports();
    assert!(!reports.is_empty(), "no report reached the GS");
    let r = reports.last().unwrap();
    assert_eq!(r.offset_ns, 12_345_000);
    assert!(r.error_ns >= 20_000_000 && r.error_ns < 30_000_000, "{r:?}");
    assert_eq!(r.sender_tag, timesync_sender_tag("RF"));
    // Sync keeps working with report cookies.
    assert!(p.rf_error_ns().abs() < 3_000_000);
    // An offset that does not fit 41 bits is not sent at all.
    assert!(encode_utc_report_word(1 << 41, 1, 0).is_none());
    assert_eq!(decode_utc_report_word(encode_utc_report_word(-5, 3, 9).unwrap()), (-5, 3));
}
