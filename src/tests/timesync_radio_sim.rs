//! Host sim of the AV-bay time sync with real routers: GS (source) over a
//! lossy turn-taking radio to RF, RF re-serving FC and PB over CAN. Stamps are
//! taken where the firmware takes them (transmit complete at the UART, receive
//! at the frame's last byte); what the stamps cannot see is modelled after
//! them: modem buffering and waiting for the other station's turn (0..hold ms),
//! air time, and loss in each direction. Each board runs on its own crystal.
use crate::router::{Clock, Router, RouterConfig, RouterSideId};
use crate::timesync::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const UTC_NS: i128 = 1_793_000_000_000_000_000;
const MS: u64 = 1_000_000;

struct Osc {
    now_ns: Arc<AtomicU64>,
    skew_ppm: i64,
}

fn local(true_ns: u64, skew_ppm: i64) -> u64 {
    let t = true_ns as i128;
    (t + t * skew_ppm as i128 / 1_000_000) as u64
}

impl Clock for Osc {
    fn now_ms(&self) -> u64 {
        self.now_ns() / MS
    }
    fn now_ns(&self) -> u64 {
        local(self.now_ns.load(Ordering::SeqCst), self.skew_ppm)
    }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// Link conditions.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RadioLink {
    /// Loss per frame in each direction.
    pub loss: f64,
    /// Probability that a frame waits for the other station's turn after its
    /// UART stamp, and the most it waits (uniform).
    pub hold_p: f64,
    pub hold_ms: f64,
    /// Fixed path after the stamp (modem, packet close, air), ms.
    pub base_ms: f64,
    /// Shortest wait of a held frame, ms (above 0: a held frame never
    /// crosses directly).
    pub hold_min_ms: f64,
    /// Only the station's frames wait (it waits for its gap; RF owns the
    /// turns): a one-sided, consistent asymmetry.
    pub station_only: bool,
}

pub(crate) const NODES: [(&str, i64); 4] = [("GS", 0), ("RF", 160), ("FC", -90), ("PB", 45)];
const GS: usize = 0;
/// 115200 baud, 10 bits per byte.
const BYTE_UART_MS: f64 = 10.0 / 115.2;
thread_local! {
    pub(crate) static PATH_DESCRIBED: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
    /// RF's radio stamps taken this much too early (ms): (t1 transmit, t4 receive).
    pub(crate) static RF_STAMP_EARLY_MS: std::cell::Cell<(f64, f64)> = const { std::cell::Cell::new((0.0, 0.0)) };
    /// FC's CAN stamps taken this much too early (ms): (t1 transmit, t4 receive),
    /// and the stamping uncertainty FC describes for its CAN side (ms, 0: none).
    pub(crate) static FC_CAN_STAMP_EARLY_MS: std::cell::Cell<(f64, f64, f64)> = const { std::cell::Cell::new((0.0, 0.0, 0.0)) };
}
const FC: usize = 2;

/// RF radio stamp at local `ns`, moved early (negative: late) by the bias.
fn rf_stamp(node: usize, radio: bool, receive: bool, ns: u64) -> u64 {
    if node == FC && !radio {
        let (t1, t4, _) = FC_CAN_STAMP_EARLY_MS.with(|e| e.get());
        return (ns as i64 - ((if receive { t4 } else { t1 }) * 1e6) as i64) as u64;
    }
    if node != RF || !radio {
        return ns;
    }
    let (t1, t4) = RF_STAMP_EARLY_MS.with(|e| e.get());
    (ns as i64 - ((if receive { t4 } else { t1 }) * 1e6) as i64) as u64
}
const RF: usize = 1;

struct Net {
    now: Arc<AtomicU64>,
    nodes: Vec<Router>,
    /// (node, side) of every side; outbox per side.
    sides: Vec<(usize, RouterSideId, bool, Arc<Mutex<Vec<Vec<u8>>>>)>,
    /// In flight: (arrival true ns, to side index, bytes).
    flight: Vec<(u64, usize, Vec<u8>)>,
    rng: Rng,
    link: RadioLink,
}

fn cfg(source: bool, request_ms: u64, announce_ms: u64) -> TimeSyncConfig {
    TimeSyncConfig {
        role: if source { TimeSyncRole::Source } else { TimeSyncRole::Consumer },
        priority: if source { 50 } else { 100 },
        source_timeout_ms: 5_000,
        announce_interval_ms: announce_ms,
        request_interval_ms: request_ms,
        consumer_promotion_enabled: true,
        max_slew_ppm: 50_000,
    }
}

impl Net {
    fn new(link: RadioLink, seed: u64) -> Self {
        let now = Arc::new(AtomicU64::new(5_000_000_000));
        let nodes: Vec<Router> = NODES
            .iter()
            .enumerate()
            .map(|(i, (name, skew))| {
                // The GS defaults (1 s); the boards' firmware intervals (2 s).
                let ts = if i == GS { cfg(true, 1_000, 1_000) } else { cfg(false, 2_000, 2_000) };
                Router::new_with_clock(
                    RouterConfig::default().with_sender(*name).with_timesync(ts),
                    Box::new(Osc { now_ns: now.clone(), skew_ppm: *skew }),
                )
            })
            .collect();
        let mut net = Self { now, nodes, sides: Vec::new(), flight: Vec::new(), rng: Rng(seed | 1), link };
        net.add_side(GS, true); // 0: GS radio
        net.add_side(RF, true); // 1: RF radio
        net.add_side(RF, false); // 2: RF CAN
        net.add_side(2, false); // 3: FC CAN
        net.add_side(3, false); // 4: PB CAN
        if PATH_DESCRIBED.with(|d| d.get()) {
            // RF describes its radio path: air plus receiving UART per byte.
            let byte_ns = (1e6 / 8.0 + BYTE_UART_MS * 1e6) as u32;
            net.nodes[RF].set_side_timesync_path(net.sides[1].1, byte_ns, 0);
        }
        // RF knows its radio path's physical minimum one-way delay: the fixed
        // path after the stamps plus 20 B of air framing (a true lower bound).
        let min_ns = ((link.base_ms + 20.0 / 8.0) * 1e6) as u32;
        net.nodes[RF].set_side_timesync_min_delay(net.sides[1].1, min_ns);
        let fc_can_stamp_ms = FC_CAN_STAMP_EARLY_MS.with(|e| e.get()).2;
        if fc_can_stamp_ms > 0.0 {
            net.nodes[FC].set_side_timesync_stamp_uncertainty(net.sides[3].1, (fc_can_stamp_ms * 1e6) as u32);
        }
        net
    }

    fn add_side(&mut self, node: usize, radio: bool) {
        let out: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
        let tx = out.clone();
        let side = self.nodes[node].add_side_packed(if radio { "radio" } else { "can" }, move |b: &[u8]| {
            tx.lock().unwrap().push(b.to_vec());
            Ok(())
        });
        self.sides.push((node, side, radio, out));
    }

    fn true_ns(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }

    fn local_ns(&self, node: usize, true_ns: u64) -> u64 {
        local(true_ns, NODES[node].1)
    }

    fn step(&mut self) {
        let t = self.true_ns();
        if t % 1_000_000_000 < MS {
            let gs = NetworkTime::from_unix_ns(UTC_NS + t as i128).unwrap();
            self.nodes[GS].set_local_network_time(gs.into());
        }
        for node in &self.nodes {
            let _ = node.periodic(0);
        }
        for from in 0..self.sides.len() {
            let (node, side, radio, out) = (self.sides[from].0, self.sides[from].1, self.sides[from].2, self.sides[from].3.clone());
            for b in std::mem::take(&mut *out.lock().unwrap()) {
                // Transmit complete at the UART (radio) or the CAN controller.
                self.nodes[node].note_frame_sent(side, &b, rf_stamp(node, radio, false, self.local_ns(node, t)));
                if radio {
                    let to = if from == 0 { 1 } else { 0 };
                    if self.rng.unit() < self.link.loss {
                        continue;
                    }
                    // Air time plus the receiving UART per byte (store and
                    // forward), 20 B of air framing.
                    let mut ms = self.link.base_ms + (b.len() as f64 + 20.0) / 8.0 + b.len() as f64 * BYTE_UART_MS;
                    if (!self.link.station_only || from == 0) && self.rng.unit() < self.link.hold_p {
                        ms += self.link.hold_min_ms + self.rng.unit() * (self.link.hold_ms - self.link.hold_min_ms);
                    }
                    self.flight.push((t + (ms * MS as f64) as u64, to, b));
                } else {
                    // One CAN bus: every other CAN side hears it 0.2..1.2 ms later.
                    for to in 2..self.sides.len() {
                        if to != from {
                            let us = 200 + self.rng.next() % 1_000;
                            self.flight.push((t + us * 1_000, to, b.clone()));
                        }
                    }
                }
            }
        }
        let next = t + MS;
        let mut due = Vec::new();
        self.flight.retain(|f| {
            if f.0 < next {
                due.push(f.clone());
                false
            } else {
                true
            }
        });
        due.sort_by_key(|f| f.0);
        for (at, to, b) in due {
            let (node, side, radio) = (self.sides[to].0, self.sides[to].1, self.sides[to].2);
            // Receive stamp at the frame's last byte.
            let rx_ns = rf_stamp(node, radio, true, self.local_ns(node, at));
            let _ = self.nodes[node].rx_packed_from_side_at(&b, side, rx_ns);
            let _ = self.nodes[node].drain_queues_with_timeout(0);
        }
        self.now.store(next, Ordering::SeqCst);
    }

    fn error_ns(&self, node: usize) -> Option<i128> {
        self.nodes[node]
            .network_time_ns()
            .map(|n| n - (UTC_NS + self.true_ns() as i128))
    }
}

/// Per board: |error| p50/p95/max (ms), and how often the reported error
/// bound was smaller than the real error while synced.
#[derive(Debug)]
pub(crate) struct Stats {
    pub name: &'static str,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub max_ms: f64,
    pub synced_fraction: f64,
    pub bound_violations: usize,
    pub bound_p50_ms: f64,
}

pub(crate) fn run(link: RadioLink, warm_s: u64, measure_s: u64, seed: u64) -> Vec<Stats> {
    let mut net = Net::new(link, seed);
    for _ in 0..warm_s * 1_000 {
        net.step();
    }
    let mut errs: Vec<Vec<f64>> = vec![Vec::new(); NODES.len()];
    let mut bounds: Vec<Vec<f64>> = vec![Vec::new(); NODES.len()];
    let mut synced = vec![0usize; NODES.len()];
    let mut violations = vec![0usize; NODES.len()];
    let mut samples = 0usize;
    for i in 0..measure_s * 1_000 {
        net.step();
        if i % 100 != 0 {
            continue;
        }
        samples += 1;
        for node in 1..NODES.len() {
            let Some(err) = net.error_ns(node) else { continue };
            errs[node].push(err.unsigned_abs() as f64 / 1e6);
            if let Some(st) = net.nodes[node].timesync_status() {
                if st.state.is_synced() {
                    synced[node] += 1;
                }
                if st.error_bound_ns != u64::MAX {
                    bounds[node].push(st.error_bound_ns as f64 / 1e6);
                    // Any reported bound, locked or not, must cover the error.
                    if (st.error_bound_ns as u128) < err.unsigned_abs() {
                        violations[node] += 1;
                    }
                }
            }
        }
    }
    let pct = |v: &mut Vec<f64>, p: f64| {
        if v.is_empty() {
            return f64::NAN;
        }
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v[((v.len() - 1) as f64 * p) as usize]
    };
    (1..NODES.len())
        .map(|node| Stats {
            name: NODES[node].0,
            p50_ms: pct(&mut errs[node], 0.5),
            p95_ms: pct(&mut errs[node], 0.95),
            max_ms: pct(&mut errs[node], 1.0),
            synced_fraction: synced[node] as f64 / samples.max(1) as f64,
            bound_violations: violations[node],
            bound_p50_ms: pct(&mut bounds[node], 0.5),
        })
        .collect()
}

fn report(label: &str, stats: &[Stats]) {
    for s in stats {
        println!(
            "{label} {:>2}: |err| p50 {:7.3} p95 {:7.3} max {:8.3} ms; synced {:5.1}%; reported bound p50 {:7.3} ms; bound < err {}",
            s.name, s.p50_ms, s.p95_ms, s.max_ms, s.synced_fraction * 100.0, s.bound_p50_ms, s.bound_violations
        );
    }
}

const CLEAN: RadioLink = RadioLink { loss: 0.0, hold_p: 0.5, hold_ms: 200.0, base_ms: 20.0, hold_min_ms: 0.0, station_only: false };
const LOSSY: RadioLink = RadioLink { loss: 0.3, hold_p: 0.5, hold_ms: 200.0, base_ms: 20.0, hold_min_ms: 0.0, station_only: false };
/// Every frame waits 20..200 ms after its stamps: no exchange ever crosses
/// directly. `STATION_WAITS` makes it one-sided: only the station's frames
/// wait (consistent asymmetry the samples cannot reveal by disagreeing).
const EVERY_WAITS: RadioLink = RadioLink { hold_p: 1.0, hold_min_ms: 20.0, ..CLEAN };
const STATION_WAITS: RadioLink = RadioLink { station_only: true, ..EVERY_WAITS };

/// 0% loss with turn-taking holds: RF, FC and PB within 3 ms p95, and the
/// reported bound never below the real error.
#[test]
fn radio_sim_clean_link() {
    let stats = run(CLEAN, 120, 180, 0x5eed);
    report("0%", &stats);
    for s in &stats {
        assert!(s.synced_fraction > 0.9, "{s:?}");
    }
    for s in &stats {
        assert!(s.p95_ms <= 3.0, "{s:?}");
        assert_eq!(s.bound_violations, 0, "{s:?}");
    }
}

/// 30% loss each way with turn-taking holds: a stated bound, and the
/// reported bound never below the real error.
#[test]
fn radio_sim_lossy_link() {
    let stats = run(LOSSY, 120, 180, 0x5eed);
    report("30%", &stats);
    for s in &stats {
        assert!(s.p95_ms <= 5.0, "{s:?}");
        assert_eq!(s.bound_violations, 0, "{s:?}");
    }
}

/// Every frame waits 0..200 ms for a turn after its stamps: no exchange ever
/// crosses directly, so there is no evidence for a tight bound. The bound must
/// never be below the real error (it widens and the boards report Acquiring).
#[test]
fn radio_sim_every_frame_waits() {
    for (label, link) in [
        ("0% every waits", EVERY_WAITS),
        ("30% every waits", RadioLink { loss: 0.3, ..EVERY_WAITS }),
        ("0% station waits", STATION_WAITS),
        ("30% station waits", RadioLink { loss: 0.3, ..STATION_WAITS }),
    ] {
        for seed in [0x5eed, 0x9e37_79b9] {
            let stats = run(link, 120, 180, seed);
            report(label, &stats);
            for s in &stats {
                assert_eq!(s.bound_violations, 0, "{link:?} seed {seed} {s:?}");
            }
        }
    }
}

/// Every 100 ms from boot, per board: samples reported synced (locked or
/// holdover) with a bound below the real error. The honest report the boards
/// owe: a bound that covers the error, or not synced.
fn synced_with_short_bound(link: RadioLink, seconds: u64, seed: u64) -> (Vec<(&'static str, usize, usize)>, u64) {
    let mut net = Net::new(link, seed);
    let mut out: Vec<(&'static str, usize, usize)> = (1..NODES.len()).map(|n| (NODES[n].0, 0, 0)).collect();
    for i in 0..seconds * 1_000 {
        net.step();
        if i % 100 != 0 {
            continue;
        }
        for node in 1..NODES.len() {
            let (Some(err), Some(st)) = (net.error_ns(node), net.nodes[node].timesync_status()) else { continue };
            if st.state.is_synced() {
                out[node - 1].2 += 1;
                if (st.error_bound_ns as u128) < err.unsigned_abs() {
                    if out[node - 1].1 == 0 {
                        println!(
                            "first short bound: {} at {:.1} s err {:.3} ms bound {:.3} ms {:?}",
                            NODES[node].0, i as f64 / 1e3, err as f64 / 1e6, st.error_bound_ns as f64 / 1e6, st.state
                        );
                    }
                    out[node - 1].1 += 1;
                }
            }
        }
    }
    (out, net.nodes[RF].export_runtime_stats().timesync_sub_minimum_rejects)
}

/// Returns RF's sub-minimum rejections over all runs.
fn assert_honest_with_rf_stamps_early(t1_ms: f64, t4_ms: f64) -> u64 {
    RF_STAMP_EARLY_MS.with(|e| e.set((t1_ms, t4_ms)));
    let mut failures = Vec::new();
    let mut rejects = 0;
    for (label, link) in [("0%", CLEAN), ("30%", LOSSY)] {
        for seed in [0x5eed, 0x9e37_79b9, 7] {
            let (res, rf_rejects) = synced_with_short_bound(link, 300, seed);
            rejects += rf_rejects;
            println!("t1 early {t1_ms} ms, t4 early {t4_ms} ms, {label} seed {seed}: (board, synced with bound < error, synced samples) {res:?}, RF sub-minimum rejects {rf_rejects}");
            if res.iter().any(|r| r.1 != 0) {
                failures.push((label, seed, res));
            }
        }
    }
    RF_STAMP_EARLY_MS.with(|e| e.set((0.0, 0.0)));
    assert!(failures.is_empty(), "synced with a bound below the real error: {failures:?}");
    rejects
}

/// A downstream board inherits an honest bound from a biased upstream: RF's
/// receive stamp early by 6..20 ms (small enough that RF may still lock on a
/// widened bound), FC and PB syncing to RF over CAN. Neither may report itself
/// synced with a bound below its real error, and the propagation is
/// exercised: they do lock on RF's (honest, wider) bound.
#[test]
fn radio_sim_downstream_inherits_honest_bound_from_biased_rf() {
    let mut downstream_synced = 0;
    for t4_ms in [6.0, 12.0, 20.0] {
        RF_STAMP_EARLY_MS.with(|e| e.set((0.0, t4_ms)));
        let mut failures = Vec::new();
        for (label, link) in [("0%", CLEAN), ("30%", LOSSY)] {
            for seed in [0x5eed, 0x9e37_79b9, 7] {
                let (res, rejects) = synced_with_short_bound(link, 300, seed);
                println!("RF t4 early {t4_ms} ms, {label} seed {seed}: {res:?}, RF sub-minimum rejects {rejects}");
                downstream_synced += res[1].2 + res[2].2;
                if res.iter().any(|r| r.1 != 0) {
                    failures.push((t4_ms, label, seed, res));
                }
            }
        }
        RF_STAMP_EARLY_MS.with(|e| e.set((0.0, 0.0)));
        assert!(failures.is_empty(), "synced with a bound below the real error: {failures:?}");
    }
    assert!(downstream_synced > 0, "FC/PB never locked: the propagation was not exercised");
}

/// FC's own CAN stamps off: early by 0.5 ms within the stamping uncertainty
/// FC describes for its CAN side (the bound must carry it), and by 1.5 ms
/// and 5 ms with nothing described (a round trip shorter than the turnaround
/// or than zero proves the stamp wrong; it must not tighten the bound).
#[test]
fn radio_sim_can_leg_stamp_error_stays_honest() {
    for (t4_ms, described_ms) in [(0.5, 0.5), (1.5, 0.0), (5.0, 0.0)] {
        FC_CAN_STAMP_EARLY_MS.with(|e| e.set((0.0, t4_ms, described_ms)));
        let mut failures = Vec::new();
        for (label, link) in [("0%", CLEAN), ("30%", LOSSY)] {
            for seed in [0x5eed, 0x9e37_79b9, 7] {
                let (res, _) = synced_with_short_bound(link, 300, seed);
                println!("FC CAN t4 early {t4_ms} ms (described {described_ms} ms), {label} seed {seed}: {res:?}");
                if res.iter().any(|r| r.1 != 0) {
                    failures.push((t4_ms, label, seed, res));
                }
            }
        }
        FC_CAN_STAMP_EARLY_MS.with(|e| e.set((0.0, 0.0, 0.0)));
        assert!(failures.is_empty(), "synced with a bound below the real error: {failures:?}");
    }
}

/// RF's transmit stamp (t1) 38 ms early: the round trip looks 38 ms longer
/// and the phase 19 ms ahead. At every sample each board's bound covers its
/// real error or the board does not report itself synced. 38 ms late (the
/// round trip looks shorter, like an early t4) must stay honest too.
#[test]
fn radio_sim_rf_t1_stamped_38ms_early_stays_honest() {
    assert_eq!(assert_honest_with_rf_stamps_early(38.0, 0.0), 0, "a longer round trip proves nothing");
    assert!(assert_honest_with_rf_stamps_early(-38.0, 0.0) > 0, "sub-minimum round trips are counted");
}

/// RF's receive stamp (t4) 38 ms early: the round trip looks 38 ms shorter,
/// often below the radio's physical minimum, which proves a stamp is wrong;
/// it must never make a sample look like a direct crossing.
#[test]
fn radio_sim_rf_t4_stamped_38ms_early_stays_honest() {
    assert_eq!(assert_honest_with_rf_stamps_early(0.0, 0.0), 0, "true stamps never measure below the minimum");
    assert!(assert_honest_with_rf_stamps_early(0.0, 38.0) > 0, "sub-minimum round trips are counted");
}

/// Prints RF's error, bound, rate and sample age over time (diagnosis).
#[test]
#[ignore = "host sim trace"]
fn radio_sim_trace() {
    let loss: f64 = std::env::var("SIM_LOSS").ok().and_then(|v| v.parse().ok()).unwrap_or(0.3);
    let hold_p: f64 = std::env::var("SIM_HOLD").ok().and_then(|v| v.parse().ok()).unwrap_or(0.5);
    let seed: u64 = std::env::var("SIM_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(0x5eed);
    let mut net = Net::new(RadioLink { loss, hold_p, ..LOSSY }, seed);
    for i in 0..300_000u64 {
        net.step();
        if i % 2_000 == 0 {
            let st = net.nodes[RF].timesync_status().unwrap();
            println!(
                "t {:5.0}s RF err {:9.3} ms bound {:9.3} ms state {:?} rate {:8} ppb offset {:9.3} ms age {} ms",
                i as f64 / 1e3,
                net.error_ns(RF).unwrap_or(0) as f64 / 1e6,
                st.error_bound_ns as f64 / 1e6,
                st.state,
                st.rate_ppb,
                st.offset_ns as f64 / 1e6,
                st.last_sample_age_ms
            );
        }
    }
}

/// Seeds and harsher links: every frame held (hold_p 1), and RF's radio path
/// undescribed (the 18 B request/response size difference becomes a bias).
#[test]
#[ignore = "host sim sweep"]
fn radio_sim_sweep() {
    let mut worst_violations = 0;
    for (label, link, described, honest) in [
        ("0% hold .5", CLEAN, true, true),
        ("30% hold .5", LOSSY, true, true),
        ("50% hold .5", RadioLink { loss: 0.5, ..LOSSY }, true, true),
        ("0% undescribed", CLEAN, false, true),
        ("30% undescribed", LOSSY, false, true),
        ("0% hold 1", RadioLink { hold_p: 1.0, ..CLEAN }, true, true),
        ("30% hold 1", RadioLink { hold_p: 1.0, ..LOSSY }, true, true),
    ] {
        PATH_DESCRIBED.with(|d| d.set(described));
        let mut p95 = 0f64;
        let mut max = 0f64;
        let mut bound = 0f64;
        let mut synced = 1f64;
        for seed in 1..=6u64 {
            for s in run(link, 120, 300, seed * 0x9e37_79b9) {
                p95 = p95.max(s.p95_ms);
                max = max.max(s.max_ms);
                bound = bound.max(s.bound_p50_ms);
                synced = synced.min(s.synced_fraction);
                if honest {
                    worst_violations += s.bound_violations;
                }
                if s.bound_violations > 0 || s.p95_ms > 3.0 {
                    println!("{label} seed {seed}: {s:?}");
                }
            }
        }
        println!("{label:>16}: worst p95 {p95:6.3} ms, max {max:7.3} ms, bound p50 up to {bound:6.3} ms, synced >= {:5.1}%", synced * 100.0);
    }
    PATH_DESCRIBED.with(|d| d.set(true));
    assert_eq!(worst_violations, 0);
}

/// 50% loss each way, seed 11: an early fit on lossy samples learns a rate
/// near 2% while the true one is -0.016%. Every reported bound, Acquiring
/// included, must cover the real error from boot: the frequency uncertainty
/// may not be capped below the rate the fit could be wrong by.
#[test]
fn radio_sim_heavy_loss_bound_covers_error_while_acquiring() {
    let stats = run(RadioLink { loss: 0.5, ..LOSSY }, 0, 420, 11 * 0x9e37_79b9);
    report("50% seed 11", &stats);
    for s in &stats {
        assert_eq!(s.bound_violations, 0, "{s:?}");
    }
}

/// Reading the time sync status is an observation: a network whose boards'
/// status is read every 100 ms follows exactly the same trajectory as one
/// whose status is never read.
#[test]
fn reading_timesync_status_does_not_change_the_trajectory() {
    for (link, seed) in [(RadioLink { loss: 0.5, ..LOSSY }, 6 * 0x9e37_79b9), (LOSSY, 0x5eed)] {
        let mut watched = Net::new(link, seed);
        let mut quiet = Net::new(link, seed);
        for i in 0..240_000u64 {
            watched.step();
            quiet.step();
            if i % 100 == 0 {
                for node in 1..NODES.len() {
                    let _ = watched.nodes[node].timesync_status();
                }
            }
            if i % 10_000 == 0 {
                for node in 1..NODES.len() {
                    assert_eq!(watched.error_ns(node), quiet.error_ns(node), "node {node} diverged at {} s", i / 1_000);
                }
            }
        }
    }
}
