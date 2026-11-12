//! Clock discipline for two-way time sync exchanges.
//!
//! A follower measures `phi = network - monotonic` once per exchange, at the
//! exchange midpoint. This module:
//! - keeps the last [`DISCIPLINE_SAMPLES`] accepted samples (NTP's clock filter)
//!   and rejects samples whose path delay is well above the recent minimum, so
//!   queueing on a busy link costs sample rate, not accuracy;
//! - fits phase and oscillator frequency by weighted least squares;
//! - reports an error bound and a locked/holdover state.
//!
//! Pure 64-bit arithmetic over monotonic nanoseconds (one shared 128-bit
//! multiply-divide helper), sized for Cortex-M flash budgets.

/// Accepted samples kept per follower.
pub const DISCIPLINE_SAMPLES: usize = 8;
/// Error bound at or below which a follower reports itself locked.
pub const TIMESYNC_LOCK_THRESHOLD_NS: u64 = 20_000_000;
/// Error bound above which a locked follower drops back to unlocked.
pub const TIMESYNC_UNLOCK_THRESHOLD_NS: u64 = 40_000_000;
/// Half round trip above which a sample says nothing useful and is dropped.
pub const TIMESYNC_MAX_HALF_DELAY_NS: u64 = 2_000_000_000;
/// Frequency wander assumed between samples (oscillator temperature drift and
/// estimate noise not captured by the window), parts per billion.
pub const TIMESYNC_DRIFT_ALLOWANCE_PPB: u64 = 50_000;
/// Largest frequency correction accepted: 3% covers a 1% HSI with margin.
pub const TIMESYNC_MAX_RATE_PPB: i64 = 30_000_000;
/// Minimum span of the window before the frequency is estimated.
const MIN_FREQ_SPAN_NS: u64 = 3_000_000_000;
/// Consecutive rejected samples after which the filter accepts a sample
/// anyway: the path delay has changed and the old minimum is stale.
const MAX_REJECT_RUN: u8 = 4;
/// Samples needed before a follower may report itself locked.
const MIN_LOCK_SAMPLES: u8 = 3;
/// Longest round trip considered (bounds the arithmetic).
const MAX_ROUND_TRIP_NS: u64 = 60_000_000_000;

/// `a * b / c` in 64-bit arithmetic, splitting `a` by `c` when the product
/// would overflow (callers keep `b` and `c` below 2^31), saturating. One
/// out-of-line copy keeps the scaling small on Cortex-M.
#[inline(never)]
pub fn mul_div(a: i64, b: i64, c: i64) -> i64 {
    if c == 0 {
        return 0;
    }
    match a.checked_mul(b) {
        Some(p) => p / c,
        None => (a / c).saturating_mul(b).saturating_add((a % c).saturating_mul(b) / c),
    }
}

/// One two-way exchange reduced to its midpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DisciplineSample {
    /// Local monotonic time of the exchange midpoint, ns.
    pub mono_ns: u64,
    /// Network time minus local monotonic time at the midpoint, ns.
    pub phi_ns: i64,
    /// Half the round-trip path delay (turnaround excluded), ns.
    pub half_delay_ns: u32,
    /// The source's own error bound when it answered, ns.
    pub source_error_ns: u32,
}

/// Builds a sample from the four exchange stamps.
///
/// `t1`/`t4` are the requester's monotonic transmit/receive instants (ns),
/// `t2`/`t3` the responder's network receive/transmit instants (Unix ns).
/// `local_rate_ppb` is the learned frequency correction: the round trip is
/// measured on the local oscillator, the turnaround on the network clock, and
/// a 1% HSI over a 7 s responder queue would otherwise add 70 ms of delay.
/// `asymmetry_ns` is (response one-way delay - request one-way delay) / 2.
/// Returns `None` for an impossible exchange (reply before request, negative
/// turnaround or delay) or one whose half delay exceeds
/// [`TIMESYNC_MAX_HALF_DELAY_NS`].
pub fn exchange_sample(
    t1_mono_ns: u64,
    t2_net_ns: i64,
    t3_net_ns: i64,
    t4_mono_ns: u64,
    source_error_ns: u64,
    asymmetry_ns: i64,
    local_rate_ppb: i64,
) -> Option<DisciplineSample> {
    if t4_mono_ns < t1_mono_ns || t3_net_ns < t2_net_ns {
        return None;
    }
    let round_trip_mono = t4_mono_ns - t1_mono_ns;
    if round_trip_mono > MAX_ROUND_TRIP_NS {
        return None;
    }
    let round_trip_mono = round_trip_mono as i64;
    let round_trip = round_trip_mono + mul_div(round_trip_mono, local_rate_ppb, 1_000_000_000);
    let turnaround = t3_net_ns - t2_net_ns;
    let delay = round_trip - turnaround;
    if delay < 0 {
        // The responder took longer than the whole round trip by our clock:
        // either its stamps are wrong or the rates differ grossly.
        return None;
    }
    let half = (delay / 2) as u64;
    if half > TIMESYNC_MAX_HALF_DELAY_NS {
        return None;
    }
    let mono_mid = t1_mono_ns + (round_trip_mono / 2) as u64;
    // Midpoint of the responder's stamps, corrected for a known path asymmetry.
    let net_mid = t2_net_ns + turnaround / 2 + asymmetry_ns;
    Some(DisciplineSample {
        mono_ns: mono_mid,
        phi_ns: net_mid.wrapping_sub(mono_mid as i64),
        half_delay_ns: half as u32,
        source_error_ns: source_error_ns.min(u64::from(u32::MAX)) as u32,
    })
}

/// Lock state published with the sync quality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncState {
    /// No usable exchange yet.
    Unsynced,
    /// Exchanges are arriving but the error bound is above the lock threshold.
    Acquiring,
    /// Error bound at or below the lock threshold with a live source.
    Locked,
    /// Locked earlier, source silent, free-running on the learned frequency
    /// with the error bound still under the unlock threshold.
    Holdover,
}

impl SyncState {
    /// Numeric code for C and health words.
    pub fn code(self) -> u8 {
        match self {
            SyncState::Unsynced => 0,
            SyncState::Acquiring => 1,
            SyncState::Locked => 2,
            SyncState::Holdover => 3,
        }
    }

    /// Timestamps produced in this state may be marked as synced.
    pub fn is_synced(self) -> bool {
        matches!(self, SyncState::Locked | SyncState::Holdover)
    }
}

/// Steering decision for the local network clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisciplineTarget {
    /// Network time the clock should read at `mono_ns`, Unix ns.
    pub net_ns: i64,
    /// Monotonic instant of the target.
    pub mono_ns: u64,
    /// Frequency correction to apply to the local oscillator, ppb.
    pub rate_ppb: i64,
}

/// Follower-side filter, frequency estimate and quality tracking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClockDiscipline {
    ring: [DisciplineSample; DISCIPLINE_SAMPLES],
    len: u8,
    head: u8,
    reject_run: u8,
    accepted: u8,
    was_locked: bool,
    rate_ppb: i64,
    freq_uncertainty_ppb: u64,
    fit_mono_ns: u64,
    fit_phi_ns: i64,
    fit_error_ns: u64,
}

impl Default for ClockDiscipline {
    fn default() -> Self {
        Self {
            ring: [DisciplineSample::default(); DISCIPLINE_SAMPLES],
            len: 0,
            head: 0,
            reject_run: 0,
            accepted: 0,
            was_locked: false,
            rate_ppb: 0,
            // Unknown oscillator: assume the 1% HSI worst case until measured.
            freq_uncertainty_ppb: 10_000_000,
            fit_mono_ns: 0,
            fit_phi_ns: 0,
            fit_error_ns: u64::MAX,
        }
    }
}

impl ClockDiscipline {
    /// Forgets all samples (new source, configuration change).
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Restarts sample collection after a source change but keeps the learned
    /// frequency: the local oscillator did not change.
    pub fn restart_keep_frequency(&mut self) {
        let rate = self.rate_ppb;
        let unc = self.freq_uncertainty_ppb;
        *self = Self::default();
        self.rate_ppb = rate;
        self.freq_uncertainty_ppb = unc;
    }

    /// Number of samples currently held.
    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    /// `true` before the first accepted sample.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Current frequency correction, ppb.
    pub fn rate_ppb(&self) -> i64 {
        self.rate_ppb
    }

    fn samples(&self) -> &[DisciplineSample] {
        &self.ring[..usize::from(self.len)]
    }

    /// Monotonic instant of the newest accepted sample.
    pub fn newest_mono_ns(&self) -> Option<u64> {
        self.samples().iter().map(|s| s.mono_ns).max()
    }

    fn min_half_delay(&self) -> u32 {
        self.samples().iter().map(|s| s.half_delay_ns).min().unwrap_or(0)
    }

    /// The random part of a sample's error: delay above the window minimum
    /// (queueing that may be one-sided) plus the source's own error.
    fn noise_ns(&self, s: &DisciplineSample, min_half: u32) -> u64 {
        u64::from(s.half_delay_ns.saturating_sub(min_half)) + u64::from(s.source_error_ns)
    }

    /// Offers a sample. Returns `true` when it was accepted into the filter.
    pub fn offer(&mut self, sample: DisciplineSample) -> bool {
        if self.newest_mono_ns().is_some_and(|m| sample.mono_ns <= m) {
            return false;
        }
        if self.len >= MIN_LOCK_SAMPLES && self.reject_run < MAX_REJECT_RUN {
            let best = self
                .samples()
                .iter()
                .map(|s| u64::from(s.half_delay_ns) + u64::from(s.source_error_ns))
                .min()
                .unwrap_or(0);
            // Popcorn filter: within twice the recent best plus 2 ms.
            let own = u64::from(sample.half_delay_ns) + u64::from(sample.source_error_ns);
            if own > best.saturating_mul(2).saturating_add(2_000_000) {
                self.reject_run += 1;
                return false;
            }
        }
        self.reject_run = 0;
        self.ring[usize::from(self.head)] = sample;
        self.head = (self.head + 1) % DISCIPLINE_SAMPLES as u8;
        self.len = (self.len + 1).min(DISCIPLINE_SAMPLES as u8);
        self.accepted = self.accepted.saturating_add(1);
        self.fit();
        true
    }

    /// Weighted least-squares fit of `phi` against monotonic time. Weights are
    /// 1/(1 + (noise/64 us)^2): a sample taken while the source itself was
    /// unsynced (error about 1 s) barely counts. The slope is the oscillator's
    /// frequency error; the fit at the newest sample is the phase.
    fn fit(&mut self) {
        let Some(newest) = self.newest_mono_ns() else {
            return;
        };
        let newest_phi = self
            .samples()
            .iter()
            .find(|s| s.mono_ns == newest)
            .map_or(0, |s| s.phi_ns);
        let min_half = self.min_half_delay();
        let mut w = [0i64; DISCIPLINE_SAMPLES];
        let mut x = [0i64; DISCIPLINE_SAMPLES]; // ms before newest (<= 0)
        let mut y = [0i64; DISCIPLINE_SAMPLES]; // us relative to newest phi
        let (mut sw, mut swx, mut swy, mut swe) = (0i64, 0i64, 0i64, 0i64);
        let mut oldest = newest;
        for (i, s) in self.samples().iter().enumerate() {
            let noise_us = (self.noise_ns(s, min_half) / 1_000).min(10_000_000) as i64;
            let r = noise_us / 64;
            w[i] = (1 << 20) / (1 + r.saturating_mul(r).min(1 << 20));
            x[i] = -(((newest - s.mono_ns) / 1_000_000).min(1_000_000) as i64);
            y[i] = (s.phi_ns.wrapping_sub(newest_phi) / 1_000).clamp(-1 << 40, 1 << 40);
            sw += w[i];
            swx += w[i] * x[i];
            swy += w[i] * y[i];
            swe += w[i].saturating_mul(noise_us);
            oldest = oldest.min(s.mono_ns);
        }
        if sw == 0 {
            return;
        }
        let span = newest - oldest;
        let noise_us = (swe / sw).max(1);
        if span >= MIN_FREQ_SPAN_NS {
            let (xm, ym) = (swx / sw, swy / sw);
            let (mut sxx, mut sxy) = (0i64, 0i64);
            for i in 0..self.samples().len() {
                let dx = x[i] - xm;
                sxx = sxx.saturating_add(w[i] * dx * dx / 1_024);
                sxy = sxy.saturating_add(mul_div(w[i] * dx, y[i] - ym, 1_024));
            }
            if sxx > 0 {
                // slope in us per ms = 1e-3 -> ppb = slope * 1e6
                self.rate_ppb =
                    mul_div(sxy, 1_000_000, sxx).clamp(-TIMESYNC_MAX_RATE_PPB, TIMESYNC_MAX_RATE_PPB);
                // Two noise widths across the span.
                self.freq_uncertainty_ppb =
                    (2 * noise_us as u64 * 1_000_000_000_000 / span.max(1)).min(10_000_000);
            }
        }
        // Phase at the newest sample on the fitted (or kept) frequency.
        let mut sa = 0i64;
        for (i, s) in self.samples().iter().enumerate() {
            let dx_ns = s.mono_ns as i64 - newest as i64;
            let resid = s.phi_ns.wrapping_sub(newest_phi)
                - mul_div(dx_ns, self.rate_ppb, 1_000_000_000);
            sa = sa.saturating_add(mul_div(w[i], resid, 1));
        }
        self.fit_mono_ns = newest;
        self.fit_phi_ns = newest_phi.wrapping_add(sa / sw);
        // Half the weighted noise plus 1/8 of the smallest half delay for
        // unmodelled fixed asymmetry.
        self.fit_error_ns = noise_us as u64 * 500 + u64::from(min_half) / 8;
    }

    /// Network time the clock should read at `now_mono_ns`.
    pub fn target(&self, now_mono_ns: u64) -> Option<DisciplineTarget> {
        if self.is_empty() {
            return None;
        }
        let elapsed = now_mono_ns as i64 - self.fit_mono_ns as i64;
        let phi = self.fit_phi_ns + mul_div(elapsed, self.rate_ppb, 1_000_000_000);
        Some(DisciplineTarget {
            net_ns: (now_mono_ns as i64).wrapping_add(phi),
            mono_ns: now_mono_ns,
            rate_ppb: self.rate_ppb,
        })
    }

    /// Error bound of the target at `now_mono_ns`, excluding any correction
    /// the clock still has to slew (the caller adds that).
    pub fn error_bound_ns(&self, now_mono_ns: u64) -> Option<u64> {
        if self.is_empty() {
            return None;
        }
        let age = now_mono_ns.saturating_sub(self.fit_mono_ns) / 1_000; // us
        let wander = age.saturating_mul(self.freq_uncertainty_ppb + TIMESYNC_DRIFT_ALLOWANCE_PPB)
            / 1_000_000;
        Some(self.fit_error_ns.saturating_add(wander))
    }

    /// State and error bound at `now_mono_ns`.
    ///
    /// `source_live` is false while no source is elected (holdover).
    /// `pending_ns` is the correction the clock has not slewed out yet.
    pub fn quality(&mut self, now_mono_ns: u64, source_live: bool, pending_ns: u64) -> (SyncState, u64) {
        let Some(bound) = self.error_bound_ns(now_mono_ns) else {
            return (SyncState::Unsynced, u64::MAX);
        };
        let bound = bound.saturating_add(pending_ns);
        let threshold = if self.was_locked {
            TIMESYNC_UNLOCK_THRESHOLD_NS
        } else {
            TIMESYNC_LOCK_THRESHOLD_NS
        };
        let locked = self.accepted >= MIN_LOCK_SAMPLES && bound <= threshold;
        self.was_locked = locked;
        let state = match (locked, source_live) {
            (true, true) => SyncState::Locked,
            (true, false) => SyncState::Holdover,
            (false, _) => SyncState::Acquiring,
        };
        (state, bound)
    }
}

/// Encodes an error bound into 7 bits, rounding up: codes 0..16 are
/// microseconds, then four codes per octave (1, 1.25, 1.5, 1.75 x 2^e us) up
/// to about 70 minutes. 127 means unknown or larger.
pub fn encode_error_code(bound_ns: u64) -> u8 {
    let us = bound_ns.div_ceil(1_000);
    if us < 16 {
        return us as u8;
    }
    let mut e = 63 - us.leading_zeros(); // us in [2^e, 2^(e+1)), e >= 4
    let step = 1u64 << (e - 2);
    let mut q = us.div_ceil(step); // 4..=8
    if q == 8 {
        q = 4;
        e += 1;
    }
    let code = 16 + u64::from(e - 4) * 4 + (q - 4);
    code.min(127) as u8
}

/// Decodes [`encode_error_code`] to an upper bound in nanoseconds
/// (`u64::MAX` for 127).
pub fn decode_error_code(code: u8) -> u64 {
    let code = u64::from(code.min(127));
    if code == 127 {
        return u64::MAX;
    }
    if code < 16 {
        return code * 1_000;
    }
    let e = (code - 16) / 4 + 4;
    let q = (code - 16) % 4 + 4;
    (q << (e - 2)) * 1_000
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1_000_000_000;
    const MS: u64 = 1_000_000;

    /// A simulated follower: local monotonic = true time * (1 + skew).
    struct Path {
        skew_ppb: i64,
        offset_ns: i128,
    }

    impl Path {
        fn local(&self, true_ns: u64) -> u64 {
            (true_ns as i128 + true_ns as i128 * self.skew_ppb as i128 / 1_000_000_000) as u64
        }
        fn net(&self, true_ns: u64) -> i64 {
            (true_ns as i128 + self.offset_ns) as i64
        }
        /// One exchange starting at true time `t` with uplink/downlink delays and turnaround.
        fn exchange(&self, t: u64, up: u64, turn: u64, down: u64) -> DisciplineSample {
            let t1 = self.local(t);
            let t2 = self.net(t + up);
            let t3 = self.net(t + up + turn);
            let t4 = self.local(t + up + turn + down);
            exchange_sample(t1, t2, t3, t4, 0, 0, 0).expect("valid exchange")
        }
        /// Error of `target` against truth at local time `mono`.
        fn error(&self, d: &ClockDiscipline, true_ns: u64) -> i128 {
            let mono = self.local(true_ns);
            (d.target(mono).unwrap().net_ns - self.net(true_ns)) as i128
        }
    }

    #[test]
    fn symmetric_exchange_recovers_offset_exactly() {
        let s = exchange_sample(1_000, 5_000_000_000 + 1_500, 5_000_000_000 + 9_000_000, 9_002_000, 0, 0, 0)
            .unwrap();
        // round trip 9.001 ms, turnaround 8.9985 ms, delay 2.5 us
        assert_eq!(s.half_delay_ns, 1_250);
        assert_eq!(s.mono_ns, 1_000 + 9_001_000 / 2);
    }

    #[test]
    fn long_responder_queue_does_not_bias_the_sample() {
        // 7 s spent in the responder's radio queue: turnaround, not path delay.
        let p = Path { skew_ppb: 0, offset_ns: 123_456_789 };
        let s = p.exchange(10 * S, 25 * MS, 7 * S, 25 * MS);
        assert_eq!(s.half_delay_ns as u64, 25 * MS);
        let mut d = ClockDiscipline::default();
        d.offer(s);
        let err = p.error(&d, 20 * S);
        assert!(err.abs() < 1_000, "error {err} ns");
    }

    #[test]
    fn rejects_impossible_and_overflowing_exchanges() {
        assert!(exchange_sample(10, 0, 0, 5, 0, 0, 0).is_none());
        assert!(exchange_sample(0, 10, 5, 100, 0, 0, 0).is_none());
        // turnaround longer than the round trip
        assert!(exchange_sample(0, 0, 200, 100, 0, 0, 0).is_none());
        assert!(exchange_sample(0, 0, 0, 5 * S, 0, 0, 0).is_none());
    }

    #[test]
    fn learns_one_percent_hsi_and_holds_over_sixty_seconds() {
        let p = Path { skew_ppb: 10_000_000, offset_ns: 1_767_225_600_000_000_000 };
        let mut d = ClockDiscipline::default();
        let mut t = 0;
        // Jittery radio exchanges: 25 ms base, 0-40 ms queue noise either way.
        let mut seed = 7u64;
        let mut rnd = || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (seed >> 33) % (40 * MS)
        };
        for i in 0..24 {
            let (up, down) = if i % 3 == 0 { (25 * MS, 25 * MS) } else { (25 * MS + rnd(), 25 * MS + rnd()) };
            d.offer(p.exchange(t, up, 3 * MS, down));
            t += 5 * S;
        }
        let rate = d.rate_ppb();
        // local runs 1% fast, so network-minus-local falls at about -1%.
        assert!((rate + 9_900_990).abs() < 2_000, "rate {rate}");
        let err_now = p.error(&d, t);
        assert!(err_now.abs() < 200_000, "phase error {err_now}");
        let held = p.error(&d, t + 60 * S);
        assert!(held.abs() < 1_000_000, "holdover error after 60 s {held}");
        assert_eq!(d.quality(p.local(t), true, 0).0, SyncState::Locked);
        let (state, bound) = d.quality(p.local(t + 60 * S), false, 0);
        assert_eq!(state, SyncState::Holdover);
        assert!(bound as i128 >= held.abs(), "bound {bound} must cover {held}");
    }

    #[test]
    fn popcorn_samples_are_rejected_until_the_path_really_changes() {
        let p = Path { skew_ppb: 0, offset_ns: 0 };
        let mut d = ClockDiscipline::default();
        let mut t = 0;
        for _ in 0..4 {
            assert!(d.offer(p.exchange(t, 20 * MS, MS, 20 * MS)));
            t += S;
        }
        // One sample with 500 ms of one-sided queueing would be 250 ms off.
        assert!(!d.offer(p.exchange(t, 520 * MS, MS, 20 * MS)));
        t += S;
        let err = p.error(&d, t);
        assert!(err.abs() < 1_000, "popcorn leaked: {err}");
        // A persistent change is accepted after MAX_REJECT_RUN rejections.
        let mut accepted = false;
        for _ in 0..=MAX_REJECT_RUN {
            accepted |= d.offer(p.exchange(t, 200 * MS, MS, 200 * MS));
            t += S;
        }
        assert!(accepted);
    }

    #[test]
    fn quality_flag_tracks_bound_with_hysteresis() {
        let p = Path { skew_ppb: 0, offset_ns: 0 };
        let mut d = ClockDiscipline::default();
        assert_eq!(d.quality(0, true, 0).0, SyncState::Unsynced);
        let mut t = 0;
        d.offer(p.exchange(t, 2 * MS, MS, 2 * MS));
        assert_eq!(d.quality(p.local(t), true, 0).0, SyncState::Acquiring);
        for _ in 0..4 {
            t += S;
            d.offer(p.exchange(t, 2 * MS, MS, 2 * MS));
        }
        let (state, bound) = d.quality(p.local(t + 3 * MS), true, 0);
        assert_eq!(state, SyncState::Locked);
        assert!(bound < 3 * MS);
        // A large pending slew unlocks; hysteresis keeps lock between 20 and 40 ms.
        assert_eq!(d.quality(p.local(t), true, 30 * MS).0, SyncState::Locked);
        assert_eq!(d.quality(p.local(t), true, 45 * MS).0, SyncState::Acquiring);
        assert_eq!(d.quality(p.local(t), true, 30 * MS).0, SyncState::Acquiring);
        // Long silence: holdover, then unlocked when the bound grows past 40 ms.
        assert_eq!(d.quality(p.local(t), true, 0).0, SyncState::Locked);
        assert_eq!(d.quality(p.local(t + 30 * S), false, 0).0, SyncState::Holdover);
        let (state, _) = d.quality(p.local(t + 3_000 * S), false, 0);
        assert_eq!(state, SyncState::Acquiring);
    }

    #[test]
    fn error_codes_round_up_and_saturate() {
        for &ns in &[0u64, 999, 1_000, 15_000, 16_000, 17_000, 1_000_000, 12_345_678, 23_600_000, 6_000_000_000, 1_000_000_000_000] {
            let code = encode_error_code(ns);
            assert!(code < 127, "{ns} saturated");
            let back = decode_error_code(code);
            assert!(back >= ns, "{ns} -> {code} -> {back}");
            assert!(back <= ns + ns / 4 + 1_000, "{ns} -> {back} too coarse");
        }
        assert_eq!(decode_error_code(encode_error_code(u64::MAX)), u64::MAX);
        assert_eq!(encode_error_code(u64::MAX), 127);
    }
}
