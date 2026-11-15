//! Clock discipline for two-way time sync exchanges.
//!
//! A follower measures `phi = network - monotonic` once per exchange, at the
//! exchange midpoint. This module:
//! - keeps the [`DISCIPLINE_SAMPLES`] samples that say most about the clock now
//!   (NTP's clock filter): one whose path delay is well above the window's best
//!   is rejected, and a full window replaces its worst (aged) sample, so
//!   queueing or turn waits on a busy link cost sample rate, not accuracy;
//! - fits phase and oscillator frequency by weighted least squares, weights
//!   1/sigma^2 where sigma is each sample's worst-case path error;
//! - reports an error bound built from those worst cases (never a statistic of
//!   the fit), widened by the disagreement of the best samples, and a
//!   locked/holdover state. The bound rests on evidence only: a sample is off
//!   by at most half of its round trip above the path's physical minimum
//!   (`Router::set_side_timesync_min_delay`), so the bound is tight only once
//!   an exchange crossed without waiting for a turn. Each end's stamps may be
//!   off by the side's configured stamping uncertainty (UART, DMA and ISR
//!   latency), which the bound carries as well. A round trip below the
//!   physical minimum proves a stamp wrong, not the sample precise: such a
//!   sample is rejected and its deficit raises the stamp term until stamps
//!   stop contradicting the minimum (see [`ClockDiscipline::note_stamp_deficit`]).
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
/// Oldest sample the window keeps (oscillator temperature wander).
const MAX_WINDOW_SPAN_NS: u64 = 600_000_000_000;
/// Consecutive rejected samples after which the filter accepts a sample
/// anyway: the path delay has changed and the old minimum is stale.
const MAX_REJECT_RUN: u8 = 4;
/// Samples needed before a follower may report itself locked.
const MIN_LOCK_SAMPLES: u8 = 3;
/// Longest round trip considered (bounds the arithmetic).
const MAX_ROUND_TRIP_NS: u64 = 60_000_000_000;
/// How far below the physical minimum a round trip may measure (beyond both
/// ends' stamping uncertainty) before it proves a stamp wrong.
pub const TIMESYNC_MIN_DELAY_TOLERANCE_NS: u64 = 1_000_000;

/// `x / d` for `0 < d < 2^21`, exact, in 11-bit digits so every step is a
/// 32-bit division (one instruction on Cortex-M4; a 64-bit division is a
/// software routine of a few hundred).
#[inline(never)]
pub fn div_u64_small(x: u64, d: u32) -> u64 {
    debug_assert!(d > 0 && d < 1 << 21);
    // Constant shifts only: a variable 64-bit shift is a library call on
    // Cortex-M at opt-level "z".
    let hi = (x >> 32) as u32;
    let lo = x as u32;
    let digits = [
        hi >> 23,
        (hi >> 12) & 0x7FF,
        (hi >> 1) & 0x7FF,
        ((hi & 1) << 10) | (lo >> 22),
        (lo >> 11) & 0x7FF,
        lo & 0x7FF,
    ];
    let mut q = 0u64;
    let mut r = 0u32;
    for digit in digits {
        let cur = (r << 11) | digit;
        q = (q << 11) | u64::from(cur / d);
        r = cur % d;
    }
    q
}

/// `x / 1_000_000` (exact).
#[inline]
pub fn div_u64_1e6(x: u64) -> u64 {
    div_u64_small(x >> 6, 15_625)
}

/// `x / 1_000_000_000` (exact).
#[inline]
pub fn div_u64_1e9(x: u64) -> u64 {
    div_u64_small(x >> 9, 1_953_125)
}

/// `a * b / c` for `c` = 1e6 or 1e9 with exactly [`mul_div`]'s result
/// (truncation toward zero, the same overflow path), without the software
/// 64-bit division in the common no-overflow case.
#[inline]
pub(crate) fn mul_div_pow10(a: i64, b: i64, c: i64) -> i64 {
    debug_assert!(c == 1_000_000 || c == 1_000_000_000);
    let Some(p) = a.checked_mul(b) else {
        return mul_div(a, b, c);
    };
    let m = p.unsigned_abs();
    let q = if c == 1_000_000 { div_u64_1e6(m) } else { div_u64_1e9(m) };
    // |p| <= 2^63 so q < 2^54 fits i64.
    if p < 0 { -(q as i64) } else { q as i64 }
}

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

/// `num * 1e6 / den` for `den > 0` without overflow: both are shifted right
/// together until the product fits (the ratio keeps its precision).
fn ratio_e6(mut num: i64, mut den: i64) -> i64 {
    while num.unsigned_abs() > (i64::MAX / 1_000_000) as u64 && den > 1 {
        num >>= 1;
        den >>= 1;
    }
    num.saturating_mul(1_000_000) / den.max(1)
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
    /// Half the physical minimum round trip of this exchange (0 when the
    /// path's minimum is unknown), ns: the sample is off by at most
    /// `half_delay_ns - min_half_delay_ns`.
    pub min_half_delay_ns: u32,
    /// Most either end's stamp of this exchange may be off (the side's
    /// stamping uncertainty), ns: the phase is off by at most this beyond the
    /// path term, since stamps that shorten the round trip hide path excess.
    pub stamp_error_ns: u32,
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
        min_half_delay_ns: 0,
        stamp_error_ns: 0,
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
    /// Largest round-trip deficit below the physical minimum seen lately, ns,
    /// and when (monotonic ns): proof the stamps can be off by that much.
    stamp_deficit_ns: u64,
    stamp_deficit_mono_ns: u64,
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
            stamp_deficit_ns: 0,
            stamp_deficit_mono_ns: 0,
        }
    }
}

impl ClockDiscipline {
    /// Forgets all samples (new source, configuration change).
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Restarts sample collection after a source change but keeps the learned
    /// frequency and stamp evidence: the local oscillator and transport did
    /// not change.
    pub fn restart_keep_frequency(&mut self) {
        let keep = self.clone();
        *self = Self::default();
        self.rate_ppb = keep.rate_ppb;
        self.freq_uncertainty_ppb = keep.freq_uncertainty_ppb;
        self.stamp_deficit_ns = keep.stamp_deficit_ns;
        self.stamp_deficit_mono_ns = keep.stamp_deficit_mono_ns;
    }

    /// Records an exchange (not offered) whose round trip measured
    /// `deficit_ns` below the path's physical minimum at `mono_ns`. Some stamp
    /// was off by at least that much, and the samples accepted around it may
    /// hide the same error inside a round trip that looks merely short: the
    /// bound carries the deficit until none has been seen for the window span.
    pub fn note_stamp_deficit(&mut self, deficit_ns: u64, mono_ns: u64) {
        if mono_ns.saturating_sub(self.stamp_deficit_mono_ns) > MAX_WINDOW_SPAN_NS {
            self.stamp_deficit_ns = 0;
        }
        self.stamp_deficit_ns = self.stamp_deficit_ns.max(deficit_ns);
        self.stamp_deficit_mono_ns = mono_ns;
        if !self.is_empty() {
            self.fit();
        }
    }

    /// Most any held sample's stamps may be off: the samples' configured
    /// stamping uncertainty, or proof of a larger one seen within the window
    /// span of the newest sample. Per sample, a stamp error hides up to this
    /// much path excess on top of what its round trip shows, so it widens
    /// every sample's worst case (phase and frequency alike).
    fn stamp_error_ns(&self) -> u64 {
        let configured = self.samples().iter().map(|s| u64::from(s.stamp_error_ns)).max().unwrap_or(0);
        let newest = self.newest_mono_ns().unwrap_or(0);
        if self.stamp_deficit_ns != 0 && newest.saturating_sub(self.stamp_deficit_mono_ns) <= MAX_WINDOW_SPAN_NS {
            configured.max(self.stamp_deficit_ns + TIMESYNC_MIN_DELAY_TOLERANCE_NS)
        } else {
            configured
        }
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

    /// Worst-case error of a sample's phase, us: half the round trip above
    /// the path's physical minimum, the source's own error, and a 20 us stamp
    /// floor. The true offset lies within this of `phi`.
    fn sigma_us(s: &DisciplineSample, min_half: u32) -> u64 {
        Self::path_sigma_us(s, min_half) + u64::from(s.source_error_ns) / 1_000
    }

    /// The path's part of [`Self::sigma_us`]: what differs from sample to
    /// sample. The source's own error is a slowly varying common error (its
    /// clock is disciplined), so it does not tilt the frequency estimate; it is
    /// added to the phase bound once.
    fn path_sigma_us(s: &DisciplineSample, _min_half: u32) -> u64 {
        // Evidence only: how far the round trip exceeded the path's physical
        // minimum (each direction is at least its minimum, so the asymmetry
        // is at most half the excess). A sample that waited for a turn says
        // so; with the minimum unknown the whole half round trip counts.
        u64::from(s.half_delay_ns.saturating_sub(s.min_half_delay_ns)) / 1_000 + 20
    }

    /// Offers a sample. Returns `true` when it was accepted into the filter.
    ///
    /// The window keeps the samples that say most about the clock now: when
    /// it is full, the new sample replaces the one whose error, aged by the
    /// drift allowance, is worst, if the new one is better. A run of
    /// [`MAX_REJECT_RUN`] worse samples replaces it anyway: the path itself
    /// has changed and the old minimum is stale.
    pub fn offer(&mut self, sample: DisciplineSample) -> bool {
        if self.newest_mono_ns().is_some_and(|m| sample.mono_ns <= m) {
            return false;
        }
        // With the path's physical minimum known the error of every sample is
        // measured, not inferred: a worse sample never displaces a better one
        // (a longer path shows as wider errors and an aging bound). Only an
        // undescribed path needs the forced acceptance that follows a change.
        let may_force = sample.min_half_delay_ns == 0 && self.reject_run >= MAX_REJECT_RUN;
        if self.len >= MIN_LOCK_SAMPLES && !may_force {
            // Popcorn filter: well above the window's best (one-sided
            // queueing) costs sample rate, not accuracy or a window slot.
            let min_half = self.min_half_delay().min(sample.half_delay_ns);
            let best = self.samples().iter().map(|s| Self::sigma_us(s, min_half)).min().unwrap_or(0);
            if Self::sigma_us(&sample, min_half) > best.saturating_mul(2).saturating_add(2_000) {
                self.reject_run = self.reject_run.saturating_add(1);
                return false;
            }
        }
        let slot = if usize::from(self.len) < DISCIPLINE_SAMPLES {
            usize::from(self.len)
        } else {
            let min_half = self.min_half_delay().min(sample.half_delay_ns);
            // The best samples stay: an old direct crossing anchors the
            // frequency better than a new one that waited for a turn. Only a
            // sample older than the window span goes regardless.
            let score = |s: &DisciplineSample| {
                let age_ns = sample.mono_ns - s.mono_ns;
                if age_ns > MAX_WINDOW_SPAN_NS {
                    u64::MAX
                } else {
                    // 1 us per second of age: equally good samples rotate,
                    // a sample that waited for a turn never displaces a
                    // direct crossing.
                    Self::sigma_us(s, min_half).saturating_add(age_ns / 1_000_000_000)
                }
            };
            let (worst, worst_score) = self
                .samples()
                .iter()
                .enumerate()
                .map(|(i, s)| (i, score(s)))
                .max_by_key(|(_, sc)| *sc)
                .unwrap_or((0, 0));
            if Self::sigma_us(&sample, min_half) >= worst_score && !may_force {
                self.reject_run = self.reject_run.saturating_add(1);
                return false;
            }
            worst
        };
        self.reject_run = 0;
        self.ring[slot] = sample;
        self.len = (self.len + 1).min(DISCIPLINE_SAMPLES as u8);
        self.head = (slot as u8 + 1) % DISCIPLINE_SAMPLES as u8;
        self.accepted = self.accepted.saturating_add(1);
        self.fit();
        true
    }

    /// Weighted least-squares fit of `phi` against monotonic time, weights
    /// 1/sigma^2. The slope is the oscillator's frequency error; the fit at
    /// the newest sample is the phase. Both carry worst-case bounds derived
    /// from the per-sample errors (never a statistic of the fit itself, which
    /// a single good sample among bad ones makes look precise).
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
        let n = self.samples().len();
        let stamp_us = (self.stamp_error_ns() / 1_000).min(1 << 31) as i64;
        // 64-bit only (Cortex-M flash: no 128-bit division routines): weights
        // 2^30/sigma^2 with sigma in [20 us, 2^20 us], x in ms within 2^20,
        // y in us within 2^31; products pass through `mul_div`.
        let mut w = [0i64; DISCIPLINE_SAMPLES];
        let mut sig = [0i64; DISCIPLINE_SAMPLES]; // us
        let mut x = [0i64; DISCIPLINE_SAMPLES]; // ms before newest (<= 0)
        let mut y = [0i64; DISCIPLINE_SAMPLES]; // us relative to newest phi
        let (mut sw, mut swx, mut swy) = (0i64, 0i64, 0i64);
        let mut oldest = newest;
        for (i, s) in self.samples().iter().enumerate() {
            sig[i] = Self::path_sigma_us(s, min_half).min(1 << 20) as i64;
            w[i] = ((1i64 << 30) / (sig[i] * sig[i])).max(1);
            x[i] = -(((newest - s.mono_ns) / 1_000_000).min(1 << 20) as i64);
            y[i] = (s.phi_ns.wrapping_sub(newest_phi) / 1_000).clamp(-(1 << 31), 1 << 31);
            sw += w[i];
            swx += w[i] * x[i];
            swy += w[i] * y[i];
            oldest = oldest.min(s.mono_ns);
        }
        if newest - oldest >= MIN_FREQ_SPAN_NS && n >= 2 {
            let (xm, ym) = (swx / sw, swy / sw);
            let (mut sxx, mut sxy, mut sxe) = (0i64, 0i64, 0i64);
            for i in 0..n {
                let dx = x[i] - xm;
                sxx = sxx.saturating_add(mul_div(w[i] * dx, dx, 1_024));
                sxy = sxy.saturating_add(mul_div(w[i] * dx, y[i] - ym, 1_024));
                sxe = sxe.saturating_add(mul_div(w[i] * dx.abs(), sig[i] + stamp_us, 1_024));
            }
            if sxx > 0 {
                // slope in us per ms = 1e-3 -> ppb = slope * 1e6
                self.rate_ppb = ratio_e6(sxy, sxx).clamp(-TIMESYNC_MAX_RATE_PPB, TIMESYNC_MAX_RATE_PPB);
                // Worst case over |error_i| <= sigma_i.
                self.freq_uncertainty_ppb = ratio_e6(sxe, sxx).clamp(0, 10_000_000) as u64;
            }
        }
        // Phase at the newest sample on the fitted (or kept) frequency, and
        // its worst-case error: each sample's error plus the frequency's over
        // its distance from the newest (both in us).
        let (mut sa, mut se) = (0i64, 0i64);
        for (i, s) in self.samples().iter().enumerate() {
            let dx_ns = s.mono_ns as i64 - newest as i64;
            let resid_us = (s.phi_ns.wrapping_sub(newest_phi) - mul_div(dx_ns, self.rate_ppb, 1_000_000_000)) / 1_000;
            sa = sa.saturating_add(w[i].saturating_mul(resid_us.clamp(-(1 << 31), 1 << 31)));
            let carry_us = mul_div((dx_ns.unsigned_abs() / 1_000) as i64, self.freq_uncertainty_ppb as i64, 1_000_000_000);
            se = se.saturating_add(w[i].saturating_mul(sig[i] + stamp_us + carry_us.min(1 << 31)));
        }
        self.fit_mono_ns = newest;
        self.fit_phi_ns = newest_phi.wrapping_add((sa / sw).saturating_mul(1_000));
        // The best samples must agree with the fit within the bound: when they
        // do not, their paths were asymmetric beyond the allowance (every frame
        // queued on one side) and the spread is the evidence.
        let best = sig[..n].iter().copied().min().unwrap_or(0);
        let mut spread = 0i64;
        for (i, s) in self.samples().iter().enumerate() {
            if sig[i] <= best * 2 + 1_000 {
                let dx_ns = s.mono_ns as i64 - newest as i64;
                let fitted = self.fit_phi_ns.wrapping_add(mul_div(dx_ns, self.rate_ppb, 1_000_000_000));
                spread = spread.max(s.phi_ns.wrapping_sub(fitted).saturating_abs());
            }
        }
        // The source's own error, the worst it reported over the window: its
        // clock moves under us between samples within that bound.
        let source = self.samples().iter().map(|s| u64::from(s.source_error_ns)).max().unwrap_or(0);
        self.fit_error_ns = ((se / sw).saturating_mul(1_000).max(spread.saturating_mul(3)) as u64).saturating_add(source);
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
            let mut sample = exchange_sample(t1, t2, t3, t4, 0, 0, 0).expect("valid exchange");
            // The faster direction is at its physical minimum: the sample's
            // error bound is exactly half the delay difference.
            sample.min_half_delay_ns = up.min(down).min(u64::from(sample.half_delay_ns)) as u32;
            sample
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
    fn stamp_uncertainty_and_deficit_evidence_widen_the_bound() {
        let p = Path { skew_ppb: 0, offset_ns: 0 };
        let mut d = ClockDiscipline::default();
        let mut t = 0;
        for _ in 0..5 {
            let mut s = p.exchange(t, 2 * MS, MS, 2 * MS);
            s.stamp_error_ns = 300_000;
            d.offer(s);
            t += S;
        }
        let now = p.local(t);
        let base = d.error_bound_ns(now).unwrap();
        assert!(base >= 300_000, "configured stamp uncertainty carried: {base}");
        // A round trip 38 ms below the minimum: some stamp is that far off.
        d.note_stamp_deficit(38 * MS, now);
        let (state, bound) = d.quality(now, true, 0);
        assert!(bound >= base - 300_000 + 38 * MS, "deficit carried: {bound}");
        assert_eq!(state, SyncState::Acquiring);
        // The evidence survives a source change, and lapses after the window
        // span without a new deficit.
        d.restart_keep_frequency();
        for _ in 0..5 {
            d.offer(p.exchange(t, 2 * MS, MS, 2 * MS));
            t += S;
        }
        assert!(d.error_bound_ns(p.local(t)).unwrap() >= 38 * MS);
        let later = now + MAX_WINDOW_SPAN_NS + S;
        for _ in 0..5 {
            d.offer(p.exchange(later + t, 2 * MS, MS, 2 * MS));
            t += S;
        }
        assert!(d.error_bound_ns(p.local(later + t)).unwrap() < 5 * MS);
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
