//! Time synchronization primitives, packet helpers, and network-clock utilities.
//!
//! This module:
//! - Defines the public time sync configuration and role-selection types.
//! - Encodes and decodes time sync announce/request/response packets.
//! - Tracks remote time sources and elects the current synchronization leader.
//! - Maintains partial or complete network time assembled from one or more sources.
//! - Provides a slewed clock that converges toward sampled network time without hard jumps.

use alloc::boxed::Box;
use crate::OrdMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::mem::size_of;

use crate::router::{Router, encode_slice_le};
use crate::{
    DataEndpoint, DataType, TelemetryError, TelemetryResult, config::runtime_device_identifier,
    message_meta, packet::Packet,
};

/// Number of `u64` words carried by a time sync announce payload.
pub const TIMESYNC_ANNOUNCE_WORDS: usize = 2;
/// Number of `u64` words carried by a time sync request payload.
pub const TIMESYNC_REQUEST_WORDS: usize = 2;
/// Number of `u64` words carried by a time sync response payload.
pub const TIMESYNC_RESPONSE_WORDS: usize = 4;
/// Synthetic source identifier used for a remotely learned full-network-time source.
pub const INTERNAL_TIMESYNC_SOURCE_ID: &str = "__timesync_remote__";
/// Synthetic source identifier used for a locally supplied complete date+time source.
pub const LOCAL_TIMESYNC_FULL_SOURCE_ID: &str = "__timesync_local_full__";
/// Synthetic source identifier used for a locally supplied date-only source.
pub const LOCAL_TIMESYNC_DATE_SOURCE_ID: &str = "__timesync_local_date__";
/// Synthetic source identifier used for a locally supplied time-of-day source.
pub const LOCAL_TIMESYNC_TOD_SOURCE_ID: &str = "__timesync_local_tod__";
/// Synthetic source identifier used for a locally supplied sub-second source.
pub const LOCAL_TIMESYNC_SUBSEC_SOURCE_ID: &str = "__timesync_local_subsec__";
/// Earliest Unix millisecond (2020-01-01T00:00:00Z) accepted as real UTC.
/// Earlier readings are uptime or otherwise unanchored time.
pub const TIMESYNC_UTC_FLOOR_MS: u64 = 1_577_836_800_000;
/// Largest stratum that may be followed. A node re-serves at its source's stratum plus one.
pub const TIMESYNC_MAX_STRATUM: u8 = 15;
/// Stratum assumed for a legacy (unqualified) announce carrying plausible UTC.
pub const TIMESYNC_LEGACY_STRATUM: u8 = 8;
/// Forward error, in milliseconds, above which a verified exchange steps an anchored
/// clock; unanchored clocks step onto UTC whenever their error exceeds it.
pub(crate) const TIMESYNC_STEP_THRESHOLD_MS: u64 = 5_000;
const QUALITY_MARKER: u64 = 1 << 63;
const QUALITY_UNANCHORED: u64 = 1 << 62;
const QUALITY_PRIORITY_SHIFT: u32 = 36;
const QUALITY_PRIORITY_MAX: u64 = (1 << 26) - 1;
const QUALITY_STRATUM_SHIFT: u32 = 32;

/// Declares how a node participates in time synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeSyncRole {
    /// Never originates time unless promoted by consumer fallback rules.
    Consumer,
    /// Always advertises itself as a time source.
    Source,
    /// Advertises itself only when it has usable time and no better source is active.
    Auto,
}

/// Configures time sync behavior for a router or tracker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeSyncConfig {
    /// Local participation mode used for leader election and serving behavior.
    pub role: TimeSyncRole,
    /// Lower values are preferred during source selection.
    pub priority: u64,
    /// Maximum age before an announced source is considered inactive.
    pub source_timeout_ms: u64,
    /// Interval between local announce packets while acting as leader.
    pub announce_interval_ms: u64,
    /// Interval between request packets while following a remote source.
    pub request_interval_ms: u64,
    /// Allows a consumer with usable local time to promote itself when no remote source exists.
    pub consumer_promotion_enabled: bool,
    /// Maximum slew rate applied by [`SlewedNetworkClock`] in parts per million.
    pub max_slew_ppm: u32,
}

impl Default for TimeSyncConfig {
    fn default() -> Self {
        Self {
            role: TimeSyncRole::Consumer,
            priority: 100,
            source_timeout_ms: 5_000,
            announce_interval_ms: 1_000,
            request_interval_ms: 1_000,
            consumer_promotion_enabled: true,
            max_slew_ppm: 50_000,
        }
    }
}

/// Describes the currently elected time sync leader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeSyncLeader {
    /// The local node is the current leader at the given effective priority.
    Local { priority: u64 },
    /// A remote node is the current leader.
    Remote(TimeSyncSource),
}

/// Snapshot of a remote time source learned from announce traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeSyncSource {
    /// Sender identifier for the remote source.
    pub sender: String,
    /// Advertised announce priority word. Lower is better. Qualified announces
    /// also carry time quality; see [`TimeSyncSource::quality`].
    pub priority: u64,
    /// Monotonic receive time, in milliseconds, of the last announce.
    pub last_announce_ms: u64,
    /// Network time value carried by the last announce, in Unix milliseconds.
    pub last_time_ms: u64,
}

impl TimeSyncSource {
    /// Decodes the time quality carried by the last announce.
    pub fn quality(&self) -> TimeSyncQuality {
        decode_timesync_quality(self.priority, self.last_time_ms)
    }
}

/// Time quality carried in the announce priority word.
///
/// Qualified announces set bit 63, set bit 62 for unanchored (non-UTC) time,
/// and carry a 26-bit priority in bits 36..62, the stratum in bits 32..36 and
/// the sender tag of the announcer's own source in bits 0..32 (0 for a
/// reference). Numeric order therefore still ranks anchored before unanchored,
/// then priority, then stratum, for decoders that only compare the word.
/// Legacy announces carry a plain priority and are anchored only when their
/// time is at or after [`TIMESYNC_UTC_FLOOR_MS`], at [`TIMESYNC_LEGACY_STRATUM`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeSyncQuality {
    /// Time is traceable to a real UTC reference.
    pub anchored: bool,
    /// Hops from the reference. A reference announces stratum 0.
    pub stratum: u8,
    /// Configured priority of the reference. Lower is better.
    pub priority: u64,
    /// [`timesync_sender_tag`] of the source the announcer follows, or 0.
    pub upstream: u32,
}

impl TimeSyncQuality {
    fn rank(&self) -> (bool, u64, u8) {
        (!self.anchored, self.priority, self.stratum)
    }
}

/// Encodes a qualified announce priority word.
pub fn encode_timesync_priority(quality: TimeSyncQuality) -> u64 {
    QUALITY_MARKER
        | if quality.anchored { 0 } else { QUALITY_UNANCHORED }
        | (quality.priority.min(QUALITY_PRIORITY_MAX) << QUALITY_PRIORITY_SHIFT)
        | (u64::from(quality.stratum.min(TIMESYNC_MAX_STRATUM)) << QUALITY_STRATUM_SHIFT)
        | u64::from(quality.upstream)
}

/// Decodes the time quality of an announce priority word and its time.
/// Times before [`TIMESYNC_UTC_FLOOR_MS`] are never anchored.
pub fn decode_timesync_quality(priority: u64, time_ms: u64) -> TimeSyncQuality {
    let plausible = time_ms >= TIMESYNC_UTC_FLOOR_MS;
    if priority & QUALITY_MARKER == 0 {
        return TimeSyncQuality {
            anchored: plausible,
            stratum: if plausible { TIMESYNC_LEGACY_STRATUM } else { 0 },
            priority,
            upstream: 0,
        };
    }
    TimeSyncQuality {
        anchored: plausible && priority & QUALITY_UNANCHORED == 0,
        stratum: ((priority >> QUALITY_STRATUM_SHIFT) & 0xF) as u8,
        priority: (priority >> QUALITY_PRIORITY_SHIFT) & QUALITY_PRIORITY_MAX,
        upstream: priority as u32,
    }
}

/// Stable nonzero tag identifying a sender in qualified announces and targeted requests.
pub fn timesync_sender_tag(sender: &str) -> u32 {
    crate::packet::sender_address_u32(sender)
}

/// Reports whether tracker state changed after processing or pruning sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeSyncUpdate {
    /// The active source selection stayed the same.
    NoChange,
    /// The active source selection changed.
    SourceChanged,
}

/// Decoded fields from a time sync request packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeSyncRequestFields {
    /// Request sequence number chosen by the requester.
    pub seq: u64,
    /// Requester transmit timestamp in monotonic milliseconds.
    pub t1_ms: u64,
}

/// Decoded fields from a time sync response packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeSyncResponseFields {
    /// Sequence number copied from the corresponding request.
    pub seq: u64,
    /// Original requester transmit timestamp in monotonic milliseconds.
    pub t1_ms: u64,
    /// Responder receive timestamp in network milliseconds.
    pub t2_ms: u64,
    /// Responder transmit timestamp in network milliseconds.
    pub t3_ms: u64,
}

/// Decoded fields from a time sync announce packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeSyncAnnounceFields {
    /// Advertised source priority. Lower is better.
    pub priority: u64,
    /// Advertised network time in Unix milliseconds.
    pub time_ms: u64,
}

/// Result of a four-timestamp offset/delay computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeSyncSample {
    /// Estimated clock offset in milliseconds from requester to responder.
    pub offset_ms: i64,
    /// Estimated round-trip path delay in milliseconds.
    pub delay_ms: u64,
}

/// Partial calendar/time-of-day reading assembled from one or more sources.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PartialNetworkTime {
    /// Calendar year, if known.
    pub year: Option<i32>,
    /// Calendar month in the range `1..=12`, if known.
    pub month: Option<u8>,
    /// Day of month in the range `1..=31`, if known.
    pub day: Option<u8>,
    /// Hour of day in the range `0..=23`, if known.
    pub hour: Option<u8>,
    /// Minute in the range `0..=59`, if known.
    pub minute: Option<u8>,
    /// Second in the range `0..=59`, if known.
    pub second: Option<u8>,
    /// Nanosecond within the current second, if known.
    pub nanosecond: Option<u32>,
}

impl PartialNetworkTime {
    /// Builds a complete partial-time value from Unix milliseconds when conversion succeeds.
    pub fn from_unix_ms(unix_ms: u64) -> Self {
        let unix_ns = (unix_ms as i128) * 1_000_000;
        if let Some(full) = NetworkTime::from_unix_ns(unix_ns) {
            Self::from(full)
        } else {
            Self::default()
        }
    }

    /// Returns `true` when year, month, and day are all present.
    pub fn is_complete_date(&self) -> bool {
        self.year.is_some() && self.month.is_some() && self.day.is_some()
    }

    /// Returns `true` when hour, minute, and second are all present.
    pub fn is_complete_time(&self) -> bool {
        self.hour.is_some() && self.minute.is_some() && self.second.is_some()
    }

    /// Converts this value into a full [`NetworkTime`] when all required fields are present.
    pub fn to_network_time(&self) -> Option<NetworkTime> {
        Some(NetworkTime {
            year: self.year?,
            month: self.month?,
            day: self.day?,
            hour: self.hour?,
            minute: self.minute?,
            second: self.second?,
            nanosecond: self.nanosecond.unwrap_or(0),
        })
    }
}

impl From<NetworkTime> for PartialNetworkTime {
    fn from(value: NetworkTime) -> Self {
        Self {
            year: Some(value.year),
            month: Some(value.month),
            day: Some(value.day),
            hour: Some(value.hour),
            minute: Some(value.minute),
            second: Some(value.second),
            nanosecond: Some(value.nanosecond),
        }
    }
}

/// Fully specified calendar and time-of-day in UTC-like Unix time representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkTime {
    /// Calendar year.
    pub year: i32,
    /// Calendar month in the range `1..=12`.
    pub month: u8,
    /// Day of month in the range `1..=31`.
    pub day: u8,
    /// Hour of day in the range `0..=23`.
    pub hour: u8,
    /// Minute in the range `0..=59`.
    pub minute: u8,
    /// Second in the range `0..=59`.
    pub second: u8,
    /// Nanosecond within the current second.
    pub nanosecond: u32,
}

impl NetworkTime {
    /// Converts a non-negative Unix nanosecond timestamp into calendar/time fields.
    pub fn from_unix_ns(unix_ns: i128) -> Option<Self> {
        if unix_ns < 0 {
            return None;
        }

        // Every Unix time before 2554 fits u64 nanoseconds: one 64-bit
        // division instead of 128-bit ones (software division on Cortex-M).
        let (secs, nanos) = match u64::try_from(unix_ns) {
            Ok(ns) => {
                let secs = crate::timesync_discipline::div_u64_1e9(ns);
                (secs, (ns - secs * 1_000_000_000) as u32)
            }
            Err(_) => (
                u64::try_from(unix_ns / 1_000_000_000).ok()?,
                unix_ns.rem_euclid(1_000_000_000) as u32,
            ),
        };
        // Before 2106 the seconds fit 32 bits and divide in hardware.
        let (days, sod) = match u32::try_from(secs) {
            Ok(secs) => (u64::from(secs / 86_400), secs % 86_400),
            Err(_) => (secs / 86_400, (secs % 86_400) as u32),
        };
        let (year, month, day) = civil_from_days(days)?;

        Some(Self {
            year,
            month: month as u8,
            day: day as u8,
            hour: (sod / 3_600) as u8,
            minute: ((sod % 3_600) / 60) as u8,
            second: (sod % 60) as u8,
            nanosecond: nanos,
        })
    }

    /// Whole Unix seconds of valid fields (fits i64 for every i32 year).
    fn unix_secs(&self) -> Option<i64> {
        if !(1..=12).contains(&self.month)
            || !(1..=31).contains(&self.day)
            || self.hour > 23
            || self.minute > 59
            || self.second > 59
            || self.nanosecond >= 1_000_000_000
        {
            return None;
        }
        let days = days_from_civil(self.year, self.month as u32, self.day as u32);
        Some(
            days * 86_400
                + i64::from(self.hour) * 3_600
                + i64::from(self.minute) * 60
                + i64::from(self.second),
        )
    }

    /// Converts this calendar/time value into Unix nanoseconds if the fields are valid.
    pub fn as_unix_ns(&self) -> Option<i128> {
        Some(i128::from(self.unix_secs()?) * 1_000_000_000 + self.nanosecond as i128)
    }

    /// Converts this calendar/time value into non-negative Unix milliseconds.
    pub fn as_unix_ms(&self) -> Option<u64> {
        // ns = secs * 1e9 + nanosecond with 0 <= nanosecond < 1e9, so ns < 0
        // exactly when secs < 0, and ns / 1e6 = secs * 1000 + nanosecond / 1e6:
        // no 128-bit division (a long software routine on Cortex-M).
        let secs = self.unix_secs()?;
        if secs < 0 {
            return None;
        }
        (secs as u64)
            .checked_mul(1_000)?
            .checked_add(u64::from(self.nanosecond / 1_000_000))
    }
}

/// Best-effort current network-time reading from the assembled clock state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkTimeReading {
    /// Partial or complete calendar/time-of-day reading.
    pub time: PartialNetworkTime,
    /// Absolute Unix milliseconds when the reading is complete enough to derive them.
    pub unix_time_ms: Option<u64>,
}

/// Monotonic-anchor clock that slews toward target Unix time instead of stepping immediately.
///
/// Internally 64-bit (Unix ns fits until 2262); one shared multiply-divide
/// helper does the scaling, which keeps 128-bit code off small targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlewedNetworkClock {
    anchor_mono_ns: u64,
    anchor_unix_ns: i64,
    pending_adjust_ns: i64,
    max_slew_ppm: u32,
    initialized: bool,
    /// Learned frequency correction of the local oscillator, ppb.
    rate_ppb: i64,
}

impl Default for SlewedNetworkClock {
    fn default() -> Self {
        Self {
            anchor_mono_ns: 0,
            anchor_unix_ns: 0,
            pending_adjust_ns: 0,
            max_slew_ppm: 50_000,
            initialized: false,
            rate_ppb: 0,
        }
    }
}

fn clamp_unix_ns(ns: i128) -> i64 {
    ns.clamp(0, i128::from(i64::MAX)) as i64
}

impl SlewedNetworkClock {
    /// Creates a new slewed clock with the given slew-rate cap in parts per million.
    pub fn new(max_slew_ppm: u32) -> Self {
        Self {
            max_slew_ppm: max_slew_ppm.min(999_999),
            ..Default::default()
        }
    }

    /// Returns `true` once the clock has received an initial anchor time.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Slew applied after `elapsed_ns` since the anchor, ns.
    fn applied_slew(&self, elapsed_ns: i64) -> i64 {
        let pending = self.pending_adjust_ns;
        if pending == 0 {
            return 0;
        }
        // Once the slew has run its course (the common case between
        // exchanges) the whole correction applies: floor(e*ppm/1e6) >= |p|
        // exactly when e*ppm >= |p|*1e6, so two multiplies replace the
        // software 64-bit division.
        if let (Some(budget), Some(needed)) = (
            elapsed_ns.checked_mul(i64::from(self.max_slew_ppm)),
            pending.checked_abs().and_then(|p| p.checked_mul(1_000_000)),
        ) && elapsed_ns >= 0
            && budget >= needed
        {
            return pending;
        }
        let max_adjust =
            crate::timesync_discipline::mul_div_pow10(elapsed_ns, i64::from(self.max_slew_ppm), 1_000_000);
        pending.clamp(-max_adjust, max_adjust)
    }

    fn read_ns(&self, now_mono_ns: u64) -> Option<i64> {
        if !self.initialized {
            return None;
        }
        let elapsed = now_mono_ns.saturating_sub(self.anchor_mono_ns).min(i64::MAX as u64) as i64;
        let rate = if self.rate_ppb == 0 {
            0
        } else {
            crate::timesync_discipline::mul_div_pow10(elapsed, self.rate_ppb, 1_000_000_000)
        };
        Some(
            self.anchor_unix_ns
                .saturating_add(elapsed)
                .saturating_add(rate)
                .saturating_add(self.applied_slew(elapsed)),
        )
    }

    /// Reads the current estimated Unix time in nanoseconds from a monotonic timestamp.
    pub fn read_unix_ns(&self, now_mono_ns: u64) -> Option<i128> {
        self.read_ns(now_mono_ns).map(i128::from)
    }

    /// Reads the current estimated Unix time in milliseconds from a monotonic timestamp.
    pub fn read_unix_ms(&self, now_mono_ns: u64) -> Option<u64> {
        let unix_ns = self.read_ns(now_mono_ns)?;
        (unix_ns >= 0).then(|| crate::timesync_discipline::div_u64_1e6(unix_ns as u64))
    }

    /// `read_unix_ms(now_mono_ns).is_some()` without the millisecond division.
    pub(crate) fn has_unix_time(&self, now_mono_ns: u64) -> bool {
        self.read_ns(now_mono_ns).is_some_and(|unix_ns| unix_ns >= 0)
    }

    /// Reads the clock at a monotonic instant that may precede the current
    /// anchor (a stamp taken before the last steering update), Unix ns.
    pub fn read_unix_ns_at(&self, mono_ns: u64) -> Option<i64> {
        if mono_ns >= self.anchor_mono_ns {
            return self.read_ns(mono_ns);
        }
        let before = (self.anchor_mono_ns - mono_ns).min(i64::MAX as u64) as i64;
        let anchor = self.read_ns(self.anchor_mono_ns)?;
        Some(anchor - before - crate::timesync_discipline::mul_div(before, self.rate_ppb, 1_000_000_000))
    }

    /// Correction still to be slewed out at `now_mono_ns`, ns (signed:
    /// positive when the clock reads behind its target).
    pub fn pending_signed_ns(&self, now_mono_ns: u64) -> i64 {
        if !self.initialized {
            return 0;
        }
        let elapsed = now_mono_ns.saturating_sub(self.anchor_mono_ns).min(i64::MAX as u64) as i64;
        self.pending_adjust_ns - self.applied_slew(elapsed)
    }

    /// Correction still to be slewed out at `now_mono_ns`, ns (absolute).
    pub fn pending_ns(&self, now_mono_ns: u64) -> u64 {
        self.pending_signed_ns(now_mono_ns).unsigned_abs()
    }

    /// Learned frequency correction, ppb.
    pub fn rate_ppb(&self) -> i64 {
        self.rate_ppb
    }

    /// Disciplines the clock toward a two-way-exchange target: sets the
    /// learned frequency and slews the remaining phase error. `allow_step`
    /// re-anchors directly (only before the follower first locks).
    pub(crate) fn discipline_ns(
        &mut self,
        now_mono_ns: u64,
        target_unix_ns: i64,
        rate_ppb: i64,
        allow_step: bool,
    ) {
        let current = self.read_ns(now_mono_ns);
        self.rate_ppb = rate_ppb;
        self.anchor_mono_ns = now_mono_ns;
        match current {
            Some(current) if !allow_step => {
                self.anchor_unix_ns = current;
                self.pending_adjust_ns = target_unix_ns.saturating_sub(current);
            }
            _ => {
                self.anchor_unix_ns = target_unix_ns;
                self.pending_adjust_ns = 0;
            }
        }
        self.initialized = true;
    }

    /// Steers toward an absolute reading with nanosecond resolution.
    pub fn steer_unix_ns(&mut self, now_mono_ns: u64, target_unix_ns: i64) {
        let current = self.read_ns(now_mono_ns);
        self.anchor_mono_ns = now_mono_ns;
        match current {
            Some(current) => {
                self.anchor_unix_ns = current;
                // The target is an absolute observation at `now`, not an
                // incremental correction: it replaces the residual error.
                self.pending_adjust_ns = target_unix_ns.saturating_sub(current);
            }
            None => {
                self.anchor_unix_ns = target_unix_ns;
                self.pending_adjust_ns = 0;
                self.initialized = true;
            }
        }
    }

    /// Re-anchors the clock at a target reading in either direction. Callers use
    /// this only when replacing unanchored time with time traceable to UTC.
    pub(crate) fn step_unix_ms(&mut self, now_mono_ns: u64, target_unix_ms: u64) {
        self.anchor_mono_ns = now_mono_ns;
        self.anchor_unix_ns = clamp_unix_ns(i128::from(target_unix_ms) * 1_000_000);
        self.pending_adjust_ns = 0;
        self.initialized = true;
    }

    /// Steers the clock toward a target Unix millisecond reading at the configured slew rate.
    pub fn steer_unix_ms(&mut self, now_mono_ns: u64, target_unix_ms: u64) {
        self.steer_unix_ns(now_mono_ns, clamp_unix_ns(i128::from(target_unix_ms) * 1_000_000));
    }
}

// ---------------------------------------------------------------------------
// Time sync exchange (SEDSnet 5 wire format; 4.x nodes do not interoperate).
//
// Request  [seq, t1]: seq bits 0..29 are the counter, bit 29 flags a UTC
//          report in t1, bits 32..64 the target tag. Otherwise t1 is the
//          requester's monotonic millisecond cookie; the precise transmit
//          instant is kept locally.
// Response [seq, t1, t2, t3] (NTP interleaved mode):
//          t2 = bits 0..56 responder network time in microseconds when the
//               request was received; bit 63 = responder synced; bits 56..63
//               = responder error bound code (timesync_discipline).
//          t3 = bits 0..56 network microseconds at which the responder's
//               PREVIOUS response to this requester actually left; bits
//               56..64 = low byte of that previous request's counter. 0 when
//               no earlier response is known.
// Responder queueing becomes turnaround, not path delay. No frame grew.
// ---------------------------------------------------------------------------

/// Request seq flag: the t1 word carries an absolute-time (UTC) report.
pub const TIMESYNC_UTC_REPORT: u64 = 1 << 29;
/// Request counter bits of the seq word.
pub const TIMESYNC_SEQ_COUNTER_MASK: u64 = (1 << 29) - 1;
const UTC_REPORT_OFFSET_BITS: u32 = 41;

/// Packs a UTC report into a request's t1 word: bits 0..41 signed offset in
/// microseconds (reference UTC minus the requester's network time, +-12 days),
/// bits 41..48 error code, bits 48..64 a cookie that keeps the word unique.
/// Returns `None` when the offset does not fit (the report is then not sent;
/// it is never wrapped).
pub fn encode_utc_report_word(offset_us: i64, error_code: u8, cookie: u16) -> Option<u64> {
    let limit = 1i64 << (UTC_REPORT_OFFSET_BITS - 1);
    if offset_us <= -limit || offset_us >= limit {
        return None;
    }
    let offset = (offset_us as u64) & ((1 << UTC_REPORT_OFFSET_BITS) - 1);
    Some(offset | (u64::from(error_code & 0x7F) << UTC_REPORT_OFFSET_BITS) | (u64::from(cookie) << 48))
}

/// Unpacks [`encode_utc_report_word`]: (offset microseconds, error code).
pub fn decode_utc_report_word(word: u64) -> (i64, u8) {
    let raw = word & ((1 << UTC_REPORT_OFFSET_BITS) - 1);
    let shift = 64 - UTC_REPORT_OFFSET_BITS;
    (((raw << shift) as i64) >> shift, ((word >> UTC_REPORT_OFFSET_BITS) & 0x7F) as u8)
}

/// An absolute-time report a follower sent with its request: the follower's
/// own UTC reference (e.g. GPS) minus network time, as the follower measured
/// it. Followers are synced to this node, so it measures this node's
/// network-time error against that reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtcReferenceReport {
    /// [`timesync_sender_tag`] of the reporting follower.
    pub sender_tag: u32,
    /// Reference UTC minus network time, ns.
    pub offset_ns: i64,
    /// Error bound of the report (reference error plus the follower's sync error), ns.
    pub error_ns: u64,
    /// Local monotonic receive instant, ns.
    pub received_mono_ns: u64,
}
const V2_TIME_MASK: u64 = (1 << 56) - 1;

/// Packs a v2 response t2 word.
pub fn encode_v2_receive_word(t2_unix_us: u64, synced: bool, error_code: u8) -> u64 {
    (t2_unix_us & V2_TIME_MASK)
        | (u64::from(error_code & 0x7F) << 56)
        | if synced { 1 << 63 } else { 0 }
}

/// Unpacks a v2 response t2 word: (unix microseconds, synced, error code).
pub fn decode_v2_receive_word(word: u64) -> (u64, bool, u8) {
    (word & V2_TIME_MASK, word >> 63 == 1, ((word >> 56) & 0x7F) as u8)
}

/// Packs a v2 response t3 word for the previous exchange.
pub fn encode_v2_transmit_word(prev_counter: u64, t3_unix_us: u64) -> u64 {
    (t3_unix_us & V2_TIME_MASK) | ((prev_counter & 0xFF) << 56)
}

/// Unpacks a v2 response t3 word: (previous counter low byte, unix microseconds).
/// `None` when the responder had no earlier transmit stamp.
pub fn decode_v2_transmit_word(word: u64) -> Option<(u8, u64)> {
    (word != 0).then_some(((word >> 56) as u8, word & V2_TIME_MASK))
}

/// Per-node time sync quality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeSyncStatus {
    /// Lock state.
    pub state: crate::timesync_discipline::SyncState,
    /// Hops from the reference: 0 for the reference itself.
    pub stratum: u8,
    /// Estimated error bound of network time, ns (`u64::MAX` when unknown).
    pub error_bound_ns: u64,
    /// Correction still being slewed out, ns (positive: clock is behind).
    pub offset_ns: i64,
    /// Learned oscillator frequency correction, ppb.
    pub rate_ppb: i64,
    /// Age of the newest accepted exchange sample, ms (`u64::MAX` when none).
    pub last_sample_age_ms: u64,
    /// The node is the reference others follow.
    pub is_reference: bool,
}

impl TimeSyncStatus {
    /// One-byte health summary for spare BOARD_HEALTH bits.
    ///
    /// Bit 7: synced (locked or holdover). Bits 0..7: 0 = not reported (a
    /// board without this firmware leaves the bits zero), 1..=126 = error
    /// bound code + 1 (see [`crate::timesync_discipline::encode_error_code`],
    /// codes above 125 saturate), 127 = bound unknown.
    pub fn health_byte(&self) -> u8 {
        let low = if self.error_bound_ns == u64::MAX {
            127
        } else {
            crate::timesync_discipline::encode_error_code(self.error_bound_ns).min(125) + 1
        };
        low | if self.state.is_synced() { 0x80 } else { 0 }
    }
}

/// Decodes [`TimeSyncStatus::health_byte`]: `None` when not reported, else
/// (synced, error bound ns or `u64::MAX` when unknown).
pub fn decode_health_byte(byte: u8) -> Option<(bool, u64)> {
    let low = byte & 0x7F;
    if low == 0 {
        return None;
    }
    let bound = if low == 127 {
        u64::MAX
    } else {
        crate::timesync_discipline::decode_error_code(low - 1)
    };
    Some((byte & 0x80 != 0, bound))
}

#[derive(Debug, Clone)]
struct NetworkTimeSourceState {
    priority: u64,
    updated_mono_ms: u64,
    anchor_mono_ns: u64,
    ttl_ms: Option<u64>,
    time: PartialNetworkTime,
}

pub(crate) struct PreparedClockSource<'a>(crate::peer_record::Prepared<'a, NetworkTimeSourceState>);

pub(crate) struct PreparedTrackerSource<'a> {
    ignore: bool,
    sender: &'a str,
    priority: u64,
    recv_ms: u64,
    time_ms: u64,
    insert: Option<crate::peer_record::Prepared<'a, TimeSyncSource>>,
}

/// Aggregates multiple partial or complete time sources into a current network-time reading.
#[derive(Debug, Clone, Default)]
pub struct NetworkClock {
    sources: OrdMap<String, Box<NetworkTimeSourceState>>,
}

impl NetworkClock {
    /// Inserts or replaces a named source used when assembling current network time.
    pub fn update_source(
        &mut self,
        source: &str,
        priority: u64,
        time: PartialNetworkTime,
        updated_mono_ms: u64,
        anchor_mono_ns: u64,
        ttl_ms: Option<u64>,
    ) {
        // Keep the historical infallible signature. Failure preserves the
        // previous reading instead of publishing a partially replaced source.
        let _ = self.try_update_source(
            source,
            priority,
            time,
            updated_mono_ms,
            anchor_mono_ns,
            ttl_ms,
        );
    }

    /// Fallible source update. Allocation refusal preserves the prior reading.
    pub fn try_update_source(
        &mut self,
        source: &str,
        priority: u64,
        time: PartialNetworkTime,
        updated_mono_ms: u64,
        anchor_mono_ns: u64,
        ttl_ms: Option<u64>,
    ) -> TelemetryResult<()> {
        let update = self.prepare_source(
            source,
            priority,
            time,
            updated_mono_ms,
            anchor_mono_ns,
            ttl_ms,
        )?;
        self.commit_source(update);
        Ok(())
    }

    pub(crate) fn prepare_source<'a>(
        &self,
        source: &'a str,
        priority: u64,
        time: PartialNetworkTime,
        updated_mono_ms: u64,
        anchor_mono_ns: u64,
        ttl_ms: Option<u64>,
    ) -> TelemetryResult<PreparedClockSource<'a>> {
        crate::peer_record::prepare(
            &self.sources,
            source,
            NetworkTimeSourceState {
                priority,
                updated_mono_ms,
                anchor_mono_ns,
                ttl_ms,
                time,
            },
        )
        .map(PreparedClockSource)
    }

    pub(crate) fn commit_source(&mut self, update: PreparedClockSource<'_>) {
        update.0.commit(&mut self.sources);
    }

    /// Removes a previously registered source by identifier.
    pub fn remove_source(&mut self, source: &str) {
        self.sources.remove(source);
    }

    /// Drops sources whose optional TTL has expired relative to `now_mono_ms`.
    pub fn prune_expired(&mut self, now_mono_ms: u64) {
        self.sources.retain(|_, src| {
            src.ttl_ms
                .map(|ttl| now_mono_ms.saturating_sub(src.updated_mono_ms) <= ttl)
                .unwrap_or(true)
        });
    }

    /// Returns the best current reading by preferring complete sources, then merging partial ones.
    pub fn current_time(&self, now_mono_ns: u64) -> Option<NetworkTimeReading> {
        self.current_time_filtered(now_mono_ns, |_| true)
    }

    /// Like [`Self::current_time`], using only sources whose identifier passes `keep`.
    /// `current_time_filtered(..).unix_time_ms` without building the calendar
    /// reading in the usual case (a complete source and a time before 2262).
    pub(crate) fn current_unix_ms_filtered(
        &self,
        now_mono_ns: u64,
        keep: impl Fn(&str) -> bool,
    ) -> Option<u64> {
        {
            let sources: Vec<(&str, &NetworkTimeSourceState)> = self
                .sources
                .iter()
                .filter(|(name, _)| keep(name.as_str()))
                .map(|(name, src)| (name.as_str(), src.as_ref()))
                .collect();
            if sources.is_empty() {
                return None;
            }
            let full = best_source(&sources, |src| src.time.to_network_time().is_some());
            if let Some((_, src)) = full
                && let Some(base_ns) = src.time.to_network_time().and_then(|base| base.as_unix_ns())
            {
                let elapsed_ns = now_mono_ns.saturating_sub(src.anchor_mono_ns);
                // In [0, i64::MAX] the calendar round trip is exact and lands
                // on floor(ns / 1e6); anything else takes the full path.
                if let Ok(ns) = u64::try_from(base_ns + elapsed_ns as i128)
                    && ns <= i64::MAX as u64
                {
                    return Some(crate::timesync_discipline::div_u64_1e6(ns));
                }
            }
        }
        self.current_time_filtered(now_mono_ns, keep)
            .and_then(|reading| reading.unix_time_ms)
    }

    pub(crate) fn current_time_filtered(
        &self,
        now_mono_ns: u64,
        keep: impl Fn(&str) -> bool,
    ) -> Option<NetworkTimeReading> {
        let sources: Vec<(&str, &NetworkTimeSourceState)> = self
            .sources
            .iter()
            .filter(|(name, _)| keep(name.as_str()))
            .map(|(name, src)| (name.as_str(), src.as_ref()))
            .collect();
        if sources.is_empty() {
            return None;
        }

        let full = best_source(&sources, |src| src.time.to_network_time().is_some());
        if let Some((_, src)) = full
            && let Some(base) = src.time.to_network_time()
        {
            let elapsed_ns = now_mono_ns.saturating_sub(src.anchor_mono_ns);
            if let Some(advanced) = advance_network_time(base, elapsed_ns) {
                return Some(NetworkTimeReading {
                    unix_time_ms: advanced.as_unix_ms(),
                    time: PartialNetworkTime::from(advanced),
                });
            }
        }

        let year = best_source(&sources, |src| src.time.year.is_some()).map(|(_, src)| src);
        let month = best_source(&sources, |src| src.time.month.is_some()).map(|(_, src)| src);
        let day = best_source(&sources, |src| src.time.day.is_some()).map(|(_, src)| src);
        let hour = best_source(&sources, |src| src.time.hour.is_some()).map(|(_, src)| src);
        let minute = best_source(&sources, |src| src.time.minute.is_some()).map(|(_, src)| src);
        let second = best_source(&sources, |src| src.time.second.is_some()).map(|(_, src)| src);
        let subsec = best_source(&sources, |src| src.time.nanosecond.is_some()).map(|(_, src)| src);

        let mut merged = PartialNetworkTime {
            year: year.and_then(|src| src.time.year),
            month: month.and_then(|src| src.time.month),
            day: day.and_then(|src| src.time.day),
            hour: hour.and_then(|src| src.time.hour),
            minute: minute.and_then(|src| src.time.minute),
            second: second.and_then(|src| src.time.second),
            ..Default::default()
        };
        if let Some(src) = subsec {
            merged.nanosecond = src.time.nanosecond;
        }

        if let Some(time_src) = second.or(minute).or(hour)
            && merged.is_complete_date()
            && merged.is_complete_time()
        {
            merged.nanosecond = merged.nanosecond.or(Some(0));
            let base = merged.to_network_time()?;
            let elapsed_ns = now_mono_ns.saturating_sub(time_src.anchor_mono_ns);
            if let Some(advanced) = advance_network_time(base, elapsed_ns) {
                return Some(NetworkTimeReading {
                    unix_time_ms: advanced.as_unix_ms(),
                    time: PartialNetworkTime::from(advanced),
                });
            }
        }

        Some(NetworkTimeReading {
            unix_time_ms: None,
            time: merged,
        })
    }
}

fn best_source<'a, F>(
    sources: &'a [(&'a str, &'a NetworkTimeSourceState)],
    predicate: F,
) -> Option<(&'a str, &'a NetworkTimeSourceState)>
where
    F: Fn(&NetworkTimeSourceState) -> bool,
{
    let mut best: Option<(&str, &NetworkTimeSourceState)> = None;
    for (name, src) in sources.iter().copied() {
        if !predicate(src) {
            continue;
        }
        best = match best {
            None => Some((name, src)),
            Some((best_name, best_src)) => {
                if src.priority < best_src.priority
                    || (src.priority == best_src.priority && name < best_name)
                {
                    Some((name, src))
                } else {
                    Some((best_name, best_src))
                }
            }
        };
    }
    best
}

/// Advances a complete [`NetworkTime`] forward by an elapsed monotonic duration.
pub(crate) fn advance_network_time(base: NetworkTime, elapsed_ns: u64) -> Option<NetworkTime> {
    let unix_ns = base.as_unix_ns()?;
    NetworkTime::from_unix_ns(unix_ns + elapsed_ns as i128)
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let mut era = year.div_euclid(400);
    let mut yoe = year.rem_euclid(400) - (month <= 2) as i32;
    if yoe < 0 {
        era -= 1;
        yoe += 400;
    }
    let mp = month as i32 + if month > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + day as i32 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era as i64 * 146_097 + doe as i64 - 719_468
}

fn civil_from_days(mut z: u64) -> Option<(i32, u32, u32)> {
    z += 719_468;
    // Days fit 32 bits for 11 million years: divide in hardware then.
    let era = match u32::try_from(z) {
        Ok(z) => u64::from(z / 146_097),
        Err(_) => z / 146_097,
    };
    // A Gregorian era contains exactly 146097 days. Its remaining
    // arithmetic fits in 32 bits, avoiding repeated software i64 divisions
    // on Cortex-M while retaining the full representable year range.
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as u64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = i32::try_from(y + (m <= 2) as u64).ok()?;
    Some((y, m, d))
}

/// Tracks remote time sources and performs leader/source selection decisions.
#[derive(Debug, Clone)]
pub struct TimeSyncTracker {
    cfg: TimeSyncConfig,
    local_id: String,
    sources: OrdMap<String, Box<TimeSyncSource>>,
    current_source: Option<String>,
    local_anchored: bool,
    local_tag: u32,
}

impl TimeSyncTracker {
    /// Creates a tracker with the supplied time sync configuration.
    pub fn new(cfg: TimeSyncConfig) -> Self {
        let local_id = runtime_device_identifier();
        Self {
            cfg,
            local_tag: timesync_sender_tag(&local_id),
            local_id,
            sources: OrdMap::new(),
            current_source: None,
            local_anchored: false,
        }
    }

    /// Declares whether local candidate time is traceable to UTC. Defaults to
    /// `false`; anchored remote sources then outrank the local candidate.
    pub fn set_local_time_anchored(&mut self, anchored: bool) {
        self.local_anchored = anchored;
    }

    /// Sets the sender name downstream announces use to name this node as their source.
    pub(crate) fn set_local_sender(&mut self, sender: &str) {
        self.local_tag = timesync_sender_tag(sender);
    }

    /// Returns the tracker's active configuration.
    pub fn config(&self) -> TimeSyncConfig {
        self.cfg
    }

    /// Returns the currently selected remote source, if any.
    pub fn current_source(&self) -> Option<&TimeSyncSource> {
        self.current_source
            .as_ref()
            .and_then(|sender| self.sources.get(sender).map(AsRef::as_ref))
    }

    /// Removes stale sources and re-runs source selection.
    pub fn refresh(&mut self, now_ms: u64) -> TimeSyncUpdate {
        self.sources
            .retain(|_, src| Self::source_is_active(src, now_ms, self.cfg.source_timeout_ms));
        self.reselect_source(now_ms)
    }

    /// Returns the best currently active remote source: anchored time first, then
    /// priority, stratum and sender ID. Sources that follow this node, or exceed
    /// [`TIMESYNC_MAX_STRATUM`], are never selected.
    pub fn best_active_source(&self, now_ms: u64) -> Option<&TimeSyncSource> {
        self.sources
            .values()
            .filter(|src| self.is_candidate(src, now_ms))
            .min_by(|a, b| {
                a.quality()
                    .rank()
                    .cmp(&b.quality().rank())
                    .then_with(|| a.sender.cmp(&b.sender))
            })
            .map(AsRef::as_ref)
    }

    fn is_candidate(&self, src: &TimeSyncSource, now_ms: u64) -> bool {
        let quality = src.quality();
        Self::source_is_active(src, now_ms, self.cfg.source_timeout_ms)
            && quality.upstream != self.local_tag
            && quality.stratum <= TIMESYNC_MAX_STRATUM
    }

    fn remote_may_lead(&self, now_ms: u64) -> bool {
        // Local UTC also outranks an unanchored remote for opportunistic roles.
        self.best_active_source(now_ms)
            .is_some_and(|src| !self.local_anchored || src.quality().anchored)
    }

    /// Returns the effective local candidate priority if the node may lead at `now_ms`.
    pub fn local_candidate_priority(&self, now_ms: u64, has_usable_time: bool) -> Option<u64> {
        match self.cfg.role {
            TimeSyncRole::Consumer => {
                if has_usable_time
                    && self.cfg.consumer_promotion_enabled
                    && !self.remote_may_lead(now_ms)
                {
                    Some(self.cfg.priority)
                } else {
                    None
                }
            }
            TimeSyncRole::Source => Some(self.cfg.priority),
            TimeSyncRole::Auto => {
                if has_usable_time && !self.remote_may_lead(now_ms) {
                    Some(self.cfg.priority)
                } else {
                    None
                }
            }
        }
    }

    /// Returns the elected leader between the local node and active remote sources.
    pub fn leader(&self, now_ms: u64, has_usable_time: bool) -> Option<TimeSyncLeader> {
        let local_priority = self.local_candidate_priority(now_ms, has_usable_time);
        let remote = self.best_active_source(now_ms).cloned();
        match (local_priority, remote) {
            (Some(priority), Some(remote)) => {
                let local = (!self.local_anchored, priority, 0);
                let remote_rank = remote.quality().rank();
                if local < remote_rank
                    || (local == remote_rank && self.local_id.as_str() < remote.sender.as_str())
                {
                    Some(TimeSyncLeader::Local { priority })
                } else {
                    Some(TimeSyncLeader::Remote(remote))
                }
            }
            (Some(priority), None) => Some(TimeSyncLeader::Local { priority }),
            (None, Some(remote)) => Some(TimeSyncLeader::Remote(remote)),
            (None, None) => None,
        }
    }

    /// Returns the priority to advertise in local announce packets when leading.
    pub fn local_announce_priority(&self, now_ms: u64, has_usable_time: bool) -> Option<u64> {
        let Some(TimeSyncLeader::Local { priority }) = self.leader(now_ms, has_usable_time) else {
            return None;
        };
        let tie_exists = self
            .sources
            .values()
            .filter(|src| self.is_candidate(src, now_ms))
            .map(|src| src.quality())
            .any(|q| q.priority == priority && q.stratum == 0 && q.anchored == self.local_anchored);
        Some(if tie_exists {
            priority.saturating_sub(1)
        } else {
            priority
        })
    }

    /// Returns `true` when the local node should currently emit announce packets.
    pub fn should_announce(&self, now_ms: u64, has_usable_time: bool) -> bool {
        self.local_announce_priority(now_ms, has_usable_time)
            .is_some()
    }

    /// Returns `true` when the local node should currently answer incoming requests.
    pub fn should_serve(&self, now_ms: u64, has_usable_time: bool) -> bool {
        self.should_announce(now_ms, has_usable_time)
    }

    /// Updates tracker state from an incoming announce packet.
    pub fn handle_announce(
        &mut self,
        pkt: &Packet,
        recv_ms: u64,
    ) -> TelemetryResult<TimeSyncUpdate> {
        let ann = decode_timesync_announce(pkt)?;
        if pkt.sender() == self.local_id.as_str() {
            return Ok(TimeSyncUpdate::NoChange);
        }

        let update = self.prepare_source(pkt.sender(), ann, recv_ms)?;
        Ok(self.commit_source(update))
    }

    pub(crate) fn prepare_source<'a>(
        &self,
        sender: &'a str,
        ann: TimeSyncAnnounceFields,
        recv_ms: u64,
    ) -> TelemetryResult<PreparedTrackerSource<'a>> {
        let ignore = sender == self.local_id.as_str();
        let insert = if ignore || self.sources.contains_key(sender) {
            None
        } else {
            let incoming = TimeSyncSource {
                sender: crate::peer_record::try_string(sender)?,
                priority: ann.priority,
                last_announce_ms: recv_ms,
                last_time_ms: ann.time_ms,
            };
            Some(crate::peer_record::prepare(
                &self.sources,
                sender,
                incoming,
            )?)
        };
        Ok(PreparedTrackerSource {
            ignore,
            sender,
            priority: ann.priority,
            recv_ms,
            time_ms: ann.time_ms,
            insert,
        })
    }

    pub(crate) fn commit_source(&mut self, update: PreparedTrackerSource<'_>) -> TimeSyncUpdate {
        if update.ignore {
            return TimeSyncUpdate::NoChange;
        }
        if let Some(insert) = update.insert {
            insert.commit(&mut self.sources);
        } else {
            let source = self
                .sources
                .get_mut(update.sender)
                .expect("prepared source remains present");
            source.priority = update.priority;
            source.last_announce_ms = update.recv_ms;
            source.last_time_ms = update.time_ms;
        }
        self.reselect_source(update.recv_ms)
    }

    /// Returns `true` when the current remote source is still within the active timeout window.
    pub fn is_source_active(&self, now_ms: u64) -> bool {
        self.current_source()
            .map(|s| Self::source_is_active(s, now_ms, self.cfg.source_timeout_ms))
            .unwrap_or(false)
    }

    fn source_is_active(src: &TimeSyncSource, now_ms: u64, timeout_ms: u64) -> bool {
        now_ms.saturating_sub(src.last_announce_ms) <= timeout_ms
    }

    fn best_active_source_id(&self, now_ms: u64) -> Option<String> {
        self.best_active_source(now_ms)
            .map(|src| src.sender.clone())
    }

    fn reselect_source(&mut self, now_ms: u64) -> TimeSyncUpdate {
        let prev = self.current_source.clone();
        self.current_source = self.best_active_source_id(now_ms);
        if self.current_source == prev {
            TimeSyncUpdate::NoChange
        } else {
            TimeSyncUpdate::SourceChanged
        }
    }
}

/// Computes clock offset and round-trip delay from the standard four timestamps.
pub fn compute_offset_delay(t1_ms: u64, t2_ms: u64, t3_ms: u64, t4_ms: u64) -> TimeSyncSample {
    let t1 = t1_ms as i128;
    let t2 = t2_ms as i128;
    let t3 = t3_ms as i128;
    let t4 = t4_ms as i128;

    let offset = ((t2 - t1) + (t3 - t4)) / 2;
    let delay = (t4 - t1) - (t3 - t2);
    let delay_ms = if delay < 0 { 0 } else { delay as u64 };

    TimeSyncSample {
        offset_ms: offset as i64,
        delay_ms,
    }
}

/// Estimates current network time and one-way delay from a request/response exchange.
pub fn compute_network_time_sample(
    t1_monotonic_ms: u64,
    t2_network_ms: u64,
    t3_network_ms: u64,
    t4_monotonic_ms: u64,
) -> (u64, u64) {
    let round_trip = t4_monotonic_ms.saturating_sub(t1_monotonic_ms);
    let server_processing = t3_network_ms.saturating_sub(t2_network_ms);
    let one_way_delay = round_trip.saturating_sub(server_processing) / 2;
    let estimated_network_ms = t3_network_ms.saturating_add(one_way_delay);
    (estimated_network_ms, one_way_delay)
}

/// Builds a time sync announce packet using the schema-configured sender metadata.
pub fn build_timesync_announce(priority: u64, time_ms: u64) -> TelemetryResult<Packet> {
    let meta = message_meta(DataType::TimeSyncAnnounce);
    Packet::from_u64_slice(
        DataType::TimeSyncAnnounce,
        &[priority, time_ms],
        meta.endpoints_ref(),
        time_ms,
    )
}

/// Builds a time sync announce packet with an explicit sender identifier.
pub fn build_timesync_announce_with_sender(
    sender: &'static str,
    priority: u64,
    time_ms: u64,
) -> TelemetryResult<Packet> {
    let payload = encode_slice_le(&[priority, time_ms]);
    Packet::new(
        DataType::TimeSyncAnnounce,
        &[DataEndpoint::TimeSync],
        sender,
        time_ms,
        payload,
    )
}

/// Queues a time sync announce message through the router telemetry path.
pub fn send_timesync_announce(router: &Router, priority: u64, time_ms: u64) -> TelemetryResult<()> {
    router.log_ts(DataType::TimeSyncAnnounce, time_ms, &[priority, time_ms])
}

/// Builds a time sync request packet.
pub fn build_timesync_request(seq: u64, t1_ms: u64) -> TelemetryResult<Packet> {
    let meta = message_meta(DataType::TimeSyncRequest);
    Packet::from_u64_slice(
        DataType::TimeSyncRequest,
        &[seq, t1_ms],
        meta.endpoints_ref(),
        t1_ms,
    )
}

/// Queues a time sync request message through the router telemetry path.
pub fn send_timesync_request(router: &Router, seq: u64, t1_ms: u64) -> TelemetryResult<()> {
    router.log_ts(DataType::TimeSyncRequest, t1_ms, &[seq, t1_ms])
}

/// Builds a time sync response packet.
pub fn build_timesync_response(
    seq: u64,
    t1_ms: u64,
    t2_ms: u64,
    t3_ms: u64,
) -> TelemetryResult<Packet> {
    let meta = message_meta(DataType::TimeSyncResponse);
    Packet::from_u64_slice(
        DataType::TimeSyncResponse,
        &[seq, t1_ms, t2_ms, t3_ms],
        meta.endpoints_ref(),
        t3_ms,
    )
}

/// Queues a time sync response message through the router telemetry path.
pub fn send_timesync_response(
    router: &Router,
    seq: u64,
    t1_ms: u64,
    t2_ms: u64,
    t3_ms: u64,
) -> TelemetryResult<()> {
    router.log_ts(
        DataType::TimeSyncResponse,
        t3_ms,
        &[seq, t1_ms, t2_ms, t3_ms],
    )
}

fn decode_u64_payload(
    pkt: &Packet,
    expected_ty: DataType,
    expected_words: usize,
) -> TelemetryResult<Vec<u64>> {
    if pkt.data_type() != expected_ty {
        return Err(TelemetryError::InvalidType);
    }

    let vals = pkt.data_as_u64()?;
    if vals.len() != expected_words {
        return Err(TelemetryError::SizeMismatch {
            expected: expected_words * size_of::<u64>(),
            got: vals.len() * size_of::<u64>(),
        });
    }

    Ok(vals)
}

/// Decodes a time sync announce packet into strongly typed fields.
pub fn decode_timesync_announce(pkt: &Packet) -> TelemetryResult<TimeSyncAnnounceFields> {
    let vals = decode_u64_payload(pkt, DataType::TimeSyncAnnounce, TIMESYNC_ANNOUNCE_WORDS)?;
    Ok(TimeSyncAnnounceFields {
        priority: vals[0],
        time_ms: vals[1],
    })
}

/// Decodes a time sync request packet into strongly typed fields.
pub fn decode_timesync_request(pkt: &Packet) -> TelemetryResult<TimeSyncRequestFields> {
    let vals = decode_u64_payload(pkt, DataType::TimeSyncRequest, TIMESYNC_REQUEST_WORDS)?;
    Ok(TimeSyncRequestFields {
        seq: vals[0],
        t1_ms: vals[1],
    })
}

/// Decodes a time sync response packet into strongly typed fields.
pub fn decode_timesync_response(pkt: &Packet) -> TelemetryResult<TimeSyncResponseFields> {
    let vals = decode_u64_payload(pkt, DataType::TimeSyncResponse, TIMESYNC_RESPONSE_WORDS)?;
    Ok(TimeSyncResponseFields {
        seq: vals[0],
        t1_ms: vals[1],
        t2_ms: vals[2],
        t3_ms: vals[3],
    })
}

#[cfg(test)]
mod calendar_tests {
    use super::NetworkTime;

    #[test]
    fn calendar_roundtrips_era_and_year_boundaries() {
        for year in [1970, 1999, 2000, 2024, 2100, 2400, 9999, i32::MAX] {
            for (month, day) in [(1, 1), (2, 28), (3, 1), (12, 31)] {
                let expected = NetworkTime {
                    year,
                    month,
                    day,
                    hour: 23,
                    minute: 59,
                    second: 59,
                    nanosecond: 999_999_999,
                };
                assert_eq!(
                    NetworkTime::from_unix_ns(expected.as_unix_ns().unwrap()),
                    Some(expected)
                );
            }
        }
        let leap = NetworkTime {
            year: 2024,
            month: 2,
            day: 29,
            hour: 0,
            minute: 0,
            second: 0,
            nanosecond: 123,
        };
        assert_eq!(
            NetworkTime::from_unix_ns(leap.as_unix_ns().unwrap()),
            Some(leap)
        );
        assert_eq!(NetworkTime::from_unix_ns(0).unwrap().year, 1970);
    }

    #[test]
    fn out_of_range_calendar_timestamps_are_rejected_without_wraparound() {
        assert_eq!(NetworkTime::from_unix_ns(-1), None);
        assert_eq!(NetworkTime::from_unix_ns(i128::MAX), None);
        let last = NetworkTime {
            year: i32::MAX,
            month: 12,
            day: 31,
            hour: 23,
            minute: 59,
            second: 59,
            nanosecond: 999_999_999,
        }
        .as_unix_ns()
        .unwrap();
        assert_eq!(NetworkTime::from_unix_ns(last + 1), None);
    }
}

#[cfg(test)]
mod slew_absolute_target_tests {
    use super::SlewedNetworkClock;

    #[test]
    fn remote_source_projection_survives_embedded_polling_and_source_updates() {
        use super::{TimeSyncConfig, TimeSyncRole, build_timesync_announce_with_sender};
        use crate::router::{Router, RouterConfig};
        use alloc::sync::Arc;
        use core::sync::atomic::{AtomicU64, Ordering};
        const EPOCH: u64 = 1_767_225_600_000;
        let now = Arc::new(AtomicU64::new(0));
        let clock = now.clone();
        let router = Router::new_with_clock(
            RouterConfig::default().with_timesync(TimeSyncConfig {
                role: TimeSyncRole::Consumer,
                priority: 50,
                source_timeout_ms: 10_000,
                consumer_promotion_enabled: false,
                ..Default::default()
            }),
            alloc::boxed::Box::new(move || clock.load(Ordering::SeqCst)),
        );
        for elapsed_ms in (0..=20_000).step_by(10) {
            now.store(elapsed_ms, Ordering::SeqCst);
            if elapsed_ms % 5_000 == 0 {
                // Exercise a replacement leader as well as repeated updates.
                let (source, priority) = if elapsed_ms < 10_000 {
                    ("SOURCE_A", 2)
                } else {
                    ("SOURCE_B", 1)
                };
                router
                    .rx(
                        &build_timesync_announce_with_sender(source, priority, EPOCH + elapsed_ms)
                            .unwrap(),
                    )
                    .unwrap();
            }
            for _ in 0..5 {
                router.poll_timesync().unwrap();
                assert_eq!(router.network_time_ms(), Some(EPOCH + elapsed_ms));
            }
        }
    }

    #[test]
    fn repeated_absolute_target_does_not_accumulate_phase_error() {
        for target in [9_900, 10_100] {
            let mut once = SlewedNetworkClock::new(50_000);
            once.steer_unix_ms(0, 10_000);
            once.steer_unix_ms(0, target);
            let mut repeated = once;
            for _ in 0..100 {
                repeated.steer_unix_ms(0, target);
            }
            for elapsed_ms in [1, 100, 1_000, 2_000, 3_000, 10_000] {
                assert_eq!(
                    repeated.read_unix_ms(elapsed_ms * 1_000_000),
                    once.read_unix_ms(elapsed_ms * 1_000_000)
                );
            }
        }
    }

    #[test]
    fn advancing_absolute_targets_converge_with_bounded_monotonic_slew() {
        for offset_ms in [-100i64, 100] {
            let mut clock = SlewedNetworkClock::new(50_000);
            clock.steer_unix_ms(0, 10_000);
            let mut previous = 10_000_000_000i128;
            for elapsed_ms in 1..=5_000u64 {
                let now_ns = elapsed_ms * 1_000_000;
                let target_ms = (10_000 + elapsed_ms as i64 + offset_ms) as u64;
                clock.steer_unix_ms(now_ns, target_ms);
                let current = clock.read_unix_ns(now_ns).unwrap();
                assert!((950_000..=1_050_000).contains(&(current - previous)));
                previous = current;
            }
            assert_eq!(
                clock.read_unix_ms(5_000_000_000),
                Some((15_000 + offset_ms) as u64)
            );
        }
    }
}


/// The Cortex-M fast paths (no 64/128-bit software division) give exactly
/// the results of the straightforward formulas they replaced.
#[cfg(test)]
mod fast_path_equivalence_tests {
    use super::{NetworkClock, NetworkTime, PartialNetworkTime, SlewedNetworkClock, civil_from_days};
    use crate::timesync_discipline::{div_u64_1e6, div_u64_1e9, div_u64_small, mul_div, mul_div_pow10};

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        /// Values of every magnitude, not only huge ones.
        fn wide(&mut self) -> u64 {
            let bits = self.next() % 65;
            if bits == 0 { 0 } else { self.next() >> (64 - bits) }
        }
    }

    fn reference_from_unix_ns(unix_ns: i128) -> Option<NetworkTime> {
        if unix_ns < 0 {
            return None;
        }
        let secs = u64::try_from(unix_ns / 1_000_000_000).ok()?;
        let nanos = unix_ns.rem_euclid(1_000_000_000) as u32;
        let (year, month, day) = civil_from_days(secs / 86_400)?;
        let sod = (secs % 86_400) as u32;
        Some(NetworkTime {
            year,
            month: month as u8,
            day: day as u8,
            hour: (sod / 3_600) as u8,
            minute: ((sod % 3_600) / 60) as u8,
            second: (sod % 60) as u8,
            nanosecond: nanos,
        })
    }

    fn reference_as_unix_ms(t: &NetworkTime) -> Option<u64> {
        let ns = t.as_unix_ns()?;
        if ns < 0 {
            return None;
        }
        u64::try_from(ns / 1_000_000).ok()
    }

    fn reference_read_ns(anchor_unix: i64, pending: i64, ppm: u32, rate: i64, elapsed: i64) -> i64 {
        let max_adjust = mul_div(elapsed, i64::from(ppm), 1_000_000);
        let slew = pending.clamp(-max_adjust, max_adjust);
        anchor_unix
            .saturating_add(elapsed)
            .saturating_add(mul_div(elapsed, rate, 1_000_000_000))
            .saturating_add(slew)
    }

    #[test]
    fn small_divisor_division_is_exact() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let edges = [0, 1, 999_999, 1_000_000, 1_000_000_000, u64::MAX, u64::MAX - 1, 1 << 63, (1 << 63) - 1];
        let randoms: Vec<u64> = (0..200_000).map(|_| rng.wide()).collect();
        for x in edges.into_iter().chain(randoms) {
            assert_eq!(div_u64_1e6(x), x / 1_000_000, "{x}");
            assert_eq!(div_u64_1e9(x), x / 1_000_000_000, "{x}");
            let d = (rng.next() % ((1 << 21) - 1)) as u32 + 1;
            assert_eq!(div_u64_small(x, d), x / u64::from(d), "{x}/{d}");
        }
    }

    #[test]
    fn pow10_scaling_matches_mul_div_including_overflow_and_signs() {
        let mut rng = Rng(0xD1B5_4A32_D192_ED03);
        for _ in 0..200_000 {
            let a = rng.wide() as i64;
            let b = (rng.wide() >> 33) as i64 * if rng.next() & 1 == 0 { 1 } else { -1 };
            for c in [1_000_000, 1_000_000_000] {
                assert_eq!(mul_div_pow10(a, b, c), mul_div(a, b, c), "{a}*{b}/{c}");
            }
        }
        for (a, b) in [(i64::MIN, 1), (i64::MAX, 1), (i64::MIN, -1), (i64::MAX, 999_999), (-1, 1)] {
            for c in [1_000_000, 1_000_000_000] {
                assert_eq!(mul_div_pow10(a, b, c), mul_div(a, b, c), "{a}*{b}/{c}");
            }
        }
    }

    #[test]
    fn calendar_conversions_match_the_128_bit_formulas() {
        let mut rng = Rng(0x2545_F491_4F6C_DD1D);
        let edges: [i128; 8] = [
            -1,
            0,
            1_767_225_600_123_456_789,
            i128::from(u32::MAX) * 1_000_000_000,
            i128::from(u32::MAX) * 1_000_000_000 + 999_999_999,
            i128::from(u64::MAX),
            i128::from(u64::MAX) + 1,
            i128::MAX,
        ];
        let randoms: Vec<i128> = (0..100_000)
            .map(|_| {
                let scale = if rng.next().is_multiple_of(4) { i128::from(rng.wide() % 1_000) } else { 1 };
                let v = i128::from(rng.wide()) * scale;
                if rng.next().is_multiple_of(16) { -v } else { v }
            })
            .collect();
        for ns in edges.into_iter().chain(randoms) {
            let fast = NetworkTime::from_unix_ns(ns);
            assert_eq!(fast, reference_from_unix_ns(ns), "{ns}");
            if let Some(t) = fast {
                assert_eq!(t.as_unix_ms(), reference_as_unix_ms(&t), "{t:?}");
            }
        }
        for year in [i32::MIN, -1, 0, 1969, 1970, 2026, 2106, 2262, 2263, 2554, i32::MAX] {
            let t = NetworkTime { year, month: 7, day: 4, hour: 23, minute: 59, second: 59, nanosecond: 999_999_999 };
            assert_eq!(t.as_unix_ms(), reference_as_unix_ms(&t), "{year}");
        }
    }

    #[test]
    fn slewed_clock_reads_match_the_reference_formula() {
        let mut rng = Rng(0x1234_5678_9ABC_DEF1);
        for _ in 0..50_000 {
            let ppm = [0u32, 1, 50, 500, 50_000, 999_999][(rng.next() % 6) as usize];
            let mut clock = SlewedNetworkClock::new(ppm);
            let anchor_mono = rng.next() % (1 << 50);
            let target = (rng.next() % (1 << 62)) as i64;
            let rate = (rng.next() % 40_000_001) as i64 - 20_000_000;
            clock.discipline_ns(anchor_mono, target, rate, true);
            // A second steer leaves a pending correction to slew out.
            let later = anchor_mono + rng.next() % (1 << 40);
            let offset = (rng.wide() >> 1) as i64 % 10_000_000_000 * if rng.next() & 1 == 0 { 1 } else { -1 };
            let before = clock.read_unix_ns(later).unwrap() as i64;
            clock.discipline_ns(later, before.saturating_add(offset), rate, false);
            for _ in 0..4 {
                let now = later + rng.wide() % (1 << 46);
                let elapsed = (now - later).min(i64::MAX as u64) as i64;
                let expect = reference_read_ns(clock.anchor_unix_ns, clock.pending_adjust_ns, ppm, rate, elapsed);
                assert_eq!(clock.read_unix_ns(now), Some(i128::from(expect)));
                let ms = (expect >= 0).then_some(expect as u64 / 1_000_000);
                assert_eq!(clock.read_unix_ms(now), ms);
                assert_eq!(clock.has_unix_time(now), ms.is_some());
            }
        }
    }

    #[test]
    fn source_clock_millisecond_read_matches_the_calendar_reading() {
        let mut rng = Rng(0x0F1E_2D3C_4B5A_6978);
        for _ in 0..5_000 {
            let mut clock = NetworkClock::default();
            let base_ms = rng.next() % 9_000_000_000_000;
            let anchor = rng.next() % (1 << 40);
            if rng.next().is_multiple_of(3) {
                // Date and time from separate sources (the merged path).
                let full = PartialNetworkTime::from_unix_ms(base_ms);
                clock.update_source("date", 1, PartialNetworkTime { hour: None, minute: None, second: None, nanosecond: None, ..full }, 0, anchor, None);
                clock.update_source("tod", 2, PartialNetworkTime { year: None, month: None, day: None, ..full }, 0, anchor, None);
            } else {
                clock.update_source("gps", 1, PartialNetworkTime::from_unix_ms(base_ms), 0, anchor, None);
            }
            let now = anchor + rng.wide() % (1 << 50);
            assert_eq!(
                clock.current_unix_ms_filtered(now, |_| true),
                clock.current_time_filtered(now, |_| true).and_then(|r| r.unix_time_ms)
            );
            assert_eq!(clock.current_unix_ms_filtered(now, |_| false), None);
        }
    }
}
