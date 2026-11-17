//! Interleaved (v2) time sync exchange, transport stamps and clock discipline.
//!
//! The wire format is unchanged: see the v2 notes in `timesync.rs`. Everything
//! here is local bookkeeping keyed by the exchange words (seq, t1) and, for
//! transmit-complete reports, by the transport frame's length and hash.

use super::*;
use crate::timesync::{
    NetworkStampAge, TIMESYNC_UTC_REPORT, TimeSyncLastStep, TimeSyncStepReason, encode_utc_report_word,
    TIMESYNC_SEQ_COUNTER_MASK, TimeSyncStatus,
    decode_v2_receive_word, decode_v2_transmit_word, encode_v2_receive_word,
    encode_v2_transmit_word,
};
#[cfg(feature = "std")]
use crate::timesync::{UtcReferenceReport, decode_utc_report_word};
use crate::timesync_discipline::{
    ClockDiscipline, SyncState, TIMESYNC_MIN_DELAY_TOLERANCE_NS, decode_error_code, encode_error_code,
    exchange_sample, mul_div,
};

/// Requests a follower keeps open for interleaved answers.
const EXCHANGES: usize = 4;
/// Requesters a responder remembers transmit stamps for (one per CAN peer).
const SERVED: usize = 6;
/// Time sync frames awaiting a transmit-complete report.
const TX_MARKS: usize = 4;
/// Received time sync frames awaiting processing.
#[cfg(feature = "std")]
const RX_MARKS: usize = 4;
/// Sides with a configured path asymmetry.
const ASYMMETRY_SIDES: usize = 2;
/// Locked followers exchange this many times less often (air budget).
pub(super) const LOCKED_REQUEST_DIVISOR: u64 = 4;
/// Bound at or below which a locked follower relaxes to the slow request rate.
pub(super) const RELAXED_REQUEST_BOUND_NS: u64 = 5_000_000;
/// Fastest request interval while acquiring.
pub(super) const FAST_REQUEST_MIN_MS: u64 = 250;
/// Before first lock a follower steps instead of slewing beyond this error.
const ACQUIRE_STEP_NS: u64 = 50_000_000;
/// Source error assumed for a responder that reports an unknown bound.
const UNKNOWN_SOURCE_ERROR_NS: u64 = 1_000_000_000;
/// Epoch transitions remembered for translating older stamps.
const EPOCH_LINKS: usize = 4;
/// Announces sent at [`EPOCH_ANNOUNCE_BURST_MS`] after an epoch change.
const EPOCH_ANNOUNCE_BURST: u8 = 4;
/// Interval of the announce burst after an epoch change, ms.
pub(super) const EPOCH_ANNOUNCE_BURST_MS: u64 = 150;

/// One remembered epoch transition: a stamp taken in `from` reads `delta_ns`
/// later in `to`'s time base.
#[derive(Debug, Clone, Copy, Default)]
struct EpochLink {
    from: u16,
    to: u16,
    delta_ns: i64,
}

#[derive(Debug, Clone, Copy)]
struct StepRecord {
    delta_ns: i64,
    reason: TimeSyncStepReason,
    from_epoch: u16,
    to_epoch: u16,
    at_mono_ns: u64,
}

/// Network time-base epoch of this node.
///
/// An epoch names one continuous time base. A node never steps its clock
/// backward without moving to a newer epoch, and never moves to an older one,
/// so one sender's `(epoch, timestamp)` stamps order its packets across every
/// step. A leading node starts a new epoch on each step of its own clock; a
/// follower adopts its source's epoch (stepping to the source at once) and
/// holds its clock while the source is in an older epoch; the leader adopts
/// a newer epoch its followers carry in their requests.
#[derive(Debug, Clone)]
pub(super) struct EpochState {
    pub(super) epoch: u16,
    /// Newest epoch seen on any received packet.
    pub(super) newest_seen: u16,
    /// Monotonic ns at which this node first heard of an epoch newer than its
    /// own (cleared once it reaches it): bounds the age of newer-epoch stamps.
    newer_since_ns: Option<u64>,
    /// Newest epoch carried by requests this node served (its followers).
    subtree: u16,
    /// This node served a request carrying its own current epoch: followers
    /// share its time base (a leader that has never been followed in its
    /// epoch, e.g. a restarted station, may join the network's instead).
    followed: bool,
    links: [EpochLink; EPOCH_LINKS],
    links_head: u8,
    last_step: Option<StepRecord>,
    steps: u32,
    /// The elected source is in an older epoch: the clock is held.
    pub(super) holding: bool,
    /// A local source may step a leading clock.
    pub(super) steps_allowed: bool,
    /// Announces still to send at the short burst interval after an epoch
    /// change, so lossy links learn of it within a fraction of a second.
    pub(super) announce_burst: u8,
    /// Mirror of `epoch` read without the runtime lock when stamping packets.
    shared: Arc<core::sync::atomic::AtomicU16>,
}

impl EpochState {
    pub(super) fn new(shared: Arc<core::sync::atomic::AtomicU16>) -> Self {
        Self {
            epoch: shared.load(core::sync::atomic::Ordering::Acquire),
            newest_seen: 0,
            newer_since_ns: None,
            subtree: 0,
            followed: false,
            links: [EpochLink::default(); EPOCH_LINKS],
            links_head: 0,
            last_step: None,
            steps: 0,
            holding: false,
            steps_allowed: true,
            announce_burst: 0,
            shared,
        }
    }

    /// Epoch this node's requests carry: its own, or a newer one a follower
    /// carried (so the leader learns of it through relays).
    fn request_epoch(&self) -> u16 {
        self.epoch.max(self.subtree)
    }

    /// Notes an epoch heard from the network (`true` when it is newer than
    /// every epoch heard before).
    pub(super) fn see(&mut self, epoch: u16, now_ns: u64) -> bool {
        if epoch > self.epoch && self.newer_since_ns.is_none() {
            self.newer_since_ns = Some(now_ns);
        }
        let newer = epoch > self.newest_seen;
        self.newest_seen = self.newest_seen.max(epoch);
        newer
    }

    /// Milliseconds since this node first heard of an epoch newer than its own.
    fn newer_since_ms(&self, now_ns: u64) -> u64 {
        self.newer_since_ns.map_or(0, |at| now_ns.saturating_sub(at) / 1_000_000)
    }

    fn record(&mut self, to: u16, delta_ns: i64, reason: TimeSyncStepReason, now_ns: u64) {
        let from = self.epoch;
        if to != from {
            self.announce_burst = EPOCH_ANNOUNCE_BURST;
            let head = usize::from(self.links_head);
            self.links[head] = EpochLink { from, to, delta_ns };
            self.links_head = ((head + 1) % EPOCH_LINKS) as u8;
            self.epoch = to;
            self.followed = false;
            self.newest_seen = self.newest_seen.max(to);
            self.shared.store(to, core::sync::atomic::Ordering::Release);
            if self.newest_seen <= to {
                self.newer_since_ns = None;
            }
        }
        self.steps = self.steps.saturating_add(1);
        self.last_step = Some(StepRecord { delta_ns, reason, from_epoch: from, to_epoch: to, at_mono_ns: now_ns });
    }

    /// Next epoch for a step of this node's own clock: newer than every epoch
    /// it has seen, so no other time base can already carry the number.
    fn next_epoch(&self) -> u16 {
        self.epoch.max(self.newest_seen).max(self.subtree).saturating_add(1).min(crate::packet::MAX_TIME_EPOCH)
    }

    /// Translates a stamp taken in `epoch` into this node's current time base:
    /// the sum of remembered step deltas from that epoch to now.
    fn translate(&self, epoch: u16) -> Option<i64> {
        let mut at = epoch;
        let mut total = 0i64;
        for _ in 0..=EPOCH_LINKS {
            if at == self.epoch {
                return Some(total);
            }
            let link = self.links.iter().find(|l| l.from == at && l.to != l.from && l.to > at)?;
            total = total.saturating_add(link.delta_ns);
            at = link.to;
        }
        None
    }

    fn last_step(&self, now_ns: u64) -> Option<TimeSyncLastStep> {
        self.last_step.map(|r| TimeSyncLastStep {
            delta_ns: r.delta_ns,
            reason: r.reason,
            from_epoch: r.from_epoch,
            to_epoch: r.to_epoch,
            age_ms: now_ns.saturating_sub(r.at_mono_ns) / 1_000_000,
        })
    }
}

/// The newest plausible-UTC `(epoch, timestamp)` heard on any received
/// packet and the local monotonic instant it was heard, kept under its own small
/// lock, never the time sync runtime's. It stands in for network time only while this node has none of
/// its own (it cannot sync: no reachable source, a broken exchange), so command
/// windows stay judgeable from the stamps the station sends: a lower bound of
/// network time advanced by local elapsed time, re-anchored (either direction)
/// by a newer epoch and never moved back inside one.
pub(super) struct HeardStamp(RouterMutex<Option<(u16, u64, u64)>>);

impl core::fmt::Debug for HeardStamp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HeardStamp")
    }
}

impl Default for HeardStamp {
    fn default() -> Self {
        Self(RouterMutex::new(None))
    }
}

impl HeardStamp {
    fn read(&self, now_mono_ms: u64) -> Option<(u16, u64)> {
        self.0
            .lock()
            .map(|(epoch, ms, at)| (epoch, ms.saturating_add(now_mono_ms.saturating_sub(at))))
    }

    fn note(&self, epoch: u16, ms: u64, now_mono_ms: u64) {
        if ms < TIMESYNC_UTC_FLOOR_MS {
            return;
        }
        let mut heard = self.0.lock();
        let current = heard.map(|(e, m, at)| (e, m.saturating_add(now_mono_ms.saturating_sub(at))));
        if current.is_none_or(|cur| (epoch, ms) > cur) {
            *heard = Some((epoch, ms, now_mono_ms));
        }
    }
}

/// What a follower did with a target from its source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Follow {
    /// Disciplined or slewed as usual.
    Steered,
    /// Stepped (new epoch, or re-anchored forward).
    Stepped,
    /// Clock left alone (source in an older epoch, or diverged ahead).
    Held,
}

#[derive(Debug, Clone, Copy, Default)]
struct Exchange {
    used: bool,
    answered: bool,
    counter: u32,
    cookie: u64,
    t1_ns: u64,
    t4_ns: u64,
    t2_net_us: u64,
    source_error_ns: u64,
    request_len: u16,
    response_len: u16,
}

#[derive(Debug, Clone, Copy, Default)]
struct Served {
    used: bool,
    counter: u8,
    tag: u32,
    t3_net_us: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum MarkState {
    #[default]
    Empty,
    Queued,
    Handed,
}

#[derive(Debug, Clone, Copy, Default)]
struct TxMark {
    state: MarkState,
    response: bool,
    side: RouterSideId,
    word0: u64,
    word1: u64,
    requester_tag: u32,
    len: u32,
    hash: u32,
}

#[cfg(feature = "std")]
#[derive(Debug, Clone, Copy, Default)]
struct RxMark {
    used: bool,
    response: bool,
    tag: u32,
    word0: u64,
    word1: u64,
    rx_ns: u64,
    len: u16,
}

/// v2 exchange state held inside the router's time sync runtime.
#[derive(Debug, Clone, Default)]
pub(super) struct TimeSyncV2 {
    discipline: ClockDiscipline,
    source: Option<String>,
    exchanges: [Exchange; EXCHANGES],
    exchange_head: u8,
    served: [Served; SERVED],
    served_head: u8,
    tx_marks: [TxMark; TX_MARKS],
    tx_head: u8,
    #[cfg(feature = "std")]
    rx_marks: [RxMark; RX_MARKS],
    #[cfg(feature = "std")]
    rx_head: u8,
    /// (side, delay per frame byte after the stamps in ns, fixed asymmetry ns).
    asymmetry: [(RouterSideId, u32, i32); ASYMMETRY_SIDES],
    /// (side, physical minimum one-way delay after the stamps excluding the
    /// per-byte part, ns, stamping uncertainty of each end ns): a sample's
    /// error is bounded by how far its round trip exceeds the physical
    /// minimum, plus the stamping uncertainty.
    min_delay: [(RouterSideId, u32, u32); ASYMMETRY_SIDES],
    min_delay_len: u8,
    /// Exchanges rejected because their round trip measured below the
    /// path's physical minimum (a stamp was wrong).
    sub_minimum_rejects: u32,
    asymmetry_len: u8,
    ever_locked: bool,
    locked: bool,
    stratum: u8,
    /// Round trip of the newest answered request, ms (a responder that queues
    /// for seconds must not have more requests outstanding than slots).
    last_round_trip_ms: u32,
    rx_override: u64,
    /// A local reference (host clock, GPS) feeds this node's time; set by
    /// `timesync_local_quality_locked`.
    pub(super) local_reference: bool,
    /// Local UTC reference report to send: (offset ns, error ns, set at mono ns).
    utc_report: Option<(i64, u64, u64)>,
    /// Reports received from followers (newest last, at most 4).
    #[cfg(feature = "std")]
    utc_reports: [Option<UtcReferenceReport>; 4],
    #[cfg(feature = "std")]
    utc_reports_head: u8,
}

impl TimeSyncV2 {
    /// Clears everything except configured link asymmetries.
    pub(super) fn reset(&mut self) {
        let asymmetry = self.asymmetry;
        let asymmetry_len = self.asymmetry_len;
        let min_delay = self.min_delay;
        let min_delay_len = self.min_delay_len;
        let sub_minimum_rejects = self.sub_minimum_rejects;
        *self = Self::default();
        self.asymmetry = asymmetry;
        self.asymmetry_len = asymmetry_len;
        self.min_delay = min_delay;
        self.min_delay_len = min_delay_len;
        self.sub_minimum_rejects = sub_minimum_rejects;
    }

    /// Exchanges rejected for a round trip below the physical minimum.
    pub(super) fn sub_minimum_rejects(&self) -> u32 {
        self.sub_minimum_rejects
    }

    fn path_entry(&self, side: Option<RouterSideId>) -> Option<(u32, u32)> {
        let side = side?;
        self.min_delay[..usize::from(self.min_delay_len)]
            .iter()
            .find(|(s, _, _)| *s == side)
            .map(|(_, min, stamp)| (*min, *stamp))
    }

    /// Mutable (min delay, stamp uncertainty) entry of a side, added when
    /// absent (`None` when every slot is taken).
    fn path_entry_mut(&mut self, side: RouterSideId) -> Option<&mut (RouterSideId, u32, u32)> {
        let len = usize::from(self.min_delay_len);
        if let Some(i) = self.min_delay[..len].iter().position(|(s, _, _)| *s == side) {
            return Some(&mut self.min_delay[i]);
        }
        if len >= ASYMMETRY_SIDES {
            return None;
        }
        self.min_delay[len] = (side, 0, 0);
        self.min_delay_len += 1;
        Some(&mut self.min_delay[len])
    }

    pub(super) fn has_samples_from(&self, sender: &str) -> bool {
        !self.discipline.is_empty() && self.source.as_deref() == Some(sender)
    }

    /// Receive instant of the frame being processed synchronously: the
    /// transport's stamp when given, else `now`.
    fn rx_instant(&self, now_mono_ns: u64) -> u64 {
        if self.rx_override != 0 { self.rx_override } else { now_mono_ns }
    }

    pub(super) fn discipline_is_empty(&self) -> bool {
        self.discipline.is_empty()
    }

    pub(super) fn is_locked(&self) -> bool {
        self.locked
    }

    /// Error bound of the discipline at `now_mono_ns` (no pending slew).
    pub(super) fn bound_ns(&self, now_mono_ns: u64) -> Option<u64> {
        self.discipline.error_bound_ns(now_mono_ns)
    }

    /// Round trip of the newest answered request, ms.
    pub(super) fn last_round_trip_ms(&self) -> u64 {
        u64::from(self.last_round_trip_ms)
    }

    /// Physical minimum round trip of one exchange (both one-way minima at
    /// their frame sizes), ns; 0 when the side's minimum is not described.
    fn min_round_trip_ns(&self, side: Option<RouterSideId>, ex: &Exchange) -> u64 {
        let Some(fixed) = self.path_entry(side).map(|(min, _)| u64::from(min)).filter(|&m| m != 0) else {
            return 0;
        };
        let byte_ns = self.asymmetry[..usize::from(self.asymmetry_len)]
            .iter()
            .find(|(s, _, _)| Some(*s) == side)
            .map_or(0, |(_, b, _)| u64::from(*b));
        2 * fixed + byte_ns * (u64::from(ex.request_len) + u64::from(ex.response_len))
    }

    /// (response one-way delay - request one-way delay) / 2 for one exchange.
    fn asymmetry_ns(&self, side: Option<RouterSideId>, ex: &Exchange) -> i64 {
        side.and_then(|side| {
            self.asymmetry[..usize::from(self.asymmetry_len)]
                .iter()
                .find(|(s, _, _)| *s == side)
                .map(|(_, byte_ns, fixed)| {
                    let bytes = i64::from(ex.response_len) - i64::from(ex.request_len);
                    let sized = if ex.request_len == 0 || ex.response_len == 0 {
                        0
                    } else {
                        bytes * i64::from(*byte_ns) / 2
                    };
                    sized + i64::from(*fixed)
                })
        })
        .unwrap_or(0)
    }

    fn push_tx_mark(&mut self, mark: TxMark) {
        let slot = self
            .tx_marks
            .iter()
            .position(|m| m.state == MarkState::Empty)
            .unwrap_or_else(|| {
                let head = usize::from(self.tx_head);
                self.tx_head = ((head + 1) % TX_MARKS) as u8;
                head
            });
        self.tx_marks[slot] = mark;
    }

    #[cfg(not(feature = "std"))]
    fn take_rx(&mut self, _: u32, _: bool, _: u64, _: u64) -> Option<(u64, u16)> {
        None
    }

    #[cfg(feature = "std")]
    fn take_rx(&mut self, tag: u32, response: bool, word0: u64, word1: u64) -> Option<(u64, u16)> {
        let mark = self.rx_marks.iter_mut().find(|m| {
            m.used && m.response == response && m.tag == tag && m.word0 == word0 && m.word1 == word1
        })?;
        mark.used = false;
        Some((mark.rx_ns, mark.len))
    }

    fn served_for(&self, tag: u32) -> Option<&Served> {
        self.served.iter().find(|s| s.used && s.tag == tag)
    }

    fn note_served(&mut self, tag: u32, counter: u8, t3_net_us: u64) {
        let slot = self
            .served
            .iter()
            .position(|s| s.used && s.tag == tag)
            .or_else(|| self.served.iter().position(|s| !s.used))
            .unwrap_or_else(|| {
                let head = usize::from(self.served_head);
                self.served_head = ((head + 1) % SERVED) as u8;
                head
            });
        self.served[slot] = Served { used: true, counter, tag, t3_net_us };
    }

    /// Forgets every exchange and transmit stamp: they were taken in a time
    /// base that just changed (a step or a new epoch on either end).
    pub(super) fn clear_exchanges(&mut self) {
        self.exchanges = Default::default();
        self.served = Default::default();
        self.tx_marks = Default::default();
        #[cfg(feature = "std")]
        {
            self.rx_marks = Default::default();
        }
    }

    /// Restarts acquisition after this node's time base changed: the samples
    /// describe the old base and lock must be proven again.
    pub(super) fn restart_acquisition(&mut self) {
        self.discipline.restart_keep_frequency();
        self.clear_exchanges();
        self.locked = false;
        self.ever_locked = false;
    }

    fn push_exchange(&mut self, exchange: Exchange) {
        let head = usize::from(self.exchange_head);
        self.exchanges[head] = exchange;
        self.exchange_head = ((head + 1) % EXCHANGES) as u8;
    }
}

fn frame_hash(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for &b in bytes {
        hash = (hash ^ u32::from(b)).wrapping_mul(0x0100_0193);
    }
    hash
}

fn exchange_words(data: &RouterItem) -> Option<(DataType, u32, u64, u64)> {
    #[cfg(feature = "std")]
    let owned;
    let pkt = match data {
        RouterItem::Packet(p) => p,
        // Hosts queue received frames as packed bytes; decode only time sync
        // frames. Embedded receive paths process synchronously and take the
        // receive instant from the override instead (no decode, less flash).
        #[cfg(feature = "std")]
        RouterItem::Packed(bytes) => {
            let ty = crate::shared_bytes::with_slice(bytes, wire_format::scheduling_type)
                .ok()
                .flatten()?;
            if !matches!(ty, DataType::TimeSyncRequest | DataType::TimeSyncResponse) {
                return None;
            }
            owned = crate::shared_bytes::with_slice(bytes, wire_format::unpack_packet)
                .ok()?
                .ok()?;
            &owned
        }
        #[cfg(not(feature = "std"))]
        RouterItem::Packed(_) => return None,
    };
    let ty = pkt.data_type();
    if !matches!(ty, DataType::TimeSyncRequest | DataType::TimeSyncResponse) {
        return None;
    }
    let payload = pkt.payload();
    if payload.len() < 16 {
        return None;
    }
    let word = |i: usize| {
        let mut b = [0u8; 8];
        b.copy_from_slice(&payload[i * 8..i * 8 + 8]);
        u64::from_le_bytes(b)
    };
    Some((ty, timesync_sender_tag(pkt.sender()), word(0), word(1)))
}

impl Router {
    /// Records the receive instant of a time sync request/response at the
    /// transport boundary. Ordinary frames return after a type peek.
    #[cfg(not(feature = "std"))]
    #[inline(always)]
    pub(super) fn timesync_note_rx(&self, _: &RouterItem, _: u64) {}

    #[cfg(feature = "std")]
    pub(super) fn timesync_note_rx(&self, data: &RouterItem, rx_mono_ns: u64) {
        let Some(runtime) = self.timesync.as_ref() else {
            return;
        };
        let Some((ty, tag, word0, word1)) = exchange_words(data) else {
            return;
        };
        let len = match data {
            RouterItem::Packed(bytes) => bytes.len(),
            RouterItem::Packet(pkt) => wire_format::packet_wire_size(pkt),
        }
        .min(usize::from(u16::MAX)) as u16;
        let mut st = runtime.lock();
        let v2 = &mut st.v2;
        let rx_mono_ns = if v2.rx_override != 0 { v2.rx_override } else { rx_mono_ns };
        let slot = v2.rx_marks.iter().position(|m| !m.used).unwrap_or_else(|| {
            let head = usize::from(v2.rx_head);
            v2.rx_head = ((head + 1) % RX_MARKS) as u8;
            head
        });
        v2.rx_marks[slot] = RxMark {
            used: true,
            response: ty == DataType::TimeSyncResponse,
            tag,
            word0,
            word1,
            rx_ns: rx_mono_ns,
            len,
        };
    }

    /// Called when a time sync frame is handed to a side's transport. The
    /// handoff instant is the transmit stamp unless the transport later
    /// reports the real completion through [`Router::note_frame_sent`].
    pub(super) fn timesync_note_handoff(&self, side: RouterSideId, data: &RouterItem) {
        let Some(runtime) = self.timesync.as_ref() else {
            return;
        };
        let Some((ty, _, word0, word1)) = exchange_words(data) else {
            return;
        };
        let response = ty == DataType::TimeSyncResponse;
        let now_ns = self.monotonic_now_ns();
        let mut st = runtime.lock();
        let Some(idx) = st.v2.tx_marks.iter().position(|m| {
            m.state == MarkState::Queued && m.response == response && m.word0 == word0 && m.word1 == word1
        }) else {
            return;
        };
        st.v2.tx_marks[idx].state = MarkState::Handed;
        st.v2.tx_marks[idx].side = side;
        Self::timesync_apply_tx_stamp_locked(&mut st, idx, now_ns);
        self.timesync_tx_arm
            .store((side << 8) | (idx + 1), core::sync::atomic::Ordering::Release);
    }

    /// Keys the armed handoff to the exact transport frame bytes.
    pub(super) fn timesync_note_handed_frame(&self, side: RouterSideId, bytes: &[u8]) {
        let arm = self.timesync_tx_arm.load(core::sync::atomic::Ordering::Acquire);
        if arm == 0 || arm >> 8 != side {
            return;
        }
        let Some(runtime) = self.timesync.as_ref() else {
            return;
        };
        let idx = (arm & 0xFF) - 1;
        let now_ns = self.monotonic_now_ns();
        let mut st = runtime.lock();
        if let Some(mark) = st.v2.tx_marks.get_mut(idx)
            && mark.state == MarkState::Handed
        {
            mark.len = bytes.len() as u32;
            mark.hash = frame_hash(bytes);
            Self::timesync_apply_tx_stamp_locked(&mut st, idx, now_ns);
        }
    }

    pub(super) fn timesync_disarm(&self) {
        self.timesync_tx_arm.store(0, core::sync::atomic::Ordering::Release);
    }

    fn timesync_apply_tx_stamp_locked(st: &mut TimeSyncRuntime, idx: usize, mono_ns: u64) {
        let mark = st.v2.tx_marks[idx];
        if mark.response {
            let Some(net_ns) = st.disciplined_clock.read_unix_ns_at(mono_ns) else {
                return;
            };
            let t3_us = (net_ns.max(0) / 1_000) as u64;
            st.v2.note_served(mark.requester_tag, (mark.word0 & 0xFF) as u8, t3_us);
        } else {
            let counter = (mark.word0 & TIMESYNC_SEQ_COUNTER_MASK) as u32;
            if let Some(ex) = st
                .v2
                .exchanges
                .iter_mut()
                .find(|e| e.used && e.counter == counter && e.cookie == mark.word1)
                && (!ex.answered || mono_ns <= ex.t4_ns)
            {
                ex.t1_ns = mono_ns;
                if mark.len != 0 {
                    ex.request_len = mark.len.min(u32::from(u16::MAX)) as u16;
                }
            }
        }
    }

    /// Reports that a transport finished sending `frame` (the exact bytes the
    /// side callback was given) on `side` at router-monotonic `sent_mono_ns`,
    /// e.g. from a UART/CAN transmit-complete interrupt. Frames that are not
    /// time sync frames cost one lock and a length compare.
    pub fn note_frame_sent(&self, side: RouterSideId, frame: &[u8], sent_mono_ns: u64) {
        let Some(runtime) = self.timesync.as_ref() else {
            return;
        };
        let mut st = runtime.lock();
        let len = frame.len() as u32;
        if !st
            .v2
            .tx_marks
            .iter()
            .any(|m| m.state == MarkState::Handed && m.side == side && m.len == len)
        {
            return;
        }
        let hash = frame_hash(frame);
        if let Some(idx) = st.v2.tx_marks.iter().position(|m| {
            m.state == MarkState::Handed && m.side == side && m.len == len && m.hash == hash
        }) {
            Self::timesync_apply_tx_stamp_locked(&mut st, idx, sent_mono_ns);
            st.v2.tx_marks[idx].state = MarkState::Empty;
        }
    }

    /// Describes a side's path for time sync exchanges so the requester can
    /// remove the one-way delay difference between request and response
    /// frames: `byte_ns` is the delay per frame byte that falls between the
    /// transmit stamp and the receive stamp (radio: air time + receiving UART
    /// time per byte; add the sending UART time when the transport does not
    /// report transmit completion), `fixed_asymmetry_ns` any constant
    /// (response - request) / 2 difference such as a wrapper only one direction
    /// adds. Sides without a description are treated as symmetric.
    /// Describes a side's physical minimum one-way delay between the transmit
    /// and receive stamps, excluding the per-byte part given to
    /// [`Self::set_side_timesync_path`] (radio: modem packet close and TX
    /// setup and air framing). It must be a true lower bound: a sample whose
    /// round trip exceeds the minimum by `x` is off by at most `x / 2`, and
    /// the reported error bound rests on it. Without it every sample counts
    /// as off by up to its whole half round trip.
    pub fn set_side_timesync_min_delay(&self, side: RouterSideId, min_one_way_ns: u32) {
        let Some(runtime) = self.timesync.as_ref() else {
            return;
        };
        if let Some(entry) = runtime.lock().v2.path_entry_mut(side) {
            entry.1 = min_one_way_ns;
        }
    }

    /// Describes how far each end's time sync stamp on a side may be from the
    /// instant it stands for (UART/DMA/ISR latency, tick resolution), ns. The
    /// reported error bound carries it, and a round trip may measure up to
    /// twice it (plus a small tolerance) below the physical minimum before the
    /// exchange is rejected as proof of a wrong stamp.
    pub fn set_side_timesync_stamp_uncertainty(&self, side: RouterSideId, stamp_ns: u32) {
        let Some(runtime) = self.timesync.as_ref() else {
            return;
        };
        if let Some(entry) = runtime.lock().v2.path_entry_mut(side) {
            entry.2 = stamp_ns;
        }
    }

    pub fn set_side_timesync_path(&self, side: RouterSideId, byte_ns: u32, fixed_asymmetry_ns: i32) {
        let Some(runtime) = self.timesync.as_ref() else {
            return;
        };
        let mut st = runtime.lock();
        let v2 = &mut st.v2;
        let len = usize::from(v2.asymmetry_len);
        if let Some(entry) = v2.asymmetry[..len].iter_mut().find(|(s, _, _)| *s == side) {
            *entry = (side, byte_ns, fixed_asymmetry_ns);
        } else if len < ASYMMETRY_SIDES {
            v2.asymmetry[len] = (side, byte_ns, fixed_asymmetry_ns);
            v2.asymmetry_len += 1;
        }
    }

    /// Chooses the request's t1 cookie: the monotonic ms as before, or a UTC
    /// report (flag bit in seq) while one is fresh (5 s).
    pub(super) fn timesync_request_cookie_locked(
        st: &TimeSyncRuntime,
        seq: u64,
        now_ms: u64,
        now_ns: u64,
    ) -> (u64, u64) {
        if let Some((offset_ns, error_ns, at)) = st.v2.utc_report
            && now_ns.saturating_sub(at) <= 5_000_000_000
        {
            // The follower's own sync error adds to the reference's.
            let own = st.v2.discipline.error_bound_ns(now_ns).unwrap_or(u64::MAX);
            let error = error_ns.saturating_add(own);
            let code = if error == u64::MAX { 127 } else { encode_error_code(error) };
            if code != 127
                && let Some(word) =
                    encode_utc_report_word(offset_ns / 1_000, code, (seq & 0xFFFF) as u16)
            {
                return (seq | TIMESYNC_UTC_REPORT, word);
            }
        }
        (seq, now_ms)
    }

    /// Stores a follower's UTC report carried by a request.
    #[cfg(not(feature = "std"))]
    #[inline(always)]
    pub(super) fn timesync_note_utc_report_locked(_: &mut TimeSyncRuntime, _: &str, _: u64, _: u64, _: u64) {}

    #[cfg(feature = "std")]
    pub(super) fn timesync_note_utc_report_locked(
        st: &mut TimeSyncRuntime,
        sender: &str,
        seq: u64,
        t1: u64,
        now_ns: u64,
    ) {
        if seq & TIMESYNC_UTC_REPORT == 0 {
            return;
        }
        let (offset_us, code) = decode_utc_report_word(t1);
        if code == 127 {
            return;
        }
        let head = usize::from(st.v2.utc_reports_head);
        st.v2.utc_reports[head] = Some(UtcReferenceReport {
            sender_tag: timesync_sender_tag(sender),
            offset_ns: offset_us.saturating_mul(1_000),
            error_ns: decode_error_code(code),
            received_mono_ns: now_ns,
        });
        st.v2.utc_reports_head = ((head + 1) % 4) as u8;
    }

    /// Sets this node's absolute-time reference measurement (e.g. GPS UTC
    /// minus network time, measured at the GPS fix), sent to its source in
    /// the next requests while fresh (5 s). `None` stops reporting.
    pub fn set_utc_reference_offset(&self, report: Option<(i64, u64)>) {
        let Some(runtime) = self.timesync.as_ref() else {
            return;
        };
        let now_ns = self.monotonic_now_ns();
        runtime.lock().v2.utc_report = report.map(|(offset_ns, error_ns)| (offset_ns, error_ns, now_ns));
    }

    /// Takes the UTC reports followers sent since the last call (oldest first).
    #[cfg(feature = "std")]
    pub fn take_utc_reference_reports(&self) -> Vec<UtcReferenceReport> {
        let Some(runtime) = self.timesync.as_ref() else {
            return Vec::new();
        };
        let mut st = runtime.lock();
        let head = usize::from(st.v2.utc_reports_head);
        let mut out = Vec::new();
        for i in 0..4 {
            if let Some(r) = st.v2.utc_reports[(head + i) % 4].take() {
                out.push(r);
            }
        }
        out
    }

    /// Records an outgoing v2 request so its answers can be matched.
    pub(super) fn timesync_record_request_locked(
        st: &mut TimeSyncRuntime,
        seq: u64,
        cookie: u64,
        t1_ns: u64,
    ) {
        st.v2.push_exchange(Exchange {
            used: true,
            answered: false,
            counter: (seq & TIMESYNC_SEQ_COUNTER_MASK) as u32,
            cookie,
            t1_ns,
            ..Default::default()
        });
        st.v2.push_tx_mark(TxMark {
            state: MarkState::Queued,
            response: false,
            word0: seq,
            word1: cookie,
            ..Default::default()
        });
    }

    /// Builds the response words for a request and records the response for
    /// transmit stamping. `rx_ns` is the request's receive instant.
    pub(super) fn timesync_build_response_locked(
        st: &mut TimeSyncRuntime,
        requester: &str,
        seq: u64,
        t1: u64,
        now_mono_ns: u64,
        status: &TimeSyncStatus,
    ) -> (u64, u64, u64, u64) {
        let tag = timesync_sender_tag(requester);
        let rx_ns = st.v2.take_rx(tag, false, seq, t1).map_or(st.v2.rx_instant(now_mono_ns), |(ns, _)| ns);
        let net_at = |st: &TimeSyncRuntime, mono: u64| {
            st.disciplined_clock.read_unix_ns_at(mono).or_else(|| {
                st.clock
                    .current_time(mono)
                    .and_then(|t| t.unix_time_ms)
                    .map(|ms| ms.saturating_mul(1_000_000).min(i64::MAX as u64) as i64)
            })
        };
        let t2_ns = net_at(st, rx_ns).unwrap_or(rx_ns as i64).max(0);
        let w2 = encode_v2_receive_word(
            (t2_ns / 1_000) as u64,
            status.state.is_synced(),
            if status.error_bound_ns == u64::MAX {
                127
            } else {
                encode_error_code(status.error_bound_ns)
            },
        );
        let w3 = st
            .v2
            .served_for(tag)
            .map_or(0, |s| encode_v2_transmit_word(u64::from(s.counter), s.t3_net_us));
        let words = (seq, t1, w2, w3);
        st.v2.push_tx_mark(TxMark {
            state: MarkState::Queued,
            response: true,
            word0: words.0,
            word1: words.1,
            requester_tag: tag,
            ..Default::default()
        });
        words
    }

    /// Handles a response from the elected source, whose packet carries
    /// `src_epoch`. Returns `true` when the clock was steered.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn timesync_handle_response_locked(
        st: &mut TimeSyncRuntime,
        sender: &str,
        words: (u64, u64, u64, u64),
        side: Option<RouterSideId>,
        now_mono_ns: u64,
        anchored: bool,
        src_epoch: u16,
    ) -> bool {
        let (seq, t1, t2, t3) = words;
        if st.v2.source.as_deref() != Some(sender) {
            // New source: the oscillator is the same, the samples are not.
            st.v2.discipline.restart_keep_frequency();
            st.v2.source = Some(String::from(sender));
            st.v2.locked = false;
        }
        let tag = timesync_sender_tag(sender);
        let (t4_ns, response_len) = st.v2.take_rx(tag, true, seq, t1).unwrap_or((st.v2.rx_instant(now_mono_ns), 0));
        if src_epoch != st.epoch.epoch {
            // Stamps of another time base never form a sample. A newer epoch
            // is adopted at the responder's receive stamp of this request: a
            // lower bound of its time now, so the exchanges that follow only
            // ever move the clock forward within the new epoch.
            let (t2_us, _, _) = decode_v2_receive_word(t2);
            let target = (t2_us as i64).saturating_mul(1_000);
            let elapsed = now_mono_ns.saturating_sub(t4_ns).min(i64::MAX as u64) as i64;
            let floor_ns = TIMESYNC_UTC_FLOOR_MS as i64 * 1_000_000;
            if src_epoch > st.epoch.epoch && (target >= floor_ns || !st.clock_anchored) {
                let target = target.saturating_add(elapsed);
                let followed = Self::timesync_follow_locked(st, now_mono_ns, target, None, src_epoch, None, true);
                if followed != Follow::Held {
                    st.clock_anchored = anchored && target >= floor_ns;
                    return true;
                }
            } else {
                st.epoch.holding = src_epoch < st.epoch.epoch;
            }
            return false;
        }
        // The source is in this node's epoch: nothing to hold for.
        st.epoch.holding = false;
        // The t1 cookie is the request's monotonic ms (unless it carried a UTC
        // report): the round trip is known even when the response came too
        // late to match an exchange slot.
        if seq & TIMESYNC_UTC_REPORT == 0 {
            let round_trip_ms = (t4_ns / 1_000_000).saturating_sub(t1);
            if round_trip_ms <= 60_000 {
                st.v2.last_round_trip_ms = round_trip_ms as u32;
            }
        }
        let counter = (seq & TIMESYNC_SEQ_COUNTER_MASK) as u32;
        let Some(idx) = st
            .v2
            .exchanges
            .iter()
            .position(|e| e.used && !e.answered && e.counter == counter && e.cookie == t1)
        else {
            return false;
        };
        let rate = st.disciplined_clock.rate_ppb();
        let sample = {
        let (t2_us, source_synced, code) = decode_v2_receive_word(t2);
        // A known bound passes through whole (a source more than 1 s off
        // says so); only an unknown one (code 127) stands in as 1 s.
        let source_error_ns = if code == 127 { UNKNOWN_SOURCE_ERROR_NS } else { decode_error_code(code) };
        {
            let ex = &mut st.v2.exchanges[idx];
            ex.answered = true;
            ex.t4_ns = t4_ns;

            ex.t2_net_us = t2_us;
            ex.source_error_ns = source_error_ns;
            ex.response_len = response_len;
        }
        decode_v2_transmit_word(t3).and_then(|(prev, t3_us)| {
            let prev_idx = st.v2.exchanges.iter().position(|e| {
                e.used && e.answered && (e.counter & 0xFF) as u8 == prev && e.t1_ns != 0
            })?;
            let ex = st.v2.exchanges[prev_idx];
            st.v2.exchanges[prev_idx].used = false;
            let asymmetry = st.v2.asymmetry_ns(side, &ex);
            let min_round_trip = st.v2.min_round_trip_ns(side, &ex);
            let stamp_ns = st.v2.path_entry(side).map_or(0, |(_, stamp)| stamp);
            let (t2_ns, t3_ns) = ((ex.t2_net_us as i64).saturating_mul(1_000), (t3_us as i64).saturating_mul(1_000));
            if t3_ns < t2_ns {
                // The responder's own stamps are inconsistent.
                return None;
            }
            // Path delay (round trip less turnaround) on our stamps. Below a
            // described physical minimum, even negative (a reply before its
            // request), it proves one of our stamps wrong: keep the deficit as
            // evidence and leave the exchange out; never clamp it into a
            // direct crossing. (On an undescribed side a negative delay is
            // dropped as before: the responder's slewing clock can cause it.)
            let round_trip = ex.t4_ns as i64 - ex.t1_ns as i64;
            let delay = round_trip + mul_div(round_trip, rate, 1_000_000_000) - (t3_ns - t2_ns);
            let slack = 2 * i64::from(stamp_ns) + TIMESYNC_MIN_DELAY_TOLERANCE_NS as i64;
            let floor = min_round_trip.min(i64::MAX as u64) as i64;
            if floor != 0 && delay < floor - slack {
                return Some(Err((floor - delay) as u64));
            }
            exchange_sample(ex.t1_ns, t2_ns, t3_ns, ex.t4_ns, ex.source_error_ns, asymmetry, rate).map(|mut sample| {
                sample.min_half_delay_ns = (min_round_trip / 2).min(u64::from(sample.half_delay_ns)) as u32;
                sample.stamp_error_ns = stamp_ns;
                sample.source_unsynced = !source_synced;
                Ok(sample)
            })
        })
        };
        let sample = match sample {
            None => return false,
            Some(Err(deficit)) => {
                st.v2.sub_minimum_rejects = st.v2.sub_minimum_rejects.saturating_add(1);
                st.v2.discipline.note_stamp_deficit(deficit, now_mono_ns);
                return false;
            }
            Some(Ok(sample)) => sample,
        };
        if let Some(target) = st.v2.discipline.target(sample.mono_ns)
            && target
                .net_ns
                .wrapping_sub((sample.mono_ns as i64).wrapping_add(sample.phi_ns))
                .unsigned_abs()
                > 1_000_000_000
        {
            // The source's own clock stepped (uptime replaced by UTC, a new
            // epoch): old samples describe a different timescale.
            st.v2.discipline.restart_keep_frequency();
        }
        if !st.v2.discipline.offer(sample) {
            return false;
        }
        Self::timesync_discipline_steer_locked(st, now_mono_ns, anchored, src_epoch);
        true
    }

    fn timesync_discipline_steer_locked(st: &mut TimeSyncRuntime, now_mono_ns: u64, anchored: bool, src_epoch: u16) {
        let Some(target) = st.v2.discipline.target(now_mono_ns) else {
            return;
        };
        let floor_ns = TIMESYNC_UTC_FLOOR_MS as i64 * 1_000_000;
        let anchored = anchored && target.net_ns >= floor_ns;
        let current = st.disciplined_clock.read_unix_ns_at(now_mono_ns);
        if !anchored && current.is_some_and(|c| c >= floor_ns) {
            // Unanchored time never drags a clock that already reads UTC.
            return;
        }
        let error = current.map(|c| (target.net_ns - c).unsigned_abs());
        let allow_step = match error {
            None => true,
            // UTC replaces unanchored time at once.
            Some(_) if anchored && !st.clock_anchored => true,
            // Before first lock timestamps are marked unsynced: converge now.
            // Once locked, slew only.
            Some(e) => {
                (!st.v2.ever_locked && e > ACQUIRE_STEP_NS)
                    // The source re-anchored (a station coarse-set its UTC):
                    // the first sample of the new timescale steps.
                    || (st.v2.discipline.len() <= 1 && e > 1_000_000_000)
            }
        };
        // A forward error beyond the step threshold steps; one as far ahead,
        // beyond what the exchange itself may be off, names a newer epoch.
        let bound = st.v2.discipline.error_bound_ns(now_mono_ns);
        let followed = Self::timesync_follow_locked(
            st,
            now_mono_ns,
            target.net_ns,
            Some(target.rate_ppb),
            src_epoch,
            bound,
            allow_step,
        );
        if followed != Follow::Held {
            st.clock_anchored = anchored;
        }
    }

    /// Step threshold of the active configuration, ns.
    pub(super) fn timesync_step_threshold_ns(st: &TimeSyncRuntime) -> u64 {
        st.cfg.map_or(
            crate::timesync::TIMESYNC_DEFAULT_STEP_THRESHOLD_MS * 1_000_000,
            |cfg| cfg.step_threshold_ns(),
        )
    }

    /// Records an epoch change (or a step within the epoch when `to` is the
    /// current epoch) and invalidates every exchange stamp of the old base.
    /// The next announce and request go out at once.
    pub(super) fn timesync_epoch_changed_locked(
        st: &mut TimeSyncRuntime,
        to: u16,
        delta_ns: i64,
        reason: TimeSyncStepReason,
        now_ns: u64,
    ) {
        st.epoch.record(to, delta_ns, reason, now_ns);
        st.v2.clear_exchanges();
        st.pending_request = None;
        st.next_announce_mono_ms = 0;
        st.next_request_mono_ms = 0;
    }

    /// Steps this (leading) node's own clock to `target_ns` and starts a new
    /// epoch, so followers re-anchor at once and every node can order stamps
    /// across the step.
    pub(super) fn timesync_local_step_locked(
        st: &mut TimeSyncRuntime,
        now_ns: u64,
        target_ns: i64,
        reason: TimeSyncStepReason,
    ) {
        let delta = st
            .disciplined_clock
            .read_unix_ns_at(now_ns)
            .map_or(0, |current| target_ns.saturating_sub(current));
        let rate = st.disciplined_clock.rate_ppb();
        st.disciplined_clock.discipline_ns(now_ns, target_ns, rate, true);
        let next = st.epoch.next_epoch();
        Self::timesync_epoch_changed_locked(st, next, delta, reason, now_ns);
        st.v2.restart_acquisition();
    }

    /// Applies a local time source reading to this node's own clock while it
    /// does not follow a remote: a step and a new epoch beyond the step
    /// threshold (steps allowed), otherwise a slew at the reference rate.
    pub(super) fn timesync_local_steer_locked(st: &mut TimeSyncRuntime, now_ns: u64, target_ns: i64) {
        let threshold = Self::timesync_step_threshold_ns(st);
        let current = st.disciplined_clock.read_unix_ns_at(now_ns);
        match current {
            Some(current)
                if st.epoch.steps_allowed
                    && target_ns.saturating_sub(current).unsigned_abs() > threshold =>
            {
                Self::timesync_local_step_locked(st, now_ns, target_ns, TimeSyncStepReason::LocalSource);
            }
            _ => {
                let ppm = st.cfg.map_or(
                    crate::timesync::TIMESYNC_DEFAULT_REFERENCE_SLEW_PPM,
                    |cfg| cfg.reference_slew_ppm,
                );
                st.disciplined_clock.steer_unix_ns_at_rate(now_ns, target_ns, ppm);
            }
        }
    }

    /// Applies a target from the elected source, whose packets carry
    /// `src_epoch`.
    ///
    /// - Source in a newer epoch: adopt it, step to the target when it is off
    ///   by more than the acquisition step, and prove lock again.
    /// - Source in an older epoch: hold the clock (the source adopts this
    ///   node's epoch from its requests).
    /// - Same epoch: more than the step threshold behind, step forward; more
    ///   than the threshold (plus the target's own error bound, when known)
    ///   ahead, announce a newer epoch upstream and hold (before this node
    ///   first locked in the epoch it steps back instead, as when acquiring:
    ///   its stamps are still marked unsynced); otherwise
    ///   discipline (`rate_ppb`) or slew as before (`allow_step` permits the
    ///   usual acquisition step).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn timesync_follow_locked(
        st: &mut TimeSyncRuntime,
        now_ns: u64,
        target_ns: i64,
        rate_ppb: Option<i64>,
        src_epoch: u16,
        target_bound_ns: Option<u64>,
        allow_step: bool,
    ) -> Follow {
        let own = st.epoch.epoch;
        if src_epoch < own {
            st.epoch.holding = true;
            return Follow::Held;
        }
        st.epoch.holding = false;
        let threshold = Self::timesync_step_threshold_ns(st);
        let current = st.disciplined_clock.read_unix_ns_at(now_ns);
        let error = current.map(|c| target_ns.saturating_sub(c));
        let rate = rate_ppb.unwrap_or_else(|| st.disciplined_clock.rate_ppb());
        if src_epoch > own {
            let step = error.is_none_or(|e| e.unsigned_abs() > ACQUIRE_STEP_NS);
            if step {
                st.disciplined_clock.discipline_ns(now_ns, target_ns, rate, true);
            } else if rate_ppb.is_some() {
                st.disciplined_clock.discipline_ns(now_ns, target_ns, rate, false);
            } else {
                st.disciplined_clock.steer_unix_ns(now_ns, target_ns);
            }
            let delta = if step { error.unwrap_or(0) } else { 0 };
            Self::timesync_epoch_changed_locked(st, src_epoch, delta, TimeSyncStepReason::SourceEpoch, now_ns);
            st.v2.restart_acquisition();
            return if step { Follow::Stepped } else { Follow::Steered };
        }
        // Before it first locks in this epoch a node's stamps are marked
        // unsynced, and it may still step either way (as when acquiring).
        let locked_before = st.v2.ever_locked;
        match error {
            Some(e)
                if e.unsigned_abs() > threshold
                    && (e > 0 || (!locked_before && target_bound_ns.is_some())) =>
            {
                // The samples describe the source, which did not change: only
                // this node's clock (and the stamps it served) moved.
                st.disciplined_clock.discipline_ns(now_ns, target_ns, rate, true);
                Self::timesync_epoch_changed_locked(st, own, e, TimeSyncStepReason::Resync, now_ns);
                Follow::Stepped
            }
            Some(e)
                if e < 0
                    && locked_before
                    && target_bound_ns
                        .is_some_and(|bound| e.unsigned_abs() > threshold.saturating_add(bound)) =>
            {
                // Stepping back inside this epoch would let this node's later
                // stamps sort before its earlier ones. Name a newer epoch
                // instead; the source adopts it from the next request.
                let next = st.epoch.next_epoch();
                Self::timesync_epoch_changed_locked(st, next, 0, TimeSyncStepReason::Diverged, now_ns);
                st.epoch.holding = true;
                Follow::Held
            }
            _ => {
                match rate_ppb {
                    Some(rate) => st.disciplined_clock.discipline_ns(now_ns, target_ns, rate, allow_step),
                    None if allow_step => {
                        let rate = st.disciplined_clock.rate_ppb();
                        st.disciplined_clock.discipline_ns(now_ns, target_ns, rate, true);
                    }
                    None => st.disciplined_clock.steer_unix_ns(now_ns, target_ns),
                }
                Follow::Steered
            }
        }
    }

    /// A leading node serving a request that carries a newer epoch adopts it:
    /// the follower's time base is the network's. When the follower's stamp
    /// disagrees with this clock by more than the step threshold the bases
    /// differ, and a still newer epoch names this node's base.
    ///
    /// `fresh_stamp` marks a time sync request, whose stamp is taken as it is
    /// sent: only such a stamp may serve as the network's time. While steps
    /// are inhibited ([`Router::set_timesync_steps_allowed`]) a leader that
    /// disagrees with a fresh, plausible (UTC) request stamp joins the
    /// network's time base instead of making every follower step to its own:
    /// the network stays continuous (a station restarted in flight), and the
    /// leader's local sources then correct it under the usual policy (slewed
    /// while inhibited, stepped once steps are allowed again). Any other packet
    /// in a newer epoch is adopted only when its stamp agrees with this clock.
    pub(super) fn timesync_leader_note_request_epoch_locked(
        st: &mut TimeSyncRuntime,
        req_epoch: u16,
        req_stamp_ms: u64,
        now_ns: u64,
        fresh_stamp: bool,
    ) {
        st.epoch.see(req_epoch, now_ns);
        if req_epoch <= st.epoch.epoch {
            if fresh_stamp && req_epoch == st.epoch.epoch {
                st.epoch.followed = true;
            }
            return;
        }
        let threshold_ms = Self::timesync_step_threshold_ns(st) / 1_000_000;
        let current = st.disciplined_clock.read_unix_ms(now_ns);
        let agrees = current.is_some_and(|now_ms| now_ms.abs_diff(req_stamp_ms) <= threshold_ms);
        if agrees {
            Self::timesync_epoch_changed_locked(st, req_epoch, 0, TimeSyncStepReason::Renamed, now_ns);
            return;
        }
        if !fresh_stamp {
            // A data packet's stamp may have waited in queues: never act on
            // a disagreement it shows. The next request settles it.
            return;
        }
        // Only a leader no follower shares a base with yet joins: one that is
        // followed is the reference, and a follower in a newer epoch on
        // another base (one that named a divergence) steps back onto it.
        if !st.epoch.steps_allowed && !st.epoch.followed && req_stamp_ms >= TIMESYNC_UTC_FLOOR_MS {
            let target_ns = (i128::from(req_stamp_ms) * 1_000_000).min(i128::from(i64::MAX)) as i64;
            let delta = current.map_or(0, |c| target_ns.saturating_sub((i128::from(c) * 1_000_000) as i64));
            let rate = st.disciplined_clock.rate_ppb();
            st.disciplined_clock.discipline_ns(now_ns, target_ns, rate, true);
            st.clock_anchored = true;
            Self::timesync_epoch_changed_locked(st, req_epoch, delta, TimeSyncStepReason::Joined, now_ns);
            st.v2.restart_acquisition();
            return;
        }
        // A different base: a still newer epoch names this node's, and the
        // followers step onto it.
        Self::timesync_epoch_changed_locked(st, req_epoch.saturating_add(1).min(crate::packet::MAX_TIME_EPOCH), 0, TimeSyncStepReason::Renamed, now_ns);
    }

    /// A relay serving a request that carries a newer epoch passes it upstream
    /// in its own requests.
    pub(super) fn timesync_note_subtree_epoch_locked(st: &mut TimeSyncRuntime, req_epoch: u16, now_ns: u64) {
        st.epoch.subtree = st.epoch.subtree.max(req_epoch);
        st.epoch.see(req_epoch, now_ns);
        if req_epoch > st.epoch.epoch {
            st.next_request_mono_ms = 0;
        }
    }

    /// Epoch this node's requests carry.
    pub(super) fn timesync_request_epoch_locked(st: &TimeSyncRuntime) -> u16 {
        st.epoch.request_epoch()
    }

    /// Interval to the next announce: short while an epoch change is still
    /// being announced in a burst.
    pub(super) fn timesync_next_announce_interval_locked(st: &mut TimeSyncRuntime, interval_ms: u64) -> u64 {
        if st.epoch.announce_burst > 0 {
            st.epoch.announce_burst -= 1;
            interval_ms.min(EPOCH_ANNOUNCE_BURST_MS)
        } else {
            interval_ms
        }
    }

    /// Notes the epoch of any received packet: a newer one means this node's
    /// time base is behind the network's, so it asks its source at once.
    ///
    /// A leading node (a restarted station, epoch 0) adopts a newer epoch
    /// whose stamp agrees with its clock at once, so its own writes order
    /// after everything the network already holds from the first packet it
    /// hears rather than from the first request it serves.
    pub(super) fn timesync_note_rx_epoch(&self, epoch: u16, timestamp_ms: u64) {
        self.timesync_heard.note(epoch, timestamp_ms, self.monotonic_now_ms());
        if epoch == 0 || epoch <= self.timesync_epoch.load(core::sync::atomic::Ordering::Acquire) {
            return;
        }
        let Some(runtime) = self.timesync.as_ref() else {
            return;
        };
        let now_ms = self.monotonic_now_ms();
        let now_ns = self.monotonic_now_ns();
        let mut st = runtime.lock();
        if st.epoch.see(epoch, now_ns) {
            st.next_request_mono_ms = 0;
        }
        if st.cfg.is_some() && !Self::timesync_following_remote_locked(&st, now_ms, now_ns) {
            Self::timesync_leader_note_request_epoch_locked(&mut st, epoch, timestamp_ms, now_ns, false);
        }
    }

    /// Raises this node's network time-base epoch to at least `min_epoch`
    /// without changing its clock, e.g. at boot from an epoch persisted with
    /// an ordering mark (a replay floor stored as `(epoch, timestamp)`).
    ///
    /// A follower raised above its source holds until the source adopts the
    /// epoch from its requests (or names a newer one when the clocks disagree),
    /// so the network's epoch never falls below an epoch any node remembers,
    /// even after every node restarted. Returns the epoch after the call.
    pub fn raise_network_time_epoch(&self, min_epoch: u16) -> u16 {
        let Some(runtime) = self.timesync.as_ref() else {
            return 0;
        };
        let now_ns = self.monotonic_now_ns();
        let mut st = runtime.lock();
        let min_epoch = min_epoch.min(crate::packet::MAX_TIME_EPOCH);
        if min_epoch > st.epoch.epoch {
            Self::timesync_epoch_changed_locked(&mut st, min_epoch, 0, TimeSyncStepReason::Raised, now_ns);
        }
        st.epoch.epoch
    }

    /// Current network time-base epoch (0 before any step was seen).
    pub fn network_time_epoch(&self) -> u16 {
        self.timesync_epoch.load(core::sync::atomic::Ordering::Acquire)
    }

    /// Current network time with its epoch, read together: a stamp to compare
    /// with [`Router::network_stamp_age_ms`] or to put on a packet built by
    /// the application ([`Packet::with_time_epoch`]).
    pub fn network_time_ms_with_epoch(&self) -> Option<(u64, u16)> {
        for _ in 0..2 {
            let before = self.network_time_epoch();
            let ms = self.network_time_ms()?;
            if self.network_time_epoch() == before {
                return Some((ms, before));
            }
        }
        let epoch = self.network_time_epoch();
        self.network_time_ms().map(|ms| (ms, epoch))
    }

    /// Age of a `(time_epoch, timestamp)` stamp against this node's network
    /// time, translated across the recent steps this node remembers. Use it
    /// for freshness checks instead of comparing a raw timestamp with
    /// `network_time_ms()`: a command stamped just before a 4 h step back is
    /// seconds old, not 4 h in the future, and a copy stamped before an older
    /// step is reported as [`NetworkStampAge::OlderEpoch`].
    pub fn network_stamp_age_ms(&self, epoch: u16, timestamp_ms: u64) -> NetworkStampAge {
        let Some(runtime) = self.timesync.as_ref() else {
            return NetworkStampAge::NoTime;
        };
        // Our own time judges a UTC stamp only when it reads UTC itself (a
        // board following an RF without a GPS fix holds uptime-based time).
        let own = self
            .network_time_ms()
            .filter(|ms| *ms >= TIMESYNC_UTC_FLOOR_MS || timestamp_ms < TIMESYNC_UTC_FLOOR_MS);
        let Some(now_ms) = own else {
            // No usable network time of our own (never synced, or no source
            // can be reached): judge against the newest stamp heard.
            return match self.timesync_heard.read(self.monotonic_now_ms()) {
                Some((heard_epoch, heard_ms)) if epoch == heard_epoch => {
                    NetworkStampAge::Age((i128::from(heard_ms) - i128::from(timestamp_ms)).clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64)
                }
                Some((heard_epoch, _)) if epoch > heard_epoch => NetworkStampAge::NewerEpoch { since_ms: 0 },
                Some(_) => NetworkStampAge::OlderEpoch,
                None => NetworkStampAge::NoTime,
            };
        };
        let now_ns = self.monotonic_now_ns();
        let st = runtime.lock();
        if epoch > st.epoch.epoch {
            let since_ms = if epoch > st.epoch.newest_seen { 0 } else { st.epoch.newer_since_ms(now_ns) };
            return NetworkStampAge::NewerEpoch { since_ms };
        }
        match st.epoch.translate(epoch) {
            Some(delta_ns) => {
                let stamp = i128::from(timestamp_ms) + i128::from(delta_ns / 1_000_000);
                NetworkStampAge::Age((i128::from(now_ms) - stamp).clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64)
            }
            None => NetworkStampAge::OlderEpoch,
        }
    }

    /// Whether a `(time_epoch, timestamp)` stamp is inside a validity window
    /// of this node's network time: at most `max_age_ms` old and at most
    /// `max_ahead_ms` ahead, judged by [`Router::network_stamp_age_ms`] and
    /// [`NetworkStampAge::is_fresh`]. This is the check for command-validity
    /// windows: it never compares a stamp with this node's clock across a
    /// step, accepts a command stamped in a newer epoch only while this node
    /// is still re-anchoring onto it, and refuses stamps from before steps it
    /// no longer remembers, and everything while it has no network time.
    pub fn network_stamp_is_fresh(&self, epoch: u16, timestamp_ms: u64, max_age_ms: u64, max_ahead_ms: u64) -> bool {
        self.network_stamp_age_ms(epoch, timestamp_ms).is_fresh(max_age_ms, max_ahead_ms)
    }

    /// Allows or inhibits steps of this node's clock by local time sources
    /// (operator/host time, GPS) and [`Router::step_local_network_time_ns`].
    /// Inhibited, such corrections are slewed at the reference rate however
    /// large; followers still follow their source's steps. Inhibit during
    /// flight phases where a leading clock must stay continuous.
    pub fn set_timesync_steps_allowed(&self, allowed: bool) {
        if let Some(runtime) = self.timesync.as_ref() {
            runtime.lock().epoch.steps_allowed = allowed;
        }
    }

    /// Changes the step threshold and/or reference slew rate of the active
    /// configuration in place, keeping all time sync state (unlike
    /// [`Router::set_timesync_config`]). `None` keeps a value. Returns `false`
    /// when time sync is not configured.
    pub fn set_timesync_step_policy(&self, step_threshold_ms: Option<u64>, reference_slew_ppm: Option<u32>) -> bool {
        let Some(runtime) = self.timesync.as_ref() else {
            return false;
        };
        let mut st = runtime.lock();
        let Some(cfg) = st.cfg.as_mut() else {
            return false;
        };
        if let Some(ms) = step_threshold_ms {
            cfg.step_threshold_ms = ms;
        }
        if let Some(ppm) = reference_slew_ppm {
            cfg.reference_slew_ppm = ppm;
        }
        if let Some(tracker) = st.tracker.as_mut() {
            tracker.set_step_policy(step_threshold_ms, reference_slew_ppm);
        }
        true
    }

    /// Quality of this node's network time, committing the lock hysteresis
    /// (the node's own periodic evaluation and the responses it serves).
    pub(super) fn timesync_status_locked(
        st: &mut TimeSyncRuntime,
        leader: Option<&TimeSyncLeader>,
        now_mono_ns: u64,
    ) -> TimeSyncStatus {
        let (status, discipline_evaluated) = Self::timesync_status_peek_locked(st, leader, now_mono_ns);
        if discipline_evaluated {
            let pending = st.disciplined_clock.pending_ns(now_mono_ns);
            let live = matches!(leader, Some(TimeSyncLeader::Remote(_)));
            let _ = st.v2.discipline.quality(now_mono_ns, live, pending);
        }
        if matches!(leader, Some(TimeSyncLeader::Remote(_))) {
            st.v2.stratum = status.stratum;
        }
        st.v2.locked = status.state.is_synced();
        st.v2.ever_locked |= st.v2.locked;
        status
    }

    /// Quality of this node's network time without changing any state, and
    /// whether the discipline's quality was evaluated (its hysteresis is what
    /// [`Self::timesync_status_locked`] commits).
    fn timesync_status_peek_locked(
        st: &TimeSyncRuntime,
        leader: Option<&TimeSyncLeader>,
        now_mono_ns: u64,
    ) -> (TimeSyncStatus, bool) {
        let pending = st.disciplined_clock.pending_ns(now_mono_ns);
        let offset_ns = st.disciplined_clock.pending_signed_ns(now_mono_ns);
        let rate_ppb = st.disciplined_clock.rate_ppb();
        let last_sample_age_ms = st
            .v2
            .discipline
            .newest_mono_ns()
            .map_or(u64::MAX, |m| now_mono_ns.saturating_sub(m) / 1_000_000);
        let local_reference = st.v2.local_reference;
        let mut evaluated = false;
        let (state, error_bound_ns, stratum, is_reference) = match leader {
            Some(TimeSyncLeader::Local { .. }) if local_reference => {
                (SyncState::Locked, pending, 0, true)
            }
            Some(TimeSyncLeader::Local { .. }) => {
                evaluated = true;
                let (state, bound) = st.v2.discipline.peek_quality(now_mono_ns, false, pending);
                (state, bound, st.v2.stratum, true)
            }
            Some(TimeSyncLeader::Remote(remote)) => {
                let stratum = remote.quality().stratum.saturating_add(1);
                if st.v2.has_samples_from(&remote.sender) {
                    evaluated = true;
                    let (state, bound) = st.v2.discipline.peek_quality(now_mono_ns, true, pending);
                    (state, bound, stratum, false)
                } else if st.disciplined_clock.is_initialized() {
                    (SyncState::Acquiring, u64::MAX, stratum, false)
                } else {
                    (SyncState::Unsynced, u64::MAX, stratum, false)
                }
            }
            None if !st.v2.discipline.is_empty() => {
                evaluated = true;
                let (state, bound) = st.v2.discipline.peek_quality(now_mono_ns, false, pending);
                (state, bound, st.v2.stratum, false)
            }
            None => (SyncState::Unsynced, u64::MAX, 0, false),
        };
        (
            TimeSyncStatus {
                // A clock held for its source's newer epoch is not synced.
                state: if st.epoch.holding && state.is_synced() { SyncState::Acquiring } else { state },
                stratum,
                // A held clock is off its source by more than the discipline
                // knows: report the bound as unknown.
                error_bound_ns: if st.epoch.holding { u64::MAX } else { error_bound_ns },
                offset_ns,
                rate_ppb,
                last_sample_age_ms,
                is_reference,
                epoch: st.epoch.epoch,
                newest_seen_epoch: st.epoch.newest_seen.max(st.epoch.epoch),
                holding: st.epoch.holding,
                steps: st.epoch.steps,
                last_step: st.epoch.last_step(now_mono_ns),
                steps_allowed: st.epoch.steps_allowed,
            },
            evaluated,
        )
    }

    /// Time sync exchanges rejected because their round trip measured below
    /// the side's physical minimum: some stamp was wrong.
    pub fn timesync_sub_minimum_rejects(&self) -> u64 {
        self.timesync.as_ref().map_or(0, |runtime| u64::from(runtime.lock().v2.sub_minimum_rejects()))
    }

    /// Current time sync quality: lock state, error bound, pending offset and
    /// learned frequency. `None` when time sync is not configured.
    ///
    /// A read only: it changes no state (the lock hysteresis is committed by
    /// the node's own periodic evaluation), so observing a node never changes
    /// what it does.
    pub fn timesync_status(&self) -> Option<TimeSyncStatus> {
        let runtime = self.timesync.as_ref()?;
        let now_ms = self.monotonic_now_ms();
        let now_ns = self.monotonic_now_ns();
        let st = runtime.lock();
        st.cfg?;
        let has_usable_time = Self::timesync_has_usable_time_locked(&st, now_ns);
        let leader = st.tracker.as_ref().and_then(|t| t.leader(now_ms, has_usable_time));
        Some(Self::timesync_status_peek_locked(&st, leader.as_ref(), now_ns).0)
    }

    /// Coarse-sets this node's network time to `unix_ns` at once (a step, not a
    /// slew) while it leads, e.g. when a station without an RTC first learns
    /// UTC. The step starts a new time-base epoch: followers re-anchor to it
    /// at once and order stamps across it. Returns `false` (nothing changed)
    /// while following a remote source or while steps are inhibited
    /// ([`Router::set_timesync_steps_allowed`]).
    pub fn step_local_network_time_ns(&self, unix_ns: i64) -> bool {
        let Some(t) = crate::timesync::NetworkTime::from_unix_ns(i128::from(unix_ns.max(0))) else {
            return false;
        };
        let steps_before = {
            let Some(runtime) = self.timesync.as_ref() else {
                return false;
            };
            let st = runtime.lock();
            if !st.epoch.steps_allowed {
                return false;
            }
            st.epoch.steps
        };
        if self.try_set_local_network_time(t.into()).is_err() {
            return false;
        }
        let Some(runtime) = self.timesync.as_ref() else {
            return false;
        };
        let now_ms = self.monotonic_now_ms();
        let now_ns = self.monotonic_now_ns();
        let mut st = runtime.lock();
        if Self::timesync_following_remote_locked(&st, now_ms, now_ns) {
            return false;
        }
        // The local setter above already stepped beyond the step threshold;
        // a step to the same reading needs no second epoch.
        if st.epoch.steps != steps_before {
            if let Some(last) = st.epoch.last_step.as_mut() {
                last.reason = TimeSyncStepReason::Explicit;
            }
        } else {
            Self::timesync_local_step_locked(&mut st, now_ns, unix_ns, TimeSyncStepReason::Explicit);
        }
        true
    }

    /// The router's monotonic clock, ns: the timebase of transport stamps
    /// passed to [`Router::note_frame_sent`] and the `_at` receive calls.
    pub fn clock_now_ns(&self) -> u64 {
        self.monotonic_now_ns()
    }

    /// Current network time with nanosecond resolution, when available.
    pub fn network_time_ns(&self) -> Option<i128> {
        let runtime = self.timesync.as_ref()?;
        self.refresh_timesync_state(self.monotonic_now_ms());
        let now_ns = self.monotonic_now_ns();
        runtime.lock().disciplined_clock.read_unix_ns(now_ns)
    }

    /// Receives packed bytes from a side with the transport's receive
    /// instant (router-monotonic ns), e.g. captured in the RX interrupt.
    pub fn rx_packed_from_side_at(
        &self,
        bytes: &[u8],
        side: RouterSideId,
        rx_mono_ns: u64,
    ) -> TelemetryResult<()> {
        self.timesync_set_rx_override(rx_mono_ns);
        let result = self.rx_packed_from_side(bytes, side);
        self.timesync_set_rx_override(0);
        result
    }

    /// Queues packed bytes from a side with the transport's receive instant.
    pub fn rx_packed_queue_from_side_at(
        &self,
        bytes: &[u8],
        side: RouterSideId,
        rx_mono_ns: u64,
    ) -> TelemetryResult<()> {
        self.timesync_set_rx_override(rx_mono_ns);
        let result = self.rx_packed_queue_from_side(bytes, side);
        self.timesync_set_rx_override(0);
        result
    }

    fn timesync_set_rx_override(&self, rx_mono_ns: u64) {
        if let Some(runtime) = self.timesync.as_ref() {
            runtime.lock().v2.rx_override = rx_mono_ns;
        }
    }
}
