//! Interleaved (v2) time sync exchange, transport stamps and clock discipline.
//!
//! The wire format is unchanged: see the v2 notes in `timesync.rs`. Everything
//! here is local bookkeeping keyed by the exchange words (seq, t1) and, for
//! transmit-complete reports, by the transport frame's length and hash.

use super::*;
use crate::timesync::{
    TIMESYNC_UTC_REPORT, encode_utc_report_word,
    TIMESYNC_SEQ_COUNTER_MASK, TIMESYNC_V2_REQUEST, TIMESYNC_V2_RESPONSE, TimeSyncStatus,
    decode_v2_receive_word, decode_v2_transmit_word, encode_v2_receive_word,
    encode_v2_transmit_word,
};
#[cfg(feature = "std")]
use crate::timesync::{UtcReferenceReport, decode_utc_report_word};
use crate::timesync_discipline::{
    ClockDiscipline, SyncState, decode_error_code, encode_error_code, exchange_sample,
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
/// Before first lock a follower steps instead of slewing beyond this error.
const ACQUIRE_STEP_NS: u64 = 50_000_000;
/// Source error assumed for a responder that reports an unknown bound.
const UNKNOWN_SOURCE_ERROR_NS: u64 = 1_000_000_000;

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
    asymmetry_len: u8,
    ever_locked: bool,
    locked: bool,
    stratum: u8,
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
        *self = Self::default();
        self.asymmetry = asymmetry;
        self.asymmetry_len = asymmetry_len;
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
        if seq & TIMESYNC_V2_REQUEST == 0 || seq & TIMESYNC_UTC_REPORT == 0 {
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
        now_mono_ms: u64,
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
        let words = if seq & TIMESYNC_V2_REQUEST != 0 {
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
            (seq | TIMESYNC_V2_RESPONSE, t1, w2, w3)
        } else {
            // Legacy answer: t2 is now the real receive instant; t3 is the
            // build instant (the legacy requester only needs t3 >= t2).
            let t2_ms = (t2_ns / 1_000_000) as u64;
            let t3_ms = net_at(st, now_mono_ns)
                .map(|ns| (ns.max(0) / 1_000_000) as u64)
                .unwrap_or(now_mono_ms)
                .max(t2_ms);
            (seq, t1, t2_ms, t3_ms)
        };
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

    /// Handles a response from the elected source. Returns `true` when the
    /// clock was steered.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn timesync_handle_response_locked(
        st: &mut TimeSyncRuntime,
        sender: &str,
        words: (u64, u64, u64, u64),
        side: Option<RouterSideId>,
        now_mono_ns: u64,
        anchored: bool,
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
        let sample = if seq & TIMESYNC_V2_RESPONSE != 0 {
            let (t2_us, _synced, code) = decode_v2_receive_word(t2);
            let source_error_ns = decode_error_code(code).min(UNKNOWN_SOURCE_ERROR_NS);
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
                exchange_sample(
                    ex.t1_ns,
                    (ex.t2_net_us as i64).saturating_mul(1_000),
                    (t3_us as i64).saturating_mul(1_000),
                    ex.t4_ns,
                    ex.source_error_ns,
                    asymmetry,
                    rate,
                )
            })
        } else {
            // Legacy responder: millisecond stamps of its processing instant.
            let mut ex = st.v2.exchanges[idx];
            ex.response_len = response_len;
            st.v2.exchanges[idx].used = false;
            let asymmetry = st.v2.asymmetry_ns(side, &ex);
            exchange_sample(
                ex.t1_ns,
                (t2 as i64).saturating_mul(1_000_000),
                (t3 as i64).saturating_mul(1_000_000),
                t4_ns,
                1_000_000,
                asymmetry,
                rate,
            )
        };
        let Some(sample) = sample else {
            return false;
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
        Self::timesync_discipline_steer_locked(st, now_mono_ns, anchored);
        true
    }

    fn timesync_discipline_steer_locked(st: &mut TimeSyncRuntime, now_mono_ns: u64, anchored: bool) {
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
        st.disciplined_clock
            .discipline_ns(now_mono_ns, target.net_ns, target.rate_ppb, allow_step);
        st.clock_anchored = anchored;
    }

    /// Quality of this node's network time.
    pub(super) fn timesync_status_locked(
        st: &mut TimeSyncRuntime,
        leader: Option<&TimeSyncLeader>,
        now_mono_ns: u64,
    ) -> TimeSyncStatus {
        let pending = st.disciplined_clock.pending_ns(now_mono_ns);
        let offset_ns = st.disciplined_clock.pending_signed_ns(now_mono_ns);
        let rate_ppb = st.disciplined_clock.rate_ppb();
        let last_sample_age_ms = st
            .v2
            .discipline
            .newest_mono_ns()
            .map_or(u64::MAX, |m| now_mono_ns.saturating_sub(m) / 1_000_000);
        let local_reference = st.v2.local_reference;
        let (state, error_bound_ns, stratum, is_reference) = match leader {
            Some(TimeSyncLeader::Local { .. }) if local_reference => {
                (SyncState::Locked, pending, 0, true)
            }
            Some(TimeSyncLeader::Local { .. }) => {
                let (state, bound) = st.v2.discipline.quality(now_mono_ns, false, pending);
                (state, bound, st.v2.stratum, true)
            }
            Some(TimeSyncLeader::Remote(remote)) => {
                let stratum = remote.quality().stratum.saturating_add(1);
                if st.v2.has_samples_from(&remote.sender) {
                    let (state, bound) = st.v2.discipline.quality(now_mono_ns, true, pending);
                    (state, bound, stratum, false)
                } else if st.disciplined_clock.is_initialized() {
                    (SyncState::Acquiring, u64::MAX, stratum, false)
                } else {
                    (SyncState::Unsynced, u64::MAX, stratum, false)
                }
            }
            None if !st.v2.discipline.is_empty() => {
                let (state, bound) = st.v2.discipline.quality(now_mono_ns, false, pending);
                (state, bound, st.v2.stratum, false)
            }
            None => (SyncState::Unsynced, u64::MAX, 0, false),
        };
        if matches!(leader, Some(TimeSyncLeader::Remote(_))) {
            st.v2.stratum = stratum;
        }
        st.v2.locked = state.is_synced();
        st.v2.ever_locked |= st.v2.locked;
        TimeSyncStatus {
            state,
            stratum,
            error_bound_ns,
            offset_ns,
            rate_ppb,
            last_sample_age_ms,
            is_reference,
        }
    }

    /// Current time sync quality: lock state, error bound, pending offset and
    /// learned frequency. `None` when time sync is not configured.
    pub fn timesync_status(&self) -> Option<TimeSyncStatus> {
        let runtime = self.timesync.as_ref()?;
        let now_ms = self.monotonic_now_ms();
        self.refresh_timesync_state(now_ms);
        let now_ns = self.monotonic_now_ns();
        let mut st = runtime.lock();
        st.cfg?;
        let has_usable_time = Self::timesync_has_usable_time_locked(&st, now_ns);
        let leader = st.tracker.as_ref().and_then(|t| t.leader(now_ms, has_usable_time));
        Some(Self::timesync_status_locked(&mut st, leader.as_ref(), now_ns))
    }

    /// Coarse-sets this node's network time to `unix_ns` at once (a step, not a
    /// slew) while it leads, e.g. when a station without an RTC first learns
    /// UTC. Followers see the step as a new timescale and re-acquire. Returns
    /// `false` (nothing changed) while following a remote source. Callers
    /// must not step once followers are locked during flight.
    pub fn step_local_network_time_ns(&self, unix_ns: i64) -> bool {
        let Some(t) = crate::timesync::NetworkTime::from_unix_ns(i128::from(unix_ns.max(0))) else {
            return false;
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
        let rate = st.disciplined_clock.rate_ppb();
        st.disciplined_clock.discipline_ns(now_ns, unix_ns, rate, true);
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
