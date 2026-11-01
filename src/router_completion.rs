//! Opt-in SDK-owned bookkeeping for asynchronous packed transports.
use super::*;
use std::cell::Cell;
use std::sync::{
    Weak,
    atomic::{AtomicU8, AtomicU64, Ordering},
};
static SERIAL: AtomicU64 = AtomicU64::new(1);
pub(super) fn serial() -> u64 {
    next_serial(&SERIAL)
}
fn next_serial(counter: &AtomicU64) -> u64 {
    let mut n = counter.load(Ordering::SeqCst);
    loop {
        let Some(next) = n.checked_add(1) else {
            return 0;
        };
        match counter.compare_exchange(n, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return n,
            Err(current) => n = current,
        }
    }
}
#[derive(Clone, Copy)]
struct Intent {
    router: u64,
    parent: u64,
    birth: u64,
    retry: bool,
}
thread_local! { static INTENT: Cell<Option<Intent>> = const { Cell::new(None) }; }
pub(super) fn is_retry_intent() -> bool {
    INTENT.get().is_some_and(|i| i.retry)
}
pub(super) struct IntentGuard(Option<Intent>);
impl Drop for IntentGuard {
    fn drop(&mut self) {
        INTENT.set(self.0);
    }
}
/// Independent limits for pending ownership and physically drained history.
#[derive(Clone, Copy, Debug)]
pub struct RetryTrackerLimits {
    pub max_pending: usize,
    pub max_pending_bytes: usize,
    pub history_entries: usize,
    pub history_bytes: usize,
}
impl Default for RetryTrackerLimits {
    fn default() -> Self {
        Self {
            max_pending: 32,
            max_pending_bytes: 2048,
            history_entries: 4,
            history_bytes: 768,
        }
    }
}
struct History {
    parent: u64,
    birth: u64,
    bytes: Arc<[u8]>,
}
struct Ledger {
    fence: u64,
    pending: Vec<Weak<Write>>,
    history: Vec<History>,
}
pub(super) struct TrackerInner {
    router: u64,
    side: AtomicU64,
    limits: RetryTrackerLimits,
    ledger: RouterMutex<Ledger>,
}
/// A side-instance handle. Reset after a known transport or peer generation change.
#[derive(Clone)]
pub struct RetryTracker(Arc<TrackerInner>);
impl PartialEq for RetryTracker {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for RetryTracker {}
impl Debug for RetryTracker {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetryTracker").finish_non_exhaustive()
    }
}
const ADMITTED: u8 = 1;
const STARTED: u8 = 2;
const DRAINED: u8 = 4;
const RETIRED: u8 = 8;
const DISCARDED: u8 = 16;
struct Write {
    bytes: Arc<[u8]>,
    fence: u64,
    parent: u64,
    birth: u64,
    eligible: bool,
    admitted: AtomicU64,
    flags: AtomicU8,
}
/// Opaque ownership of ONE logical transport write. Clones refer to that same
/// write, never another queue owner or physical attempt. Keep it through drain.
#[derive(Clone)]
pub struct PackedWriteLease {
    write: Arc<Write>,
    tracker: Option<Arc<TrackerInner>>,
}
impl Debug for PackedWriteLease {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PackedWriteLease")
            .field("bytes", &self.write.bytes.len())
            .finish_non_exhaustive()
    }
}
/// Decision at the physical IO boundary, after pacing and capacity waits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteStart {
    Ready,
    PendingAdmission,
    Retired,
}
impl RetryTracker {
    pub fn invalidate_generation(&self) -> TelemetryResult<()> {
        let mut l = self.0.ledger.lock();
        l.fence = serial();
        l.history.clear();
        Ok(())
    }
    fn offer(&self, bytes: &[u8]) -> PackedWriteLease {
        // External payload ownership is allocated outside the tracker lock.
        let owned_bytes: Arc<[u8]> = Arc::from(bytes);
        let mut l = self.0.ledger.lock();
        l.pending.retain(|w| w.strong_count() != 0);
        let intent = INTENT.get().filter(|i| {
            i.router == self.0.router && i.birth != 0 && l.fence != 0 && i.birth > l.fence
        });
        let used = l
            .pending
            .iter()
            .filter_map(Weak::upgrade)
            .map(|w| w.bytes.len())
            .sum::<usize>();
        let tracked = intent.filter(|_| {
            l.pending.len() < self.0.limits.max_pending
                && used
                    .checked_add(bytes.len())
                    .is_some_and(|n| n <= self.0.limits.max_pending_bytes)
                && canonical(bytes)
        });
        let eligible = tracked.is_some_and(|i| {
            i.retry
                && l.history.iter().any(|h| {
                    h.parent == i.parent && h.birth == i.birth && h.bytes.as_ref() == bytes
                })
        });
        let w = Arc::new(Write {
            bytes: owned_bytes,
            fence: l.fence,
            parent: tracked.map_or(0, |i| i.parent),
            birth: tracked.map_or(0, |i| i.birth),
            eligible,
            admitted: AtomicU64::new(0),
            flags: AtomicU8::new(0),
        });
        if tracked.is_some() {
            l.pending.push(Arc::downgrade(&w));
        }
        PackedWriteLease {
            write: w,
            tracker: Some(self.0.clone()),
        }
    }
}
impl PackedWriteLease {
    pub fn bytes(&self) -> &[u8] {
        &self.write.bytes
    }
    /// Call at actual external queue admission, before publishing to a worker.
    pub fn admit(&self) -> TelemetryResult<()> {
        if let Some(t) = &self.tracker {
            let _l = t.ledger.lock();
            if self.write.flags.load(Ordering::Acquire) & ADMITTED == 0 {
                self.write.admitted.store(serial(), Ordering::Release);
                self.write.flags.fetch_or(ADMITTED, Ordering::AcqRel);
            }
        } else {
            self.write.flags.fetch_or(ADMITTED, Ordering::AcqRel);
        }
        Ok(())
    }
    pub fn discard_if_retired(&self) -> bool {
        let Some(t) = &self.tracker else { return false };
        let l = t.ledger.lock();
        let f = self.write.flags.load(Ordering::Acquire);
        if f & DISCARDED != 0 {
            return true;
        }
        if l.fence != 0 && l.fence == self.write.fence && f & RETIRED != 0 && f & STARTED == 0 {
            self.write.flags.fetch_or(DISCARDED, Ordering::AcqRel);
            true
        } else {
            false
        }
    }
    pub fn try_start(&self) -> WriteStart {
        let _l = self.tracker.as_ref().map(|t| t.ledger.lock());
        let f = self.write.flags.load(Ordering::Acquire);
        if f & DISCARDED != 0
            || (f & RETIRED != 0
                && f & STARTED == 0
                && _l
                    .as_ref()
                    .is_some_and(|l| l.fence != 0 && l.fence == self.write.fence))
        {
            self.write.flags.fetch_or(DISCARDED, Ordering::AcqRel);
            return WriteStart::Retired;
        }
        if f & ADMITTED == 0 {
            return WriteStart::PendingAdmission;
        }
        self.write.flags.fetch_or(STARTED, Ordering::AcqRel);
        WriteStart::Ready
    }
    /// Atomically start a group belonging to one transport side. A retired
    /// member leaves every not-yet-started member untouched for queue pruning.
    pub fn try_start_batch(leases: &[&Self]) -> TelemetryResult<WriteStart> {
        let Some(first) = leases.first() else {
            return Ok(WriteStart::Ready);
        };
        for (index, lease) in leases.iter().enumerate() {
            if leases[..index]
                .iter()
                .any(|other| Arc::ptr_eq(&other.write, &lease.write))
            {
                return Err(TelemetryError::BadArg);
            }
            match (&first.tracker, &lease.tracker) {
                (Some(a), Some(b)) if Arc::ptr_eq(a, b) => {}
                (None, None) => {}
                _ => return Err(TelemetryError::BadArg),
            }
        }
        let ledger = first.tracker.as_ref().map(|t| t.ledger.lock());
        for lease in leases {
            let flags = lease.write.flags.load(Ordering::Acquire);
            if flags & DISCARDED != 0
                || (flags & RETIRED != 0
                    && flags & STARTED == 0
                    && ledger
                        .as_ref()
                        .is_some_and(|l| l.fence != 0 && l.fence == lease.write.fence))
            {
                return Ok(WriteStart::Retired);
            }
        }
        if leases
            .iter()
            .any(|lease| lease.write.flags.load(Ordering::Acquire) & ADMITTED == 0)
        {
            return Ok(WriteStart::PendingAdmission);
        }
        for lease in leases {
            lease.write.flags.fetch_or(STARTED, Ordering::AcqRel);
        }
        Ok(WriteStart::Ready)
    }
    /// Report only a complete physical write AND drain, never callback success.
    pub fn report_drained(&self) -> TelemetryResult<()> {
        let Some(t) = &self.tracker else {
            return Ok(());
        };
        let mut l = t.ledger.lock();
        let f = self.write.flags.load(Ordering::Acquire);
        if f & STARTED == 0 || f & DISCARDED != 0 {
            return Err(TelemetryError::BadArg);
        }
        if f & DRAINED != 0 {
            return Ok(());
        }
        self.write.flags.fetch_or(DRAINED, Ordering::AcqRel);
        if self.write.birth == 0
            || l.fence == 0
            || l.fence != self.write.fence
            || self.write.bytes.len() > t.limits.history_bytes
            || t.limits.history_entries == 0
        {
            return Ok(());
        }
        while !l.history.is_empty()
            && (l.history.len() >= t.limits.history_entries
                || l.history
                    .iter()
                    .map(|h| h.bytes.len())
                    .sum::<usize>()
                    .saturating_add(self.write.bytes.len())
                    > t.limits.history_bytes)
        {
            l.history.remove(0);
        }
        l.history.push(History {
            parent: self.write.parent,
            birth: self.write.birth,
            bytes: self.write.bytes.clone(),
        });
        Ok(())
    }
}
fn canonical(bytes: &[u8]) -> bool {
    bytes.first().is_some_and(|flags| flags & 0x11 == 0)
        && wire_format::peek_routing_frame_info(bytes).is_ok_and(|f| {
            f.reliable.is_some_and(|h| {
                h.flags == wire_format::RELIABLE_FLAG_UNSEQUENCED && h.seq == 0 && h.ack == 0
            }) && f.envelope.wire_shape.is_some()
                && f.envelope.target_senders().len() != 0
        })
}
fn same_contract(id: u64, data: &RouterItem, bytes: &[u8]) -> bool {
    let Ok(retry) = wire_format::unpack_packet(bytes) else {
        return false;
    };
    let same = |original: &Packet| {
        original.packet_id() == id
            && retry.packet_id() == id
            && original.data_type() == retry.data_type()
            && crate::packet::sender_address_u32(original.sender())
                == crate::packet::sender_address_u32(retry.sender())
            && original.timestamp() == retry.timestamp()
            && original.nonce() == retry.nonce()
            && original.data_size() == retry.data_size()
            && original.payload() == retry.payload()
            && original.wire_shape().is_some()
            && original.wire_shape() == retry.wire_shape()
            && !original.wire_target_senders().is_empty()
            && original.wire_target_senders() == retry.wire_target_senders()
            && wire_format::unique_sorted_endpoints(original.endpoints())
                .eq(wire_format::unique_sorted_endpoints(retry.endpoints()))
    };
    match data {
        RouterItem::Packet(original) => same(original),
        RouterItem::Packed(original) => {
            wire_format::unpack_packet(original.as_ref()).is_ok_and(|packet| same(&packet))
        }
    }
}
impl Router {
    /// Register an opt-in asynchronous side with SDK-owned retry leases.
    /// Existing packed sides allocate no tracker. Leases may remain untracked
    /// when limits, transport encoding, or progress evidence do not permit pruning.
    pub fn add_side_packed_leased_with_priority_and_options<N, F>(
        &self,
        name: N,
        tx: F,
        options: RouterSideOptions,
        limits: RetryTrackerLimits,
    ) -> TelemetryResult<(RouterSideId, RetryTracker)>
    where
        N: AsRef<str>,
        F: Fn(PackedWriteLease, u8) -> TelemetryResult<()> + Send + Sync + 'static,
    {
        let mut registry = self.retry_trackers.lock();
        registry.retain(|t| t.strong_count() != 0);
        let router = registry
            .iter()
            .find_map(Weak::upgrade)
            .map_or_else(serial, |t| t.router);
        let fence = serial();
        let tracker = RetryTracker(Arc::new(TrackerInner {
            router,
            side: AtomicU64::new(u64::MAX),
            limits,
            ledger: RouterMutex::new(Ledger {
                fence,
                pending: Vec::new(),
                history: Vec::new(),
            }),
        }));
        registry.push(Arc::downgrade(&tracker.0));
        drop(registry);
        let callback_tracker = tracker.clone();
        let side = self.add_side_packed_with_priority_and_options(
            name,
            move |bytes, priority| tx(callback_tracker.offer(bytes), priority),
            options,
        );
        tracker.0.side.store(side as u64, Ordering::Release);
        // Publish a final fence after side installation. Parents born while
        // registration was in progress remain conservatively ineligible.
        tracker.invalidate_generation()?;
        Ok((side, tracker))
    }
    #[cfg(feature = "discovery")]
    pub(super) fn retry_birth(&self) -> u64 {
        if self
            .retry_trackers
            .lock()
            .iter()
            .any(|w| w.strong_count() != 0)
        {
            serial()
        } else {
            0
        }
    }
    pub(super) fn retry_queued_intent(&self, claim: Option<TxClaim>) -> IntentGuard {
        let queued = claim.filter(|c| c.side_retry).and_then(|c| {
            let st = self.state.lock();
            let index = st.claim_index(c.token)?;
            let q = st.transmit_queue.get(index)?;
            Some((q.deferred_since_ms, q.disposable & TX_E2E_RETRY != 0))
        });
        self.retry_intent(queued.map(|q| q.0), queued.is_some_and(|q| q.1))
    }
    pub(super) fn retry_intent(&self, parent: Option<u64>, retry: bool) -> IntentGuard {
        let next = parent.and_then(|parent| {
            let birth = self
                .state
                .lock()
                .end_to_end_reliable_tx
                .get(&parent)?
                .completion_epoch;
            let router = self
                .retry_trackers
                .lock()
                .iter()
                .find_map(Weak::upgrade)?
                .router;
            Some(Intent {
                router,
                parent,
                birth,
                retry,
            })
        });
        IntentGuard(INTENT.replace(next))
    }
    pub(super) fn invalidate_retry_side(&self, side: RouterSideId) {
        self.retry_trackers.lock().retain(|weak| {
            let Some(t) = weak.upgrade() else {
                return false;
            };
            if t.side.load(Ordering::Acquire) == side as u64 {
                let _ = RetryTracker(t).invalidate_generation();
                false
            } else {
                true
            }
        });
    }
    pub(super) fn retire_completed_writes(
        &self,
        id: u64,
        completed: &EndToEndReliableSent,
        cutoff: u64,
    ) {
        if cutoff == 0 || completed.completion_epoch == 0 {
            return;
        }
        for t in self.retry_trackers.lock().iter().filter_map(Weak::upgrade) {
            let mut l = t.ledger.lock();
            l.pending.retain(|w| w.strong_count() != 0);
            for w in l.pending.iter().filter_map(Weak::upgrade) {
                let f = w.flags.load(Ordering::Acquire);
                let admission = w.admitted.load(Ordering::Acquire);
                if w.eligible
                    && w.parent == id
                    && w.birth == completed.completion_epoch
                    && l.fence != 0
                    && w.fence == l.fence
                    && admission != 0
                    && admission < cutoff
                    && f & ADMITTED != 0
                    && f & (STARTED | DISCARDED) == 0
                    && same_contract(id, &completed.data, &w.bytes)
                {
                    w.flags.fetch_or(RETIRED, Ordering::AcqRel);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checked_serial_never_wraps_or_reuses_on_exhaustion() {
        let serial = AtomicU64::new(u64::MAX - 1);
        assert_eq!(next_serial(&serial), u64::MAX - 1);
        assert_eq!(next_serial(&serial), 0);
        assert_eq!(next_serial(&serial), 0);
        assert_eq!(serial.load(Ordering::Relaxed), u64::MAX);
    }
    fn tracker(limits: RetryTrackerLimits) -> RetryTracker {
        RetryTracker(Arc::new(TrackerInner {
            router: 1,
            side: AtomicU64::new(0),
            limits,
            ledger: RouterMutex::new(Ledger {
                fence: 1,
                pending: Vec::new(),
                history: Vec::new(),
            }),
        }))
    }
    #[test]
    fn opaque_writes_have_no_pruning_or_drain_history() {
        let tracker = tracker(RetryTrackerLimits::default());
        let lease = tracker.offer(b"not a canonical packet");
        assert_eq!(lease.try_start(), WriteStart::PendingAdmission);
        assert!(lease.report_drained().is_err());
        lease.admit().unwrap();
        assert_eq!(lease.try_start(), WriteStart::Ready);
        lease.report_drained().unwrap();
        lease.report_drained().unwrap();
        assert!(tracker.0.ledger.lock().history.is_empty());
        assert!(tracker.0.ledger.lock().pending.is_empty());
        assert!(!lease.discard_if_retired());
    }
    #[test]
    fn atomic_group_never_starts_prefix_before_retired_or_unadmitted_follower() {
        let tracker = tracker(RetryTrackerLimits::default());
        let first = tracker.offer(b"a");
        let last = tracker.offer(b"b");
        first.admit().unwrap();
        assert_eq!(
            PackedWriteLease::try_start_batch(&[&first, &last]).unwrap(),
            WriteStart::PendingAdmission
        );
        assert_eq!(first.write.flags.load(Ordering::Relaxed) & STARTED, 0);
        last.admit().unwrap();
        last.write.flags.fetch_or(RETIRED, Ordering::Relaxed);
        assert_eq!(
            PackedWriteLease::try_start_batch(&[&first, &last]).unwrap(),
            WriteStart::Retired
        );
        assert_eq!(first.write.flags.load(Ordering::Relaxed) & STARTED, 0);
        tracker.invalidate_generation().unwrap();
        assert_eq!(
            PackedWriteLease::try_start_batch(&[&first, &last]).unwrap(),
            WriteStart::Ready
        );
        assert_ne!(first.write.flags.load(Ordering::Relaxed) & STARTED, 0);
    }
    #[test]
    fn group_rejects_duplicates_and_other_transport_instances() {
        let a = tracker(RetryTrackerLimits::default());
        let b = tracker(RetryTrackerLimits::default());
        let x = a.offer(b"a");
        let y = b.offer(b"b");
        assert!(PackedWriteLease::try_start_batch(&[&x, &x.clone()]).is_err());
        assert!(PackedWriteLease::try_start_batch(&[&x, &y]).is_err());
        assert_eq!(
            PackedWriteLease::try_start_batch(&[]).unwrap(),
            WriteStart::Ready
        );
    }
    #[cfg(feature = "discovery")]
    fn parent(limits: RetryTrackerLimits) -> (Router, RetryTracker, RouterItem, u64) {
        crate::tests::ensure_common_test_schema();
        let router =
            Router::new_with_clock(RouterConfig::new([]).with_sender("GS"), Box::new(|| 0));
        let (_, tracker) = router
            .add_side_packed_leased_with_priority_and_options(
                "radio",
                |_, _| Ok(()),
                RouterSideOptions::default(),
                limits,
            )
            .unwrap();
        let ty = DataType::named("GPS_DATA");
        let packet = Packet::new_with_wire_contract(
            ty,
            &[DataEndpoint::named("RADIO")],
            "GS",
            1,
            1,
            Arc::from([0u8; 12]),
            Some(crate::config::get_message_meta(ty).element),
            vec![Router::sender_hash("FC")].into(),
        )
        .unwrap();
        let id = packet.packet_id();
        let item = RouterItem::Packet(packet);
        router
            .register_end_to_end_reliable_tx(
                &item,
                Some(BTreeMap::from([(Router::sender_hash("FC"), 0)])),
            )
            .unwrap();
        (router, tracker, item, id)
    }
    #[cfg(feature = "discovery")]
    fn offered(
        router: &Router,
        tracker: &RetryTracker,
        item: &RouterItem,
        id: u64,
        retry: bool,
    ) -> PackedWriteLease {
        let _intent = router.retry_intent(Some(id), retry);
        let RouterItem::Packet(packet) = item else {
            panic!("packet fixture")
        };
        tracker.offer(&wire_format::pack_packet(packet))
    }
    #[test]
    #[cfg(feature = "discovery")]
    fn admission_after_final_receipt_cutoff_before_scan_is_retained() {
        let (router, tracker, item, id) = parent(RetryTrackerLimits::default());
        let first = offered(&router, &tracker, &item, id, false);
        first.admit().unwrap();
        assert_eq!(first.try_start(), WriteStart::Ready);
        first.report_drained().unwrap();
        let early = offered(&router, &tracker, &item, id, true);
        early.admit().unwrap();
        let late = offered(&router, &tracker, &item, id, true);
        let cutoff = serial();
        let completed = router
            .state
            .lock()
            .end_to_end_reliable_tx
            .remove(&id)
            .unwrap();
        late.admit().unwrap();
        router.retire_completed_writes(id, &completed, cutoff);
        assert!(early.discard_if_retired());
        assert!(!late.discard_if_retired());
        assert_eq!(late.try_start(), WriteStart::Ready);
    }
    #[test]
    #[cfg(feature = "discovery")]
    fn bounded_pending_drop_releases_once_and_drain_history_is_idempotent() {
        let (router, tracker, item, id) = parent(RetryTrackerLimits {
            max_pending: 1,
            ..Default::default()
        });
        let first = offered(&router, &tracker, &item, id, false);
        let clone = first.clone();
        first.admit().unwrap();
        assert_eq!(first.try_start(), WriteStart::Ready);
        first.report_drained().unwrap();
        first.report_drained().unwrap();
        assert_eq!(tracker.0.ledger.lock().history.len(), 1);
        let blocked = offered(&router, &tracker, &item, id, true);
        assert_eq!(blocked.write.birth, 0);
        drop(blocked);
        drop(first);
        let still_blocked = offered(&router, &tracker, &item, id, true);
        assert_eq!(still_blocked.write.birth, 0);
        drop(still_blocked);
        drop(clone);
        let retry = offered(&router, &tracker, &item, id, true);
        assert_ne!(retry.write.birth, 0);
        assert!(retry.write.eligible);
        assert_eq!(tracker.0.ledger.lock().pending.len(), 1);
    }
    #[test]
    #[cfg(feature = "discovery")]
    fn same_bytes_new_logical_send_and_old_generation_drain_are_not_retry_evidence() {
        let (router, tracker, item, id) = parent(RetryTrackerLimits::default());
        let first = offered(&router, &tracker, &item, id, false);
        first.admit().unwrap();
        assert_eq!(first.try_start(), WriteStart::Ready);
        first.report_drained().unwrap();
        let another_first = offered(&router, &tracker, &item, id, false);
        assert!(!another_first.write.eligible);
        let retry = offered(&router, &tracker, &item, id, true);
        assert!(retry.write.eligible);
        tracker.invalidate_generation().unwrap();
        let late = offered(&router, &tracker, &item, id, true);
        assert_eq!(late.write.birth, 0);
        assert_eq!(retry.try_start(), WriteStart::PendingAdmission);
        retry.admit().unwrap();
        assert_eq!(retry.try_start(), WriteStart::Ready);
        retry.report_drained().unwrap();
        assert!(tracker.0.ledger.lock().history.is_empty());
    }
    #[test]
    #[cfg(feature = "discovery")]
    fn changed_contract_or_encoded_bytes_never_match_completion() {
        let (_router, _tracker, item, id) = parent(RetryTrackerLimits::default());
        let RouterItem::Packet(p) = &item else {
            panic!("packet fixture")
        };
        let changed = Packet::new_with_wire_contract(
            p.data_type(),
            p.endpoints(),
            p.sender(),
            p.timestamp(),
            p.nonce(),
            Arc::from(p.payload()),
            p.wire_shape(),
            vec![Router::sender_hash("OTHER")].into(),
        )
        .unwrap();
        assert_eq!(changed.packet_id(), id);
        assert!(!same_contract(
            id,
            &item,
            &wire_format::pack_packet(&changed)
        ));
        let mut wire = wire_format::pack_packet(p).to_vec();
        assert!(canonical(&wire));
        wire[0] |= 0x11;
        assert!(!canonical(&wire));
        assert!(!same_contract(id, &item, &wire));
    }
}
