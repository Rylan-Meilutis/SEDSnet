//! Opt-in replacement of never-encoded canonical egress samples.
use super::*;
use core::cmp::Ordering;
pub(super) fn managed_turn_item(
    queued: &TxQueued,
    side: Option<RouterSideId>,
    max_frame_bytes: usize,
) -> bool {
    let RouterTxItem::ToSide { dst, data, .. } = &queued.item else {
        return false;
    };
    Some(*dst) == side
        && (matches!(data, RouterItem::Packet(packet)
        if packet.wire_shape().is_none() && packet.wire_target_senders().is_empty()
                && Router::canonical_catalog_stream(packet, max_frame_bytes))
            || queued.disposable & (TX_LATEST_PENDING | TX_LATEST_TURN) != 0)
}

#[derive(Clone)]
enum Endpoints<'a> {
    Packet(core::iter::Copied<core::slice::Iter<'a, DataEndpoint>>),
    Packed(wire_format::RoutingEndpointIter<'a>),
}
impl Iterator for Endpoints<'_> {
    type Item = DataEndpoint;
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Packet(iter) => iter.next(),
            Self::Packed(iter) => iter.next(),
        }
    }
}
enum View<'a> {
    Packet(&'a Packet),
    Packed(wire_format::RoutingFrameInfo<'a>),
}
impl View<'_> {
    fn ty(&self) -> DataType {
        match self {
            Self::Packet(p) => p.data_type(),
            Self::Packed(p) => p.envelope.ty,
        }
    }
    fn source(&self) -> u32 {
        match self {
            Self::Packet(p) => sender_address_u32(p.sender()),
            Self::Packed(p) => p.envelope.source_address,
        }
    }
    fn timestamp(&self) -> u64 {
        match self {
            Self::Packet(p) => p.timestamp(),
            Self::Packed(p) => p.envelope.timestamp_ms,
        }
    }
    fn endpoints(&self) -> Endpoints<'_> {
        match self {
            Self::Packet(p) => Endpoints::Packet(p.endpoints().iter().copied()),
            Self::Packed(p) => Endpoints::Packed(p.envelope.endpoints()),
        }
    }
}
fn with_view<R>(data: &RouterItem, inspect: impl FnOnce(View<'_>) -> R) -> Option<R> {
    match data {
        RouterItem::Packet(packet) => {
            if packet.validate().is_err()
                || packet.wire_shape().is_some()
                || !packet.wire_target_senders().is_empty()
            {
                return None;
            }
            Some(inspect(View::Packet(packet)))
        }
        RouterItem::Packed(bytes) => crate::shared_bytes::with_slice(bytes, |raw| {
            // Compressed/encrypted or contract-bearing owners may already have
            // codec/receipt obligations; they are deliberately never replaceable.
            if raw.first().is_none_or(|flags| flags & 0x15 != 0) {
                return None;
            }
            let frame = wire_format::peek_latest_plain_frame_info(raw).ok()?;
            if frame.envelope.is_reliable || frame.reliable.is_some() {
                return None;
            }
            Some(inspect(View::Packed(frame)))
        })
        .ok()
        .flatten(),
    }
}
fn same_endpoints(a: Endpoints<'_>, b: Endpoints<'_>) -> bool {
    a.clone().count() == b.clone().count()
        && a.clone().all(|endpoint| {
            a.clone().filter(|value| *value == endpoint).count()
                == b.clone().filter(|value| *value == endpoint).count()
        })
}
impl RouterInner {
    pub(super) fn latest_side(&self) -> Option<RouterSideId> {
        let encoded = self.tx_policy_flags >> 1;
        (encoded != 0).then(|| usize::from(encoded - 1))
    }
    pub(super) fn latest_data_eligible(&self, data: &RouterItem, priority: u8) -> bool {
        if priority >= 200 {
            return false;
        }
        with_view(data, |view| {
            let ty = view.ty();
            !is_internal_control_type(ty)
                && ty != DataType::P2pMessage
                && !self.is_managed_variable(ty.as_u32())
                && crate::config::try_get_message_meta(ty).is_some_and(|meta| {
                    meta.reliable == crate::ReliableMode::None
                        && meta.element.message_type() == crate::MessageClass::Data
                        && crate::transport_priority(ty) < 200
                })
        })
        .unwrap_or(false)
    }
    pub(super) fn latest_entry_eligible(&self, item: &TxQueued) -> bool {
        if item.delivery_state != QueuedDelivery::Untracked
            || item.retry_after_ms != 0
            || item.deferred_since_ms != 0
            || !item.ignore_local
        {
            return false;
        }
        let RouterTxItem::ToSide { dst, data, .. } = &item.item else {
            return false;
        };
        self.latest_side() == Some(*dst) && self.latest_data_eligible(data, item.priority)
    }
    pub(super) fn canonical_catalog_owner(&self, queued: &TxQueued) -> bool {
        let RouterTxItem::ToSide {
            dst,
            data: RouterItem::Packet(packet),
            ..
        } = &queued.item
        else {
            return false;
        };
        let Some(side) = self.sides.get(*dst).and_then(Option::as_ref) else {
            return false;
        };
        !side.opts.reliable_enabled
            && side.opts.max_frame_bytes > crate::side_transport::SIDE_TRANSPORT_CHUNK_OVERHEAD
            && matches!(
                side.tx_handler,
                RouterTxHandlerFn::Packed(_) | RouterTxHandlerFn::PackedWithPriority(_)
            )
            && packet.wire_shape().is_none()
            && packet.wire_target_senders().is_empty()
            && Router::canonical_catalog_stream(packet, side.opts.max_frame_bytes)
    }
    fn independently_streaming_catalog(&self, queued: &TxQueued, _now_ms: u64) -> bool {
        self.canonical_catalog_owner(queued)
    }
    pub(super) fn clear_canonical_turn_flags(&mut self) {
        for i in 0..self.transmit_queue.len() {
            self.transmit_queue
                .update_metadata(i, |q| q.disposable &= !(TX_CANONICAL_TURN | TX_LATEST_TURN));
        }
        for side in self.side_transport.values_mut() {
            if let Some(progress) = side.tx_chunk_progress.as_mut() {
                progress.clear_latest_owner();
            }
        }
    }
    pub(super) fn latest_dispatch_tag(&self, queued: &TxQueued) -> u8 {
        let Some(side) = self.latest_side() else {
            return 0;
        };
        if !matches!(&queued.item, RouterTxItem::ToSide { dst, .. } if *dst == side) {
            return 0;
        }
        let kind = match self.latest_turn_phase {
            3 if queued.disposable & TX_CANONICAL_OWED != 0
                && self.canonical_catalog_owner(queued) =>
            {
                1
            }
            4 if queued.disposable & TX_LATEST_TURN != 0 => 2,
            _ => 0,
        };
        if kind == 0 { 0 } else { side as u8 + 1 }
    }
    fn canonical_cursor_available(&self, queued: &TxQueued, now_ms: u64) -> bool {
        let RouterTxItem::ToSide {
            dst,
            data: RouterItem::Packet(packet),
            ..
        } = &queued.item
        else {
            return false;
        };
        let Some(progress) = self
            .side_transport
            .get(dst)
            .and_then(|side| side.tx_chunk_progress.as_ref())
        else {
            return true;
        };
        // Keep one of the existing cursors available for late fragmented
        // reports or protected control. Existing catalog cursors still resume.
        if progress.available_slots(now_ms) >= 2 {
            return true;
        }
        let Some(side) = self.sides.get(*dst).and_then(Option::as_ref) else {
            return false;
        };
        packet.scoped_packet_id().is_ok_and(|id| {
            progress.has_live_key(
                crate::side_transport::canonical_packet_progress_key(id, side.opts.max_frame_bytes),
                now_ms,
            )
        })
    }

    pub(super) fn latest_turn_selection(
        &mut self,
        fresh_allowed: bool,
        now_ms: u64,
    ) -> Option<usize> {
        let side = self.latest_side()?;
        // Callback ownership is still outside the queue; a nested dispatcher
        // cannot transfer its reserved turn to a different owned item.
        if self.latest_turn_phase >= 3 {
            return Some(usize::MAX);
        }
        // A report that has already entered encoding is one immutable history
        // owner, including every remaining fragment after partial admission.
        let owned_latest = self.transmit_queue.iter().position(|q| {
            q.disposable & TX_LATEST_TURN != 0
                && matches!(&q.item, RouterTxItem::ToSide { dst, .. } if *dst == side)
        });
        let latest_capacity_blocked = self
            .side_transport
            .get(&side)
            .and_then(|state| state.tx_chunk_progress.as_ref())
            .is_some_and(|progress| {
                !progress.has_available_slot(now_ms) && !progress.has_live_latest_owner(now_ms)
            });
        if let Some(owner) = owned_latest
            && !latest_capacity_blocked
        {
            return Some(owner);
        }
        // Retain a report waiting for its first cursor while live
        // independent or protected continuations make space available.
        let is_side =
            |q: &TxQueued| matches!(&q.item, RouterTxItem::ToSide { dst, .. } if *dst == side);
        let first = self
            .transmit_queue
            .iter()
            .position(|q| is_side(q) && self.canonical_catalog_owner(q));
        let Some(_first) = first else {
            self.latest_turn_phase = 0;
            self.latest_turn_credit = 0;
            return None;
        };
        if self.latest_turn_credit > 0
            && let Some(fresh) = self
                .transmit_queue
                .iter()
                .enumerate()
                .find_map(|(index, q)| {
                    let RouterTxItem::ToSide { dst, data, .. } = &q.item else {
                        return None;
                    };
                    (Some(index) != owned_latest
                        && *dst == side
                        && self.latest_data_eligible(data, q.priority)
                        && (fresh_allowed || q.disposable & TX_HISTORY_OWNED != 0))
                        .then_some(index)
                })
        {
            return Some(fresh);
        }
        let Some(first_ready) = self.transmit_queue.iter().position(|q| {
            is_side(q)
                && self.canonical_catalog_owner(q)
                && self.canonical_cursor_available(q, now_ms)
        }) else {
            // Every physical cursor belongs to other live work. Keep the new
            // owner queued; controls and non-managed continuations may proceed.
            return Some(usize::MAX);
        };
        let owed = self.transmit_queue.iter().position(|q| {
            is_side(q)
                && self.canonical_catalog_owner(q)
                && q.disposable & TX_CANONICAL_OWED != 0
                && self.canonical_cursor_available(q, now_ms)
        });
        let selected = if let Some(owed) = owed {
            owed
        } else {
            if let Some(index) = self.transmit_queue.iter().position(|q| {
                is_side(q)
                    && self.canonical_catalog_owner(q)
                    && q.disposable & TX_CANONICAL_SERVED == 0
                    && self.canonical_cursor_available(q, now_ms)
            }) {
                index
            } else {
                for i in 0..self.transmit_queue.len() {
                    self.transmit_queue
                        .update_metadata(i, |q| q.disposable &= !TX_CANONICAL_SERVED);
                }
                first_ready
            }
        };
        self.transmit_queue
            .update_metadata(selected, |q| q.disposable |= TX_CANONICAL_OWED);
        self.latest_turn_phase = 1;
        Some(selected)
    }

    // A refused/partial owner must finish before another fresh report can
    // advance this side's encoding history. Controls and other sides bypass it.
    pub(super) fn latest_blocked_side(&self, now_ms: u64) -> Option<RouterSideId> {
        let side = self.latest_side()?;
        let partial = self.side_transport.get(&side).is_some_and(|state| {
            state
                .tx_chunk_progress
                .as_ref()
                .is_some_and(|progress| progress.blocks_latest())
        });
        (partial
            || self.transmit_queue.iter().any(|queued| {
                queued.disposable & TX_HISTORY_OWNED != 0
                    && matches!(&queued.item, RouterTxItem::ToSide { dst, .. } if *dst == side)
                    && !self.independently_streaming_catalog(queued, now_ms)
            }))
        .then_some(side)
    }

    #[inline(never)]
    pub(super) fn replace_latest_pending(
        &mut self,
        incoming: &mut TxQueued,
    ) -> TelemetryResult<bool> {
        if !self.latest_entry_eligible(incoming) {
            return Ok(false);
        }
        let RouterTxItem::ToSide {
            dst,
            data: new_data,
            ..
        } = &incoming.item
        else {
            return Ok(false);
        };
        let found = self
            .transmit_queue
            .iter()
            .enumerate()
            .find_map(|(index, old)| {
                if old.disposable & (TX_DISPOSABLE | TX_LATEST_PENDING)
                    != (TX_DISPOSABLE | TX_LATEST_PENDING)
                    || old.priority != incoming.priority
                    || !self.latest_entry_eligible(old)
                {
                    return None;
                }
                let RouterTxItem::ToSide {
                    dst: old_dst,
                    data: old_data,
                    ..
                } = &old.item
                else {
                    return None;
                };
                if old_dst != dst {
                    return None;
                }
                with_view(new_data, |new_view| {
                    with_view(old_data, |old_view| {
                        (new_view.ty() == old_view.ty()
                            && new_view.source() == old_view.source()
                            && same_endpoints(new_view.endpoints(), old_view.endpoints()))
                        .then(|| (index, new_view.timestamp().cmp(&old_view.timestamp())))
                    })
                    .flatten()
                })
                .flatten()
            });
        let Some((index, order)) = found else {
            return Ok(false);
        };
        if order == Ordering::Less {
            return Ok(true);
        }
        // Fallible parking and both byte-budget checks precede replacement.
        // Failure preserves the old accepted sample and all control owners.
        #[cfg(feature = "compact-packet-store")]
        incoming.park_for_queue()?;
        let old_cost = self
            .transmit_queue
            .get(index)
            .ok_or(TelemetryError::BadArg)?
            .byte_cost();
        let cost = incoming.byte_cost();
        if self
            .shared_queue_bytes_used()
            .saturating_sub(old_cost)
            .saturating_add(cost)
            > self.memory.max_queue_budget
        {
            return Err(TelemetryError::Io("latest sample exceeds shared budget"));
        }
        self.transmit_queue
            .update_admitted(index, cost, |old| core::mem::swap(old, incoming))?;
        Ok(true)
    }
}

impl Router {
    #[inline(never)]
    pub(super) fn queue_latest_egress(
        &self,
        side: RouterSideId,
        src: Option<RouterSideId>,
        data: &RouterItem,
    ) -> TelemetryResult<bool> {
        if self.state.lock().latest_side() != Some(side) {
            return Ok(false);
        }
        self.enqueue_latest_egress(side, src, data)
    }
    #[inline(never)]
    fn enqueue_latest_egress(
        &self,
        side: RouterSideId,
        src: Option<RouterSideId>,
        data: &RouterItem,
    ) -> TelemetryResult<bool> {
        let mut st = self.state.lock();
        if st.latest_side() != Some(side) {
            return Ok(false);
        }
        let priority = Self::router_item_priority(data)?;
        if !st.latest_data_eligible(data, priority) {
            return Ok(false);
        }
        st.push_transmit(TxQueued {
            disposable: TX_DISPOSABLE | TX_LATEST_PENDING,
            item: RouterTxItem::ToSide {
                src,
                dst: side,
                data: data.clone(),
            },
            ignore_local: true,
            priority,
            delivery_state: QueuedDelivery::Untracked,
            accepted_type: 0,
            deferred_since_ms: 0,
            retry_after_ms: 0,
        })?;
        Ok(true)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    fn schema(name: &str, reliable: crate::ReliableMode, priority: u8) -> (DataType, DataEndpoint) {
        let ep = crate::config::register_endpoint(name, false).unwrap();
        let ty = crate::config::register_data_type(
            name,
            MessageElement::Dynamic(crate::MessageDataType::UInt8, crate::MessageClass::Data),
            &[ep],
            reliable,
            priority,
        )
        .unwrap();
        (ty, ep)
    }
    fn packet(ty: DataType, ep: &[DataEndpoint], sender: &str, tick: u64, n: usize) -> RouterItem {
        RouterItem::Packet(
            Packet::new(ty, ep, sender, tick, Arc::from(vec![tick as u8; n])).unwrap(),
        )
    }
    fn queued(side: usize, data: RouterItem) -> TxQueued {
        TxQueued {
            disposable: TX_DISPOSABLE | TX_LATEST_PENDING,
            item: RouterTxItem::ToSide {
                src: None,
                dst: side,
                data,
            },
            ignore_local: true,
            priority: 0,
            delivery_state: QueuedDelivery::Untracked,
            accepted_type: 0,
            deferred_since_ms: 0,
            retry_after_ms: 0,
        }
    }
    fn setup() -> (Router, usize) {
        let router =
            Router::new_with_clock(RouterConfig::new([]).with_sender("GS"), Box::new(|| 0));
        let side = router.add_side_packed("radio", |_| Ok(()));
        router.clear_tx_queue();
        (router, side)
    }
    fn ticks(st: &RouterInner) -> Vec<u64> {
        st.transmit_queue
            .iter()
            .map(|q| {
                let RouterTxItem::ToSide { data, .. } = &q.item else {
                    panic!("side owner")
                };
                with_view(data, |v| v.timestamp()).unwrap()
            })
            .collect()
    }
    #[test]
    fn disabled_is_lossless_enabled_keeps_newest_in_same_fifo_slot() {
        let (ty, ep) = schema("LATEST_FIFO", crate::ReliableMode::None, 0);
        let (router, side) = setup();
        {
            let mut st = router.state.lock();
            for tick in 1..=3 {
                st.push_transmit(queued(side, packet(ty, &[ep], "GS", tick, 1)))
                    .unwrap();
            }
            assert_eq!(ticks(&st), [1, 2, 3]);
        }
        router.clear_tx_queue();
        router.set_latest_value_side(Some(side)).unwrap();
        let mut st = router.state.lock();
        st.push_transmit(queued(side, packet(ty, &[ep], "GS", 10, 1)))
            .unwrap();
        st.push_transmit(queued(side, packet(ty, &[ep], "VALVE", 11, 1)))
            .unwrap();
        for tick in 12..=100 {
            st.push_transmit(queued(side, packet(ty, &[ep], "GS", tick, 1)))
                .unwrap();
        }
        assert_eq!(
            ticks(&st),
            [100, 11],
            "replacement retains FIFO turn beside another flow"
        );
        st.push_transmit(queued(side, packet(ty, &[ep], "GS", 99, 1)))
            .unwrap();
        assert_eq!(
            ticks(&st),
            [100, 11],
            "stale arrivals do not replace newer timestamp"
        );
        let before = st.transmit_queue.bytes_used();
        st.push_transmit(queued(side, packet(ty, &[ep], "GS", 100, 2)))
            .unwrap();
        assert!(st.transmit_queue.bytes_used() >= before);
        assert_eq!(st.transmit_queue.len(), 2);
    }
    #[test]
    fn flow_is_source_type_and_endpoint_multiset_and_selected_side_only() {
        let (ty, ep) = schema("LATEST_FLOW", crate::ReliableMode::None, 0);
        let (other, ep2) = schema("LATEST_FLOW_OTHER", crate::ReliableMode::None, 0);
        let (router, side) = setup();
        let sd = router.add_side_packed("sd", |_| Ok(()));
        router.clear_tx_queue();
        router.set_latest_value_side(Some(side)).unwrap();
        let mut st = router.state.lock();
        for (dst, ty, eps, sender, tick) in [
            (side, ty, vec![ep, ep2], "GS", 1),
            (side, ty, vec![ep2, ep], "GS", 2),
            (side, ty, vec![ep], "GS", 3),
            (side, other, vec![ep2], "GS", 4),
            (side, ty, vec![ep], "VALVE", 5),
            (sd, ty, vec![ep], "GS", 6),
            (sd, ty, vec![ep], "GS", 7),
        ] {
            st.push_transmit(queued(dst, packet(ty, &eps, sender, tick, 1)))
                .unwrap();
        }
        assert_eq!(ticks(&st), [2, 3, 4, 5, 6, 7]);
    }
    #[test]
    fn attempted_retry_partial_and_priority_owners_are_never_replaced() {
        let (ty, ep) = schema("LATEST_ATTEMPT", crate::ReliableMode::None, 0);
        let (router, side) = setup();
        router.set_latest_value_side(Some(side)).unwrap();
        let mut st = router.state.lock();
        st.push_transmit(queued(side, packet(ty, &[ep], "GS", 1, 1)))
            .unwrap();
        let work = Router::pop_transmit_queue_locked(&mut st, 0, false).unwrap();
        assert_eq!(work.queued.disposable & TX_LATEST_PENDING, 0);
        st.push_transmit(work.queued).unwrap(); // even immediate callback refusal protects history
        st.push_transmit(queued(side, packet(ty, &[ep], "GS", 2, 1)))
            .unwrap();
        st.push_transmit(queued(side, packet(ty, &[ep], "GS", 3, 1)))
            .unwrap();
        assert_eq!(ticks(&st), [1, 3]);
        st.side_transport.get_mut(&side).unwrap().tx_chunk_progress = Some(Box::default());
        let progress = st
            .side_transport
            .get_mut(&side)
            .unwrap()
            .tx_chunk_progress
            .as_mut()
            .unwrap();
        progress.begin(123, 0, true).unwrap();
        progress.finish(123, 1, 0, &Err::<(), _>(TelemetryError::Io("side tx busy")));
        st.push_transmit(queued(side, packet(ty, &[ep], "GS", 4, 1)))
            .unwrap();
        assert_eq!(ticks(&st), [1, 4]);
        st.side_transport
            .get_mut(&side)
            .unwrap()
            .tx_chunk_progress
            .as_mut()
            .unwrap()
            .finish(123, 2, 0, &Ok(()));
        st.push_transmit(queued(side, packet(ty, &[ep], "GS", 5, 1)))
            .unwrap();
        assert_eq!(
            ticks(&st),
            [1, 5],
            "partial cursor owner stays protected while never-attempted pending values coalesce"
        );
        let mut high = queued(side, packet(ty, &[ep], "GS", 6, 1));
        high.priority = 200;
        st.push_transmit(high.clone()).unwrap();
        st.push_transmit(high).unwrap();
        assert_eq!(st.transmit_queue.len(), 4);
    }
    #[test]
    fn queue_budget_failure_never_evicts_the_previously_accepted_sample() {
        let (ty, ep) = schema("LATEST_QUEUE_FIT", crate::ReliableMode::None, 0);
        let (router, side) = setup();
        router.set_latest_value_side(Some(side)).unwrap();
        let mut st = router.state.lock();
        st.transmit_queue = BoundedDeque::new(256, 256, 1.0);
        st.push_transmit(queued(side, packet(ty, &[ep], "GS", 1, 1)))
            .unwrap();
        let before = st.transmit_queue.bytes_used();
        assert!(
            st.push_transmit(queued(side, packet(ty, &[ep], "GS", 2, 512)))
                .is_err()
        );
        assert_eq!(ticks(&st), [1]);
        assert_eq!(st.transmit_queue.bytes_used(), before);
    }
    #[cfg(feature = "discovery")]
    #[test]
    fn discovery_ack_and_ordered_schema_never_enter_latest_policy() {
        let (ordered, ep) = schema("LATEST_ORDERED", crate::ReliableMode::Ordered, 0);
        let (ty, _) = schema("LATEST_ACK", crate::ReliableMode::None, 0);
        let (router, side) = setup();
        router.set_latest_value_side(Some(side)).unwrap();
        let st = router.state.lock();
        assert!(!st.latest_data_eligible(&packet(ordered, &[ep], "GS", 1, 1), 0));
        let discovery = crate::discovery::build_discovery_schema_request("GS", 0).unwrap();
        assert!(!st.latest_data_eligible(&RouterItem::Packet(discovery), 0));
        let ack = wire_format::pack_reliable_ack("GS", ty, 0, 1);
        assert!(
            !st.latest_data_eligible(&RouterItem::Packed(crate::shared_bytes::convert(ack)), 0)
        );
    }
    #[test]
    fn shared_budget_failure_retains_old_sample_and_exact_accounting() {
        let (ty, ep) = schema("LATEST_FIT", crate::ReliableMode::None, 0);
        let (router, side) = setup();
        router.set_latest_value_side(Some(side)).unwrap();
        let mut st = router.state.lock();
        st.push_transmit(queued(side, packet(ty, &[ep], "GS", 1, 1)))
            .unwrap();
        let old_bytes = st.transmit_queue.bytes_used();
        let old_shared = st.shared_queue_bytes_used();
        st.memory.max_queue_budget = old_shared;
        assert!(
            st.push_transmit(queued(side, packet(ty, &[ep], "GS", 2, 512)))
                .is_err()
        );
        assert_eq!(ticks(&st), [1]);
        assert_eq!(st.transmit_queue.bytes_used(), old_bytes);
        assert_eq!(st.shared_queue_bytes_used(), old_shared);
    }
    #[test]
    fn reliable_managed_frozen_and_internal_owners_are_excluded() {
        let (ty, ep) = schema("LATEST_GUARD", crate::ReliableMode::None, 0);
        let (reliable, rep) = schema("LATEST_RELIABLE", crate::ReliableMode::Unordered, 0);
        let (router, side) = setup();
        router.set_latest_value_side(Some(side)).unwrap();
        let data = packet(ty, &[ep], "GS", 1, 1);
        {
            let st = router.state.lock();
            assert!(st.latest_data_eligible(&data, 0));
            assert!(!st.latest_data_eligible(&packet(reliable, &[rep], "GS", 1, 1), 0));
            let RouterItem::Packet(p) = &data else {
                unreachable!()
            };
            let frozen = wire_format::pack_packet_with_wire_contract(
                p,
                None,
                Some(MessageElement::Dynamic(
                    crate::MessageDataType::UInt8,
                    crate::MessageClass::Data,
                )),
                &[],
            )
            .unwrap();
            assert!(!st.latest_data_eligible(
                &RouterItem::Packed(crate::shared_bytes::convert(frozen)),
                0
            ));
            let mut broken = wire_format::pack_packet(p).to_vec();
            broken[0] |= 0x10;
            assert!(!st.latest_data_eligible(
                &RouterItem::Packed(crate::shared_bytes::convert(Arc::<[u8]>::from(broken))),
                0
            ));
        }
        router.enable_managed_variable(ty).unwrap();
        assert!(!router.state.lock().latest_data_eligible(&data, 0));
        assert!(!router.state.lock().latest_data_eligible(&data, 255));
    }
    #[test]
    fn actual_transport_refusal_keeps_attempted_owner_beside_newest_pending() {
        use std::sync::{
            Mutex,
            atomic::{AtomicBool, AtomicU64, Ordering},
        };
        let (ty, ep) = schema("LATEST_REFUSAL", crate::ReliableMode::None, 0);
        let now = Arc::new(AtomicU64::new(0));
        let clock = now.clone();
        let router = Router::new_with_clock(
            RouterConfig::new([]).with_sender("GS"),
            Box::new(move || clock.load(Ordering::SeqCst)),
        );
        let denied = Arc::new(AtomicBool::new(true));
        let refuse = denied.clone();
        let received = Arc::new(Mutex::new(Vec::new()));
        let output = received.clone();
        let side = router.add_side_packed("radio", move |raw| {
            if refuse.load(Ordering::SeqCst) {
                return Err(TelemetryError::Io("side tx busy"));
            }
            if let Ok(p) = wire_format::unpack_packet(raw)
                && p.data_type() == ty
            {
                output.lock().unwrap().push(p.timestamp());
            }
            Ok(())
        });
        router.clear_tx_queue();
        router.set_latest_value_side(Some(side)).unwrap();
        router
            .queue_latest_egress(side, None, &packet(ty, &[ep], "GS", 1, 1))
            .unwrap();
        // One callback attempt creates an ordinary protected retry owner.
        let work = Router::pop_transmit_queue_locked(&mut router.state.lock(), 0, false).unwrap();
        router.dispatch_queued_item(work).unwrap();
        for tick in 2..=10 {
            router
                .queue_latest_egress(side, None, &packet(ty, &[ep], "GS", tick, 1))
                .unwrap();
        }
        assert_eq!(ticks(&router.state.lock()), [1, 10]);
        denied.store(false, Ordering::SeqCst);
        now.store(2, Ordering::SeqCst);
        router.dispatch_tx_queue_with_timeout(0).unwrap();
        assert_eq!(
            *received.lock().unwrap(),
            [1, 10],
            "refused encoded history remains deliverable"
        );
    }
    #[test]
    fn partial_sdt_owner_resumes_exactly_while_pending_coalesces_and_control_passes() {
        use std::sync::{
            Mutex,
            atomic::{AtomicU64, AtomicUsize, Ordering},
        };
        let (ty, ep) = schema("LATEST_PARTIAL_SDT", crate::ReliableMode::None, 0);
        let (command, command_ep) =
            schema("LATEST_PARTIAL_CONTROL", crate::ReliableMode::None, 255);
        let now = Arc::new(AtomicU64::new(0));
        let clock = now.clone();
        let router = Router::new_with_clock(
            RouterConfig::new([]).with_sender("GS"),
            Box::new(move || clock.load(Ordering::SeqCst)),
        );
        let allowance = Arc::new(AtomicUsize::new(1));
        let credit = allowance.clone();
        let attempts = Arc::new(AtomicUsize::new(0));
        let count = attempts.clone();
        let accepted = Arc::new(Mutex::new(Vec::<Arc<[u8]>>::new()));
        let frames = accepted.clone();
        let options = RouterSideOptions::default().with_small_packet_transport(64);
        let side = router.add_side_packed_with_priority_and_options(
            "radio",
            move |raw, priority| {
                if priority < 200 {
                    count.fetch_add(1, Ordering::SeqCst);
                    if credit
                        .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                        .is_err()
                    {
                        return Err(TelemetryError::Io("side tx busy"));
                    }
                }
                frames.lock().unwrap().push(Arc::from(raw));
                Ok(())
            },
            options.clone(),
        );
        let large = |tick| {
            let mut seed = 0x12345678u32;
            let payload = (0..512)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    seed as u8
                })
                .collect::<Vec<_>>();
            RouterItem::Packet(Packet::new(ty, &[ep], "GS", tick, Arc::from(payload)).unwrap())
        };
        router.clear_tx_queue();
        router.set_latest_value_side(Some(side)).unwrap();
        router.queue_latest_egress(side, None, &large(0)).unwrap();
        router.dispatch_tx_queue_with_timeout(0).unwrap();
        assert_eq!(accepted.lock().unwrap().len(), 1);
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(accepted.lock().unwrap()[0][3], SIDE_TRANSPORT_KIND_CHUNK);
        assert!(
            !router
                .state
                .lock()
                .side_transport
                .get(&side)
                .unwrap()
                .tx_chunk_progress
                .as_ref()
                .unwrap()
                .is_idle()
        );
        for tick in 1..=20 {
            router
                .queue_latest_egress(side, None, &large(tick))
                .unwrap();
            router.dispatch_tx_queue_with_timeout(0).unwrap();
            assert_eq!(router.state.lock().transmit_queue.len(), 2);
        }
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            2,
            "no fresh history encoded behind a partial owner"
        );
        router
            .tx_item_impl(
                RouterTxItem::ToSide {
                    src: None,
                    dst: side,
                    data: packet(command, &[command_ep], "GS", 30, 1),
                },
                true,
                false,
            )
            .unwrap();
        assert!(
            accepted.lock().unwrap().len() > 1,
            "protected control passes a blocked data prefix"
        );
        allowance.store(1000, Ordering::SeqCst);
        now.store(2, Ordering::SeqCst);
        router.dispatch_tx_queue_with_timeout(0).unwrap();
        assert_eq!(router.state.lock().transmit_queue.len(), 0);
        let received = Arc::new(Mutex::new(Vec::new()));
        let samples = received.clone();
        let handler = EndpointHandler::new_packet_handler(ep, move |p| {
            samples
                .lock()
                .unwrap()
                .push((p.timestamp(), p.payload().to_vec()));
            Ok(())
        });
        let receiver = Router::new_with_clock(
            RouterConfig::new([handler]).with_sender("RECEIVER"),
            Box::new(|| 2),
        );
        let incoming = receiver.add_side_packed_with_options("radio", |_| Ok(()), options);
        for frame in accepted.lock().unwrap().iter() {
            receiver.rx_packed_from_side(frame, incoming).unwrap();
        }
        let values = received.lock().unwrap();
        assert_eq!(
            values.iter().map(|(tick, _)| *tick).collect::<Vec<_>>(),
            [0, 20]
        );
        let RouterItem::Packet(expected) = large(0) else {
            unreachable!()
        };
        assert!(
            values
                .iter()
                .all(|(_, payload)| payload.as_slice() == expected.payload())
        );
    }
    #[test]
    #[cfg(feature = "discovery")]
    fn canonical_catalog_chunks_do_not_block_independent_latest_reports() {
        use std::sync::{
            Mutex,
            atomic::{AtomicU64, AtomicUsize, Ordering},
        };
        let (ty, ep) = schema("LATEST_CANONICAL_CATALOG", crate::ReliableMode::None, 0);
        let now = Arc::new(AtomicU64::new(0));
        let clock = now.clone();
        let router = Router::new_with_clock(
            RouterConfig::new([]).with_sender("RF"),
            Box::new(move || clock.load(Ordering::SeqCst)),
        );
        let allowance = Arc::new(AtomicUsize::new(1));
        let credit = allowance.clone();
        let captured = Arc::new(Mutex::new(Vec::<Arc<[u8]>>::new()));
        let frames = captured.clone();
        let options = RouterSideOptions::default().with_small_packet_transport(192);
        let side = router.add_side_packed_with_options(
            "radio",
            move |raw| {
                if raw.starts_with(crate::side_transport::SIDE_TRANSPORT_MAGIC)
                    && raw.get(3) == Some(&SIDE_TRANSPORT_KIND_CHUNK)
                    && credit
                        .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                        .is_err()
                {
                    return Err(TelemetryError::Io("side tx busy"));
                }
                frames.lock().unwrap().push(Arc::from(raw));
                Ok(())
            },
            options.clone(),
        );
        router.clear_tx_queue();
        router.set_latest_value_side(Some(side)).unwrap();
        let catalog = crate::discovery::build_discovery_schema("RF", 0).unwrap();
        assert!(catalog.payload().len() > 192);
        let expected_catalog = catalog.payload().to_vec();
        router
            .emit_internal_tx(
                RouterTxItem::ToSide {
                    src: None,
                    dst: side,
                    data: RouterItem::Packet(catalog),
                },
                true,
                true,
            )
            .unwrap();
        router.dispatch_tx_queue_with_timeout(0).unwrap();
        assert_eq!(captured.lock().unwrap().len(), 1);
        assert!(
            !router.state.lock().side_transport[&side]
                .tx_chunk_progress
                .as_ref()
                .unwrap()
                .is_idle()
        );
        now.store(2, Ordering::SeqCst);
        router
            .queue_latest_egress(side, None, &packet(ty, &[ep], "FC", 2, 1))
            .unwrap();
        for tick in 2..=10 {
            now.store(tick, Ordering::SeqCst);
            match router.dispatch_tx_queue_with_timeout(0) {
                Ok(()) | Err(TelemetryError::HandlerError(_)) => {}
                Err(error) => panic!("unexpected dispatch error: {error:?}"),
            }
        }
        assert!(
            captured.lock().unwrap().len() > 1,
            "a canonical catalog owns no TX dictionary history; independent reports must pass before its remaining chunks"
        );
        // Complete the exact retained transfer, then prove both original owners
        // decode in one real receiver despite report/chunk interleaving.
        allowance.store(1000, Ordering::SeqCst);
        now.store(12, Ordering::SeqCst);
        // Busy retry retains and resumes the exact original canonical owner.
        router.dispatch_tx_queue_with_timeout(0).unwrap();
        assert_eq!(router.state.lock().transmit_queue.len(), 0);
        let receiver =
            Router::new_with_clock(RouterConfig::new([]).with_sender("GS"), Box::new(|| 12));
        let input = receiver.add_side_packed_with_options("radio", |_| Ok(()), options);
        let mut catalogs = Vec::new();
        let mut reports = Vec::new();
        for frame in captured.lock().unwrap().iter() {
            if let Some(canonical) = receiver.decode_side_transport_frame(input, frame).unwrap() {
                let packet = wire_format::unpack_packet(&canonical).unwrap();
                if packet.data_type() == DataType::DiscoverySchema {
                    catalogs.push(packet.payload().to_vec());
                }
                if packet.data_type() == ty {
                    reports.push((packet.timestamp(), packet.payload().to_vec()));
                }
            }
        }
        assert_eq!(catalogs, [expected_catalog]);
        assert_eq!(reports, [(2, vec![2])]);
    }
    #[test]
    #[cfg(feature = "discovery")]
    fn schema_service_keeps_two_five_hz_flows_fresh_under_finite_capacity() {
        use std::sync::{
            Mutex,
            atomic::{AtomicU64, AtomicUsize, Ordering},
        };
        let flows = [
            schema("LATEST_CATALOG_FLOW_A", crate::ReliableMode::None, 0),
            schema("LATEST_CATALOG_FLOW_B", crate::ReliableMode::None, 0),
        ];
        let now = Arc::new(AtomicU64::new(0));
        let time = now.clone();
        let router = Router::new_with_clock(
            RouterConfig::new([]).with_sender("RF"),
            Box::new(move || time.load(Ordering::SeqCst)),
        );
        // Finite synthetic transport: at most320B per200ms, no unused credit
        // carried forward. This is an SDK service proof, not an RFD profile.
        let allowance = Arc::new(AtomicUsize::new(320));
        let credit = allowance.clone();
        let accepted = Arc::new(Mutex::new(Vec::<Arc<[u8]>>::new()));
        let output = accepted.clone();
        let options = RouterSideOptions::default().with_small_packet_transport(192);
        let side = router.add_side_packed_with_options(
            "finite-radio",
            move |raw| {
                credit
                    .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                        n.checked_sub(raw.len())
                    })
                    .map_err(|_| TelemetryError::Io("side tx busy"))?;
                output.lock().unwrap().push(Arc::from(raw));
                Ok(())
            },
            options.clone(),
        );
        router.clear_tx_queue();
        router.set_latest_value_side(Some(side)).unwrap();
        let request = crate::discovery::build_discovery_schema_request("GS", 0).unwrap();
        router
            .learn_discovery_packet(&request, Some(side), true)
            .unwrap();
        // Freeze the real service's one admitted catalog snapshot. Never inject
        // or replace its owner; production poll/dispatch must retain and finish it.
        let expected = {
            let st = router.state.lock();
            st.transmit_queue
                .iter()
                .find_map(|q| match &q.item {
                    RouterTxItem::ToSide {
                        data: RouterItem::Packet(p),
                        ..
                    } if p.data_type() == DataType::DiscoverySchema => {
                        Some((p.packet_id(), p.payload().to_vec()))
                    }
                    _ => None,
                })
                .expect("real schema request admitted a catalog")
        };
        assert!(expected.1.len() > 192);
        let duration = ((expected.1.len().div_ceil(176) as u64) * 200 + 4000).max(8000);
        assert!(
            duration <= 120000,
            "fixture catalog exceeds bounded native scene"
        );
        let time = now.clone();
        let receiver = Router::new_with_clock(
            RouterConfig::new([]).with_sender("GS"),
            Box::new(move || time.load(Ordering::SeqCst)),
        );
        let input = receiver.add_side_packed_with_options("radio", |_| Ok(()), options);
        let mut reports = [Vec::<(u64, u64)>::new(), Vec::new()];
        let mut catalogs = Vec::new();
        for ms in 0..=duration {
            now.store(ms, Ordering::SeqCst);
            if ms % 200 == 0 {
                allowance.store(320, Ordering::SeqCst);
                for (index, &(ty, ep)) in flows.iter().enumerate() {
                    router
                        .queue_latest_egress(
                            side,
                            None,
                            &packet(ty, &[ep], "FC", ms, [24, 12][index]),
                        )
                        .unwrap();
                }
            }
            router.poll_schema_response_on_side(side).unwrap();
            match router.dispatch_tx_queue_with_timeout(0) {
                Ok(()) | Err(TelemetryError::HandlerError(_)) => {}
                Err(error) => panic!("unexpected finite transport error: {error:?}"),
            }
            for raw in core::mem::take(&mut *accepted.lock().unwrap()) {
                if let Some(canonical) = receiver.decode_side_transport_frame(input, &raw).unwrap()
                {
                    let p = wire_format::unpack_packet(&canonical).unwrap();
                    if p.data_type() == DataType::DiscoverySchema {
                        crate::discovery::decode_discovery_schema(&p).unwrap();
                        catalogs.push((p.packet_id(), p.payload().to_vec()));
                    }
                    for (n, &(ty, _)) in flows.iter().enumerate() {
                        if p.data_type() == ty {
                            assert_eq!(p.payload(), vec![p.timestamp() as u8; [24, 12][n]]);
                            assert!(
                                ms - p.timestamp() <= 500,
                                "fresh report waited{}ms",
                                ms - p.timestamp()
                            );
                            reports[n].push((p.timestamp(), ms));
                        }
                    }
                }
            }
        }
        assert_eq!(
            catalogs,
            [expected],
            "the actual service must finish the single original catalog"
        );
        let state = router.state.lock();
        let throttle = &state.discovery_side_throttle[&side];
        assert!(!throttle.schema_response_active() && !throttle.schema_response_pending());
        for flow in reports {
            assert!(
                flow.first().expect("flow delivered a report").1 <= 400,
                "startup schema suppressed the first five-Hz report until {:?}",
                flow.first()
            );
            let steady = flow
                .iter()
                .filter(|(source, _)| *source >= 1000)
                .collect::<Vec<_>>();
            assert!(
                steady.len() as u64 >= (duration - 1000) / 200 - 1,
                "five-Hz report cadence lost during catalog"
            );
            assert!(
                steady.windows(2).all(|w| w[1].1 - w[0].1 <= 400),
                "unbounded report gap"
            );
        }
    }
    #[test]
    #[cfg(feature = "discovery")]
    fn canonical_stream_proof_retains_unknown_and_stateful_first_refusals() {
        let (router, side) = setup();
        router.set_latest_value_side(Some(side)).unwrap();
        let catalog = crate::discovery::build_discovery_schema("RF", 0).unwrap();
        assert!(catalog.payload().len() > 192);
        let key = crate::side_transport::canonical_packet_progress_key(catalog.packet_id(), 192);
        let mut owner = queued(side, RouterItem::Packet(catalog.clone()));
        owner.disposable = TX_HISTORY_OWNED;
        let mut state = router.state.lock();
        state.sides[side].as_mut().unwrap().opts =
            RouterSideOptions::default().with_small_packet_transport(192);
        state.push_transmit(owner).unwrap();
        assert!(
            state.independently_streaming_catalog(state.transmit_queue.get(0).unwrap(), 0),
            "the actual canonical streaming branch has no history even at its first refusal"
        );
        assert_eq!(state.latest_blocked_side(0), None);
        let mut progress = crate::side_transport::SideTxProgress::default();
        progress.begin(key ^ 1, 0, true).unwrap();
        progress.finish(
            key ^ 1,
            1,
            0,
            &Err::<(), _>(TelemetryError::Io("side tx busy")),
        );
        state
            .side_transport
            .get_mut(&side)
            .unwrap()
            .tx_chunk_progress = Some(Box::new(progress));
        assert_eq!(
            state.latest_blocked_side(0),
            Some(side),
            "no independent catalog can erase ANY outstanding stateful history"
        );
        state
            .side_transport
            .get_mut(&side)
            .unwrap()
            .tx_chunk_progress = None;
        state.sides[side].as_mut().unwrap().opts.reliable_enabled = true;
        assert!(
            !state.independently_streaming_catalog(state.transmit_queue.get(0).unwrap(), 0),
            "hop sequencing can transform the Packet before its callback"
        );
        assert_eq!(state.latest_blocked_side(0), Some(side));
        state.sides[side].as_mut().unwrap().opts.reliable_enabled = false;
        state.retain_transmit(|_| false);
        let mut packed = queued(
            side,
            RouterItem::Packed(crate::shared_bytes::convert(wire_format::pack_packet(
                &catalog,
            ))),
        );
        packed.disposable = TX_HISTORY_OWNED | TX_CANONICAL_OWED | TX_CANONICAL_SERVED;
        state.push_transmit(packed).unwrap();
        assert!(
            !state.independently_streaming_catalog(state.transmit_queue.get(0).unwrap(), 2001),
            "a type peek cannot exempt Packed canonical or wrapped SDT owners"
        );
        assert_eq!(state.latest_blocked_side(2001), Some(side));
        assert_eq!(
            state.transmit_queue.get(0).unwrap().disposable & TX_CANONICAL_TURN,
            0,
            "representation conversion invalidates only its private turn flags"
        );
        assert!(RouterInner::transmit_eviction_candidate(&state.transmit_queue).is_none());
    }
    #[test]
    fn fair_and_priority_pressure_never_evict_opt_in_encoded_history() {
        let (ty, ep) = schema("LATEST_HISTORY_EVICT", crate::ReliableMode::None, 0);
        let (router, side) = setup();
        router.set_latest_value_side(Some(side)).unwrap();
        let mut st = router.state.lock();
        st.transmit_queue = BoundedDeque::new(512, 512, 1.0);
        st.push_transmit(queued(side, packet(ty, &[ep], "GS", 0, 1)))
            .unwrap();
        let work = Router::pop_transmit_queue_locked(&mut st, 0, false).unwrap();
        assert_eq!(work.queued.disposable, TX_HISTORY_OWNED);
        let mut retry = work.queued;
        retry.retry_after_ms = 1;
        st.push_transmit(retry).unwrap();
        assert!(RouterInner::tx_bulk_owner(st.transmit_queue.get(0).unwrap()).is_none());
        for tick in 1..=40 {
            let _ = st.push_transmit(queued(
                side,
                packet(ty, &[ep], &format!("FLOOD_{tick}"), tick, 1),
            ));
            assert!(
                st.transmit_queue
                    .iter()
                    .any(|q| q.disposable == TX_HISTORY_OWNED)
            );
        }
        // Priority admission may reclaim disposable freshness samples, never history.
        let mut control = queued(side, packet(ty, &[ep], "CONTROL", 100, 1));
        control.priority = 255;
        st.push_transmit(control).unwrap();
        assert!(
            st.transmit_queue
                .iter()
                .any(|q| q.disposable == TX_HISTORY_OWNED)
        );
        assert!(st.transmit_queue.bytes_used() <= 512);
        st.memory.max_queue_budget = st.shared_queue_bytes_used();
        let _ = st.push_transmit(queued(side, packet(ty, &[ep], "NEW", 101, 128)));
        assert!(
            st.transmit_queue
                .iter()
                .any(|q| q.disposable == TX_HISTORY_OWNED)
        );
        assert!(st.shared_queue_bytes_used() <= st.memory.max_queue_budget);
    }
    fn repeated_refusal(interval: u64) {
        use std::sync::{
            Mutex,
            atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        };
        let (ty, ep) = schema(
            if interval == 0 {
                "LATEST_BUSY_SUBMS"
            } else {
                "LATEST_BUSY_1MS"
            },
            crate::ReliableMode::None,
            0,
        );
        let (_, remote) = schema(
            if interval == 0 {
                "LATEST_BUSY_REMOTE0"
            } else {
                "LATEST_BUSY_REMOTE1"
            },
            crate::ReliableMode::None,
            0,
        );
        let (command, command_ep) = schema(
            if interval == 0 {
                "LATEST_COMMAND0"
            } else {
                "LATEST_COMMAND1"
            },
            crate::ReliableMode::None,
            255,
        );
        let now = Arc::new(AtomicU64::new(0));
        let clock = now.clone();
        let sd = Arc::new(AtomicUsize::new(0));
        let disk = sd.clone();
        let handler = EndpointHandler::new_packet_handler(ep, move |_| {
            disk.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        let router = Router::new_with_clock(
            RouterConfig::new([handler]).with_sender("GS"),
            Box::new(move || clock.load(Ordering::SeqCst)),
        );
        let busy = Arc::new(AtomicBool::new(true));
        let refuse = busy.clone();
        let attempts = Arc::new(AtomicUsize::new(0));
        let count = attempts.clone();
        let controls = Arc::new(AtomicUsize::new(0));
        let control = controls.clone();
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let output = delivered.clone();
        let side = router.add_side_packed("radio", move |raw| {
            let info = wire_format::peek_frame_info(raw)?;
            if info.envelope.ty == ty && !info.ack_only() {
                count.fetch_add(1, Ordering::SeqCst);
                if refuse.load(Ordering::SeqCst) {
                    return Err(TelemetryError::Io("side tx busy"));
                }
                output.lock().unwrap().push(info.envelope.timestamp_ms);
            } else {
                control.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        });
        router.clear_tx_queue();
        router.set_latest_value_side(Some(side)).unwrap();
        router
            .queue_latest_egress(side, None, &packet(ty, &[remote], "GS", 0, 1))
            .unwrap();
        router.dispatch_tx_queue_with_timeout(0).unwrap();
        for tick in 1..=20 {
            now.store(tick * interval, Ordering::SeqCst);
            router
                .tx_item(RouterTxItem::Broadcast(packet(ty, &[ep], "GS", tick, 1)))
                .unwrap();
            router
                .queue_latest_egress(side, None, &packet(ty, &[remote], "GS", tick, 1))
                .unwrap();
            router.dispatch_tx_queue_with_timeout(0).unwrap();
            assert_eq!(
                ticks(&router.state.lock()).len(),
                2,
                "one attempted owner plus newest pending, not one attempted owner per sample"
            );
        }
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            if interval == 0 { 1 } else { 21 },
            "busy service must retry only the existing encoded owner"
        );
        assert_eq!(sd.load(Ordering::SeqCst), 20, "SD acquisition never slows");
        // Commands and ACKs use their ordinary ownership and remain dispatchable.
        router
            .tx_item_impl(
                RouterTxItem::ToSide {
                    src: None,
                    dst: side,
                    data: packet(command, &[command_ep], "GS", 30, 1),
                },
                true,
                false,
            )
            .unwrap();
        let ack = wire_format::pack_reliable_ack("GS", ty, 30, 1);
        router
            .tx_item_impl(
                RouterTxItem::ToSide {
                    src: None,
                    dst: side,
                    data: RouterItem::Packed(crate::shared_bytes::convert(ack)),
                },
                true,
                false,
            )
            .unwrap();
        assert_eq!(controls.load(Ordering::SeqCst), 2);
        let other_count = Arc::new(AtomicUsize::new(0));
        let other = other_count.clone();
        let other_side = router.add_side_packet("other-side", move |_| {
            other.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        for tick in 1..=20 {
            router
                .tx_item_impl(
                    RouterTxItem::ToSide {
                        src: None,
                        dst: other_side,
                        data: packet(ty, &[remote], "GS", tick, 1),
                    },
                    true,
                    false,
                )
                .unwrap();
        }
        assert_eq!(other_count.load(Ordering::SeqCst), 20);
        busy.store(false, Ordering::SeqCst);
        now.store(30, Ordering::SeqCst);
        router.dispatch_tx_queue_with_timeout(0).unwrap();
        assert_eq!(*delivered.lock().unwrap(), [0, 20]);
    }
    #[test]
    fn submillisecond_refusal_defers_fresh_encoding_without_blocking_sd_controls_or_other_sides() {
        repeated_refusal(0);
    }
    #[test]
    fn millisecond_refusal_defers_fresh_encoding_without_blocking_sd_controls_or_other_sides() {
        repeated_refusal(1);
    }
    #[test]
    fn invalid_packed_payload_cannot_displace_a_valid_pending_sample() {
        let (ty, ep) = schema("LATEST_INVALID", crate::ReliableMode::None, 0);
        let (router, side) = setup();
        router.set_latest_value_side(Some(side)).unwrap();
        let RouterItem::Packet(p) = packet(ty, &[ep], "GS", 2, 1) else {
            unreachable!()
        };
        let mut raw = wire_format::pack_packet(&p).to_vec();
        raw.truncate(raw.len() - 4);
        raw.push(99); // valid CRC, mismatched declared payload length
        let crc = crc32fast::hash(&raw);
        raw.extend_from_slice(&crc.to_le_bytes());
        let invalid = RouterItem::Packed(crate::shared_bytes::convert(Arc::<[u8]>::from(raw)));
        let mut st = router.state.lock();
        st.push_transmit(queued(side, packet(ty, &[ep], "GS", 1, 1)))
            .unwrap();
        assert!(!st.latest_data_eligible(&invalid, 0));
        st.push_transmit(queued(side, invalid)).unwrap();
        assert_eq!(st.transmit_queue.len(), 2);
        assert_eq!(
            with_view(
                match &st.transmit_queue.get(0).unwrap().item {
                    RouterTxItem::ToSide { data, .. } => data,
                    _ => unreachable!(),
                },
                |v| v.timestamp()
            ),
            Some(1)
        );
    }
    #[test]
    fn setting_and_retry_hint_are_independent_and_remove_clears_policy() {
        let (router, side) = setup();
        router.state.lock().tx_policy_flags |= 1;
        router.set_latest_value_side(Some(side)).unwrap();
        assert_eq!(router.state.lock().tx_policy_flags & 1, 1);
        {
            let mut st = router.state.lock();
            st.tx_policy_flags &= !1;
            st.refresh_retry_hint();
            assert_eq!(st.latest_side(), Some(side));
        }
        assert!(router.set_latest_value_side(Some(127)).is_err());
        let packet_side = router.add_side_packet("callback", |_| Ok(()));
        assert!(router.set_latest_value_side(Some(packet_side)).is_err());
        router.remove_side(side).unwrap();
        assert_eq!(router.state.lock().latest_side(), None);
        router.set_latest_value_side(None).unwrap();
    }
    #[test]
    fn direct_routing_defers_radio_encoding_but_preserves_sd_every_sample() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (ty, ep) = schema("LATEST_FANOUT", crate::ReliableMode::None, 0);
        let (_, remote_ep) = schema("LATEST_REMOTE", crate::ReliableMode::None, 0);
        let sd_count = Arc::new(AtomicUsize::new(0));
        let sd = sd_count.clone();
        let handler = EndpointHandler::new_packet_handler(ep, move |p| {
            if p.data_type() == ty {
                sd.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        });
        let router = Router::new_with_clock(
            RouterConfig::new([handler]).with_sender("GS"),
            Box::new(|| 0),
        );
        let radio_count = Arc::new(AtomicUsize::new(0));
        let radio = radio_count.clone();
        let side = router.add_side_packed("radio", move |raw| {
            if wire_format::peek_frame_info(raw).is_ok_and(|f| f.envelope.ty == ty) {
                radio.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        });
        router.clear_tx_queue();
        router.set_latest_value_side(Some(side)).unwrap();
        for tick in 1..=10 {
            router
                .tx_item(RouterTxItem::Broadcast(packet(
                    ty,
                    &[ep, remote_ep],
                    "GS",
                    tick,
                    1,
                )))
                .unwrap();
        }
        assert_eq!(
            radio_count.load(Ordering::SeqCst),
            0,
            "nothing encoded for radio before dispatch"
        );
        assert_eq!(
            sd_count.load(Ordering::SeqCst),
            10,
            "local SD/acquisition fanout keeps every value"
        );
        assert_eq!(ticks(&router.state.lock()), [10]);
        router.dispatch_tx_queue_with_timeout(0).unwrap();
        assert_eq!(radio_count.load(Ordering::SeqCst), 1);
    }
    fn first_canonical_chunk_for_turn_test() -> Vec<u8> {
        let packet =
            wire_format::unpack_packet(include_bytes!("tests/captured-local-gs.bin")).unwrap();
        let mut first = None;
        let mut next = 0;
        let result =
            crate::side_transport::send_packet_chunks(&packet, 80, b"GS", &mut next, |raw| {
                if first.is_some() {
                    return Err(TelemetryError::Io("side tx busy"));
                }
                first = Some(raw.to_vec());
                Ok(())
            });
        assert!(result.is_err());
        assert_eq!(next, 1);
        first.unwrap()
    }
    #[test]
    fn earned_bytes_require_the_exact_successful_dispatch_reservation() {
        let (router, side) = setup();
        router.set_latest_value_side(Some(side)).unwrap();
        {
            let mut st = router.state.lock();
            st.sides[side].as_mut().unwrap().opts.max_frame_bytes = 80;
            st.latest_service_seq = 7;
            st.latest_turn_phase = 3;
        }
        let tag = EgressService {
            token: 7,
            side: 1,
            kind: 1,
        };
        let good = RouterTxHandlerFn::Packed(Arc::new(|_| Ok(())));
        let busy = RouterTxHandlerFn::Packed(Arc::new(|_| Err(TelemetryError::Io("side tx busy"))));
        let raw = first_canonical_chunk_for_turn_test();
        assert!(
            router
                .packed_handler_call(side, &busy, &raw, 254, tag)
                .is_err()
        );
        assert_eq!(router.state.lock().latest_turn_credit, 0);
        router
            .packed_handler_call(side, &good, &raw, 255, EgressService::default())
            .unwrap();
        assert_eq!(
            router.state.lock().latest_turn_credit,
            0,
            "control bypass earns no catalog credit"
        );
        router
            .packed_handler_call(side, &good, &raw, 254, EgressService { token: 6, ..tag })
            .unwrap();
        assert_eq!(
            router.state.lock().latest_turn_credit,
            0,
            "stale dispatch cannot earn"
        );
        router
            .packed_handler_call(side, &good, &raw, 254, tag)
            .unwrap();
        assert_eq!(router.state.lock().latest_turn_credit, raw.len() as i32);
        {
            let mut st = router.state.lock();
            st.latest_turn_phase = 4;
        }
        router
            .packed_handler_call(side, &good, &raw, 0, EgressService { kind: 2, ..tag })
            .unwrap();
        assert_eq!(
            router.state.lock().latest_turn_credit,
            -(raw.len() as i32),
            "actual bytes spend once and retain bounded debt"
        );
        // Queue completion itself cannot earn/spend a second time.
        let context = DispatchContext {
            admitted: true,
            completion_flags: TX_LATEST_TURN,
            latest_service: EgressService { kind: 2, ..tag },
            ..Default::default()
        };
        router.finish_dispatch_turn(false, &context);
        assert_eq!(router.state.lock().latest_turn_credit, -(raw.len() as i32));
        {
            let mut st = router.state.lock();
            st.latest_turn_phase = 3;
            st.latest_turn_credit = i32::MAX - 1;
            st.sides[side].as_mut().unwrap().opts.max_frame_bytes = usize::MAX;
        }
        router
            .packed_handler_call(side, &good, &raw, 254, tag)
            .unwrap();
        assert_eq!(
            router.state.lock().latest_turn_credit,
            i32::MAX,
            "MTU*burst and earned bytes saturate without overflow"
        );
    }

    #[test]
    fn nested_control_and_rebinding_cannot_consume_the_outer_credit() {
        let router = Arc::new(Router::new_with_clock(
            RouterConfig::new([]).with_sender("GS"),
            Box::new(|| 0),
        ));
        let side = router.add_side_packed("radio", |_| Ok(()));
        router.set_latest_value_side(Some(side)).unwrap();
        {
            let mut st = router.state.lock();
            st.latest_service_seq = 10;
            st.latest_turn_phase = 3;
            st.sides[side].as_mut().unwrap().opts.max_frame_bytes = 80;
        }
        let weak = Arc::downgrade(&router);
        let nested = RouterTxHandlerFn::Packed(Arc::new(move |raw| {
            let router = weak.upgrade().unwrap();
            let control = RouterTxHandlerFn::Packed(Arc::new(|_| Ok(())));
            router.packed_handler_call(side, &control, raw, 255, EgressService::default())?;
            assert_eq!(router.state.lock().latest_turn_credit, 0);
            assert_eq!(router.state.lock().latest_turn_phase, 3);
            Ok(())
        }));
        let raw = first_canonical_chunk_for_turn_test();
        let tag = EgressService {
            token: 10,
            side: 1,
            kind: 1,
        };
        router
            .packed_handler_call(side, &nested, &raw, 254, tag)
            .unwrap();
        assert_eq!(router.state.lock().latest_turn_credit, raw.len() as i32);
        router.state.lock().latest_turn_credit = 0;
        let weak = Arc::downgrade(&router);
        let rebind = RouterTxHandlerFn::Packed(Arc::new(move |_| {
            let router = weak.upgrade().unwrap();
            router.set_latest_value_side(None)?;
            router.set_latest_value_side(Some(side))?;
            Ok(())
        }));
        router
            .packed_handler_call(side, &rebind, &raw, 254, tag)
            .unwrap();
        assert_eq!(router.state.lock().latest_turn_credit, 0);
        let old = DispatchContext {
            admitted: true,
            completion_flags: TX_CANONICAL_OWED,
            latest_service: tag,
            ..Default::default()
        };
        router.finish_dispatch_turn(false, &old);
        assert_eq!(
            router.state.lock().latest_turn_phase,
            0,
            "old callback cannot advance a new side-policy generation"
        );
    }

    #[test]
    fn large_side_ids_never_alias_an_encoded_latest_service_side() {
        let (router, side) = setup();
        router.set_latest_value_side(Some(side)).unwrap();
        let mut last = side;
        for n in 1..=256 {
            last = router.add_side_packed(format!("other-{n}"), |_| Ok(()));
        }
        assert!(last > 255);
        router.clear_tx_queue();
        assert!(router.set_latest_value_side(Some(last)).is_err());
        let (ty, ep) = schema("LATEST_LARGE_SIDE", crate::ReliableMode::None, 0);
        let mut owner = queued(last, packet(ty, &[ep], "FC", 0, 1));
        owner.disposable = TX_HISTORY_OWNED | TX_LATEST_TURN;
        let mut st = router.state.lock();
        st.latest_turn_phase = 4;
        assert_eq!(st.latest_dispatch_tag(&owner), 0);
        st.push_transmit(owner).unwrap();
        assert_eq!(
            st.transmit_queue.get(0).unwrap().disposable & TX_LATEST_TURN,
            0,
            "changing an owner destination cannot carry its old-side turn marker"
        );
        assert_eq!(st.latest_side(), Some(side));
    }

    #[test]
    fn turn_flag_space_and_deferred_owner_are_stable_without_payload_or_queue_growth() {
        assert_eq!(
            TX_DISPOSABLE
                | TX_LATEST_PENDING
                | TX_HISTORY_OWNED
                | TX_E2E_CHILD
                | TX_E2E_RETRY
                | TX_CANONICAL_OWED
                | TX_CANONICAL_SERVED
                | TX_LATEST_TURN,
            u8::MAX
        );
        let (router, side) = setup();
        router.set_latest_value_side(Some(side)).unwrap();
        let original =
            wire_format::unpack_packet(include_bytes!("tests/captured-local-gs.bin")).unwrap();
        let mut st = router.state.lock();
        st.sides[side].as_mut().unwrap().opts =
            RouterSideOptions::default().with_small_packet_transport(80);
        let mut owner = queued(side, RouterItem::Packet(original.clone()));
        owner.disposable = TX_HISTORY_OWNED | TX_CANONICAL_OWED;
        owner.retry_after_ms = 123;
        owner.deferred_since_ms = 0;
        st.push_transmit(owner.clone()).unwrap();
        let before = st.transmit_queue.bytes_used();
        assert!(Router::pop_transmit_queue_locked(&mut st, 122, false).is_none());
        assert_eq!(st.latest_turn_phase, 1);
        assert_eq!(st.transmit_queue.bytes_used(), before);
        assert_eq!(st.transmit_queue.get(0).unwrap().retry_after_ms, 123);
        assert_eq!(st.transmit_queue.get(0).unwrap().deferred_since_ms, 0);
        let work = Router::pop_transmit_queue_locked(&mut st, 123, false).unwrap();
        assert_eq!(
            work.queued.disposable & TX_CANONICAL_OWED,
            TX_CANONICAL_OWED
        );
        assert_eq!(work.service.side, 1);
        assert!(work.service.token != 0);
        assert_eq!(st.latest_turn_phase, 3);
        assert_eq!(
            st.latest_turn_selection(true, 0),
            Some(usize::MAX),
            "nested pop cannot steal an in-flight owner"
        );
        let RouterTxItem::ToSide {
            data: RouterItem::Packet(packet),
            ..
        } = work.queued.item
        else {
            panic!()
        };
        assert_eq!(packet, original);
    }
    #[test]
    #[cfg(feature = "compact-packet-store")]
    fn compact_turn_metadata_scans_never_pin_or_duplicate_the_catalog_payload() {
        let original =
            wire_format::unpack_packet(include_bytes!("tests/captured-local-gs.bin")).unwrap();
        let store = crate::packet_store::PacketStore::new(8192, 8, usize::MAX).unwrap();
        let payload = crate::config::StandardSmallPayload::Managed(
            crate::packet_store::ParkedPayload::new(store.store(original.payload()).unwrap()),
        );
        let mut catalog = Packet::new_with_owned_wire_contract(
            original.data_type(),
            Arc::from(original.endpoints()),
            Arc::from(original.sender()),
            original.timestamp(),
            original.nonce(),
            payload,
            None,
            None,
        )
        .unwrap();
        catalog.park_for_queue().unwrap();
        assert_eq!(store.stats().pinned_bytes, 0);
        let (router, side) = setup();
        router.set_latest_value_side(Some(side)).unwrap();
        let mut st = router.state.lock();
        st.sides[side].as_mut().unwrap().opts =
            RouterSideOptions::default().with_small_packet_transport(80);
        let mut owner = queued(side, RouterItem::Packet(catalog));
        owner.disposable = TX_HISTORY_OWNED | TX_CANONICAL_OWED;
        owner.retry_after_ms = 1;
        st.push_transmit(owner).unwrap();
        let before = st.transmit_queue.bytes_used();
        let live_bytes = store.stats().live_bytes;
        for _ in 0..1000 {
            assert!(st.canonical_catalog_owner(st.transmit_queue.get(0).unwrap()));
            assert_eq!(st.latest_blocked_side(0), None);
            assert_eq!(st.latest_turn_selection(true, 0), Some(0));
            assert_eq!(
                store.stats().pinned_bytes,
                0,
                "metadata scanning must not hash/read the retained3.7KB payload"
            );
        }
        let clone = st.transmit_queue.get(0).unwrap().clone();
        st.retain_transmit(|_| false);
        st.push_transmit(clone).unwrap();
        assert_eq!(st.transmit_queue.bytes_used(), before);
        assert_eq!(store.stats().live_bytes, live_bytes);
        assert_eq!(store.stats().live_handles, 1);
        assert_eq!(store.stats().pinned_bytes, 0);
        assert_eq!(
            st.transmit_queue.get(0).unwrap().disposable & TX_CANONICAL_OWED,
            TX_CANONICAL_OWED
        );
    }

    #[test]
    #[cfg(feature = "cryptography")]
    fn actual_hop_reliable_and_force_all_schema_paths_preserve_their_encoding_and_ack_owner() {
        use std::sync::Mutex;
        for force_all in [false, true] {
            for hop in [false, true] {
                let mut config = RouterConfig::new([])
                    .with_sender("GS")
                    .with_reliable_enabled(true);
                if force_all {
                    config = config.with_e2e_encryption(RouterE2eEncryptionMode::ForceAll);
                }
                let tx = Router::new_with_clock(config, Box::new(|| 0));
                let frames = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
                let output = frames.clone();
                let mut opts = RouterSideOptions::default().with_small_packet_transport(80);
                opts.reliable_enabled = hop;
                let side = tx.add_side_packed_with_options(
                    "radio",
                    move |raw| {
                        output.lock().unwrap().push(raw.to_vec());
                        Ok(())
                    },
                    opts.clone(),
                );
                tx.clear_tx_queue();
                tx.set_latest_value_side(Some(side)).unwrap();
                let catalog =
                    wire_format::unpack_packet(include_bytes!("tests/captured-local-gs.bin"))
                        .unwrap();
                let owner = queued(side, RouterItem::Packet(catalog.clone()));
                assert_eq!(tx.state.lock().canonical_catalog_owner(&owner), !hop);
                // This direct encoder-path proof holds its caller-owned Packet;
                // the separate SchemaRequest service regression proves queue ownership.
                for _ in 0..100 {
                    match tx.send_reliable_to_side(side, RouterItem::Packet(catalog.clone()), false)
                    {
                        Ok(()) => break,
                        Err(TelemetryError::Io("side tx busy")) if !hop => {}
                        other => panic!("unexpected schema path result: {other:?}"),
                    }
                }
                let rx =
                    Router::new_with_clock(RouterConfig::new([]).with_sender("RF"), Box::new(|| 0));
                let input = rx.add_side_packed_with_options("radio", |_| Ok(()), opts);
                let mut complete = Vec::new();
                for raw in frames.lock().unwrap().iter() {
                    if let Some(raw) = rx.decode_side_transport_frame(input, raw).unwrap() {
                        complete.push(raw);
                    }
                }
                assert_eq!(complete.len(), 1);
                let info = wire_format::peek_routing_frame_info(complete[0].as_ref()).unwrap();
                assert_eq!(
                    wire_format::unpack_packet(complete[0].as_ref()).unwrap(),
                    catalog
                );
                if hop {
                    let seq = info.reliable.unwrap().seq;
                    assert_ne!(seq, 0);
                    assert_eq!(
                        tx.state
                            .lock()
                            .reliable_tx
                            .get(&(side, DataType::DiscoverySchema.as_u32()))
                            .unwrap()
                            .sent
                            .len(),
                        1
                    );
                    tx.rx_packed_from_side(
                        &wire_format::pack_reliable_ack(
                            "RF",
                            DataType::DiscoverySchema,
                            0,
                            seq.wrapping_sub(1),
                        ),
                        side,
                    )
                    .unwrap();
                    assert_eq!(
                        tx.state
                            .lock()
                            .reliable_tx
                            .get(&(side, DataType::DiscoverySchema.as_u32()))
                            .unwrap()
                            .sent
                            .len(),
                        1
                    );
                    tx.rx_packed_from_side(
                        &wire_format::pack_reliable_ack("RF", DataType::DiscoverySchema, 0, seq),
                        side,
                    )
                    .unwrap();
                    assert!(
                        tx.state
                            .lock()
                            .reliable_tx
                            .get(&(side, DataType::DiscoverySchema.as_u32()))
                            .unwrap()
                            .sent
                            .is_empty()
                    );
                } else {
                    assert_eq!(
                        complete[0].as_ref(),
                        &include_bytes!("tests/captured-local-gs.bin")[..]
                    );
                    assert!(info.reliable.is_some_and(|h| h.flags
                        == wire_format::RELIABLE_FLAG_UNSEQUENCED
                        && h.seq == 0));
                    assert!(
                        tx.state
                            .lock()
                            .reliable_tx
                            .values()
                            .all(|state| state.sent.is_empty())
                    );
                }
            }
        }
    }
    #[test]
    fn partially_admitted_large_report_finishes_before_canonical_turns_resume() {
        use std::sync::{
            Mutex,
            atomic::{AtomicU64, AtomicUsize, Ordering},
        };
        let now = Arc::new(AtomicU64::new(0));
        let time = now.clone();
        let router = Router::new_with_clock(
            RouterConfig::new([]).with_sender("GS"),
            Box::new(move || time.load(Ordering::SeqCst)),
        );
        let allowance = Arc::new(AtomicUsize::new(1));
        let credit = allowance.clone();
        let output = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let frames = output.clone();
        let opts = RouterSideOptions::default().with_small_packet_transport(80);
        let side = router.add_side_packed_with_options(
            "radio",
            move |raw| {
                credit
                    .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                    .map_err(|_| TelemetryError::Io("side tx busy"))?;
                frames.lock().unwrap().push(raw.to_vec());
                Ok(())
            },
            opts.clone(),
        );
        router.clear_tx_queue();
        router.set_latest_value_side(Some(side)).unwrap();
        let schema_packet =
            wire_format::unpack_packet(include_bytes!("tests/captured-local-gs.bin")).unwrap();
        let (ty, ep) = schema("LATEST_LARGE_MARKED_OWNER", crate::ReliableMode::None, 0);
        let original =
            Packet::new_with_nonce(ty, &[ep], "FC", 0, 7, Arc::from(vec![0x55; 1024])).unwrap();
        router
            .emit_internal_tx(
                RouterTxItem::ToSide {
                    src: None,
                    dst: side,
                    data: RouterItem::Packet(schema_packet),
                },
                true,
                true,
            )
            .unwrap();
        router
            .queue_latest_egress(side, None, &RouterItem::Packet(original.clone()))
            .unwrap();
        router.dispatch_tx_queue_with_timeout(0).unwrap();
        let receiver_time = now.clone();
        let receiver = Router::new_with_clock(
            RouterConfig::new([]).with_sender("RF"),
            Box::new(move || receiver_time.load(Ordering::SeqCst)),
        );
        let input = receiver.add_side_packed_with_options("radio", |_| Ok(()), opts);
        let mut original_received = false;
        let mut saw_partial_marker = false;
        let mut schema_frames_during_large = 0;
        let mut catalog_frames_before_large = 0;
        for ms in 1..=64 {
            now.store(ms, Ordering::SeqCst);
            allowance.store(1, Ordering::SeqCst);
            router
                .queue_latest_egress(side, None, &packet(ty, &[ep], "FC", ms, 16))
                .unwrap();
            router.dispatch_tx_queue_with_timeout(0).unwrap();
            {
                let st = router.state.lock();
                let marked = st
                    .transmit_queue
                    .iter()
                    .filter(|q| q.disposable & TX_LATEST_TURN != 0)
                    .count();
                assert!(marked <= 1, "a fresh grant has exactly one immutable owner");
                saw_partial_marker |= marked == 1;
            }
            for raw in core::mem::take(&mut *output.lock().unwrap()) {
                let schema_chunk = raw.starts_with(b"SDT\x03")
                    && u32::from_le_bytes(raw[4..8].try_into().unwrap()) == 3937645761;
                if schema_chunk && !original_received {
                    if saw_partial_marker && ms > 1 {
                        schema_frames_during_large += 1;
                    } else {
                        catalog_frames_before_large += 1;
                    }
                }
                if let Some(raw) = receiver.decode_side_transport_frame(input, &raw).unwrap() {
                    let packet = wire_format::unpack_packet(&raw).unwrap();
                    if packet.packet_id() == original.packet_id() {
                        assert_eq!(packet, original);
                        original_received = true;
                    }
                }
            }
            if original_received {
                break;
            }
        }
        assert!(catalog_frames_before_large > 0);
        assert!(
            saw_partial_marker && original_received,
            "the actual partial SDT owner must finish"
        );
        assert_eq!(
            schema_frames_during_large, 0,
            "canonical service must not steal an already-started report's remaining fragments"
        );
    }

    #[test]
    fn queued_dispatch_snapshot_cannot_pick_up_a_later_policy_generation() {
        let router =
            Router::new_with_clock(RouterConfig::new([]).with_sender("GS"), Box::new(|| 0));
        let allowance = Arc::new(std::sync::atomic::AtomicUsize::new(1));
        let credit = allowance.clone();
        let side = router.add_side_packed("radio", move |_| {
            credit
                .try_update(
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst,
                    |n| n.checked_sub(1),
                )
                .map_err(|_| TelemetryError::Io("side tx busy"))?;
            Ok(())
        });
        router.clear_tx_queue();
        router.set_latest_value_side(Some(side)).unwrap();
        let original =
            wire_format::unpack_packet(include_bytes!("tests/captured-local-gs.bin")).unwrap();
        let work = {
            let mut st = router.state.lock();
            st.sides[side].as_mut().unwrap().opts =
                RouterSideOptions::default().with_small_packet_transport(80);
            st.push_transmit(queued(side, RouterItem::Packet(original.clone())))
                .unwrap();
            Router::pop_transmit_queue_locked(&mut st, 0, false).unwrap()
        };
        let old = work.service;
        router.set_latest_value_side(None).unwrap();
        router.set_latest_value_side(Some(side)).unwrap();
        assert_ne!(router.state.lock().latest_service_seq, old.token);
        router.dispatch_queued_item(work).unwrap();
        let st = router.state.lock();
        assert_eq!(st.latest_turn_credit, 0);
        assert_eq!(st.latest_turn_phase, 0);
        assert!(
            st.transmit_queue
                .iter()
                .all(|q| q.disposable & (TX_CANONICAL_TURN | TX_LATEST_TURN) == 0)
        );
        assert!(
            st.transmit_queue.iter().any(|q| matches!(&q.item,
            RouterTxItem::ToSide { data: RouterItem::Packet(packet), .. } if packet == &original)),
            "generation invalidation retains the original partially accepted owner"
        );
    }
    #[test]
    fn egress_transition_and_service_sequence_exhaustion_fail_closed_without_owner_loss() {
        let (router, side) = setup();
        router.set_latest_value_side(Some(side)).unwrap();
        let old = {
            let mut st = router.state.lock();
            st.latest_service_seq = 10;
            st.latest_turn_phase = 3;
            st.latest_turn_credit = 80;
            EgressService {
                token: 10,
                side: 1,
                kind: 1,
            }
        };
        router.set_side_egress_enabled(side, false).unwrap();
        router.set_side_egress_enabled(side, true).unwrap();
        let context = DispatchContext {
            admitted: true,
            completion_flags: TX_CANONICAL_OWED,
            latest_service: old,
            ..Default::default()
        };
        assert_eq!(router.current_egress_requeue(&context), (0, false));
        router.finish_dispatch_turn(false, &context);
        assert_eq!(router.state.lock().latest_turn_credit, 0);
        assert_eq!(router.state.lock().latest_turn_phase, 0);
        let original =
            wire_format::unpack_packet(include_bytes!("tests/captured-local-gs.bin")).unwrap();
        {
            let mut st = router.state.lock();
            st.sides[side].as_mut().unwrap().opts =
                RouterSideOptions::default().with_small_packet_transport(80);
            st.push_transmit(queued(side, RouterItem::Packet(original.clone())))
                .unwrap();
            st.latest_service_seq = u32::MAX;
        }
        assert!(router.set_latest_value_side(Some(side)).is_err());
        let mut st = router.state.lock();
        let work = Router::pop_transmit_queue_locked(&mut st, 0, false).unwrap();
        assert_eq!(
            st.latest_side(),
            None,
            "exhaustion disables only the optional policy"
        );
        assert_eq!(work.service.side, 0);
        let RouterTxItem::ToSide {
            data: RouterItem::Packet(packet),
            ..
        } = work.queued.item
        else {
            panic!()
        };
        assert_eq!(
            packet, original,
            "fallback work retains the exact original owner"
        );
    }

    #[test]
    #[cfg(feature = "discovery")]
    fn five_concurrent_catalogs_retain_all_owners_under_fresh_report_pressure() {
        use std::sync::Mutex;
        use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
        let now = Arc::new(AtomicU64::new(0));
        let time = now.clone();
        let memory = crate::config::RuntimeMemoryConfig::new(1024 * 1024, 128, 4096, 1.5).unwrap();
        let router = Router::new_with_clock(
            RouterConfig::new([])
                .with_sender("RF")
                .with_memory_config(memory)
                .unwrap(),
            Box::new(move || time.load(Ordering::SeqCst)),
        );
        let allowance = Arc::new(AtomicUsize::new(80));
        let credit = allowance.clone();
        let accepted = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let output = accepted.clone();
        let options = RouterSideOptions::default().with_small_packet_transport(80);
        let side = router.add_side_packed_with_options(
            "finite-radio",
            move |raw| {
                assert!(raw.len() <= 80);
                credit
                    .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                        n.checked_sub(raw.len())
                    })
                    .map_err(|_| TelemetryError::Io("side tx busy"))?;
                output.lock().unwrap().push(raw.to_vec());
                Ok(())
            },
            options.clone(),
        );
        router.clear_tx_queue();
        router.set_latest_value_side(Some(side)).unwrap();
        let flows: Vec<_> = (0..8)
            .map(|n| {
                schema(
                    &format!("CATALOG_CAPACITY_REPORT_{n}"),
                    crate::ReliableMode::None,
                    0,
                )
            })
            .collect();
        let mut expected = Vec::new();
        for n in 0..5 {
            let catalog = crate::discovery::build_discovery_schema(&format!("CAT_{n}"), 0).unwrap();
            crate::discovery::decode_discovery_schema(&catalog).unwrap();
            assert!(catalog.data_size() > 80);
            expected.push((catalog.packet_id(), catalog.payload().to_vec()));
            let mut owner = queued(side, RouterItem::Packet(catalog));
            owner.priority = crate::transport_priority(DataType::DiscoverySchema);
            router.state.lock().push_transmit(owner).unwrap();
        }
        let time = now.clone();
        let receiver = Router::new_with_clock(
            RouterConfig::new([]).with_sender("GS"),
            Box::new(move || time.load(Ordering::SeqCst)),
        );
        let input = receiver.add_side_packed_with_options("finite-radio", |_| Ok(()), options);
        let mut completed = Vec::new();
        let mut terminal = None;
        let mut events = Vec::new();
        for ms in 0..=5000 {
            now.store(ms, Ordering::SeqCst);
            allowance.store(80, Ordering::SeqCst);
            for &(ty, ep) in &flows {
                assert!(
                    router
                        .queue_latest_egress(side, None, &packet(ty, &[ep], "FC", ms, 16))
                        .unwrap()
                );
            }
            let result = router.dispatch_tx_queue_with_timeout(0);
            for frame in core::mem::take(&mut *accepted.lock().unwrap()) {
                if let Some(raw) = receiver.decode_side_transport_frame(input, &frame).unwrap() {
                    let p = wire_format::unpack_packet(&raw).unwrap();
                    if p.data_type() == DataType::DiscoverySchema {
                        crate::discovery::decode_discovery_schema(&p).unwrap();
                        completed.push((p.packet_id(), p.payload().to_vec()));
                    }
                }
            }
            let st = router.state.lock();
            let queued_catalog_ids: Vec<_> = st
                .transmit_queue
                .iter()
                .filter_map(|q| match &q.item {
                    RouterTxItem::ToSide {
                        data: RouterItem::Packet(p),
                        ..
                    } if p.data_type() == DataType::DiscoverySchema => Some(p.packet_id()),
                    _ => None,
                })
                .collect();
            events.push((
                ms,
                format!("{result:?}"),
                queued_catalog_ids,
                format!(
                    "{:?}",
                    st.side_transport.get(&side).unwrap().tx_chunk_progress
                ),
            ));
            drop(st);
            if let Err(error) = result {
                terminal = Some(error);
                break;
            }
            if completed.len() == expected.len() {
                break;
            }
        }
        eprintln!(
            "FIVE_CATALOG_CAPACITY expected_ids={:?} completed_ids={:?} terminal={terminal:?} events={events:#?}",
            expected.iter().map(|x| x.0).collect::<Vec<_>>(),
            completed.iter().map(|x| x.0).collect::<Vec<_>>()
        );
        assert!(
            terminal.is_none(),
            "a legal fifth canonical catalog must retain its owner and service prior cursors, not return a terminal saturation error"
        );
        expected.sort_by_key(|x| x.0);
        completed.sort_by_key(|x| x.0);
        assert_eq!(
            completed, expected,
            "all original catalog IDs and exact payloads complete once before expiry; no owner is silently lost"
        );
    }
    #[test]
    #[cfg(feature = "discovery")]
    fn late_fragmented_fresh_report_survives_four_existing_catalog_prefixes() {
        use std::sync::Mutex;
        use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
        let now = Arc::new(AtomicU64::new(0));
        let time = now.clone();
        let memory = crate::config::RuntimeMemoryConfig::new(1024 * 1024, 128, 4096, 1.5).unwrap();
        let router = Router::new_with_clock(
            RouterConfig::new([])
                .with_sender("RF")
                .with_memory_config(memory)
                .unwrap(),
            Box::new(move || time.load(Ordering::SeqCst)),
        );
        let allowance = Arc::new(AtomicUsize::new(80));
        let credit = allowance.clone();
        let accepted = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let output = accepted.clone();
        let callback_time = now.clone();
        let options = RouterSideOptions::default().with_small_packet_transport(80);
        let side = router.add_side_packed_with_options(
            "finite-radio",
            move |raw| {
                assert!(raw.len() <= 80);
                credit
                    .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                        n.checked_sub(raw.len())
                    })
                    .map_err(|_| TelemetryError::Io("side tx busy"))?;
                output.lock().unwrap().push(raw.to_vec());
                // Finite accepted work consumes the public dispatch budget, so a
                // pre-policy pass services one real owner instead of draining all.
                callback_time.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            options.clone(),
        );
        router.clear_tx_queue();
        assert_eq!(router.state.lock().latest_side(), None);
        let mut expected_catalogs = Vec::new();
        for n in 0..4 {
            let catalog =
                crate::discovery::build_discovery_schema(&format!("LATE_CAT_{n}"), 0).unwrap();
            crate::discovery::decode_discovery_schema(&catalog).unwrap();
            assert!(catalog.data_size() > 160);
            expected_catalogs.push((catalog.packet_id(), catalog.payload().to_vec()));
            let mut owner = queued(side, RouterItem::Packet(catalog));
            owner.priority = crate::transport_priority(DataType::DiscoverySchema);
            router.state.lock().push_transmit(owner).unwrap();
        }
        for _ in 0..4 {
            allowance.store(80, Ordering::SeqCst);
            router.dispatch_tx_queue_with_timeout(1).unwrap();
            now.fetch_add(1, Ordering::SeqCst);
        }
        let first_frames = core::mem::take(&mut *accepted.lock().unwrap());
        assert_eq!(
            first_frames.len(),
            4,
            "one actual accepted prefix per pre-policy turn"
        );
        let transfers: std::collections::BTreeSet<_> = first_frames
            .iter()
            .map(|raw| {
                assert!(raw.starts_with(b"SDT\x03"));
                u32::from_le_bytes(raw[4..8].try_into().unwrap())
            })
            .collect();
        assert_eq!(
            transfers.len(),
            4,
            "four different original catalog transfers actually started"
        );
        let initial_progress = format!(
            "{:?}",
            router
                .state
                .lock()
                .side_transport
                .get(&side)
                .unwrap()
                .tx_chunk_progress
        );
        assert_eq!(
            initial_progress.matches("Some(SideTxCursor").count(),
            4,
            "the negative precondition is four real live cursors, never fabricated state"
        );
        router.set_latest_value_side(Some(side)).unwrap();
        assert_eq!(
            router.state.lock().latest_turn_credit,
            0,
            "policy enable does not invent credit"
        );
        let (ty, ep) = schema(
            "CAPACITY_LATE_FRAGMENTED_FRESH",
            crate::ReliableMode::None,
            0,
        );
        let original = Packet::new_with_nonce(
            ty,
            &[ep],
            "FC",
            now.load(Ordering::SeqCst),
            7,
            Arc::from(vec![0x55; 1024]),
        )
        .unwrap();
        assert!(
            router
                .queue_latest_egress(side, None, &RouterItem::Packet(original.clone()))
                .unwrap()
        );
        let time = now.clone();
        let receiver = Router::new_with_clock(
            RouterConfig::new([]).with_sender("GS"),
            Box::new(move || time.load(Ordering::SeqCst)),
        );
        let input = receiver.add_side_packed_with_options("finite-radio", |_| Ok(()), options);
        for frame in &first_frames {
            assert!(
                receiver
                    .decode_side_transport_frame(input, frame)
                    .unwrap()
                    .is_none()
            );
        }
        let mut completed_catalogs = Vec::new();
        let mut original_received = false;
        let mut errors = Vec::new();
        let mut events = Vec::new();
        for _ in 0..5000 {
            allowance.store(80, Ordering::SeqCst);
            let at = now.load(Ordering::SeqCst);
            let result = router.dispatch_tx_queue_with_timeout(1);
            for frame in core::mem::take(&mut *accepted.lock().unwrap()) {
                if let Some(raw) = receiver.decode_side_transport_frame(input, &frame).unwrap() {
                    let p = wire_format::unpack_packet(&raw).unwrap();
                    if p.data_type() == DataType::DiscoverySchema {
                        completed_catalogs.push((p.packet_id(), p.payload().to_vec()));
                    }
                    if p.packet_id() == original.packet_id() {
                        assert_eq!(
                            p, original,
                            "actual independent receiver gets the exact large fresh owner"
                        );
                        assert!(!original_received, "large original completes only once");
                        assert!(
                            now.load(Ordering::SeqCst)
                                .saturating_sub(original.timestamp())
                                <= 1500,
                            "original source-forward age gate is unchanged"
                        );
                        original_received = true;
                    }
                }
            }
            let st = router.state.lock();
            let large_owners = st
                .transmit_queue
                .iter()
                .filter(|q| match &q.item {
                    RouterTxItem::ToSide {
                        data: RouterItem::Packet(p),
                        ..
                    } => p.packet_id() == original.packet_id(),
                    _ => false,
                })
                .count();
            let markers = st
                .transmit_queue
                .iter()
                .filter(|q| q.disposable & TX_LATEST_TURN != 0)
                .count();
            events.push((
                at,
                format!("{result:?}"),
                st.latest_turn_credit,
                large_owners,
                markers,
                format!(
                    "{:?}",
                    st.side_transport.get(&side).unwrap().tx_chunk_progress
                ),
            ));
            drop(st);
            if let Err(error) = result {
                errors.push((at, error));
                break;
            }
            if original_received && completed_catalogs.len() == expected_catalogs.len() {
                break;
            }
            now.fetch_add(1, Ordering::SeqCst);
        }
        eprintln!(
            "LATE_FRAGMENTED_FRESH original_id={} initial_progress={} errors={errors:?} original_received={original_received} completed_catalogs={} events={events:#?}",
            original.packet_id(),
            initial_progress,
            completed_catalogs.len()
        );
        assert!(
            errors.is_empty(),
            "an earned fragmented fresh owner must survive full catalog cursor capacity without terminal loss"
        );
        assert!(
            original_received,
            "a waiting latest marker must not pin ahead of live catalog continuations until expiry"
        );
        expected_catalogs.sort_by_key(|x| x.0);
        completed_catalogs.sort_by_key(|x| x.0);
        assert_eq!(
            completed_catalogs, expected_catalogs,
            "every exact original catalog also completes once"
        );
    }
    #[test]
    #[cfg(feature = "discovery")]
    fn startup_optin_fixed_time_late_fragmented_fresh_report_keeps_all_originals() {
        use std::sync::Mutex;
        use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
        let now = Arc::new(AtomicU64::new(0));
        let time = now.clone();
        let memory = crate::config::RuntimeMemoryConfig::new(1024 * 1024, 128, 4096, 1.5).unwrap();
        let router = Router::new_with_clock(
            RouterConfig::new([])
                .with_sender("RF")
                .with_memory_config(memory)
                .unwrap(),
            Box::new(move || time.load(Ordering::SeqCst)),
        );
        let allowance = Arc::new(AtomicUsize::new(80));
        let credit = allowance.clone();
        let accepted = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let output = accepted.clone();
        let callback_time = now.clone();
        let options = RouterSideOptions::default().with_small_packet_transport(80);
        let side = router.add_side_packed_with_options(
            "finite-radio",
            move |raw| {
                assert!(raw.len() <= 80);
                credit
                    .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                        n.checked_sub(raw.len())
                    })
                    .map_err(|_| TelemetryError::Io("side tx busy"))?;
                output.lock().unwrap().push(raw.to_vec());
                // Finite accepted work consumes the public dispatch budget, so a
                // pre-policy pass services one real owner instead of draining all.
                callback_time.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            options.clone(),
        );
        router.clear_tx_queue();
        router.set_latest_value_side(Some(side)).unwrap();
        let mut expected_catalogs = Vec::new();
        for n in 0..4 {
            let catalog =
                crate::discovery::build_discovery_schema(&format!("STARTUP_LATE_CAT_{n}"), 0)
                    .unwrap();
            crate::discovery::decode_discovery_schema(&catalog).unwrap();
            assert!(catalog.data_size() > 160);
            expected_catalogs.push((catalog.packet_id(), catalog.payload().to_vec()));
            let mut owner = queued(side, RouterItem::Packet(catalog));
            owner.priority = crate::transport_priority(DataType::DiscoverySchema);
            router.state.lock().push_transmit(owner).unwrap();
        }
        for _ in 0..4 {
            allowance.store(80, Ordering::SeqCst);
            router.dispatch_tx_queue_with_timeout(1).unwrap();
            now.fetch_add(1, Ordering::SeqCst);
        }
        let first_frames = core::mem::take(&mut *accepted.lock().unwrap());
        assert_eq!(
            first_frames.len(),
            4,
            "one actual accepted prefix per pre-policy turn"
        );
        let transfers: std::collections::BTreeSet<_> = first_frames
            .iter()
            .map(|raw| {
                assert!(raw.starts_with(b"SDT\x03"));
                u32::from_le_bytes(raw[4..8].try_into().unwrap())
            })
            .collect();
        assert!(
            matches!(transfers.len(), 3 | 4),
            "baseline opens four; reserve-one candidate may open three, keeping fourth queued"
        );
        let initial_progress = format!(
            "{:?}",
            router
                .state
                .lock()
                .side_transport
                .get(&side)
                .unwrap()
                .tx_chunk_progress
        );
        let live_cursors = initial_progress.matches("Some(SideTxCursor").count();
        assert!(
            matches!(live_cursors, 3 | 4),
            "explicit startup reservation boundary: baseline four vs candidate three"
        );
        let queued_catalog_count = router
            .state
            .lock()
            .transmit_queue
            .iter()
            .filter(|q| match &q.item {
                RouterTxItem::ToSide {
                    data: RouterItem::Packet(p),
                    ..
                } => p.data_type() == DataType::DiscoverySchema,
                _ => false,
            })
            .count();
        assert_eq!(
            queued_catalog_count, 4,
            "reservation must retain the unstarted fourth original catalog"
        );
        assert_eq!(
            now.load(Ordering::SeqCst),
            8,
            "same fixed injection time, not after a convenient completion"
        );
        assert!(
            router.state.lock().latest_turn_credit > 0,
            "accepted canonical frames really earned the fresh turn"
        );
        let (ty, ep) = schema(
            "CAPACITY_STARTUP_LATE_FRAGMENTED_FRESH",
            crate::ReliableMode::None,
            0,
        );
        let original = Packet::new_with_nonce(
            ty,
            &[ep],
            "FC",
            now.load(Ordering::SeqCst),
            7,
            Arc::from(vec![0x55; 1024]),
        )
        .unwrap();
        assert!(
            router
                .queue_latest_egress(side, None, &RouterItem::Packet(original.clone()))
                .unwrap()
        );
        let time = now.clone();
        let receiver = Router::new_with_clock(
            RouterConfig::new([]).with_sender("GS"),
            Box::new(move || time.load(Ordering::SeqCst)),
        );
        let input = receiver.add_side_packed_with_options("finite-radio", |_| Ok(()), options);
        for frame in &first_frames {
            assert!(
                receiver
                    .decode_side_transport_frame(input, frame)
                    .unwrap()
                    .is_none()
            );
        }
        let mut completed_catalogs = Vec::new();
        let mut original_received = false;
        let mut errors = Vec::new();
        let mut events = Vec::new();
        for _ in 0..5000 {
            allowance.store(80, Ordering::SeqCst);
            let at = now.load(Ordering::SeqCst);
            let result = router.dispatch_tx_queue_with_timeout(1);
            for frame in core::mem::take(&mut *accepted.lock().unwrap()) {
                if let Some(raw) = receiver.decode_side_transport_frame(input, &frame).unwrap() {
                    let p = wire_format::unpack_packet(&raw).unwrap();
                    if p.data_type() == DataType::DiscoverySchema {
                        completed_catalogs.push((p.packet_id(), p.payload().to_vec()));
                    }
                    if p.packet_id() == original.packet_id() {
                        assert_eq!(
                            p, original,
                            "actual independent receiver gets the exact large fresh owner"
                        );
                        assert!(!original_received, "large original completes only once");
                        assert!(
                            now.load(Ordering::SeqCst)
                                .saturating_sub(original.timestamp())
                                <= 1500,
                            "original source-forward age gate is unchanged"
                        );
                        original_received = true;
                    }
                }
            }
            let st = router.state.lock();
            let large_owners = st
                .transmit_queue
                .iter()
                .filter(|q| match &q.item {
                    RouterTxItem::ToSide {
                        data: RouterItem::Packet(p),
                        ..
                    } => p.packet_id() == original.packet_id(),
                    _ => false,
                })
                .count();
            let markers = st
                .transmit_queue
                .iter()
                .filter(|q| q.disposable & TX_LATEST_TURN != 0)
                .count();
            events.push((
                at,
                format!("{result:?}"),
                st.latest_turn_credit,
                large_owners,
                markers,
                format!(
                    "{:?}",
                    st.side_transport.get(&side).unwrap().tx_chunk_progress
                ),
            ));
            drop(st);
            if let Err(error) = result {
                errors.push((at, error));
                break;
            }
            if original_received && completed_catalogs.len() == expected_catalogs.len() {
                break;
            }
            now.fetch_add(1, Ordering::SeqCst);
        }
        eprintln!(
            "STARTUP_LATE_FRAGMENTED_FRESH original_id={} initial_progress={} errors={errors:?} original_received={original_received} completed_catalogs={} events={events:#?}",
            original.packet_id(),
            initial_progress,
            completed_catalogs.len()
        );
        assert!(
            errors.is_empty(),
            "an earned fragmented fresh owner must survive full catalog cursor capacity without terminal loss"
        );
        assert!(
            original_received,
            "a waiting latest marker must not pin ahead of live catalog continuations until expiry"
        );
        expected_catalogs.sort_by_key(|x| x.0);
        completed_catalogs.sort_by_key(|x| x.0);
        assert_eq!(
            completed_catalogs, expected_catalogs,
            "every exact original catalog also completes once"
        );
    }
    #[test]
    #[cfg(feature = "discovery")]
    fn partially_admitted_report_with_three_catalogs_keeps_cursor_ownership() {
        use std::sync::Mutex;
        use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
        let now = Arc::new(AtomicU64::new(0));
        let time = now.clone();
        let memory = crate::config::RuntimeMemoryConfig::new(1024 * 1024, 128, 4096, 1.5).unwrap();
        let router = Router::new_with_clock(
            RouterConfig::new([])
                .with_sender("RF")
                .with_memory_config(memory)
                .unwrap(),
            Box::new(move || time.load(Ordering::SeqCst)),
        );
        let allowance = Arc::new(AtomicUsize::new(80));
        let credit = allowance.clone();
        let accepted = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let output = accepted.clone();
        let callback_time = now.clone();
        let options = RouterSideOptions::default().with_small_packet_transport(80);
        let side = router.add_side_packed_with_options(
            "finite-radio",
            move |raw| {
                assert!(raw.len() <= 80);
                credit
                    .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                        n.checked_sub(raw.len())
                    })
                    .map_err(|_| TelemetryError::Io("side tx busy"))?;
                output.lock().unwrap().push(raw.to_vec());
                // Finite accepted work consumes the public dispatch budget, so a
                // pre-policy pass services one real owner instead of draining all.
                callback_time.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            options.clone(),
        );
        router.clear_tx_queue();
        assert_eq!(router.state.lock().latest_side(), None);
        let mut expected_catalogs = Vec::new();
        for n in 0..3 {
            let catalog =
                crate::discovery::build_discovery_schema(&format!("PARTIAL_CAT_{n}"), 0).unwrap();
            crate::discovery::decode_discovery_schema(&catalog).unwrap();
            assert!(catalog.data_size() > 160);
            expected_catalogs.push((catalog.packet_id(), catalog.payload().to_vec()));
            let mut owner = queued(side, RouterItem::Packet(catalog));
            owner.priority = crate::transport_priority(DataType::DiscoverySchema);
            router.state.lock().push_transmit(owner).unwrap();
        }
        for _ in 0..3 {
            allowance.store(80, Ordering::SeqCst);
            router.dispatch_tx_queue_with_timeout(1).unwrap();
            now.fetch_add(1, Ordering::SeqCst);
        }
        let first_frames = core::mem::take(&mut *accepted.lock().unwrap());
        assert_eq!(
            first_frames.len(),
            3,
            "one actual accepted prefix per pre-policy turn"
        );
        let transfers: std::collections::BTreeSet<_> = first_frames
            .iter()
            .map(|raw| {
                assert!(raw.starts_with(b"SDT\x03"));
                u32::from_le_bytes(raw[4..8].try_into().unwrap())
            })
            .collect();
        assert_eq!(
            transfers.len(),
            3,
            "three different original catalog transfers actually started"
        );
        let initial_progress = format!(
            "{:?}",
            router
                .state
                .lock()
                .side_transport
                .get(&side)
                .unwrap()
                .tx_chunk_progress
        );
        assert_eq!(
            initial_progress.matches("Some(SideTxCursor").count(),
            3,
            "the negative precondition is three real live cursors, never fabricated state"
        );
        router.set_latest_value_side(Some(side)).unwrap();
        assert_eq!(
            router.state.lock().latest_turn_credit,
            0,
            "policy enable does not invent credit"
        );
        let (ty, ep) = schema("CAPACITY_PARTIAL_THREE_FRESH", crate::ReliableMode::None, 0);
        let original = Packet::new_with_nonce(
            ty,
            &[ep],
            "FC",
            now.load(Ordering::SeqCst),
            7,
            Arc::from(vec![0x55; 1024]),
        )
        .unwrap();
        assert!(
            router
                .queue_latest_egress(side, None, &RouterItem::Packet(original.clone()))
                .unwrap()
        );
        let time = now.clone();
        let receiver = Router::new_with_clock(
            RouterConfig::new([]).with_sender("GS"),
            Box::new(move || time.load(Ordering::SeqCst)),
        );
        let input = receiver.add_side_packed_with_options("finite-radio", |_| Ok(()), options);
        for frame in &first_frames {
            assert!(
                receiver
                    .decode_side_transport_frame(input, frame)
                    .unwrap()
                    .is_none()
            );
        }
        let mut fresh_started = false;
        let mut saw_full_cursor_capacity = false;
        let mut completed_catalogs = Vec::new();
        let mut original_received = false;
        let mut errors = Vec::new();
        let mut events = Vec::new();
        for _ in 0..5000 {
            allowance.store(80, Ordering::SeqCst);
            let at = now.load(Ordering::SeqCst);
            let result = router.dispatch_tx_queue_with_timeout(1);
            for frame in core::mem::take(&mut *accepted.lock().unwrap()) {
                if frame.starts_with(b"SDT\x03") {
                    let transfer = u32::from_le_bytes(frame[4..8].try_into().unwrap());
                    if transfers.contains(&transfer) {
                        assert!(
                            !fresh_started || original_received,
                            "an admitted fragmented fresh owner must finish before canonical turns resume, even with all four cursors live"
                        );
                    } else {
                        fresh_started = true;
                        let progress = format!(
                            "{:?}",
                            router
                                .state
                                .lock()
                                .side_transport
                                .get(&side)
                                .unwrap()
                                .tx_chunk_progress
                        );
                        saw_full_cursor_capacity |=
                            progress.matches("Some(SideTxCursor").count() == 4;
                    }
                }
                if let Some(raw) = receiver.decode_side_transport_frame(input, &frame).unwrap() {
                    let p = wire_format::unpack_packet(&raw).unwrap();
                    if p.data_type() == DataType::DiscoverySchema {
                        completed_catalogs.push((p.packet_id(), p.payload().to_vec()));
                    }
                    if p.packet_id() == original.packet_id() {
                        assert_eq!(
                            p, original,
                            "actual independent receiver gets the exact large fresh owner"
                        );
                        assert!(!original_received, "large original completes only once");
                        assert!(
                            now.load(Ordering::SeqCst)
                                .saturating_sub(original.timestamp())
                                <= 1500,
                            "original source-forward age gate is unchanged"
                        );
                        original_received = true;
                    }
                }
            }
            let st = router.state.lock();
            let large_owners = st
                .transmit_queue
                .iter()
                .filter(|q| match &q.item {
                    RouterTxItem::ToSide {
                        data: RouterItem::Packet(p),
                        ..
                    } => p.packet_id() == original.packet_id(),
                    _ => false,
                })
                .count();
            let markers = st
                .transmit_queue
                .iter()
                .filter(|q| q.disposable & TX_LATEST_TURN != 0)
                .count();
            events.push((
                at,
                format!("{result:?}"),
                st.latest_turn_credit,
                large_owners,
                markers,
                format!(
                    "{:?}",
                    st.side_transport.get(&side).unwrap().tx_chunk_progress
                ),
            ));
            drop(st);
            if let Err(error) = result {
                errors.push((at, error));
                break;
            }
            if original_received && completed_catalogs.len() == expected_catalogs.len() {
                break;
            }
            now.fetch_add(1, Ordering::SeqCst);
        }
        eprintln!(
            "LATE_FRAGMENTED_FRESH original_id={} initial_progress={} errors={errors:?} original_received={original_received} completed_catalogs={} events={events:#?}",
            original.packet_id(),
            initial_progress,
            completed_catalogs.len()
        );
        assert!(
            errors.is_empty(),
            "an earned fragmented fresh owner must survive full catalog cursor capacity without terminal loss"
        );
        assert!(
            original_received,
            "a waiting latest marker must not pin ahead of live catalog continuations until expiry"
        );
        assert!(
            fresh_started && saw_full_cursor_capacity,
            "actual partial fresh report shares four live slots with three catalogs"
        );
        expected_catalogs.sort_by_key(|x| x.0);
        completed_catalogs.sort_by_key(|x| x.0);
        assert_eq!(
            completed_catalogs, expected_catalogs,
            "every exact original catalog also completes once"
        );
    }

    #[test]
    fn scoped_packet_ids_match_public_and_wire_identity() {
        let (ty, ep) = schema("SCOPED_ID_EQUIVALENCE", crate::ReliableMode::None, 0);
        let other = crate::config::register_endpoint("SCOPED_ID_OTHER_ENDPOINT", false).unwrap();
        for size in [0, 1, 16, 128, 4096] {
            for timestamp in [0, 127, 65536, 1_767_225_600_000] {
                let mut original = Packet::new_with_nonce(
                    ty,
                    &[other, ep, other],
                    "SOURCE",
                    timestamp,
                    19,
                    Arc::from((0..size).map(|index| index as u8).collect::<Vec<_>>()),
                )
                .unwrap();
                let expected = original.packet_id();
                original.park_for_queue().unwrap();
                assert_eq!(original.scoped_packet_id().unwrap(), expected);
                let raw = wire_format::pack_packet(&original);
                assert_eq!(wire_format::packet_id_from_wire(&raw).unwrap(), expected);
                let decoded = wire_format::unpack_packet(&raw).unwrap();
                assert_eq!(decoded.scoped_packet_id().unwrap(), expected);
            }
        }
    }

    #[test]
    fn cursor_latest_provenance_survives_retry_but_not_new_owner_or_expiry() {
        let mut progress = crate::side_transport::SideTxProgress::default();
        let busy: TelemetryResult<()> = Err(TelemetryError::Io("side tx busy"));
        assert_eq!(progress.begin_classified(11, 10, false, true).unwrap(), 0);
        progress.finish(11, 1, 10, &busy);
        assert!(progress.has_live_latest_owner(10));
        assert_eq!(progress.begin_classified(11, 11, false, false).unwrap(), 1);
        assert!(
            progress.has_live_latest_owner(11),
            "retry cannot erase ownership"
        );
        progress.clear_latest_owner();
        assert!(!progress.has_live_latest_owner(11));
        assert!(
            progress.has_live_key(11, 11),
            "clearing provenance never clears bytes/progress"
        );
        assert_eq!(progress.begin_classified(12, 20, true, true).unwrap(), 0);
        progress.finish(12, 1, 20, &busy);
        assert!(progress.has_live_latest_owner(2020));
        assert!(!progress.has_live_latest_owner(2021));
        assert!(progress.has_available_slot(2021));
        assert_eq!(
            progress.begin_classified(13, 2021, false, false).unwrap(),
            0
        );
        assert!(
            !progress.has_live_latest_owner(2021),
            "expired classification is not inherited"
        );
    }

    #[test]
    #[cfg(feature = "compact-packet-store")]
    fn saturated_cursor_selection_and_scoped_ids_never_retain_arena_pins() {
        let original =
            wire_format::unpack_packet(include_bytes!("tests/captured-local-gs.bin")).unwrap();
        let store = crate::packet_store::PacketStore::new(65536, 16, usize::MAX).unwrap();
        let stored = store.store(original.payload()).unwrap();
        let (router, side) = setup();
        router.set_latest_value_side(Some(side)).unwrap();
        {
            let mut state = router.state.lock();
            state.sides[side].as_mut().unwrap().opts =
                RouterSideOptions::default().with_small_packet_transport(80);
            let mut progress = crate::side_transport::SideTxProgress::default();
            for nonce in 1..=4 {
                let plain = Packet::new_with_nonce(
                    original.data_type(),
                    original.endpoints(),
                    &format!("SCOPED_CATALOG_{nonce}"),
                    original.timestamp(),
                    nonce,
                    Arc::from(original.payload()),
                )
                .unwrap();
                let expected = plain.packet_id();
                let payload = crate::config::StandardSmallPayload::Managed(
                    crate::packet_store::ParkedPayload::new(stored.clone()),
                );
                let mut managed = Packet::new_with_owned_wire_contract(
                    original.data_type(),
                    Arc::from(original.endpoints()),
                    Arc::from(plain.sender()),
                    original.timestamp(),
                    nonce,
                    payload,
                    None,
                    None,
                )
                .unwrap();
                managed.park_for_queue().unwrap();
                assert_eq!(managed.scoped_packet_id().unwrap(), expected);
                let key = crate::side_transport::canonical_packet_progress_key(expected, 80);
                progress.begin_classified(key, 0, false, false).unwrap();
                progress.finish(key, 1, 0, &Err::<(), _>(TelemetryError::Io("side tx busy")));
                let mut owner = queued(side, RouterItem::Packet(managed));
                owner.disposable = TX_HISTORY_OWNED | TX_CANONICAL_SERVED;
                state.push_transmit(owner).unwrap();
            }
            state
                .side_transport
                .entry(side)
                .or_default()
                .tx_chunk_progress = Some(Box::new(progress));
            assert_eq!(
                state.transmit_queue.len(),
                4,
                "four distinct source owners avoid legitimate schema-snapshot coalescence"
            );
            let before = store.stats();
            assert_eq!(before.pinned_bytes, 0);
            let queue_bytes = state.transmit_queue.bytes_used();
            for _ in 0..1000 {
                assert!(
                    state
                        .latest_turn_selection(true, 0)
                        .is_some_and(|index| index != usize::MAX)
                );
                let stats = store.stats();
                assert_eq!(stats.pinned_bytes, 0);
                assert_eq!(stats.live_bytes, before.live_bytes);
                assert_eq!(stats.live_handles, before.live_handles);
                assert_eq!(state.transmit_queue.bytes_used(), queue_bytes);
            }
        }
        drop(router);
        drop(stored);
        assert_eq!(store.stats().live_handles, 0);
        assert_eq!(store.stats().live_bytes, 0);
        assert_eq!(store.stats().pinned_bytes, 0);
    }

    #[cfg(feature = "discovery")]
    fn fragmented_forwarding_control_and_latest_share_capacity(control_first: bool) {
        use std::sync::{
            Mutex,
            atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        };
        let now = Arc::new(AtomicU64::new(0));
        let clock = now.clone();
        let memory = crate::config::RuntimeMemoryConfig::new(1024 * 1024, 128, 4096, 1.5).unwrap();
        let router = Router::new_with_clock(
            RouterConfig::new([])
                .with_sender("RF")
                .with_memory_config(memory)
                .unwrap(),
            Box::new(move || clock.load(Ordering::SeqCst)),
        );
        let allowance = Arc::new(AtomicUsize::new(80));
        let credit = allowance.clone();
        let accepted = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let output = accepted.clone();
        let control_started = Arc::new(AtomicBool::new(false));
        let started = control_started.clone();
        let clock = now.clone();
        let options = RouterSideOptions::default().with_small_packet_transport(80);
        let side = router.add_side_packed_with_priority_and_options(
            "finite-radio",
            move |raw, priority| {
                assert!(raw.len() <= 80);
                // Declared driver refusal after the first control prefix. This is
                // an ownership test, not a physical-RFD latency benchmark.
                if priority == 255
                    && started.load(Ordering::SeqCst)
                    && clock.load(Ordering::SeqCst) < 100
                {
                    return Err(TelemetryError::Io("side tx busy"));
                }
                credit
                    .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                        n.checked_sub(raw.len())
                    })
                    .map_err(|_| TelemetryError::Io("side tx busy"))?;
                if priority == 255 {
                    started.store(true, Ordering::SeqCst);
                }
                output.lock().unwrap().push(raw.to_vec());
                clock.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            options.clone(),
        );
        router.clear_tx_queue();
        let suffix = if control_first {
            "CONTROL_FIRST"
        } else {
            "FRESH_FIRST"
        };
        let (fresh_ty, fresh_ep) = schema(
            &format!("CAPACITY_FRESH_{suffix}"),
            crate::ReliableMode::None,
            0,
        );
        let (control_ty, control_ep) = schema(
            &format!("CAPACITY_CONTROL_{suffix}"),
            crate::ReliableMode::Ordered,
            255,
        );
        let control = Packet::new_with_owned_wire_contract(
            control_ty,
            Arc::from([control_ep]),
            Arc::from("SOURCE"),
            0,
            91,
            crate::config::StandardSmallPayload::from_arc(Arc::from(vec![0x33; 512])),
            Some(MessageElement::Dynamic(
                crate::MessageDataType::UInt8,
                crate::MessageClass::Data,
            )),
            Some(Arc::from([0x1919u64])),
        )
        .unwrap();
        let mut expected_catalogs = Vec::new();
        for n in 0..3 {
            let catalog =
                discovery::build_discovery_schema(&format!("CONTROL_CAT_{suffix}_{n}"), 0).unwrap();
            expected_catalogs.push((catalog.packet_id(), catalog.payload().to_vec()));
            let mut item = queued(side, RouterItem::Packet(catalog));
            item.priority = crate::transport_priority(DataType::DiscoverySchema);
            router.state.lock().push_transmit(item).unwrap();
        }
        for _ in 0..3 {
            allowance.store(80, Ordering::SeqCst);
            router.dispatch_tx_queue_with_timeout(1).unwrap();
            now.fetch_add(1, Ordering::SeqCst);
        }
        let prefixes = core::mem::take(&mut *accepted.lock().unwrap());
        assert_eq!(prefixes.len(), 3);
        let catalog_transfers: std::collections::BTreeSet<_> = prefixes
            .iter()
            .map(|raw| u32::from_le_bytes(raw[4..8].try_into().unwrap()))
            .collect();
        assert_eq!(catalog_transfers.len(), 3);
        router.set_latest_value_side(Some(side)).unwrap();
        let fresh = Packet::new_with_nonce(
            fresh_ty,
            &[fresh_ep],
            "FC",
            now.load(Ordering::SeqCst),
            7,
            Arc::from(vec![0x55; 1024]),
        )
        .unwrap();
        // Earned credit is actual canonical admission, never seeded numerically.
        allowance.store(80, Ordering::SeqCst);
        router.dispatch_tx_queue_with_timeout(1).unwrap();
        let mut pending_frames = prefixes;
        pending_frames.extend(core::mem::take(&mut *accepted.lock().unwrap()));
        let queue_control = || {
            let mut item = queued(side, RouterItem::Packet(control.clone()));
            // Exact forwarding-stage frozen owner: non-disposable, no minted
            // latest service tag, original wire shape and receipt targets.
            item.disposable = 0;
            item.priority = 255;
            router.state.lock().push_transmit(item).unwrap();
        };
        if control_first {
            queue_control();
        } else {
            assert!(
                router
                    .queue_latest_egress(side, None, &RouterItem::Packet(fresh.clone()))
                    .unwrap()
            );
        }
        let mut first_transfer = None;
        for _ in 0..32 {
            allowance.store(80, Ordering::SeqCst);
            router.dispatch_tx_queue_with_timeout(1).unwrap();
            for raw in core::mem::take(&mut *accepted.lock().unwrap()) {
                if raw.starts_with(b"SDT\x03") {
                    let transfer = u32::from_le_bytes(raw[4..8].try_into().unwrap());
                    if !catalog_transfers.contains(&transfer) {
                        first_transfer = Some(transfer);
                    }
                }
                pending_frames.push(raw);
            }
            if first_transfer.is_some() {
                break;
            }
            now.fetch_add(1, Ordering::SeqCst);
        }
        let first_transfer = first_transfer.expect("first fragmented owner actually starts");
        assert_eq!(
            format!(
                "{:?}",
                router
                    .state
                    .lock()
                    .side_transport
                    .get(&side)
                    .unwrap()
                    .tx_chunk_progress
            )
            .matches("Some(SideTxCursor")
            .count(),
            4
        );
        if control_first {
            assert!(
                router
                    .queue_latest_egress(side, None, &RouterItem::Packet(fresh.clone()))
                    .unwrap()
            );
        } else {
            queue_control();
        }
        let clock = now.clone();
        let receiver = Router::new_with_clock(
            RouterConfig::new([]).with_sender("RECEIVER"),
            Box::new(move || clock.load(Ordering::SeqCst)),
        );
        let input = receiver.add_side_packed_with_options("finite-radio", |_| Ok(()), options);
        let mut fresh_started = false;
        let mut fresh_received = false;
        let mut control_received = false;
        let mut catalogs = Vec::new();
        let mut saw_blocked_control_owner = false;
        for _ in 0..5000 {
            for raw in core::mem::take(&mut pending_frames) {
                if raw.starts_with(b"SDT\x03") {
                    let transfer = u32::from_le_bytes(raw[4..8].try_into().unwrap());
                    let is_fresh = if control_first {
                        !catalog_transfers.contains(&transfer) && transfer != first_transfer
                    } else {
                        transfer == first_transfer
                    };
                    if is_fresh {
                        fresh_started = true;
                    }
                    if catalog_transfers.contains(&transfer) {
                        assert!(
                            !fresh_started || fresh_received,
                            "partial fresh cursor keeps serialization ahead of catalogs"
                        );
                    }
                }
                if let Some(wire) = receiver.decode_side_transport_frame(input, &raw).unwrap() {
                    let p = wire_format::unpack_packet(&wire).unwrap();
                    if p.data_type() == DataType::DiscoverySchema {
                        catalogs.push((p.packet_id(), p.payload().to_vec()));
                    }
                    if p.packet_id() == fresh.packet_id() {
                        assert_eq!(p, fresh);
                        assert!(!fresh_received);
                        assert!(
                            now.load(Ordering::SeqCst).saturating_sub(fresh.timestamp()) <= 1500
                        );
                        fresh_received = true;
                    }
                    if p.packet_id() == control.packet_id() {
                        assert!(!control_received);
                        assert_eq!(p.payload(), control.payload());
                        assert_eq!(p.wire_shape(), control.wire_shape());
                        assert_eq!(p.wire_target_senders(), control.wire_target_senders());
                        control_received = true;
                    }
                }
            }
            if !control_received {
                let state = router.state.lock();
                let count = state
                    .transmit_queue
                    .iter()
                    .filter(|q| q.priority == 255 && q.disposable & TX_DISPOSABLE == 0)
                    .count();
                assert_eq!(
                    count, 1,
                    "accepted untagged protected forwarding owner stays queued until fully handed off"
                );
                saw_blocked_control_owner |= now.load(Ordering::SeqCst) < 100;
            }
            if fresh_received && control_received && catalogs.len() == expected_catalogs.len() {
                break;
            }
            allowance.store(80, Ordering::SeqCst);
            router.dispatch_tx_queue_with_timeout(1).unwrap();
            pending_frames.extend(core::mem::take(&mut *accepted.lock().unwrap()));
            now.fetch_add(1, Ordering::SeqCst);
        }
        assert!(saw_blocked_control_owner && control_received && fresh_received);
        catalogs.sort_by_key(|x| x.0);
        expected_catalogs.sort_by_key(|x| x.0);
        assert_eq!(catalogs, expected_catalogs);
        // Decoder reconstruction is not an application receipt; no ACK was
        // fabricated and this fixture makes no end-to-end confirmation claim.
    }
    #[test]
    #[cfg(feature = "discovery")]
    fn protected_fragmented_control_before_large_fresh_retains_all_owned_bytes() {
        fragmented_forwarding_control_and_latest_share_capacity(true);
    }
    #[test]
    #[cfg(feature = "discovery")]
    fn protected_fragmented_control_after_large_fresh_retains_all_owned_bytes() {
        fragmented_forwarding_control_and_latest_share_capacity(false);
    }

    #[test]
    fn reentrant_rebind_cannot_resurrect_an_old_cursor_service_classification() {
        let (router, side) = setup();
        router.set_latest_value_side(Some(side)).unwrap();
        {
            let mut state = router.state.lock();
            state.latest_service_seq = 100;
            state.latest_turn_phase = 4;
            state.side_transport.entry(side).or_default();
        }
        let service = EgressService {
            token: 100,
            side: side as u8 + 1,
            kind: 2,
        };
        // Private reservation-boundary test. No physical write, receipt, or
        // delivery completion is synthesized by these zero-prefix callbacks.
        let result: TelemetryResult<()> =
            router.run_side_chunk_transfer(side, 123, false, service, |_next| {
                assert!(
                    router
                        .state
                        .lock()
                        .side_transport
                        .get(&side)
                        .unwrap()
                        .tx_chunk_progress
                        .as_ref()
                        .unwrap()
                        .has_live_latest_owner(0)
                );
                router.set_latest_value_side(None).unwrap();
                router.set_latest_value_side(Some(side)).unwrap();
                assert!(
                    !router
                        .state
                        .lock()
                        .side_transport
                        .get(&side)
                        .unwrap()
                        .tx_chunk_progress
                        .as_ref()
                        .unwrap()
                        .has_live_latest_owner(0)
                );
                Err(TelemetryError::Io("side tx busy"))
            });
        assert!(result.is_err());
        router
            .run_side_chunk_transfer(side, 124, false, service, |_next| {
                assert!(
                    !router
                        .state
                        .lock()
                        .side_transport
                        .get(&side)
                        .unwrap()
                        .tx_chunk_progress
                        .as_ref()
                        .unwrap()
                        .has_live_latest_owner(0),
                    "stale token/phase cannot claim a newly allocated cursor"
                );
                Ok(())
            })
            .unwrap();
        assert!(
            router
                .state
                .lock()
                .side_transport
                .get(&side)
                .unwrap()
                .tx_chunk_progress
                .as_ref()
                .unwrap()
                .is_idle()
        );
    }
}
