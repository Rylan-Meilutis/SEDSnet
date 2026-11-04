//! Local, non-protocol Ordered side continuations. One active group per type;
//! the normal claimed Broadcast slot becomes the first child, not a parent.
//! IDs/UTC stay in immutable data; grouping/claim matching never parses payload.
use super::*;

pub(super) struct ClaimUnwind<'a> {
    pub(super) router: &'a Router,
    pub(super) claim: Option<TxClaim>,
    pub(super) armed: bool,
    pub(super) cancel_original: bool,
}
impl Drop for ClaimUnwind<'_> {
    fn drop(&mut self) {
        if self.armed
            && let Some(claim) = self.claim
        {
            let mut st = self.router.state.lock();
            if let Some(index) = st.claim_index(claim.token)
                && let Some(row) = st.transmit_queue.get(index)
                && (RouterInner::local_ordered_side(row)
                    || (self.cancel_original
                        && row.delivery_state == QueuedDelivery::ClaimedOrdered
                        && matches!(&row.item, RouterTxItem::Broadcast(_))))
            {
                let ty = row.accepted_type;
                st.cancel_accepted_type(ty);
                st.refresh_retry_hint();
            }
        }
    }
}
// Covers all preclaimed siblings, including a panic before their first send.
// Exact tokens fence cleanup from a newer same-type group after cancellation.
struct LocalGroupUnwind<'a> {
    router: &'a Router,
    work: &'a [(RouterTxItem, TxClaim)],
    armed: bool,
}
impl Drop for LocalGroupUnwind<'_> {
    fn drop(&mut self) {
        if !self.armed { return; }
        let mut st = self.router.state.lock();
        for (_, claim) in self.work {
            if let Some(index) = st.claim_index(claim.token)
                && let Some(row) = st.transmit_queue.get(index)
                && RouterInner::local_ordered_side(row)
            {
                let ty = row.accepted_type;
                st.cancel_accepted_type(ty);
                st.refresh_retry_hint();
                break;
            }
        }
    }
}

impl RouterInner {
    pub(super) fn local_ordered_side(row: &TxQueued) -> bool {
        row.disposable & TX_E2E_CHILD == 0
            && matches!(&row.item, RouterTxItem::ToSide { src: None, .. })
            && matches!(
                row.delivery_state,
                QueuedDelivery::LocalOrderedSide
                    | QueuedDelivery::DeferredLocalOrderedSide
                    | QueuedDelivery::ClaimedLocalOrderedSide
                    | QueuedDelivery::ClaimedAnchoredLocalOrderedSide
            )
    }
    pub(super) fn local_side_anchor(row: &TxQueued) -> Option<u64> {
        match row.delivery_state {
            QueuedDelivery::DeferredLocalOrderedSide => Some(row.deferred_since_ms),
            QueuedDelivery::ClaimedAnchoredLocalOrderedSide => Some(row.retry_after_ms),
            _ => None,
        }
    }
    fn anchor_local_ordered_group(&mut self, ty: u32, first: u64) {
        for index in 0..self.transmit_queue.len() {
            let row = self.transmit_queue.get(index).unwrap();
            if row.accepted_type != ty || !Self::local_ordered_side(row) {
                continue;
            }
            if let Some(anchor) = Self::local_side_anchor(row) {
                assert_eq!(anchor, first, "one immutable group anchor");
                continue;
            }
            self.transmit_queue.update_metadata(index, |row| {
                match row.delivery_state {
                    QueuedDelivery::LocalOrderedSide => {
                        row.delivery_state = QueuedDelivery::DeferredLocalOrderedSide;
                        row.deferred_since_ms = first;
                        row.retry_after_ms = 0; // Sibling remains immediately eligible.
                    }
                    QueuedDelivery::ClaimedLocalOrderedSide => {
                        // deferred_since remains the exact current claim token.
                        row.delivery_state = QueuedDelivery::ClaimedAnchoredLocalOrderedSide;
                        row.retry_after_ms = first;
                    }
                    _ => unreachable!("checked unanchored local sibling"),
                }
            });
        }
    }
    pub(super) fn promote_local_ordered_tail(&mut self, ty: u32) {
        if self
            .transmit_queue
            .iter()
            .any(|row| row.accepted_type == ty && Self::local_ordered_side(row))
        {
            return;
        }
        let next = self.transmit_queue.iter().position(|row| {
            row.accepted_type == ty && row.delivery_state == QueuedDelivery::OrderedTail
        });
        if let Some(next) = next {
            self.transmit_queue
                .update_metadata(next, |row| row.delivery_state = QueuedDelivery::Ordered);
        }
    }
}
impl Router {
    pub(super) fn local_ordered_candidate(
        &self,
        data: &RouterItem,
        ty: DataType,
    ) -> TelemetryResult<bool> {
        if !self.cfg.role.local_services()
            || is_internal_control_type(ty)
            || !matches!(reliable_mode(ty), crate::ReliableMode::Ordered)
        {
            return Ok(false);
        }
        let local = self.sender_arc();
        Ok(match data {
            RouterItem::Packet(packet) => {
                packet.sender() == local.as_ref() && packet.wire_target_senders().is_empty()
            }
            RouterItem::Packed(bytes) => {
                // CRC/shape-validated numeric identity works without std's
                // hostname registry. Do not decode/decrypt/hash payloads here.
                let frame = wire_format::peek_routing_frame_info(bytes.as_ref())?;
                frame.envelope.source_address == sender_address_u32(local.as_ref())
                    && frame.envelope.target_senders().len() == 0
            }
        })
    }
    pub(super) fn local_ordered_retired() -> TelemetryError {
        TelemetryError::HandlerError("local ordered claim retired before dispatch")
    }
    pub(super) fn dispatch_local_side_work(
        &self,
        item: RouterTxItem,
        context: &mut DispatchContext,
        called_from_queue: bool,
    ) -> TelemetryResult<()> {
        // Preserve the exact guard formerly installed by generic ToSide entry.
        #[cfg(feature = "std")]
        let _clear_retry_intent = self.retry_queued_intent(context.claim);
        let Some(claim) = context
            .claim
            .filter(|claim| claim.ordered && !claim.side_retry)
        else {
            return Err(Self::local_ordered_retired());
        };
        let result = match item {
            RouterTxItem::ToSide {
                src: None,
                dst,
                data,
            } => self.send_local_ordered_side(dst, data, context, called_from_queue),
            _ => Err(TelemetryError::BadArg),
        };
        if result.as_ref().is_err_and(Self::is_transient_tx_error) {
            context.mark_refused();
        }
        // Finish here even for the first converted side. The outer Broadcast
        // finisher then finds its old claim retired/deferred, never a child to
        // remove/promote twice. No E2E ownership flag is repurposed.
        self.finish_local_ordered_claim(claim, context, result)
    }

    #[allow(unused_mut)]
    #[cfg_attr(not(feature = "std"), inline(never))]
    pub(super) fn dispatch_direct_local_ordered(
        &self,
        mut data: RouterItem,
        ignore_local: bool,
    ) -> TelemetryResult<()> {
        let ty = Self::item_data_type(&data)?;
        #[cfg(feature = "compression")]
        if let RouterItem::Packed(bytes) = &mut data
            && bytes.first().is_some_and(|flags| flags & 0x11 == 1)
        {
            // The budget snapshot is the only Core operation in staging.
            // Decode/allocator admission happens outside Core, before any new
            // original ownership. Never leave compressed data for the legacy
            // push_transmit(None) codec helper to decode under the owner.
            let budget = { self.state.lock().memory.max_queue_budget };
            let raw = wire_format::payload_encoding_for_retention(bytes.as_ref(), budget)?
                .ok_or(TelemetryError::Io("compressed local original not prepared"))?;
            if raw.first().is_some_and(|flags| flags & 0x11 == 1) {
                return Err(TelemetryError::Io("compressed local original not prepared"));
            }
            *bytes = crate::shared_bytes::convert(raw);
        }
        let priority = self.item_service_priority(&data)?;
        let mut row = TxQueued {
            disposable: 0,
            item: RouterTxItem::Broadcast(data),
            ignore_local,
            priority,
            delivery_state: QueuedDelivery::Ordered,
            accepted_type: ty.as_u32(),
            deferred_since_ms: 0,
            retry_after_ms: 0,
        };
        let work = {
            let mut st = self.state.lock();
            let older = st.transmit_queue.iter().find_map(|queued| {
                (RouterInner::ordered_original_type(queued) == Some(ty)).then_some(queued.priority)
            });
            #[cfg(feature = "std")]
            let can_claim = self
                .active_queued_tx
                .load(core::sync::atomic::Ordering::Acquire)
                != usize::MAX;
            #[cfg(not(feature = "std"))]
            let can_claim = true;
            let mut token = st.ordered_claim_seq.wrapping_add(1).max(1);
            while st.claim_index(token).is_some() {
                token = token.wrapping_add(1).max(1);
            }
            if let Some(priority) = older {
                row.priority = priority;
                row.delivery_state = QueuedDelivery::OrderedTail;
            } else if can_claim {
                row.delivery_state = QueuedDelivery::ClaimedOrdered;
                row.deferred_since_ms = u64::from(token);
            }
            let claimed = row.delivery_state == QueuedDelivery::ClaimedOrdered;
            // Admission and the final same-type race check share Core. The
            // legacy queue's capacity/protection policy remains authoritative.
            st.push_transmit(row)?;
            let work = if claimed {
                st.ordered_claim_seq = token;
                st.tx_policy_flags |= 1;
                let index = st.claim_index(token).expect("new claimed original");
                Some(TxWork {
                    queued: st.transmit_queue.get(index).unwrap().clone(),
                    claim: Some(TxClaim {
                        token,
                        ordered: true,
                        side_retry: false,
                    }),
                    owed_turn: false,
                    #[cfg(feature = "latest-value-egress")]
                    service: EgressService::default(),
                })
            } else {
                None
            };
            #[cfg(feature = "std")]
            let work = self.track_queued_tx(&mut st, work);
            work
        };
        let Some(work) = work else {
            return Ok(());
        };
        #[cfg(feature = "std")]
        let (work, _activity) = work;
        let mut unwind = ClaimUnwind {
            router: self,
            claim: work.claim,
            armed: true,
            cancel_original: true,
        };
        #[cfg(all(test, feature = "std", feature = "discovery"))]
        if let RouterTxItem::Broadcast(data) = &work.queued.item {
            managed_order_side_gate_causal::after_tail_guard(self, data, false, ignore_local);
        }
        let result = self.dispatch_queued_item_with_origin(work, false);
        unwind.armed = false;
        result
    }

    fn side_row_cost(row: &TxQueued) -> usize {
        let RouterTxItem::ToSide { data, .. } = &row.item else {
            return usize::MAX;
        };
        let payload = match data {
            RouterItem::Packet(packet) => packet.queue_byte_cost_saturated(),
            RouterItem::Packed(bytes) => {
                size_of::<crate::SharedBytes>().saturating_add(bytes.len())
            }
        };
        TxQueued::cost_with_item(payload)
    }
    #[cfg_attr(not(feature = "std"), inline(never))]
    pub(super) fn admit_local_ordered_group(
        &self,
        data: &RouterItem,
        sides: &[RouterSideId],
        claim: TxClaim,
        since: Option<u64>,
    ) -> TelemetryResult<Option<Vec<(RouterTxItem, TxClaim)>>> {
        let temporary_bytes = sides
            .len()
            .checked_mul(size_of::<(TxQueued, usize)>()
                .saturating_add(size_of::<usize>())
                .saturating_add(size_of::<(RouterTxItem, TxClaim)>()))
            .ok_or(TelemetryError::Io("memory pressure"))?;
        crate::memory_admission::check(temporary_bytes, temporary_bytes)?;
        let mut children = Vec::new();
        let mut costs = Vec::new();
        let mut work = Vec::new();
        work.try_reserve_exact(sides.len())
            .map_err(|_| TelemetryError::Io("memory pressure"))?;
        children
            .try_reserve_exact(sides.len())
            .map_err(|_| TelemetryError::Io("memory pressure"))?;
        costs
            .try_reserve_exact(sides.len())
            .map_err(|_| TelemetryError::Io("memory pressure"))?;
        for (n, side) in sides.iter().copied().enumerate() {
            #[allow(unused_mut)]
            let mut child = TxQueued {
                disposable: 0,
                item: RouterTxItem::ToSide {
                    src: None,
                    dst: side,
                    data: data.clone(),
                },
                ignore_local: true,
                priority: 0,
                // Unpublished staging row; every child is claimed atomically below.
                delivery_state: QueuedDelivery::LocalOrderedSide,
                deferred_since_ms: if n == 0 { u64::from(claim.token) } else { 0 },
                retry_after_ms: since.unwrap_or(0),
                accepted_type: 0,
            };
            #[cfg(feature = "compact-packet-store")]
            child.park_for_queue()?;
            let cost = Self::side_row_cost(&child);
            costs.push(cost);
            children.push((child, cost));
        }
        #[cfg(all(test, feature = "std", feature = "discovery"))]
        managed_order_side_gate_causal::before_local_group_accounting(self, claim);
        let mut st = self.state.lock();
        let Some(index) = st.claim_index(claim.token) else {
            return Ok(None);
        };
        let original = st.transmit_queue.get(index).unwrap();
        if original.delivery_state != QueuedDelivery::ClaimedOrdered
            || !matches!(&original.item, RouterTxItem::Broadcast(_))
        {
            return Err(TelemetryError::BadArg);
        }
        let ty = original.accepted_type;
        let priority = original.priority;
        let old_cost = original.byte_cost();
        assert!(
            !st.transmit_queue
                .iter()
                .any(|row| row.accepted_type == ty && RouterInner::local_ordered_side(row)),
            "one active local group per type"
        );
        for side in sides {
            Self::side_ref(&st, *side)?;
        }
        #[cfg(feature = "std")]
        let schema = crate::config::ordinary_schema_guard()
            .ok_or(TelemetryError::Io("memory pressure"))?;
        #[cfg(feature = "std")]
        let used = st.queued_packet_budget_used(&schema);
        #[cfg(not(feature = "std"))]
        let used = st.shared_queue_bytes_used();
        if used == usize::MAX
            || costs.contains(&usize::MAX)
            || used
                .checked_sub(old_cost)
                .and_then(|used| {
                    costs
                        .iter()
                        .try_fold(used, |used, cost| used.checked_add(*cost))
                })
                .is_none_or(|used| used > st.memory.max_queue_budget)
            || !st.transmit_queue.fits_replacement_group(index, &costs)
        {
            return Err(TelemetryError::Io("memory pressure"));
        }
        // Compute every token before publishing any converted row. Exhaustion
        // refuses the original intact; tokens never wrap into retired work.
        let mut next_token = st.ordered_claim_seq;
        for (n, (child, _)) in children.iter_mut().enumerate() {
            let token = if n == 0 { claim.token } else {
                loop {
                    next_token = next_token.checked_add(1).ok_or(
                        TelemetryError::HandlerError("local ordered claim tokens exhausted"))?;
                    if next_token != claim.token && st.claim_index(next_token).is_none() {
                        break next_token;
                    }
                }
            };
            child.delivery_state = if since.is_some() {
                QueuedDelivery::ClaimedAnchoredLocalOrderedSide
            } else { QueuedDelivery::ClaimedLocalOrderedSide };
            child.deferred_since_ms = u64::from(token);
            child.accepted_type = ty;
            child.priority = priority;
            work.push((child.item.clone(), TxClaim { token, ordered: true, side_retry: false }));
        }
        st.transmit_queue
            .replace_prepared_group(index, children, |row| row.priority);
        st.ordered_claim_seq = next_token;
        st.refresh_retry_hint();
        Ok(Some(work))
    }

    #[cfg_attr(not(feature = "std"), inline(never))]
    pub(super) fn dispatch_local_ordered_group(
        &self,
        data: RouterItem,
        sides: &[RouterSideId],
        context: &mut DispatchContext,
        called_from_queue: bool,
    ) -> TelemetryResult<()> {
        if sides.is_empty() {
            return Ok(());
        }
        let claim = context.claim.expect("checked original claim");
        match self.admit_local_ordered_group(&data, sides, claim, context.since) {
            Ok(Some(work)) => {
                let mut unwind = LocalGroupUnwind { router: self, work: &work, armed: true };
                let mut result = Ok(());
                for (item, claim) in &work {
                    let mut child = DispatchContext {
                        priority: context.priority,
                        claim: Some(*claim),
                        since: context.since,
                        #[cfg(feature = "latest-value-egress")]
                        latest_service: context.latest_service,
                        ..DispatchContext::default()
                    };
                    let sent = self.dispatch_local_side_work(item.clone(), &mut child, called_from_queue);
                    context.admitted |= child.admitted;
                    if child.refused() { context.mark_refused(); }
                    if sent.is_err() { result = sent; break; }
                }
                if result.is_err() { context.mark_terminal(); }
                else { unwind.armed = false; }
                result
            },
            Ok(None) => Err(Self::local_ordered_retired()),
            Err(error) if Self::is_transient_tx_error(&error) => {
                self.defer_accepted_original(context)
            }
            Err(error) => {
                context.mark_terminal();
                Err(error)
            }
        }
    }

    fn expire_local_ordered_claim(
        &self,
        ty: DataType,
        since: u64,
        claim: TxClaim,
    ) -> TelemetryResult<()> {
        let lifetime = runtime_reliable_retransmit_ms()
            .saturating_mul(u64::from(runtime_reliable_max_retries()) + 1);
        let now = self.clock.now_ms();
        let mut st = self.state.lock();
        let current = !claim.side_retry
            && claim.ordered
            && st
                .claim_index(claim.token)
                .and_then(|index| st.transmit_queue.get(index))
                .is_some_and(|row| {
                    RouterInner::local_ordered_side(row)
                        && row.delivery_state == QueuedDelivery::ClaimedAnchoredLocalOrderedSide
                        && row.accepted_type == ty.as_u32()
                        && row.retry_after_ms == since
                });
        if !current {
            return Err(TelemetryError::HandlerError(
                "local ordered claim retired before dispatch",
            ));
        }
        if now >= since && now - since < lifetime {
            return Ok(());
        }
        // Validation and this whole-group cancellation share the exact owner.
        // A canceled old work item can never cancel a newer same-type group.
        st.cancel_accepted_type(ty.as_u32());
        st.refresh_retry_hint();
        Err(TelemetryError::HandlerError(
            "accepted reliable delivery expired before dispatch",
        ))
    }

    #[allow(unused_mut)]
    #[cfg_attr(not(feature = "std"), inline(never))]
    pub(super) fn send_local_ordered_side(
        &self,
        side: RouterSideId,
        mut data: RouterItem,
        context: &mut DispatchContext,
        called_from_queue: bool,
    ) -> TelemetryResult<()> {
        let claim = context.claim.expect("checked local side claim");
        let ty = Self::item_data_type(&data)?;
        let current_anchor = {
            let st = self.state.lock();
            st.claim_index(claim.token)
                .and_then(|index| st.transmit_queue.get(index))
                .filter(|row| RouterInner::local_ordered_side(row))
                .map(RouterInner::local_side_anchor)
        };
        let Some(current_anchor) = current_anchor else {
            return Err(Self::local_ordered_retired());
        };
        context.since = current_anchor;
        if let Some(since) = context.since {
            #[cfg(all(test, feature = "std", feature = "discovery"))]
            managed_order_side_gate_causal::before_local_expiry(self, claim);
            self.expire_local_ordered_claim(ty, since, claim)?;
        }
        if !self.claim_schema_is_current(ty, Some(claim))? {
            return Err(Self::local_ordered_retired());
        }
        let allowed = {
            let st = self.state.lock();
            self.route_allowed_locked(&st, None, Some(ty), side)
        };
        if !allowed {
            return Err(TelemetryError::HandlerError(
                "local ordered side route revoked",
            ));
        }
        let admission = self.admit_side_tx(side)?;
        #[cfg(feature = "compression")]
        {
            let mut reservation = self.prepare_queued_payload(side, &mut data)?;
            if reservation.is_some() {
                let retained = {
                    let st = self.state.lock();
                    st.claim_index(claim.token)
                        .and_then(|index| st.transmit_queue.get(index).cloned())
                };
                let Some(mut row) = retained else {
                    return Err(Self::local_ordered_retired());
                };
                let RouterTxItem::ToSide { data: retained, .. } = &mut row.item else {
                    return Err(TelemetryError::BadArg);
                };
                *retained = data.clone();
                #[cfg(feature = "compact-packet-store")]
                row.park_for_queue()?;
                let cost = Self::side_row_cost(&row);
                let RouterTxItem::ToSide { data: prepared, .. } = &row.item else {
                    unreachable!()
                };
                let prepared = prepared.clone();
                let mut st = self.state.lock();
                if let Some(reservation) = &mut reservation {
                    reservation.release_locked(&mut st);
                }
                let Some(index) = st.claim_index(claim.token) else {
                    return Err(Self::local_ordered_retired());
                };
                let old = st.transmit_queue.get(index).unwrap();
                if !RouterInner::local_ordered_side(old) || old.accepted_type != row.accepted_type {
                    return Err(TelemetryError::BadArg);
                }
                let old_cost = old.byte_cost();
                row.delivery_state = old.delivery_state;
                row.deferred_since_ms = old.deferred_since_ms;
                row.retry_after_ms = old.retry_after_ms;
                #[cfg(feature = "std")]
                let schema = crate::config::ordinary_schema_guard()
                    .ok_or(TelemetryError::Io("memory pressure"))?;
                #[cfg(feature = "std")]
                let used = st.queued_packet_budget_used(&schema);
                #[cfg(not(feature = "std"))]
                let used = st.shared_queue_bytes_used();
                if used == usize::MAX
                    || cost == usize::MAX
                    || used
                        .checked_sub(old_cost)
                        .and_then(|used| used.checked_add(cost))
                        .is_none_or(|used| used > st.memory.max_queue_budget)
                    || !st.transmit_queue.fits_replacement_group(index, &[cost])
                {
                    return Err(TelemetryError::Io("memory pressure"));
                }
                st.transmit_queue.replace_prepared_item(index, row, cost);
                data = prepared;
            }
        }
        // A sibling may have recorded the first refusal while this claim was
        // outside Core preparing its retained codec owner. Re-read that live
        // anchor before effects; never continue with a stale None snapshot.
        let live_anchor = {
            let st = self.state.lock();
            st.claim_index(claim.token)
                .and_then(|index| st.transmit_queue.get(index))
                .filter(|row| RouterInner::local_ordered_side(row))
                .map(RouterInner::local_side_anchor)
        };
        let Some(live_anchor) = live_anchor else {
            return Err(Self::local_ordered_retired());
        };
        if live_anchor != context.since {
            context.since = live_anchor;
            if let Some(since) = live_anchor {
                #[cfg(all(test, feature = "std", feature = "discovery"))]
                managed_order_side_gate_causal::before_local_expiry(self, claim);
                self.expire_local_ordered_claim(ty, since, claim)?;
            }
        }
        let service = context.egress_service();
        let reporting_data = data.clone();
        let result = self.send_reliable_to_admitted_side_with_service(
            &admission, data, false, &mut context.admitted, service,
        );
        // Diagnostic callbacks may reenter the router. Release the admitted
        // side first, exactly as the legacy Broadcast caller did on return.
        drop(admission);
        match result {
            Err(error) if !Self::is_transient_tx_error(&error) => {
                match &reporting_data {
                    RouterItem::Packet(packet) => {
                        let _ = self.handle_callback_error(packet, None, error, called_from_queue);
                    }
                    RouterItem::Packed(bytes) => {
                        if let Ok(env) = wire_format::peek_envelope(bytes.as_ref()) {
                            let _ = self.handle_callback_error_from_env(&env, None, error, called_from_queue);
                        }
                    }
                }
                Err(TelemetryError::HandlerError("tx handler failed"))
            }
            other => other,
        }
    }

    #[cfg_attr(not(feature = "std"), inline(never))]
    pub(super) fn finish_local_ordered_claim(
        &self,
        claim: TxClaim,
        context: &DispatchContext,
        result: TelemetryResult<()>,
    ) -> TelemetryResult<()> {
        let now = self.clock.now_ms();
        let mut st = self.state.lock();
        let Some(index) = st.claim_index(claim.token) else {
            return result.and(Err(Self::local_ordered_retired()));
        };
        let row = st.transmit_queue.get(index).unwrap();
        if !RouterInner::local_ordered_side(row) {
            return result.and(Err(Self::local_ordered_retired()));
        }
        let ty = row.accepted_type;
        let anchor = RouterInner::local_side_anchor(row);
        if result.as_ref().is_err_and(Self::is_transient_tx_error) || context.refused() {
            let Some(retry_after) = now.checked_add(1) else {
                st.cancel_accepted_type(ty);
                st.refresh_retry_hint();
                return Err(TelemetryError::HandlerError(
                    "accepted reliable clock exhausted",
                ));
            };
            let anchor = anchor.unwrap_or(now);
            st.anchor_local_ordered_group(ty, anchor);
            st.transmit_queue.update_metadata(index, |row| {
                row.delivery_state = QueuedDelivery::DeferredLocalOrderedSide;
                row.deferred_since_ms = anchor;
                row.retry_after_ms = retry_after;
            });
            st.refresh_retry_hint();
            return Ok(());
        }
        if result.is_ok() && context.admitted {
            let _ = st.transmit_queue.remove_pos(index);
            st.promote_local_ordered_tail(ty);
            st.refresh_retry_hint();
            return Ok(());
        }
        // No full callback success is proved. Partial progress/unknown owner is
        // never completion, even if an internal path returned Ok.
        st.cancel_accepted_type(ty);
        st.refresh_retry_hint();
        result.and(Err(TelemetryError::HandlerError(
            "local ordered side did not complete",
        )))
    }
}
