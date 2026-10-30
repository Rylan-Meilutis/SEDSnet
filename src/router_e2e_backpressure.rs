//! Stable ownership for publisher-side E2E retries through side backpressure.
use super::*;
pub(super) struct ChildUnwind<'a> {
    pub(super) router: &'a Router,
    pub(super) claim: TxClaim,
    pub(super) armed: bool,
}
impl Drop for ChildUnwind<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.router.restore_e2e_child_claim(self.claim);
        }
    }
}
pub(super) struct ParentLease<'a> {
    router: &'a Router,
    id: u64,
}
impl Drop for ParentLease<'_> {
    fn drop(&mut self) {
        if let Some(owner) = self
            .router
            .state
            .lock()
            .end_to_end_reliable_tx
            .get_mut(&self.id)
        {
            owner.queued = false;
        }
    }
}
impl Router {
    pub(super) fn lease_e2e_send(&self, id: Option<u64>) -> Option<ParentLease<'_>> {
        let id = id?;
        self.state
            .lock()
            .end_to_end_reliable_tx
            .get_mut(&id)?
            .queued = true;
        Some(ParentLease { router: self, id })
    }
    pub(super) fn e2e_child_owned(
        queue: &BoundedDeque<TxQueued>,
        side: usize,
        parent: u64,
    ) -> bool {
        queue.iter().any(|q| {
            q.disposable & TX_E2E_CHILD != 0
                && q.deferred_since_ms == parent
                && matches!(&q.item,RouterTxItem::ToSide{dst,..} if *dst==side)
        })
    }
    pub(super) fn enqueue_e2e_child(
        &self,
        item: RouterTxItem,
        priority: u8,
        parent: u64,
        #[cfg(feature = "compression")] reservation: &mut Option<
            crate::payload_codec::QueueReservation<'_, RouterInner>,
        >,
    ) -> TelemetryResult<()> {
        let mut st = self.state.lock();
        #[cfg(feature = "compression")]
        if let Some(reservation) = reservation {
            reservation.release_locked(&mut st);
        }
        st.push_transmit(TxQueued {
            disposable: TX_E2E_CHILD | {
                #[cfg(feature = "std")]
                {
                    if completion::is_retry_intent() {
                        TX_E2E_RETRY
                    } else {
                        0
                    }
                }
                #[cfg(not(feature = "std"))]
                {
                    0
                }
            },
            item,
            ignore_local: true,
            priority,
            delivery_state: QueuedDelivery::Untracked,
            accepted_type: 0,
            deferred_since_ms: parent,
            retry_after_ms: self.clock.now_ms().saturating_add(1),
        })
    }
    pub(super) fn restore_e2e_child_claim(&self, claim: TxClaim) -> TelemetryResult<()> {
        let mut st = self.state.lock();
        let Some(index) = st.claim_index(claim.token) else {
            return Ok(());
        };
        st.transmit_queue.update_metadata(index, |q| {
            q.delivery_state = QueuedDelivery::Untracked;
            q.retry_after_ms = self.clock.now_ms().saturating_add(1);
            if let RouterTxItem::ToSide { src, .. } = &mut q.item {
                *src = None;
            }
        });
        st.refresh_retry_hint();
        Ok(())
    }
    pub(super) fn finish_e2e_child_claim(
        &self,
        claim: TxClaim,
        parent: u64,
        context: &DispatchContext,
        ok: bool,
    ) -> TelemetryResult<()> {
        let mut st = self.state.lock();
        if let Some(index) = st.claim_index(claim.token) {
            if ok && !context.refused() {
                st.transmit_queue.remove_pos(index);
                if context.admitted
                    && let Some(owner) = st.end_to_end_reliable_tx.get_mut(&parent)
                {
                    owner.last_send_ms = self.clock.now_ms();
                }
            } else {
                st.transmit_queue.update_metadata(index, |q| {
                    q.delivery_state = QueuedDelivery::Untracked;
                    q.retry_after_ms = self.clock.now_ms().saturating_add(1);
                    if let RouterTxItem::ToSide { src, .. } = &mut q.item {
                        *src = None;
                    }
                });
            }
        }
        st.refresh_retry_hint();
        Ok(())
    }
    #[cfg(feature = "compression")]
    pub(super) fn prepare_e2e_child_for_send(
        &self,
        claim: TxClaim,
        side: usize,
        data: &mut RouterItem,
    ) -> TelemetryResult<()> {
        let mut reservation = self.prepare_queued_payload(side, data)?;
        if reservation.is_none() {
            return Ok(());
        }
        let mut st = self.state.lock();
        if let Some(reservation) = &mut reservation {
            reservation.release_locked(&mut st);
        }
        let Some(index) = st.claim_index(claim.token) else {
            return Err(TelemetryError::Io("side tx busy"));
        };
        let old = st.transmit_queue.get(index).expect("claimed child");
        let old_cost = old.byte_cost();
        let mut replacement = old.clone();
        let RouterTxItem::ToSide { data: retained, .. } = &mut replacement.item else {
            return Err(TelemetryError::BadArg);
        };
        *retained = data.clone();
        #[cfg(feature = "compact-packet-store")]
        replacement.park_for_queue()?;
        let cost = replacement.byte_cost();
        if st
            .shared_queue_bytes_used()
            .saturating_sub(old_cost)
            .saturating_add(cost)
            > st.memory.max_queue_budget
        {
            return Err(TelemetryError::Io("memory pressure"));
        }
        let RouterTxItem::ToSide { data: prepared, .. } = &replacement.item else {
            unreachable!()
        };
        let prepared = prepared.clone();
        st.transmit_queue
            .update_admitted(index, cost, |owner| *owner = replacement)?;
        *data = prepared;
        Ok(())
    }
}
