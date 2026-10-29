//! Opt-in replacement of never-encoded canonical egress samples.
use super::*;
use core::cmp::Ordering;

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
    // A refused/partial owner must finish before another fresh report can
    // advance this side's encoding history. Controls and other sides bypass it.
    pub(super) fn latest_blocked_side(&self) -> Option<RouterSideId> {
        let side = self.latest_side()?;
        let partial = self.side_transport.get(&side).is_some_and(|state| {
            state
                .tx_chunk_progress
                .as_ref()
                .is_some_and(|progress| !progress.is_idle())
        });
        (partial
            || self.transmit_queue.iter().any(|queued| {
                queued.disposable & TX_HISTORY_OWNED != 0
                    && matches!(&queued.item, RouterTxItem::ToSide { dst, .. } if *dst == side)
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
        progress.begin(123, 0).unwrap();
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
}
