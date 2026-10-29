//! Opt-in hosted transport cancellation proof from an actual final owner receipt.
use super::*;

/// Transport progress is owned by the caller, never inferred from packet bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingCanonicalWrite {
    /// No authoritative retry/progress information. Keep the owner.
    Unknown,
    /// The first transmission may still be required. Keep the owner.
    NeverStartedFirst,
    /// A complete retry that has never begun a UART write in this generation.
    NeverStartedRetry { epoch: u64 },
    /// Any prefix was attempted or written; preserve its encoded history.
    Started,
}

/// Borrowed proof emitted only after every frozen owner supplied a matching receipt.
///
/// It is valid for synchronous pruning of eligible external transport owners.
/// This is not a modem-drain guarantee or permission to cancel SDT/codec history.
pub struct DeliveryCompletion<'a> {
    epoch: u64,
    packet_id: u64,
    data: &'a RouterItem,
}

/// The observer must be bounded and nonblocking. It runs without SDK state locks.
pub type DeliveryCompletionObserver = dyn for<'a> Fn(DeliveryCompletion<'a>) + Send + Sync;

pub(super) struct ObserverRegistration {
    pub(super) epoch: u64,
    callback: Arc<DeliveryCompletionObserver>,
}

impl DeliveryCompletion<'_> {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn packet_id(&self) -> u64 {
        self.packet_id
    }

    /// Check a never-started canonical retry against this exact completed contract.
    ///
    /// The caller must hold its transport ownership/generation lock through this
    /// check and cancellation. Reconnect, known peer restart, or loss of progress
    /// information must advance/invalidate the current epoch. An unknown peer
    /// restart cannot be inferred from the existing wire protocol.
    pub fn can_cancel(
        &self,
        bytes: &[u8],
        state: PendingCanonicalWrite,
        current_epoch: u64,
    ) -> bool {
        if !matches!(state, PendingCanonicalWrite::NeverStartedRetry { epoch }
            if epoch != 0 && epoch == self.epoch && epoch == current_epoch)
            || bytes.first().is_none_or(|flags| flags & 0x11 != 0)
        {
            return false;
        }
        let Ok(frame) = wire_format::peek_routing_frame_info(bytes) else {
            return false;
        };
        if !frame.reliable.is_some_and(|header| {
            header.flags == wire_format::RELIABLE_FLAG_UNSEQUENCED
                && header.seq == 0
                && header.ack == 0
        }) || frame.envelope.wire_shape.is_none()
            || frame.envelope.target_senders().len() == 0
        {
            return false;
        }
        let Ok(retry) = wire_format::unpack_packet(bytes) else {
            return false;
        };
        let same = |original: &Packet| {
            original.packet_id() == self.packet_id
                && retry.packet_id() == self.packet_id
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
        match self.data {
            RouterItem::Packet(original) => same(original),
            RouterItem::Packed(original) => {
                wire_format::unpack_packet(original.as_ref()).is_ok_and(|packet| same(&packet))
            }
        }
    }
}

impl Router {
    /// Opt in to positive completion notifications for external transport retries.
    ///
    /// Use a fresh nonzero epoch whenever transport/peer generation changes.
    /// Pending deliveries retain their creation epoch: replacing the observer
    /// never retroactively authorizes pruning them. `None` disables notifications.
    /// No observer, epoch field, or API exists in a no_std build.
    pub fn set_delivery_completion_observer(
        &self,
        epoch: u64,
        observer: Option<Arc<DeliveryCompletionObserver>>,
    ) -> TelemetryResult<()> {
        if observer.is_some() && epoch == 0 {
            return Err(TelemetryError::BadArg);
        }
        *self.completion_observer.lock() =
            observer.map(|callback| Arc::new(ObserverRegistration { epoch, callback }));
        Ok(())
    }

    pub(super) fn notify_delivery_completion(&self, id: u64, completed: &EndToEndReliableSent) {
        if completed.completion_epoch == 0 {
            return;
        }
        let frozen = match &completed.data {
            RouterItem::Packet(packet) => {
                packet.wire_shape().is_some() && !packet.wire_target_senders().is_empty()
            }
            RouterItem::Packed(bytes) => wire_format::peek_routing_envelope(bytes.as_ref())
                .is_ok_and(|envelope| {
                    envelope.wire_shape.is_some() && envelope.target_senders().len() != 0
                }),
        };
        if !frozen {
            return;
        }
        let observer = self.completion_observer.lock().clone();
        if let Some(observer) =
            observer.filter(|observer| observer.epoch == completed.completion_epoch)
        {
            (observer.callback)(DeliveryCompletion {
                epoch: completed.completion_epoch,
                packet_id: id,
                data: &completed.data,
            });
        }
    }
}
