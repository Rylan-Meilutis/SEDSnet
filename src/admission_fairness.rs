//! Cold-path pressure arbitration. No retained state, payload copies or heap scratch.
use crate::{DataType, packet::Packet, wire_format};

pub(crate) fn packet_owner(packet: &Packet, priority: u8) -> Option<u32> {
    let meta = crate::config::try_get_message_meta(packet.data_type())?;
    eligible(
        packet.data_type(),
        priority,
        meta.reliable != crate::ReliableMode::None,
        !packet.wire_target_senders().is_empty(),
    )
    .then(|| wire_format::source_address_for_sender(packet.sender()))
}
pub(crate) fn packed_owner(bytes: &[u8], priority: u8) -> Option<u32> {
    if priority >= 200 {
        return None;
    }
    let frame = wire_format::peek_routing_frame_info(bytes).ok()?;
    eligible(
        frame.envelope.ty,
        priority,
        frame.envelope.is_reliable || frame.reliable.is_some(),
        frame.envelope.target_senders().len() != 0,
    )
    .then_some(frame.envelope.source_address)
}
pub(crate) fn incoming(bytes: &[u8]) -> Option<(u32, u8)> {
    let ty = wire_format::scheduling_type(bytes)?;
    crate::config::try_get_message_meta(ty)?;
    let priority = crate::scheduler_priority(ty);
    packed_owner(bytes, priority).map(|owner| (owner, priority))
}
fn eligible(ty: DataType, priority: u8, reliable: bool, frozen: bool) -> bool {
    // Unknown runtime fragments cannot allocate UNKNOWN_TYPE fallback metadata
    // while we are deciding which retained payload is safe to reclaim.
    crate::config::try_get_message_meta(ty).is_some()
        && priority < 200
        && crate::transport_priority(ty) < 200
        && ty != DataType::P2pMessage
        && !reliable
        && !frozen
}
#[derive(Clone, Copy, Default)]
struct Load {
    sender: u32,
    bytes: usize,
    count: usize,
}
pub(crate) struct Loads {
    peers: [Load; 32],
    len: usize,
    overflow: bool,
}
impl Loads {
    pub fn new() -> Self {
        Self {
            peers: [Load::default(); 32],
            len: 0,
            overflow: false,
        }
    }
    pub fn record(&mut self, sender: u32, bytes: usize) {
        let slot = if let Some(index) = self.peers[..self.len]
            .iter()
            .position(|p| p.sender == sender)
        {
            index
        } else {
            if self.len == self.peers.len() {
                self.overflow = true;
                return;
            }
            self.peers[self.len].sender = sender;
            self.len += 1;
            self.len - 1
        };
        let peer = &mut self.peers[slot];
        peer.bytes = peer.bytes.saturating_add(bytes);
        peer.count += 1;
    }
    pub fn dominant_other(&self, incoming: u32) -> Option<u32> {
        // Beyond the bounded scratch catalog, refuse rather than guess which
        // peer owns the backlog. This is not a limit on network membership.
        if self.overflow {
            return None;
        }
        let incoming_bytes = self.peers[..self.len]
            .iter()
            .find(|p| p.sender == incoming)
            .map_or(0, |p| p.bytes);
        self.peers[..self.len]
            .iter()
            .filter(|p| p.sender != incoming && p.count > 1 && p.bytes > incoming_bytes)
            .max_by_key(|p| p.bytes)
            .map(|p| p.sender)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protected_and_frozen_packets_never_become_bulk_victims() {
        use alloc::sync::Arc;
        let ep = crate::config::register_endpoint("FAIR_KEEP_ENDPOINT", false).unwrap();
        let register = |name, mode| {
            crate::config::register_data_type_with_description(
                name,
                "",
                crate::MessageElement::Static(
                    4,
                    crate::MessageDataType::UInt8,
                    crate::MessageClass::Data,
                ),
                &[ep],
                mode,
                0,
            )
            .unwrap()
        };
        let plain = register("FAIR_PLAIN_REPORT", crate::ReliableMode::None);
        let reliable = register("FAIR_KEEP_RELIABLE", crate::ReliableMode::Ordered);
        let make = |ty| Packet::new(ty, &[ep], "SOURCE", 1, Arc::<[u8]>::from([1; 4])).unwrap();
        let packet = make(plain);
        assert!(packet_owner(&packet, 0).is_some());
        assert!(packed_owner(&wire_format::pack_packet(&packet), 0).is_some());
        assert!(packed_owner(&wire_format::pack_packet(&packet), 200).is_none());
        let packet = make(reliable);
        assert!(packet_owner(&packet, 0).is_none());
        assert!(packed_owner(&wire_format::pack_packet(&packet), 0).is_none());
        let frozen = Packet::new_with_wire_contract(
            plain,
            &[ep],
            "SOURCE",
            1,
            1,
            Arc::<[u8]>::from([1; 4]),
            None,
            Arc::from([42u64]),
        )
        .unwrap();
        assert!(packet_owner(&frozen, 0).is_none());
        assert!(packed_owner(&wire_format::pack_packet(&frozen), 0).is_none());
    }
    #[test]
    fn unknown_large_membership_does_not_guess_an_eviction_victim() {
        let mut loads = Loads::new();
        for source in 1..=33 {
            loads.record(source, 100);
            loads.record(source, 100);
        }
        assert_eq!(loads.dominant_other(100), None);
    }
    #[test]
    fn largest_backlog_yields_without_sacrificing_another_peers_only_report() {
        let mut loads = Loads::new();
        loads.record(1, 500);
        loads.record(1, 500);
        loads.record(2, 50);
        loads.record(3, 50);
        assert_eq!(loads.dominant_other(2), Some(1));
        assert_eq!(loads.dominant_other(1), None);
        let mut singles = Loads::new();
        singles.record(1, 500);
        assert_eq!(singles.dominant_other(2), None);
    }
}
