#![no_std]
extern crate sedsnet;
use sedsnet::packet::Packet;
use sedsnet::router::{
    FrozenRecipient, FrozenTargetPacket, PrepareTargetedPacketError,
    PrepareTargetedPacketErrorKind, Router,
};

pub fn prepare(
    router: &Router,
    packet: Packet,
) -> Result<FrozenTargetPacket, PrepareTargetedPacketError> {
    router.prepare_targeted_packet(packet, &["probe-sensor"])
}
pub fn recipient(value: &FrozenRecipient) -> (&str, u64, Option<u32>, Option<u64>, Option<u64>) {
    (
        value.hostname(),
        value.wire_target_symbol(),
        value.assigned_address(),
        value.birth_ms(),
        value.owner_hash(),
    )
}
pub fn original(error: PrepareTargetedPacketError) -> (PrepareTargetedPacketErrorKind, Packet) {
    (error.reason(), error.into_packet())
}
