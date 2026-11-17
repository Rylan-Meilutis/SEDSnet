//! Time sync nonces and end-to-end sealing.
//!
//! Time sync packets take their nonce from a short counter (1..=16383) so a
//! board's CAN time sync response fits one frame. The packet nonce feeds the
//! AEAD nonce of a sealed frame (type, 48-bit timestamp, nonce), so a short
//! nonce must never be sealed: time sync packets are internal control traffic
//! the router never seals, and the frame encoder refuses to. Every other packet
//! keeps its full nonce.
use super::*;

fn data_packet(nonce: u16) -> Packet {
    crate::tests::ensure_common_test_schema();
    let endpoint = DataEndpoint::named("RADIO");
    let ty = crate::config::register_data_type(
        "TIMESYNC_NONCE_E2E_DATA",
        crate::MessageElement::Dynamic(crate::MessageDataType::Binary, crate::MessageClass::Data),
        &[endpoint],
        crate::ReliableMode::None,
        10,
    )
    .unwrap();
    Packet::new_with_nonce(ty, &[endpoint], "HOST", 1_793_000_000_000, nonce, Arc::from(vec![b'A'; 24])).unwrap()
}

/// The nonce of a canonical frame, read from its header.
fn wire_nonce(frame: &[u8]) -> Option<u16> {
    let flags = frame[0];
    let mut off = 2;
    for _ in 0..3 {
        crate::side_transport::read_uleb128_local(frame, &mut off).ok()?;
    }
    (flags & 0x08 != 0).then(|| crate::side_transport::read_uleb128_local(frame, &mut off).ok().map(|n| n as u16))?
}

fn sealing_router() -> Router {
    let router = Router::new_with_clock(
        RouterConfig::default()
            .with_sender("HOST")
            .with_timesync(crate::timesync::TimeSyncConfig::default())
            .with_e2e_encryption(RouterE2eEncryptionMode::ForceAll)
            .with_e2e_key_id(0x7153),
        Box::new(|| 100),
    );
    crate::crypto::register_software_key(0x7153, b"0123456789abcdef0123456789abcdef").unwrap();
    router
}

#[test]
fn sealed_packets_keep_their_full_nonce_and_time_sync_is_never_sealed() {
    let router = sealing_router();
    for nonce in [0xBEEFu16, 0xFFFF, 0x4001] {
        let sealed = router.pack_packet_for_router(&data_packet(nonce), None).unwrap();
        assert_ne!(sealed[0] & 0x10, 0, "sealed");
        assert_eq!(wire_nonce(&sealed), Some(nonce), "a sealed packet keeps its full nonce");
    }
    for ty in [DataType::TimeSyncAnnounce, DataType::TimeSyncRequest, DataType::TimeSyncResponse] {
        let words: &[u64] = if ty == DataType::TimeSyncResponse { &[1, 2, 3, 4] } else { &[1, 2] };
        let pkt = router.timesync_packet(ty, words, 1_793_000_000_000, 1).unwrap();
        assert!((128..=16_383).contains(&pkt.nonce()));
        // The router never seals time sync, even when it seals everything else.
        let frame = router.pack_packet_for_router(&pkt, None).unwrap();
        assert_eq!(frame[0] & 0x10, 0, "{ty:?} sealed");
        // The encoder refuses to, whoever asks.
        assert!(
            crate::wire_format::pack_routed_packet(
                &pkt,
                None,
                None,
                &[],
                Some(crate::wire_format::E2eSealConfig { key_id: 0x7153 }),
            )
            .is_err(),
            "{ty:?}"
        );
    }
}

/// No two time sync packets of one router stamped in the same millisecond
/// share a nonce until 16256 of them have been sent, so (type, timestamp,
/// nonce) never repeats within that span.
#[test]
fn time_sync_nonces_do_not_repeat_within_their_cycle() {
    let router = sealing_router();
    let mut seen = std::collections::HashMap::new();
    for i in 0..40_000u32 {
        let pkt = router.timesync_packet(DataType::TimeSyncResponse, &[u64::from(i), 2, 3, 4], 1_793_000_000_000, 1).unwrap();
        let key = (pkt.data_type().as_u32(), pkt.timestamp(), pkt.nonce());
        if let Some(prev) = seen.insert(key, i) {
            assert!(i - prev >= 16_256, "nonce {} reused after {} packets", pkt.nonce(), i - prev);
        }
    }
}
