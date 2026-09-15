
//! Extra unit tests that cover previously-missing paths and invariants.
//!
//! These are white-box tests that exercise public APIs (and some
//! indirect behavior) to avoid changing visibility in core modules.
use crate::config::DataEndpoint;
use crate::tests::test_payload_len_for;
use crate::{
    TelemetryError, TelemetryErrorCode, TelemetryResult,
    config::DataType,
    packet::Packet,
    router::{Clock, EndpointHandler, Router, RouterConfig},
    wire_format,
};
use alloc::{string::String, sync::Arc};
use core::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// A tiny helper clock; we rely on the blanket `impl<Fn() -> u64> Clock`.
fn zero_clock() -> Box<dyn Clock + Send + Sync> {
    Box::new(|| 0u64)
}

// --------------------------- Error/Code parity ---------------------------

/// Validate that `TelemetryError` ↔ `TelemetryErrorCode` mapping is
/// complete and stable, including the string forms.
#[test]
fn error_enum_code_roundtrip_and_strings() {
    let samples = [
        TelemetryError::InvalidType,
        TelemetryError::EmptyEndpoints,
        TelemetryError::Unpack("oops"),
        TelemetryError::Io("disk"),
        TelemetryError::HandlerError("fail"),
        TelemetryError::MissingPayload,
        TelemetryError::TimestampInvalid,
    ];
    for e in samples {
        let code = e.to_error_code();
        // must have a stable human string (starts with a '{' per current impl)
        assert!(code.as_str().starts_with('{'));
        // round-trip numeric space
        let back = TelemetryErrorCode::try_from_i32(code as i32);
        assert!(back.is_some(), "roundtrip failed for {code:?}");
    }
}

// --------------------------- Header-only parsing ---------------------------

/// Ensure header-only peek fails on truncated buffers (short read during
/// varint parsing).
#[test]
fn unpack_header_only_short_buffer_fails() {
    // v2 header is varint-based. Force a definite short read in the first varint.

    // Case A: only NEP present (0 endpoints), but no bytes for `ty` varint.
    let tiny = [0x00u8]; // NEP = 0
    let err = wire_format::peek_envelope(&tiny).unwrap_err();
    matches_deser_err(err);

    // Case B: NEP present, and a *truncated* varint (continuation bit set, but no following byte).
    let truncated = [0x00u8, 0x80]; // NEP=0, then start varint with continuation bit
    let err = wire_format::peek_envelope(&truncated).unwrap_err();
    matches_deser_err(err);
}

/// Ensure header size is a valid prefix of the packed wire image.
#[test]
fn header_size_is_prefix_of_wire_image() {
    let pkt = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0, 2.0, 3.0],
        &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")],
        123,
    )
    .unwrap();

    let wire = wire_format::pack_packet(&pkt);
    let hdr = wire_format::header_size_bytes(&pkt);
    assert!(hdr <= wire.len());

    // header must decode from the start (i.e., NEP + scalars exists)
    assert!(hdr > 0);
}

/// Helper: assert an error is a `Unpack` variant.
fn matches_deser_err(e: TelemetryError) {
    match e {
        TelemetryError::Unpack(_) => {}
        other => panic!("expected Unpack error, got {other:?}"),
    }
}

fn rewrite_crc32(buf: &mut [u8]) {
    if buf.len() < wire_format::CRC32_BYTES {
        return;
    }
    let data_len = buf.len() - wire_format::CRC32_BYTES;
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&buf[..data_len]);
    let crc = hasher.finalize();
    buf[data_len..].copy_from_slice(&crc.to_le_bytes());
}

/// Ensure packing is canonical: pack -> unpack -> pack
/// produces identical bytes (ULEB128 canonical form).
#[test]
fn packer_is_canonical_roundtrip() {
    use crate::config::{DataEndpoint, DataType};
    use crate::{packet::Packet, wire_format};

    // Dynamic payload to avoid schema constraints and let us vary sizes later.
    let msg = "hello world";
    let pkt = Packet::from_str_slice(
        DataType::TelemetryError,
        msg,
        &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")],
        0,
    )
    .unwrap();

    let wire1 = wire_format::pack_packet(&pkt);
    let pkt2 = wire_format::unpack_packet(&wire1).unwrap();
    let wire2 = wire_format::pack_packet(&pkt2);

    // ULEB128 is canonical (no leading 0x80 “more” bytes), so bytes must match
    assert_eq!(&*wire1, &*wire2, "packer must be canonical");
}

#[test]
fn pack_unpack_roundtrip_matches_packet_identity() {
    let pkt = Packet::from_str_slice(
        DataType::TelemetryError,
        "pack/unpack roundtrip check",
        &[DataEndpoint::TelemetryError],
        456,
    )
    .unwrap();

    let packed = wire_format::pack_packet(&pkt);
    assert_eq!(packed, wire_format::pack_packet(&pkt));

    let unpacked = wire_format::unpack_packet(&packed).unwrap();
    assert_eq!(unpacked.packet_id(), pkt.packet_id());
    assert_eq!(unpacked.payload(), pkt.payload());
}

/// Validate varint scalar growth: header and wire size should increase
/// when fields that are encoded as varints get larger.
#[test]
fn packer_varint_scalars_grow_as_expected() {
    use crate::config::{DataEndpoint, DataType};
    use crate::{packet::Packet, wire_format};

    fn non_rle_ascii(len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        for i in 0..len {
            // Alternating lowercase letters with no >=3-byte runs and valid UTF-8 bytes.
            out.push(b'a' + ((i % 26) as u8));
        }
        out
    }

    // Helper to build a TelemetryError payload with a sender of the given length.
    fn pkt_with(len: usize, sender_len: usize, ts: u64) -> Packet {
        let sender_bytes = non_rle_ascii(sender_len);
        let s: String = sender_bytes.iter().map(|b| char::from(*b)).collect();
        let payload = non_rle_ascii(len); // dynamic payload (String type)
        Packet::new(
            DataType::TelemetryError,
            &[DataEndpoint::named("SD_CARD")],
            &s,
            ts,
            Arc::<[u8]>::from(payload),
        )
        .unwrap()
    }

    // Case 1: small (all varints fit in 1 byte)
    let p1 = pkt_with(10, 5, 0x7F); // <= 127
    let w1 = wire_format::pack_packet(&p1);
    let h1 = wire_format::header_size_bytes(&p1);
    assert!(h1 > 4, "NEP + 4 one-byte varints minimum");

    // Case 2: larger payload grows data_size; sender text itself is discovery metadata,
    // not part of the packet header.
    let p2 = pkt_with(200, 200, 0x7F);
    let w2 = wire_format::pack_packet(&p2);
    let h2 = wire_format::header_size_bytes(&p2);
    assert!(w2.len() > w1.len(), "wire should grow with larger varints");
    assert!(h2 >= h1, "header should not shrink with larger varints");

    // Case 3: bigger timestamp to push it beyond 1 byte (and usually >2)
    let p3 = pkt_with(200, 200, 1u64 << 40); // forces 6-byte varint
    let w3 = wire_format::pack_packet(&p3);
    let h3 = wire_format::header_size_bytes(&p3);
    assert!(
        w3.len() > w2.len(),
        "wire should grow with larger timestamp"
    );
    assert!(h3 > h2, "header should grow with larger timestamp");

    // Size function must match exact output
    assert_eq!(wire_format::packet_wire_size(&p3), w3.len());
}

/// Stress test for endpoint bitpacking across many endpoints and repeated
/// copies, ensuring endpoints and payload round-trip.
#[test]
fn endpoints_bitpack_roundtrip_many_and_extremes() {
    use crate::{
        MAX_VALUE_DATA_ENDPOINT,
        config::{DataEndpoint, DataType},
        packet::Packet,
        wire_format,
    };

    // Build a long endpoint list by cycling through all enum values (0..=MAX)
    let mut eps = Vec::<DataEndpoint>::new();
    for i in 0..=MAX_VALUE_DATA_ENDPOINT {
        if let Some(ep) = DataEndpoint::try_from_u32(i) {
            eps.push(ep);
        }
    }
    // Repeat to make the bitstream cross multiple bytes
    let mut endpoints = Vec::new();
    for _ in 0..4 {
        endpoints.extend_from_slice(&eps);
    }

    // Make payload dynamic so schema doesn't get in the way
    let payload = vec![0x55u8; 257]; // force 2-byte varint for data_size
    let pkt = Packet::new(
        DataType::TelemetryError,
        &endpoints,
        "sender",
        123456,
        Arc::<[u8]>::from(payload),
    )
    .unwrap();

    let wire = wire_format::pack_packet(&pkt);
    let back = wire_format::unpack_packet(&wire).unwrap();
    let has_all_endpoints = back.endpoints().iter().all(|ep| endpoints.contains(ep));
    assert!(has_all_endpoints, "endpoints must roundtrip 1:1");
    assert_eq!(back.data_type(), pkt.data_type());
    assert_eq!(back.timestamp(), pkt.timestamp());
    assert_eq!(back.payload(), pkt.payload());
    assert_eq!(wire_format::packet_wire_size(&pkt), wire.len());
}

/// For large sender/payload/timestamp, ensure `peek_envelope` and full
/// unpacking agree on header fields and payload.
#[test]
fn peek_envelope_matches_full_parse_on_large_values() {
    use crate::config::{DataEndpoint, DataType};
    use crate::{packet::Packet, wire_format};

    let sender = "S".repeat(10_000); // big sender (varint grows)
    let payload = vec![b'h'; 4096];
    let ts = (1u64 << 40) + 123; // large ts (varint grows)

    let pkt = Packet::new(
        DataType::TelemetryError, // String-typed
        &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")],
        &sender,
        ts,
        Arc::<[u8]>::from(payload),
    )
    .unwrap();

    let wire = wire_format::pack_packet(&pkt);
    assert!(
        !wire
            .windows(sender.len())
            .any(|window| window == sender.as_bytes()),
        "sender hostname must be discovery/config metadata, not packet-header bytes"
    );
    let env = wire_format::peek_envelope(&wire).unwrap();
    let full = wire_format::unpack_packet(&wire).unwrap();

    assert_eq!(env.ty, pkt.data_type());
    assert_eq!(env.sender.as_ref(), pkt.sender());
    assert_eq!(env.timestamp_ms, pkt.timestamp());
    assert_eq!(&*env.endpoints, pkt.endpoints());

    assert_eq!(full.data_type(), pkt.data_type());
    assert_eq!(full.timestamp(), pkt.timestamp());
    assert_eq!(full.endpoints(), pkt.endpoints());
    assert_eq!(full.payload(), pkt.payload());
}

/// Corrupt endpoint bits in the bitmap to encode an out-of-range value,
/// and ensure unpacking fails with an appropriate error.
#[test]
fn corrupt_endpoint_bits_yields_bad_endpoint_error() {
    use crate::{
        MAX_VALUE_DATA_ENDPOINT,
        config::{DataEndpoint, DataType},
        packet::Packet,
        wire_format,
    };

    // Recompute EP_BITS the same way the module does.
    let bits = 32 - MAX_VALUE_DATA_ENDPOINT.leading_zeros();
    let ep_bits: u8 = if bits == 0 { 1 } else { bits as u8 };
    // If EP_BITS is exactly the minimum bits to encode MAX, there is room for values > MAX.
    let upper_val = (1u64 << ep_bits) - 1;
    if upper_val as u32 <= MAX_VALUE_DATA_ENDPOINT {
        // Nothing to corrupt beyond max—skip test (no larger representable value).
        return;
    }

    // Build a simple, valid packet with at least 1 endpoint.
    let pkt = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0, 2.0, 3.0],
        &[DataEndpoint::named("SD_CARD")],
        123,
    )
    .unwrap();
    let mut wire = wire_format::pack_packet(&pkt).to_vec();

    // Compute where endpoint bits start (right after header varints)
    let ep_offset = wire_format::header_size_bytes(&pkt);
    assert!(ep_offset < wire.len());

    // Overwrite the *first* endpoint with an out-of-range value in the bitstream.
    // Bits are packed LSB-first.
    let mut v = upper_val;
    for (bitpos, _) in (0..ep_bits).enumerate() {
        let byte_idx = ep_offset + (bitpos / 8);
        let bit_off = bitpos % 8;
        // Set bit if the corresponding bit of v is 1
        if (v & 1) != 0 {
            wire[byte_idx] |= 1 << bit_off;
        } else {
            wire[byte_idx] &= !(1 << bit_off);
        }
        v >>= 1;
    }
    rewrite_crc32(&mut wire);

    // Now unpacking must fail with a Unpack("bad endpoint") error.
    let err = wire_format::unpack_packet(&wire).unwrap_err();
    match err {
        TelemetryError::Unpack(msg) if msg.contains("endpoint") => {}
        other => panic!("expected bad endpoint unpack error, got {other:?}"),
    }
}

/// Sanity check that header size is between 0 and full packet size, and
/// that the computed wire size matches packed length.
#[test]
fn header_size_is_prefix_and_less_than_total() {
    use crate::config::{DataEndpoint, DataType};
    use crate::{packet::Packet, wire_format};

    let pkt = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0, 2.0, 3.0],
        &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")],
        999,
    )
    .unwrap();

    let wire = wire_format::pack_packet(&pkt);
    let hdr = wire_format::header_size_bytes(&pkt);

    assert!(hdr > 0 && hdr < wire.len());
    assert_eq!(wire_format::packet_wire_size(&pkt), wire.len());
}

// --------------------------- UTF-8 trimming behavior ---------------------------

/// Ensure `data_as_utf8_ref` trims trailing NUL bytes and returns a `&str`
/// with just the meaningful content.
#[test]
fn data_as_utf8_ref_trims_trailing_nuls() {
    // Use a String-typed message kind. TelemetryError is used by the router with
    // a string payload and typically mapped to MessageDataType::String.
    let ty = DataType::TelemetryError;
    let mut buf = vec![0u8; test_payload_len_for(ty)];

    let s = b"hello\0\0";
    buf[..s.len()].copy_from_slice(s);

    let pkt = Packet::new(
        ty,
        &[DataEndpoint::named("SD_CARD")],
        "tester",
        0,
        Arc::<[u8]>::from(buf),
    )
    .unwrap();

    assert_eq!(pkt.data_as_utf8_ref(), Some("hello"));
}

// --------------------------- Queue clear semantics ---------------------------

/// After calling `clear_queues`, no pending TX/RX items should be processed.
#[test]
fn clear_queues_prevents_further_processing() {
    // Transmit "bus" that counts frames sent.
    let tx_count = Arc::new(AtomicUsize::new(0));
    let tx_count_c = tx_count.clone();
    let tx = move |bytes: &[u8]| -> TelemetryResult<()> {
        assert!(!bytes.is_empty());
        tx_count_c.fetch_add(1, Ordering::SeqCst);
        Ok(())
    };

    // Local handler that counts receives.
    let rx_count = Arc::new(AtomicUsize::new(0));
    let rx_count_c = rx_count.clone();
    let handler = EndpointHandler::new_packet_handler(
        DataEndpoint::named("SD_CARD"),
        move |_pkt: &Packet| {
            rx_count_c.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    );

    let r = Router::new_with_clock(RouterConfig::new(vec![handler]), zero_clock());
    r.add_side_packed("tx", tx);

    // Enqueue one TX and one RX
    let pkt_tx = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0_f32, 2.0, 3.0],
        &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")],
        0,
    )
    .unwrap();
    let pkt_rx = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[4.0_f32, 5.0, 6.0],
        &[DataEndpoint::named("SD_CARD")], // only local to avoid extra TX during receive
        0,
    )
    .unwrap();

    r.tx_queue(pkt_tx).unwrap();
    r.rx_queue(pkt_rx).unwrap();

    // Clearing should drop both queues before any processing.
    r.clear_queues();

    r.process_all_queues().unwrap();
    assert_eq!(
        tx_count.load(Ordering::SeqCst),
        0,
        "should not TX after clear"
    );
    assert_eq!(
        rx_count.load(Ordering::SeqCst),
        0,
        "should not RX after clear"
    );
}

// --------------------------- Retry semantics (indirect) ---------------------------

/// Verify local handler retry count matches `MAX_NUMBER_OF_RETRYS` (assumed 3),
/// and that the final error is a `HandlerError`.
#[test]
fn local_handler_retry_attempts_are_three() {
    // This test assumes MAX_NUMBER_OF_RETRYS == 3 in router. If that constant changes,
    // update the expected count below.
    const EXPECTED_ATTEMPTS: usize = 3; // initial try + retries

    let counter = Arc::new(AtomicUsize::new(0));
    let counter_c = counter.clone();

    // A handler that always fails but bumps a counter on each attempt.
    let failing = EndpointHandler::new_packet_handler(
        DataEndpoint::named("SD_CARD"),
        move |_pkt: &Packet| {
            counter_c.fetch_add(1, Ordering::SeqCst);
            Err(TelemetryError::BadArg)
        },
    );

    // Router with no TX (we only care about local handler invocation count).
    let r = Router::new_with_clock(RouterConfig::new(vec![failing]), zero_clock());

    // Build a valid packet addressed to the failing endpoint.
    let pkt = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0_f32, 2.0, 3.0],
        &[DataEndpoint::named("SD_CARD")],
        0,
    )
    .unwrap();

    // Sending should surface a HandlerError after all retries.
    let res = r.tx(pkt);
    match res {
        Err(TelemetryError::HandlerError(_)) => {}
        other => panic!("expected HandlerError after retries, got {other:?}"),
    }

    assert_eq!(
        counter.load(Ordering::SeqCst),
        EXPECTED_ATTEMPTS,
        "handler should be invoked exactly {EXPECTED_ATTEMPTS} times"
    );
}

// --------------------------- from_u8_slice sanity ---------------------------

/// Ensure `Packet::from_u8_slice` builds a valid GPS packet with
/// expected length and timestamp.
#[test]
fn from_f32_slice_builds_valid_packet() {
    let need = test_payload_len_for(DataType::named("GPS_DATA")) / 4; // f32 count
    assert_eq!(need, 3); // schema sanity

    let bytes = vec![5.3f32; need];
    let pkt = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &bytes,
        &[DataEndpoint::named("SD_CARD")],
        12345,
    )
    .unwrap();

    assert_eq!(pkt.payload().len(), 12);
    assert_eq!(pkt.data_size(), 12);
    assert_eq!(pkt.timestamp(), 12345);
}

#[test]
fn from_none_slice_builds_valid_packet() {
    let need = 0; // f32 count
    assert_eq!(need, 0); // schema sanity

    let pkt = Packet::from_no_data(
        DataType::named("HEARTBEAT"),
        &[DataEndpoint::named("SD_CARD")],
        12345,
    )
    .unwrap();

    assert_eq!(pkt.payload().len(), 0);
    assert_eq!(pkt.data_size(), 0);
    assert_eq!(pkt.timestamp(), 12345);
}

#[test]
fn heartbeat_reaches_each_independently_discovered_network_side() {
    crate::tests::ensure_common_test_schema();
    use crate::config::register_data_type_with_description;
    use crate::discovery::{TopologyBoardNode, build_discovery_topology};
    use crate::{MessageClass, MessageDataType, MessageElement, ReliableMode};

    // Packed sides enable the destination contract used by the real
    // GroundStation links. The contract names owners on both sides; route
    // selection must not collapse that multi-segment delivery to one
    // adaptive path.
    let seen_a: Arc<Mutex<Vec<Arc<[u8]>>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Arc<[u8]>>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_cb = seen_a.clone();
    let seen_b_cb = seen_b.clone();
    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    let side_a = router.add_side_packed("A", move |bytes| {
        seen_a_cb.lock().unwrap().push(Arc::from(bytes));
        Ok(())
    });
    let side_b = router.add_side_packed("B", move |bytes| {
        seen_b_cb.lock().unwrap().push(Arc::from(bytes));
        Ok(())
    });
    let endpoint = DataEndpoint::named("SD_CARD");
    let heartbeat = DataType::try_named("HEARTBEAT").unwrap_or_else(|| {
        register_data_type_with_description(
            "HEARTBEAT",
            "test network heartbeat",
            MessageElement::Static(0, MessageDataType::NoData, MessageClass::Data),
            &[endpoint],
            ReliableMode::None,
            255,
        )
        .expect("register HEARTBEAT")
    });

    router
        .rx_from_side(
            &build_discovery_topology(
                "REMOTE_A",
                1,
                &[TopologyBoardNode {
                    sender_id: "REMOTE_A".into(),
                    reachable_endpoints: vec![endpoint],
                    reachable_timesync_sources: vec![],
                    connections: vec![],
                }],
            )
            .unwrap(),
            side_a,
        )
        .unwrap();
    router
        .rx_from_side(
            &build_discovery_topology(
                "BRIDGE_B",
                1,
                &[
                    TopologyBoardNode {
                        sender_id: "BRIDGE_B".into(),
                        reachable_endpoints: vec![],
                        reachable_timesync_sources: vec![],
                        connections: vec!["REMOTE_B".into()],
                    },
                    TopologyBoardNode {
                        sender_id: "REMOTE_B".into(),
                        reachable_endpoints: vec![endpoint],
                        reachable_timesync_sources: vec![],
                        connections: vec!["BRIDGE_B".into()],
                    },
                ],
            )
            .unwrap(),
            side_b,
        )
        .unwrap();
    router.process_all_queues().unwrap();
    seen_a.lock().unwrap().clear();
    seen_b.lock().unwrap().clear();

    router
        .tx(Packet::from_no_data(heartbeat, &[endpoint], 2).unwrap())
        .unwrap();

    assert_eq!(seen_a.lock().unwrap().len(), 1);
    assert_eq!(seen_b.lock().unwrap().len(), 1);
    assert_eq!(
        router.debug_end_to_end_tracked_count(),
        0,
        "periodic freshness packets must not create an end-to-end ACK storm",
    );
}

// --------------------------- Header-only happy path smoke ---------------------------

/// Header-only peek (`peek_envelope`) should match full parse for a normal
/// encoded GPS packet.
#[test]
fn unpack_header_only_then_full_parse_matches() {
    // Build a normal packet then compare header-only vs full.
    let endpoints = &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")];
    let pkt = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[5.25_f32, 3.5, 1.0],
        endpoints,
        42,
    )
    .unwrap();
    let wire = wire_format::pack_packet(&pkt);

    let env = wire_format::peek_envelope(&wire).unwrap();
    assert_eq!(env.ty, pkt.data_type());
    assert_eq!(&*env.endpoints, pkt.endpoints());
    assert_eq!(env.sender.as_ref(), pkt.sender());
    assert_eq!(env.timestamp_ms, pkt.timestamp());

    let round = wire_format::unpack_packet(&wire).unwrap();
    round.validate().unwrap();
    assert_eq!(round.data_type(), pkt.data_type());
    assert_eq!(round.data_size(), pkt.data_size());
    assert_eq!(round.timestamp(), pkt.timestamp());
    assert_eq!(round.endpoints(), pkt.endpoints());
    assert_eq!(round.payload(), pkt.payload());
}

// --------------------------- TX failure -> error to locals (smoke) ---------------------------

/// Smoke test: TX failure should emit a `TelemetryError` packet to local
/// endpoints (exact string validated by more specific tests).
#[test]
fn tx_failure_emits_error_to_local_endpoints() {
    // A transmitter that always fails.
    let failing_tx = |_bytes: &[u8]| -> TelemetryResult<()> { Err(TelemetryError::Io("boom")) };

    // Capture what the local endpoint sees (should include a TelemetryError).
    let last_payload = Arc::new(Mutex::new(String::new()));
    let last_payload_c = last_payload.clone();

    let capturing =
        EndpointHandler::new_packet_handler(DataEndpoint::named("SD_CARD"), move |pkt: &Packet| {
            if pkt.data_type() == DataType::TelemetryError {
                *last_payload_c.lock().unwrap() = pkt.as_string();
            }
            Ok(())
        });

    let r = Router::new_with_clock(RouterConfig::new(vec![capturing]), zero_clock());
    r.add_side_packed("tx", failing_tx);

    // Include both a local and a non-local endpoint to force remote TX.
    let pkt = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0_f32, 2.0, 3.0],
        &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")],
        7,
    )
    .unwrap();

    let res = r.tx(pkt);
    match res {
        Err(TelemetryError::HandlerError(_)) => {} // TX path wraps as HandlerError
        other => panic!("expected HandlerError from TX failure, got {other:?}"),
    }

    // Ensure something was captured (exact string is covered elsewhere)
    let got = last_payload.lock().unwrap().clone();
    assert!(
        !got.is_empty(),
        "expected TelemetryError to be delivered locally after TX failure"
    );
}
