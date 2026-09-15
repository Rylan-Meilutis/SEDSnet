
//! Additional coverage tests for router, packet, and packing logic.
//! These tests complement `tests_extra` by covering boundary,
//! error, and fast-path behaviors not previously exercised.
use crate::config::get_message_meta;
use crate::tests::{UnixClock, packed_frame_type};
use crate::{
    MAX_VALUE_DATA_ENDPOINT, MAX_VALUE_DATA_TYPE, MessageClass, MessageDataType, MessageElement,
    ReliableMode, TelemetryError, TelemetryErrorCode, TelemetryResult,
    config::{DataEndpoint, DataType},
    get_data_type, get_needed_message_size, message_meta,
    packet::Packet,
    router::{Clock, EndpointHandler, Router, RouterConfig},
    wire_format,
};
use alloc::{sync::Arc, vec::Vec};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc as StdArc, Mutex};

/// Clock that always returns 0 (via closure), used where wall-clock is
/// irrelevant and we only need a stable `Clock` impl.
fn zero_clock() -> Box<dyn Clock + Send + Sync> {
    Box::new(|| 0u64)
}

// ---------------------------------------------------------------------------
// Packet validation edge cases
// ---------------------------------------------------------------------------

/// Compute a concrete length for test packets, respecting schema element
/// counts for static/dynamic payloads.
fn concrete_len_for_test(ty: DataType) -> usize {
    match message_meta(ty).element {
        MessageElement::Static(_, _, _) => get_needed_message_size(ty),
        MessageElement::Dynamic(_, _) => {
            // Choose a reasonable dynamic size for tests:
            // numeric/bool → element_width * MESSAGE_ELEMENTS
            // string/hex    → 1 * MESSAGE_ELEMENTS (or any positive size)
            let w = match get_data_type(ty) {
                MessageDataType::UInt8 | MessageDataType::Int8 | MessageDataType::Bool => 1,
                MessageDataType::UInt16 | MessageDataType::Int16 => 2,
                MessageDataType::UInt32 | MessageDataType::Int32 | MessageDataType::Float32 => 4,
                MessageDataType::UInt64 | MessageDataType::Int64 | MessageDataType::Float64 => 8,
                MessageDataType::UInt128 | MessageDataType::Int128 => 16,
                MessageDataType::String | MessageDataType::Binary => 1,
                MessageDataType::NoData => 0,
            };
            let elems = get_message_meta(ty).element.into().max(1);
            core::cmp::max(1, w * elems)
        }
    }
}

/// Packet creation should reject empty endpoint lists and size mismatches
/// (for both static and dynamic payload kinds).
#[test]
fn packet_validate_rejects_empty_endpoints_and_size_mismatch() {
    let ty = DataType::named("GPS_DATA");
    let need = concrete_len_for_test(ty);

    let err = Packet::new(ty, &[], "x", 0, Arc::<[u8]>::from(vec![0u8; need])).unwrap_err();
    assert!(matches!(err, TelemetryError::EmptyEndpoints));

    // +1 ensures mismatch for both static and dynamic (not a multiple of element width)
    let err = Packet::new(
        ty,
        &[DataEndpoint::named("SD_CARD")],
        "x",
        0,
        Arc::<[u8]>::from(vec![0u8; need + 1]),
    )
    .unwrap_err();
    assert!(matches!(err, TelemetryError::SizeMismatch { .. }));
}

// ---------------------------------------------------------------------------
// Enum bounds + conversion validity
// ---------------------------------------------------------------------------

/// Ensure `DataType`, `DataEndpoint`, and `TelemetryErrorCode` all reject
/// values outside their numeric ranges.
#[test]
fn enum_conversion_bounds_and_rejections() {
    let max_ty = crate::current_max_data_type_id();
    assert!(DataType::try_from_u32(max_ty).is_some());
    assert!(DataType::try_from_u32(MAX_VALUE_DATA_TYPE + 1).is_none());

    let max_ep = crate::current_max_endpoint_id();
    assert!(DataEndpoint::try_from_u32(max_ep).is_some());
    assert!(DataEndpoint::try_from_u32(MAX_VALUE_DATA_ENDPOINT + 1).is_none());

    let min = TelemetryErrorCode::MIN;
    let max = TelemetryErrorCode::MAX;
    assert!(TelemetryErrorCode::try_from_i32(min).is_some());
    assert!(TelemetryErrorCode::try_from_i32(max).is_some());
    assert!(TelemetryErrorCode::try_from_i32(min - 1).is_none());
    assert!(TelemetryErrorCode::try_from_i32(max + 1).is_none());
}

// ---------------------------------------------------------------------------
// Wire-format header math + ByteReader edge cases
// ---------------------------------------------------------------------------

/// `packet_wire_size` must match the length of the packed output.
#[test]
fn packet_wire_size_matches_packed_len() {
    let endpoints = &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")];
    let pkt = Packet::from_f32_slice(DataType::named("GPS_DATA"), &[1.0, 2.0, 3.0], endpoints, 9)
        .unwrap();
    let need = wire_format::packet_wire_size(&pkt);
    let out = wire_format::pack_packet(&pkt);
    assert_eq!(need, out.len());
}

#[test]
fn schema_default_endpoints_omit_wire_bitmap_but_custom_endpoints_keep_it() {
    crate::tests::ensure_common_test_schema();
    let ty = DataType::named("GPS_DATA");
    let mut default_eps = message_meta(ty).endpoints.to_vec();
    default_eps.sort_unstable();
    let subset_eps = &default_eps[..1];

    let default_pkt = Packet::from_f32_slice(ty, &[1.0, 2.0, 3.0], &default_eps, 9)
        .unwrap()
        .with_nonce(7);
    let subset_pkt = Packet::from_f32_slice(ty, &[1.0, 2.0, 3.0], subset_eps, 9)
        .unwrap()
        .with_nonce(7);

    let default_wire = wire_format::pack_packet(&default_pkt);
    let subset_wire = wire_format::pack_packet(&subset_pkt);
    let bitmap_bytes = ((MAX_VALUE_DATA_ENDPOINT as usize) + 1).div_ceil(8);

    assert_eq!(
        default_wire[0] & 0x20,
        0,
        "default endpoint set omits bitmap"
    );
    assert_ne!(
        subset_wire[0] & 0x20,
        0,
        "custom endpoint set carries bitmap"
    );
    assert_eq!(subset_wire.len(), default_wire.len() + bitmap_bytes);

    let default_round = wire_format::unpack_packet(&default_wire).unwrap();
    let subset_round = wire_format::unpack_packet(&subset_wire).unwrap();
    assert_eq!(default_round.endpoints(), default_eps.as_slice());
    assert_eq!(subset_round.endpoints(), subset_eps);
    assert_eq!(
        wire_format::packet_id_from_wire(&default_wire).unwrap(),
        default_pkt.packet_id()
    );
    assert_eq!(
        wire_format::packet_id_from_wire(&subset_wire).unwrap(),
        subset_pkt.packet_id()
    );
}

fn ensure_compact_reliable_test_type() -> (DataType, DataEndpoint) {
    let ep = DataEndpoint::try_named("COMPACT_RELIABLE_EP").unwrap_or_else(|| {
        crate::config::register_endpoint_id_with_description(
            DataEndpoint(199),
            "COMPACT_RELIABLE_EP",
            "compact reliable test endpoint",
            false,
        )
        .unwrap_or_else(|_| DataEndpoint::named("COMPACT_RELIABLE_EP"))
    });
    let ty = DataType::try_named("COMPACT_RELIABLE_TYPE").unwrap_or_else(|| {
        crate::config::register_data_type_id_with_description(
            DataType(4091),
            "COMPACT_RELIABLE_TYPE",
            "compact reliable test type",
            MessageElement::Static(3, MessageDataType::Float32, MessageClass::Data),
            &[ep],
            ReliableMode::Ordered,
            1,
        )
        .unwrap_or_else(|_| DataType::named("COMPACT_RELIABLE_TYPE"))
    });
    (ty, ep)
}

#[test]
fn compact_reliable_header_roundtrips_and_shrinks_data_frames() {
    let (ty, ep) = ensure_compact_reliable_test_type();
    let pkt = Packet::from_f32_slice(ty, &[1.0, 2.0, 3.0], &[ep], 9)
        .unwrap()
        .with_nonce(7);

    let compact = wire_format::pack_packet_with_reliable(
        &pkt,
        wire_format::ReliableHeader {
            flags: 0,
            seq: 1,
            ack: 0,
        },
    );
    let fixed = wire_format::pack_packet_with_reliable(
        &pkt,
        wire_format::ReliableHeader {
            flags: 0,
            seq: u32::MAX,
            ack: u32::MAX,
        },
    );

    assert_ne!(
        compact[0] & 0x40,
        0,
        "small seq uses compact reliable header"
    );
    assert_eq!(
        fixed[0] & 0x40,
        0,
        "large seq+ack keeps fixed reliable header"
    );
    assert!(compact.len() + 7 <= fixed.len());

    let info = wire_format::peek_frame_info(&compact).unwrap();
    assert_eq!(
        info.reliable,
        Some(wire_format::ReliableHeader {
            flags: 0,
            seq: 1,
            ack: 0
        })
    );
    assert_eq!(
        wire_format::unpack_packet(&compact).unwrap().packet_id(),
        pkt.packet_id()
    );
}

#[test]
fn compact_reliable_ack_and_owned_rewrite_roundtrip() {
    let (ty, ep) = ensure_compact_reliable_test_type();
    let ack = wire_format::pack_reliable_ack("DST", ty, 0, 3);
    assert_ne!(
        ack[0] & 0x40,
        0,
        "small ACK-only frame uses compact reliable header"
    );
    let ack_info = wire_format::peek_frame_info(&ack).unwrap();
    assert_eq!(
        ack_info.reliable,
        Some(wire_format::ReliableHeader {
            flags: wire_format::RELIABLE_FLAG_ACK_ONLY,
            seq: 0,
            ack: 3
        })
    );

    let pkt = Packet::from_f32_slice(ty, &[4.0, 5.0, 6.0], &[ep], 10).unwrap();
    let fixed = wire_format::pack_packet_with_reliable(
        &pkt,
        wire_format::ReliableHeader {
            flags: 0,
            seq: u32::MAX,
            ack: u32::MAX,
        },
    );
    let rewritten = wire_format::rewrite_reliable_header_owned(&fixed, 0, 4, 0)
        .unwrap()
        .expect("reliable header present");
    assert_ne!(rewritten[0] & 0x40, 0);
    assert!(rewritten.len() < fixed.len());
    assert_eq!(
        wire_format::peek_frame_info(&rewritten).unwrap().reliable,
        Some(wire_format::ReliableHeader {
            flags: 0,
            seq: 4,
            ack: 0
        })
    );
}

// ---------------------------------------------------------------------------
// Router packing/unpacking paths
// ---------------------------------------------------------------------------

/// If only `Packed` handlers exist, the router must not unpack the
/// payload and just pass the raw bytes.
#[test]
fn packed_only_handlers_do_not_unpack() {
    let pkt = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0, 2.0, 3.0],
        &[DataEndpoint::named("SD_CARD")],
        123,
    )
    .unwrap();
    let wire = wire_format::pack_packet(&pkt);

    let called = StdArc::new(AtomicUsize::new(0));
    let c = called.clone();
    let handler = EndpointHandler::new_packed_handler(
        DataEndpoint::named("SD_CARD"),
        move |bytes: &[u8]| {
            assert!(bytes.len() >= wire_format::header_size_bytes(&pkt));
            c.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    );

    let r = Router::new_with_clock(RouterConfig::new(vec![handler]), zero_clock());
    r.rx_packed(&wire).unwrap();
    assert_eq!(called.load(Ordering::SeqCst), 1);
}

/// When mixing `Packet` and `Packed` handlers, ensure:
/// - unpacking happens only once,
/// - each endpoint handler is invoked exactly once.
#[test]
fn packet_handlers_trigger_single_unpack_and_fan_out() {
    let endpoints = &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")];
    let pkt = Packet::from_f32_slice(DataType::named("GPS_DATA"), &[1.0, 2.0, 3.0], endpoints, 5)
        .unwrap();
    let wire = wire_format::pack_packet(&pkt);

    let packet_called = StdArc::new(AtomicUsize::new(0));
    let packed_called = StdArc::new(AtomicUsize::new(0));

    let ph = packet_called.clone();
    let sh = packed_called.clone();

    let packet_h =
        EndpointHandler::new_packet_handler(DataEndpoint::named("SD_CARD"), move |_pkt| {
            ph.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });

    let packed_h = EndpointHandler::new_packed_handler(DataEndpoint::named("RADIO"), move |_b| {
        sh.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });

    let r = Router::new_with_clock(RouterConfig::new(vec![packet_h, packed_h]), zero_clock());

    r.rx_packed(&wire).unwrap();
    assert_eq!(packet_called.load(Ordering::SeqCst), 1);
    assert_eq!(packed_called.load(Ordering::SeqCst), 1);
}

/// If all addressed endpoints are local `Packet` handlers, router should
/// avoid serializing at all and never call TX.
#[test]
fn send_avoids_packing_when_only_local_packet_handlers_exist() {
    let tx_called = StdArc::new(AtomicUsize::new(0));
    let txc = tx_called.clone();
    let tx = move |bytes: &[u8]| -> TelemetryResult<()> {
        if packed_frame_type(bytes) == Some(DataType::named("GPS_DATA")) {
            txc.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    };

    let hits = StdArc::new(AtomicUsize::new(0));
    let h = hits.clone();
    let handler =
        EndpointHandler::new_packet_handler(DataEndpoint::named("SD_CARD"), move |pkt: &Packet| {
            pkt.validate().unwrap();
            h.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });

    let r = Router::new_with_clock(RouterConfig::new(vec![handler]), zero_clock());
    r.add_side_packed("tx", tx);
    let pkt = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0, 2.0, 3.0],
        &[DataEndpoint::named("SD_CARD")],
        0,
    )
    .unwrap();
    r.tx(pkt).unwrap();

    assert_eq!(tx_called.load(Ordering::SeqCst), 0);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

/// `Router::receive` for a direct packet should invoke any matching local
/// packet handlers exactly once.
#[test]
fn receive_direct_packet_invokes_handlers() {
    let called = StdArc::new(AtomicUsize::new(0));
    let c = called.clone();
    let handler =
        EndpointHandler::new_packet_handler(DataEndpoint::named("SD_CARD"), move |_pkt| {
            c.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });

    let r = Router::new_with_clock(RouterConfig::new(vec![handler]), zero_clock());
    let pkt = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[0.5, 0.5, 0.5],
        &[DataEndpoint::named("SD_CARD")],
        0,
    )
    .unwrap();
    r.rx(&pkt).unwrap();

    assert_eq!(called.load(Ordering::SeqCst), 1);
}

// ---------------------------------------------------------------------------
// Error payload truncation & encode_slice_le extra types
// ---------------------------------------------------------------------------

/// Ensure router’s internal TelemetryError payload is truncated to meta size
/// and doesn’t grow without bound.
#[test]
fn error_payload_is_truncated_to_meta_size() {
    let failing_tx = |_b: &[u8]| -> TelemetryResult<()> { Err(TelemetryError::Io("boom")) };

    let captured = StdArc::new(Mutex::new(String::new()));
    let c = captured.clone();
    let handler = EndpointHandler::new_packet_handler(DataEndpoint::named("SD_CARD"), move |pkt| {
        if pkt.data_type() == DataType::TelemetryError {
            *c.lock().unwrap() = pkt.as_string();
        }
        Ok(())
    });

    let r = Router::new_with_clock(RouterConfig::new(vec![handler]), zero_clock());
    r.add_side_packed("tx", failing_tx);
    let pkt = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0, 2.0, 3.0],
        &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")],
        1,
    )
    .unwrap();
    let _ = r.tx(pkt);

    let s = captured.lock().unwrap().clone();
    assert!(!s.is_empty());
    assert!(s.len() < 8_192);
}

/// Ensure `encode_slice_le` works correctly for both `u16` and `f64`.
#[test]
fn encode_slice_le_u16_and_f64() {
    let vals16 = [0x0102u16, 0xA1B2];
    let got = crate::router::encode_slice_le(&vals16);
    let mut exp = Vec::new();
    for v in vals16 {
        exp.extend_from_slice(&v.to_le_bytes());
    }
    assert_eq!(&*got, &exp);

    let vals64 = [1.5f64, -2.25];
    let got = crate::router::encode_slice_le(&vals64);
    let mut exp = Vec::new();
    for v in vals64 {
        exp.extend_from_slice(&v.to_le_bytes());
    }
    assert_eq!(&*got, &exp);
}

/// Ensure `test_payload_len_for` respects element widths and yields lengths
/// that are multiples of the correct width for all numeric/bool types.
#[test]
fn test_payload_len_for_respects_element_width() {
    use crate::tests::test_payload_len_for;

    for i in 0..=MAX_VALUE_DATA_TYPE {
        if let Some(ty) = DataType::try_from_u32(i) {
            let len = test_payload_len_for(ty);

            match get_data_type(ty) {
                MessageDataType::String | MessageDataType::Binary => {
                    // any positive length is fine for string/hex, just sanity check
                    assert!(len >= 1, "string/hex must have at least 1 byte for {ty:?}");
                }
                kind => {
                    let width = match kind {
                        MessageDataType::UInt8 | MessageDataType::Int8 | MessageDataType::Bool => 1,
                        MessageDataType::UInt16 | MessageDataType::Int16 => 2,
                        MessageDataType::UInt32
                        | MessageDataType::Int32
                        | MessageDataType::Float32 => 4,
                        MessageDataType::UInt64
                        | MessageDataType::Int64
                        | MessageDataType::Float64 => 8,
                        MessageDataType::UInt128 | MessageDataType::Int128 => 16,
                        MessageDataType::String | MessageDataType::Binary => 1,
                        MessageDataType::NoData => 0,
                    };
                    if width == 0 {
                        // NoData must have zero length
                        assert_eq!(
                            len, 0,
                            "NoData type must have zero-length payload for {ty:?}"
                        );
                        return;
                    }
                    assert_eq!(
                        len % width,
                        0,
                        "test payload length {len} not multiple of element width {width} for {ty:?}"
                    );
                }
            }
        }
    }
}
fn append_crc32(buf: &mut Vec<u8>) {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(buf);
    let crc = hasher.finalize();
    buf.extend_from_slice(&crc.to_le_bytes());
}
/// Construct an invalid varint (11 continuation bytes), and ensure
/// `unpack_packet` returns a `uleb128 too long` error.
#[test]
fn unpack_packet_rejects_overflowed_varint() {
    use crate::wire_format;
    // Construct a fake wire buffer with NEP=0, then an invalid varint (11 continuation bytes)
    let mut wire = vec![0x00u8]; // NEP = 0
    wire.extend([0xFFu8; 11]); // invalid ULEB128 (too long for u64)
    append_crc32(&mut wire);
    let err = wire_format::unpack_packet(&wire).unwrap_err();
    match err {
        TelemetryError::Unpack(msg) if msg.eq("uleb128 too long") => {}
        other => panic!("expected Unpack(uleb128 too long...) error, got {other:?}"),
    }
}

/// Endpoint order in the `endpoints` slice must not affect packed bytes.
#[test]
fn pack_packet_is_order_invariant_for_endpoints() {
    crate::tests::ensure_common_test_schema();
    use crate::config::{DataEndpoint, DataType};
    use crate::{packet::Packet, wire_format};

    let eps_a = &[DataEndpoint::named("RADIO"), DataEndpoint::named("SD_CARD")];
    let eps_b = &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")];

    let pkt_a = Packet::from_f32_slice(DataType::named("GPS_DATA"), &[1.0, 2.0, 3.0], eps_a, 0)
        .unwrap()
        .with_nonce(7);
    let pkt_b = Packet::from_f32_slice(DataType::named("GPS_DATA"), &[1.0, 2.0, 3.0], eps_b, 0)
        .unwrap()
        .with_nonce(7);

    let wa = wire_format::pack_packet(&pkt_a);
    let wb = wire_format::pack_packet(&pkt_b);

    assert_eq!(wa, wb, "endpoint order must not affect packed bytes");
}

/// With a large number of TX and RX items, `process_all_queues_with_timeout(0)`
/// must flush all TX and deliver all packets to handlers.
#[test]
fn process_all_queues_timeout_zero_handles_large_queues() {
    crate::tests::ensure_common_test_schema();
    use crate::config::{DataEndpoint, DataType};
    use crate::packet::Packet;
    use crate::router::{Router, RouterConfig};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let tx_count = Arc::new(AtomicUsize::new(0));
    let txc = tx_count.clone();
    let tx = move |bytes: &[u8]| -> TelemetryResult<()> {
        if packed_frame_type(bytes) == Some(DataType::named("GPS_DATA")) {
            txc.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    };

    let rx_count = Arc::new(AtomicUsize::new(0));
    let rxc = rx_count.clone();
    let handler =
        EndpointHandler::new_packet_handler(DataEndpoint::named("SD_CARD"), move |_pkt| {
            rxc.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });

    let router = Router::new_with_clock(
        RouterConfig::new(vec![handler]),
        Box::new(|| UnixClock.now_ms()),
    );
    router.add_side_packed("tx", tx);

    // Enqueue many TX and RX items with unique payloads/timestamps.
    const N: usize = 200;
    for i in 0..N {
        let base_tx = 1.0_f32 + i as f32 * 0.01;
        router
            .log_queue(DataType::named("GPS_DATA"), &[base_tx, 2.0, 3.0])
            .unwrap();

        let pkt = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[9.0 + i as f32 * 0.01, 8.0, 7.0],
            &[DataEndpoint::named("SD_CARD")],
            i as u64,
        )
        .unwrap();
        router.rx_queue(pkt).unwrap();
    }

    let (queued_rx, _queued_tx, _queued_recent) = router.debug_queue_lengths();
    assert!(queued_rx <= N, "RX queue should be bounded");
    assert!(
        router.debug_shared_queue_bytes_used() <= crate::config::MAX_QUEUE_BUDGET,
        "shared queue budget should cap retained queued bytes"
    );

    router.process_all_queues_with_timeout(0).unwrap();

    assert_eq!(
        tx_count.load(Ordering::SeqCst),
        N,
        "all queued GPS TX should flush"
    );
    assert_eq!(
        rx_count.load(Ordering::SeqCst),
        N + queued_rx,
        "each retained GPS TX local delivery + retained RX packet should invoke handler"
    );
}
