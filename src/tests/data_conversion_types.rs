// ---------------------------------------------------------------------------
// Packet typed data accessors
// ---------------------------------------------------------------------------

use crate::config::{DataEndpoint, DataType};
use crate::packet::Packet;
use crate::{MAX_VALUE_DATA_TYPE, MessageDataType, TelemetryError, get_data_type};

/// data_as_f32 should round-trip values written via from_f32_slice.
#[test]
fn data_as_f32_roundtrips_gps() {
    let eps = &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")];
    let src = [1.5_f32, -2.25, 3.0];

    let pkt = Packet::from_f32_slice(DataType::named("GPS_DATA"), &src, eps, 42).unwrap();
    let vals = pkt.data_as_f32().unwrap();

    assert_eq!(vals, src);
}

/// Calling a mismatched accessor (e.g. data_as_u16 on a Float32 packet)
/// must return TelemetryError::TypeMismatch.
#[test]
fn mismatched_typed_accessor_returns_type_mismatch() {
    let eps = &[DataEndpoint::named("SD_CARD")];
    let src = [1.0_f32, 2.0, 3.0];

    let pkt = Packet::from_f32_slice(DataType::named("GPS_DATA"), &src, eps, 0).unwrap();

    let res = pkt.data_as_u16();
    match res {
        Err(TelemetryError::TypeMismatch { .. }) => {}
        other => panic!("expected TypeMismatch, got {other:?}"),
    }
}

/// If there is a Bool-typed DataType in the schema, ensure data_as_bool
/// decodes non-zero bytes to true and zero to false.
#[test]
fn data_as_bool_decodes_nonzero() {
    // Find any Bool-typed DataType in the schema.
    let mut bool_ty_opt = None;
    for i in 0..=MAX_VALUE_DATA_TYPE {
        if let Some(ty) = DataType::try_from_u32(i)
            && get_data_type(ty) == MessageDataType::Bool
        {
            bool_ty_opt = Some(ty);
            break;
        }
    }

    // If the schema doesn't define any Bool-typed messages, skip this test.
    let bool_ty = match bool_ty_opt {
        Some(t) => t,
        None => return,
    };

    let eps = &[DataEndpoint::named("SD_CARD")];
    let vals = [true];

    let pkt = Packet::from_bool_slice(bool_ty, &vals, eps, 0).unwrap();
    let decoded = pkt.data_as_bool().unwrap();
    assert_eq!(decoded, vals);
}
