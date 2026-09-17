use crate::timesync::{
    build_timesync_request, build_timesync_response, compute_offset_delay, decode_timesync_request,
    decode_timesync_response,
};

#[test]
fn timesync_request_roundtrip() {
    let pkt = build_timesync_request(7, 1234).unwrap();
    let decoded = decode_timesync_request(&pkt).unwrap();
    assert_eq!(decoded.seq, 7);
    assert_eq!(decoded.t1_ms, 1234);
}

#[test]
fn timesync_response_roundtrip() {
    let pkt = build_timesync_response(9, 100, 110, 115).unwrap();
    let decoded = decode_timesync_response(&pkt).unwrap();
    assert_eq!(decoded.seq, 9);
    assert_eq!(decoded.t1_ms, 100);
    assert_eq!(decoded.t2_ms, 110);
    assert_eq!(decoded.t3_ms, 115);
}

#[test]
fn timesync_offset_delay_math() {
    let sample = compute_offset_delay(10, 20, 30, 40);
    assert_eq!(sample.offset_ms, 0);
    assert_eq!(sample.delay_ms, 20);
}
