//! Offline diagnostics only. Reuse the actual side codec including templates
//! and chunk assembly; never add an alternate production parser or wire API.
use super::*;
use serde_json::{Value, json};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const MAX_TRACE_BYTES: usize = 4 * 1024 * 1024;
fn bounded_read(path: &Path, max: usize) -> Vec<u8> {
    let mut data = Vec::new();
    fs::File::open(path)
        .unwrap()
        .take((max + 1) as u64)
        .read_to_end(&mut data)
        .unwrap();
    assert!(data.len() <= max, "diagnostic input exceeds bound");
    data
}
fn decoder() -> (Router, RouterSideId, Arc<AtomicU64>) {
    let now = Arc::new(AtomicU64::new(0));
    let clock = now.clone();
    let router = Router::new_with_clock(
        RouterConfig::default().with_sender("TRACE_DECODER"),
        Box::new(move || clock.load(Ordering::Relaxed)),
    );
    let mut options = RouterSideOptions::default().with_small_packet_transport(192);
    options.max_side_transport_templates = 64;
    let side = router.add_side_packed_with_options("trace", |_| Ok(()), options);
    (router, side, now)
}
fn packet_row(bytes: &[u8], at_us: u64, offset: usize) -> TelemetryResult<Value> {
    let info = wire_format::peek_frame_info(bytes)?;
    let packet = wire_format::unpack_packet(bytes)?;
    let ack_for = if Router::is_end_to_end_ack_packet(&packet) {
        Some(Router::decode_end_to_end_reliable_ack(packet.payload())?)
    } else {
        None
    };
    let name = format!("{:?}", info.envelope.ty);
    let managed_value = matches!(
        name.as_str(),
        "FLIGHT_STATE" | "FLIGHT_BUZZER" | "AV_BAY_UNDERGLOW"
    )
    .then(|| packet.payload().to_vec());
    Ok(
        json!({"at_us":at_us,"uart_offset":offset,"packet_id":wire_format::packet_id_from_wire(bytes)?,
        "type":name,"type_id":info.envelope.ty.as_u32(),"sender":info.envelope.sender.as_ref(),
        "source_address":info.envelope.source_address,"timestamp_ms":info.envelope.timestamp_ms,
        "targets":info.envelope.target_senders.as_ref(),"payload_len":packet.payload().len(),
        "managed_value":managed_value,"ack_for":ack_for,"ack_owner":Router::end_to_end_ack_sender_hash(&packet),
        "reliable":info.reliable.map(|r|json!({"flags":r.flags,"seq":r.seq,"ack":r.ack}))}),
    )
}
fn advance_codec_clock(now: &AtomicU64, at_us: u64) -> u64 {
    // Preserve all raw timestamps and byte order. Only the decoder's millisecond
    // maintenance clock uses a running max for explicitly bounded context jitter.
    let next = (at_us / 1000).max(now.load(Ordering::Relaxed));
    now.store(next, Ordering::Relaxed);
    next
}
// RRv1 is an application envelope, not an SDK wire protocol. Diagnostic-only
// implementation is checked against fixtures emitted by the actual GS source
// encode/decode functions before each driver invocation.
fn relay_envelope(bytes: &[u8]) -> Option<(u8, &[u8])> {
    if bytes.len() < 8 || bytes.len() > 4080 + 8 || &bytes[..3] != b"RR\x01" {
        return None;
    }
    let end = bytes.len() - 4;
    (crc32fast::hash(&bytes[..end]) == u32::from_le_bytes(bytes[end..].try_into().ok()?))
        .then_some((bytes[3], &bytes[4..end]))
}
fn decode_stream(path: &Path, max_clock_backstep_us: u64) -> Value {
    let bytes = bounded_read(path, MAX_TRACE_BYTES);
    assert!(bytes.len() >= 32 && &bytes[..8] == b"SEDSRBT1");
    assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 1);
    assert_eq!(u32::from_le_bytes(bytes[12..16].try_into().unwrap()), 9);
    assert_eq!((bytes.len() - 32) % 9, 0);
    let status_path = format!("{}.status.json", path.display());
    let status: Value =
        serde_json::from_slice(&bounded_read(Path::new(&status_path), 4096)).unwrap();
    assert_eq!(status["finished"], true, "trace is incomplete");
    assert_eq!(status["capped"], false, "trace is capped");
    assert_eq!(
        status["records"].as_u64().unwrap() as usize,
        (bytes.len() - 32) / 9
    );
    let mut raw = Vec::new();
    let mut times = Vec::new();
    for record in bytes[32..].as_chunks::<9>().0 {
        times.push(u64::from_le_bytes(record[..8].try_into().unwrap()));
        raw.push(record[8]);
    }
    let backwards: Vec<_> = times
        .windows(2)
        .filter(|pair| pair[0] > pair[1])
        .map(|pair| pair[0] - pair[1])
        .collect();
    assert!(max_clock_backstep_us <= 100);
    assert!(
        backwards
            .iter()
            .all(|value| *value <= max_clock_backstep_us)
    );
    let (router, side, now) = decoder();
    let mut frames = Vec::new();
    let mut packets = Vec::new();
    let mut errors = Vec::new();
    let mut offset = 0;
    let mut last_end = 0;
    // Diagnostic candidate scan: a CRC-valid following frame is recorded even
    // behind damaged/truncated framing. This is deliberately NOT proof that a
    // production UART decoder accepted it immediately or at all.
    while offset + 4 <= raw.len() {
        let kind = match raw[offset..offset + 2] {
            [0xa5, 0x5a] => "data",
            [0xa6, 0x5b] => "command",
            _ => {
                offset += 1;
                continue;
            }
        };
        let length = u16::from_le_bytes([raw[offset + 2], raw[offset + 3]]) as usize;
        if length == 0 || length > 4096 || offset + 4 + length > raw.len() {
            offset += 1;
            continue;
        }
        let end = offset + 4 + length;
        let body = &raw[offset + 4..end];
        let relay = relay_envelope(body);
        if body.starts_with(b"RR") && relay.is_none() {
            offset += 1;
            continue;
        }
        let relay_kind = relay.map(|(kind, _)| kind);
        let data_relay = matches!(relay_kind, Some(1 | 2 | 5));
        if kind == "command" && !data_relay {
            let mut frame = json!({"at_us":times[end-1],"uart_offset":offset,"length":length,"kind":kind,
                "opaque":true,"relay_kind":relay_kind,"relay_crc_verified":relay.is_some(),"preceding_gap_bytes":offset-last_end});
            if let Some((relay_kind, data)) = relay {
                frame["relay_payload_len"] = data.len().into();
                // Actual GS Mesh::tick emits HEALTH(sessionu32,sequenceu32,directu8)
                // and READY(sessionu32,sequenceu32). Never expose settings/voice.
                if (relay_kind == 0 && data.len() == 9) || (relay_kind == 7 && data.len() == 8) {
                    frame["relay_sequence"] =
                        u32::from_le_bytes(data[4..8].try_into().unwrap()).into();
                    if relay_kind == 0 {
                        frame["relay_health_direct"] = (data[8] != 0).into();
                    }
                }
            }
            frames.push(frame);
            offset = end;
            last_end = end;
            continue;
        }
        let body = if data_relay { relay.unwrap().1 } else { body };
        let wrapper = match parse_side_transport_wrapper(body) {
            Ok(wrapper) => wrapper,
            Err(_) => {
                offset += 1;
                continue;
            }
        };
        if wrapper.is_none() && wire_format::peek_frame_info(body).is_err() {
            offset += 1;
            continue;
        }
        let at = times[end - 1];
        let codec_ms = advance_codec_clock(&now, at);
        let mut frame = json!({"at_us":at,"uart_offset":offset,"length":length,"kind":kind,
            "relay_kind":relay_kind,"relay_crc_verified":relay.is_some(),"inner_length":body.len(),
            "side_kind":wrapper.map(|(kind,_)|kind),"preceding_gap_bytes":offset-last_end,"codec_clock_ms":codec_ms});
        match router.decode_side_transport_frame(side, body) {
            Ok(Some(canonical)) => match packet_row(canonical.as_ref(), at, offset) {
                Ok(mut row) => {
                    row["relay_kind"] = relay_kind.into();
                    row["outer_uart_frame_accepted_us"] = at.into();
                    frame["packet_index"] = packets.len().into();
                    packets.push(row);
                }
                Err(error) => errors.push(json!({"at_us":at,"uart_offset":offset,"stage":"canonical","error":format!("{error:?}")})),
            },
            Ok(None) => frame["codec_no_packet"] = true.into(),
            Err(error) => errors.push(json!({"at_us":at,"uart_offset":offset,"stage":"side_codec","error":format!("{error:?}")})),
        }
        frames.push(frame);
        offset = end;
        last_end = end;
    }
    json!({"file":path,"station":u32::from_le_bytes(bytes[16..20].try_into().unwrap()),
        "direction":u32::from_le_bytes(bytes[20..24].try_into().unwrap()),"raw_bytes":raw.len(),"backward_timestamp_count":backwards.len(),"fully_monotonic":backwards.is_empty(),"max_clock_backstep_us":backwards.iter().max().copied().unwrap_or(0),
        "frames":frames,"packets":packets,"errors":errors,"trailing_bytes":raw.len()-last_end})
}

fn capture_paths(
    input: Option<std::ffi::OsString>,
    output: Option<std::ffi::OsString>,
) -> Result<Option<(PathBuf, PathBuf)>, &'static str> {
    match (input, output) {
        (None, None) => Ok(None),
        (Some(input), Some(output)) if !input.is_empty() && !output.is_empty() => {
            Ok(Some((input.into(), output.into())))
        }
        _ => Err("capture manifest and output must both be explicitly provided and nonempty"),
    }
}

#[test]
#[ignore = "offline capture diagnostic; without capture arguments validates its self-contained actual-codec fixture"]
fn decode_capture() {
    match capture_paths(
        std::env::var_os("SEDSNET_RADIO_TRACE_MANIFEST"),
        std::env::var_os("SEDSNET_RADIO_TRACE_OUTPUT"),
    )
    .expect("invalid capture arguments")
    {
        Some((input, output)) => decode_capture_files(&input, &output),
        None => self_contained_trace_fixture(),
    }
}

fn decode_capture_files(input: &Path, output: &Path) {
    let manifest: Value = serde_json::from_slice(&bounded_read(input, 65_536)).unwrap();
    assert_eq!(manifest["version"], 1);
    if let Some(schemas) = manifest["schemas"].as_array() {
        assert!(schemas.len() <= 16);
        for schema in schemas {
            crate::config::register_schema_json_file_with_budget(
                schema.as_str().unwrap(),
                2 * 1024 * 1024,
            )
            .unwrap();
        }
    }
    if let Some(fixtures) = manifest["relay_fixtures"].as_array() {
        assert_eq!(fixtures.len(), 6);
        for fixture in fixtures {
            let bytes: Vec<u8> = fixture["bytes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| u8::try_from(v.as_u64().unwrap()).unwrap())
                .collect();
            if fixture["valid"] == true {
                let (kind, body) = relay_envelope(&bytes).expect("actual GS fixture rejected");
                assert_eq!(u64::from(kind), fixture["kind"].as_u64().unwrap());
                assert_eq!(body, [0, 1, 2, 128, 255]);
            } else {
                assert!(relay_envelope(&bytes).is_none());
            }
        }
    }
    let streams = manifest["streams"].as_array().unwrap();
    assert!(!streams.is_empty() && streams.len() <= 32);
    let rows: Vec<_> = streams
        .iter()
        .map(|path| {
            decode_stream(
                Path::new(path.as_str().unwrap()),
                manifest["max_clock_backstep_us"].as_u64().unwrap_or(0),
            )
        })
        .collect();
    let known_source_addresses: serde_json::Map<String, Value> = ["GS", "RRLS", "RF", "FC", "PB"]
        .into_iter()
        .map(|name| {
            (
                name.to_owned(),
                json!(crate::packet::sender_address_u32(name)),
            )
        })
        .collect();
    let result = json!({"version":1,"codec":"actual SDK Router side codec + canonical wire_format",
        "known_source_addresses": known_source_addresses,
        "relay_contract_sha256":manifest["relay_contract_sha256"],
        "relay_fixtures_validated":manifest["relay_fixtures"].as_array().map_or(0, Vec::len),
        "scope":"Diagnostic CRC-valid UART candidate scan; acceptance/timing by production UART parser is NOT inferred",
        "codec_clock":"running maximum of frame completion milliseconds; raw byte order/timestamps preserved; explicit backstep limit<=100us",
        "streams":rows});
    fs::write(output, serde_json::to_vec_pretty(&result).unwrap()).unwrap();
    println!("RADIO_TRACE_SDK_DECODE_PASS");
}

struct FixtureDirectory(PathBuf);
impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn self_contained_trace_fixture() {
    crate::tests::ensure_common_test_schema();
    let directory = FixtureDirectory(std::env::temp_dir().join(format!(
            "seds-radio-decoder-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )));
    fs::create_dir(&directory.0).unwrap();
    let tx = Router::new_with_clock(RouterConfig::default(), Box::new(|| 0));
    let options = RouterSideOptions::default().with_small_packet_transport(64);
    let side = tx.add_side_packed_with_options("fixture", |_| Ok(()), options.clone());
    let packet = Packet::new(
        DataType::TelemetryError,
        &[DataEndpoint::named("RADIO")],
        "TRACE_SOURCE",
        41,
        crate::shared_bytes::convert(Arc::<[u8]>::from(vec![b'x'; 400])),
    )
    .unwrap();
    let canonical = wire_format::pack_packet(&packet);
    let mut uart = Vec::new();
    let mut kinds = Vec::new();
    for _ in 0..2 {
        let frames = tx
            .encode_side_transport_frames(
                side,
                options.clone(),
                crate::shared_bytes::convert(canonical.clone()),
            )
            .unwrap();
        tx.send_side_frames_resumable(side, frames, |frame| {
            kinds.push(frame[3]);
            uart.extend_from_slice(&[0xa5, 0x5a]);
            uart.extend_from_slice(&u16::try_from(frame.len()).unwrap().to_le_bytes());
            uart.extend_from_slice(frame);
            Ok(())
        })
        .unwrap();
    }
    assert!(kinds.contains(&SIDE_TRANSPORT_KIND_CHUNK));
    // The400-byte compact follow-up is itself chunked at this64-byte cap;
    // outer UART frames therefore expose CHUNK rather than COMPACT kinds.
    let mut bytes = b"SEDSRBT1".to_vec();
    for word in [1u32, 9, 0, 1] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    let cutoff = (uart.len() as u64 + 1) * 100;
    bytes.extend_from_slice(&cutoff.to_le_bytes());
    let records = uart.len();
    for (index, byte) in uart.into_iter().enumerate() {
        bytes.extend_from_slice(&(index as u64 * 100).to_le_bytes());
        bytes.push(byte);
    }
    let trace = directory.0.join("fixture.bin");
    fs::write(&trace, bytes).unwrap();
    fs::write(
        trace.with_extension("bin.status.json"),
        serde_json::to_vec(&json!({"version":1,"records":records,"finished":true,"capped":false}))
            .unwrap(),
    )
    .unwrap();
    let input = directory.0.join("manifest.json");
    let output = directory.0.join("decoded.json");
    fs::write(
        &input,
        serde_json::to_vec(&json!({"version":1,"streams":[trace]})).unwrap(),
    )
    .unwrap();
    decode_capture_files(&input, &output);
    let decoded: Value = serde_json::from_slice(&bounded_read(&output, MAX_TRACE_BYTES)).unwrap();
    let stream = &decoded["streams"][0];
    assert!(stream["errors"].as_array().unwrap().is_empty());
    let packets = stream["packets"].as_array().unwrap();
    assert_eq!(packets.len(), 2);
    assert!(
        packets
            .iter()
            .all(|row| row["packet_id"].as_u64() == Some(packet.packet_id())
                && row["payload_len"] == 400)
    );
    assert_eq!(stream["trailing_bytes"], 0);
    println!("RADIO_TRACE_SELF_CONTAINED_FULL_CAMPAIGN_PASS");
}

#[test]
fn capture_argument_pair_selects_fixture_only_when_both_are_absent() {
    assert!(capture_paths(None, None).unwrap().is_none());
    assert!(capture_paths(Some("manifest".into()), None).is_err());
    assert!(capture_paths(None, Some("output".into())).is_err());
    assert!(capture_paths(Some("".into()), Some("output".into())).is_err());
    assert!(capture_paths(Some("manifest".into()), Some("".into())).is_err());
    assert_eq!(
        capture_paths(Some("manifest".into()), Some("output".into())).unwrap(),
        Some((PathBuf::from("manifest"), PathBuf::from("output")))
    );
}

#[test]
fn exact_side_codec_reconstructs_bootstrap_chunks_and_compact_followup() {
    crate::tests::ensure_common_test_schema();
    let tx = Router::new_with_clock(RouterConfig::default(), Box::new(|| 0));
    let opts = RouterSideOptions::default().with_small_packet_transport(64);
    let a = tx.add_side_packed_with_options("wire", |_| Ok(()), opts.clone());
    let (rx, b, _) = decoder();
    let packet = Packet::new(
        DataType::TelemetryError,
        &[DataEndpoint::named("RADIO")],
        "TRACE_SOURCE",
        41,
        crate::shared_bytes::convert(Arc::<[u8]>::from(vec![b'x'; 400])),
    )
    .unwrap();
    let raw = wire_format::pack_packet(&packet);
    let mut kinds = Vec::new();
    for _ in 0..2 {
        let frames = tx
            .encode_side_transport_frames(
                a,
                opts.clone(),
                crate::shared_bytes::convert(raw.clone()),
            )
            .unwrap();
        let mut decoded = None;
        tx.send_side_frames_resumable(a, frames, |wire| {
            kinds.push(wire[3]);
            if let Some(value) = rx.decode_side_transport_frame(b, wire)? {
                decoded = Some(value);
            }
            Ok(())
        })
        .unwrap();
        let decoded = decoded.unwrap();
        let reconstructed = wire_format::unpack_packet(decoded.as_ref()).unwrap();
        assert_eq!(reconstructed.payload(), packet.payload());
        assert_eq!(reconstructed.packet_id(), packet.packet_id());
    }
    assert!(kinds.contains(&SIDE_TRANSPORT_KIND_CHUNK));
    let row = packet_row(&raw, 123, 0).unwrap();
    assert_eq!(row["packet_id"].as_u64().unwrap(), packet.packet_id());
    assert_eq!(row["payload_len"], 400);
}

#[test]
fn codec_replay_clock_never_reverses_or_reorders_raw_capture_times() {
    let now = AtomicU64::new(0);
    let raw = [1005, 995, 1110];
    let ticks: Vec<_> = raw
        .iter()
        .map(|at| advance_codec_clock(&now, *at))
        .collect();
    assert_eq!(ticks, vec![1, 1, 1]);
    assert_eq!(raw, [1005, 995, 1110]);
}
