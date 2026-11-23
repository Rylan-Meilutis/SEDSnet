#![cfg(all(feature = "std", feature = "discovery", feature = "compact-bundle"))]
//! Bytes on the wire per packet kind and per link frame.
//!
//! Prints the table behind the wire-format overhead figures in the changelog
//! and asserts budgets so a regression fails. Run with
//! `cargo test --test wire_overhead_report -- --nocapture`.
//!
//! Packets use generic names with schema-hashed IDs (the normal case for
//! application types and endpoints), a network-time timestamp and time-base
//! epoch 1 (any node that has stepped its clock once).

use sedsnet::config::{DataEndpoint, DataType};
use sedsnet::packet::Packet;
use sedsnet::router::{EndpointHandler, Router, RouterConfig, RouterSideId, RouterSideOptions, SideTransportProfile};
use sedsnet::wire_format::{ReliableHeader, pack_packet, pack_packet_with_reliable, pack_reliable_ack};
use sedsnet::{MessageClass, MessageDataType, MessageElement, ReliableMode};
use std::collections::VecDeque;
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicU64, Ordering},
};

/// A network-time timestamp (late 2026, Unix milliseconds).
const NOW_MS: u64 = 1_795_000_000_000;
/// Radio budget per turn.
const RADIO_TURN_BYTES: usize = 691;
const RADIO_FRAME: usize = 192;

struct Schema {
    vector: DataType,
    sink: DataEndpoint,
    command: DataType,
    actuator: DataEndpoint,
}

fn schema() -> &'static Schema {
    static SCHEMA: OnceLock<Schema> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        let sink = sedsnet::config::register_endpoint("OVERHEAD_TELEMETRY_SINK", false).unwrap();
        let actuator = sedsnet::config::register_endpoint("OVERHEAD_COMMAND_SINK", false).unwrap();
        let vector = sedsnet::config::register_data_type(
            "OVERHEAD_VECTOR_F32X3",
            MessageElement::Static(3, MessageDataType::Float32, MessageClass::Data),
            &[sink],
            ReliableMode::None,
            0,
        )
        .unwrap();
        let command = sedsnet::config::register_data_type(
            "OVERHEAD_COMMAND_U8X2",
            MessageElement::Static(2, MessageDataType::UInt8, MessageClass::Data),
            &[actuator],
            ReliableMode::Ordered,
            0,
        )
        .unwrap();
        Schema {
            vector,
            sink,
            command,
            actuator,
        }
    })
}

fn vector_packet(ts: u64) -> Packet {
    let s = schema();
    let payload: Vec<u8> = [1.5f32, -2.25, 9.80665]
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect();
    // A fresh (newest) timestamp needs no packet nonce, as for periodic
    // telemetry; SEDSnet 6 always carried a pseudo-random one (3 bytes).
    Packet::new(s.vector, &[s.sink], "NODE_A", ts, Arc::from(payload))
        .unwrap()
        .with_nonce(0)
        .with_time_epoch(1)
}

fn words(values: &[u64]) -> Arc<[u8]> {
    values.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>().into()
}

fn timesync_packet(ty: DataType, payload: Arc<[u8]>) -> Packet {
    Packet::new(ty, &[DataEndpoint::TimeSync], "NODE_A", NOW_MS, payload)
        .unwrap()
        .with_nonce(200)
        .with_time_epoch(1)
}

/// Canonical frame sizes (what a shared CAN bus carries; no dictionary).
fn canonical_rows() -> Vec<(&'static str, usize, usize)> {
    let s = schema();
    let mut rows = Vec::new();
    let v = vector_packet(NOW_MS);
    rows.push(("telemetry f32x3", pack_packet(&v).len(), v.payload().len()));
    let cmd = Packet::new(s.command, &[s.actuator], "NODE_B", NOW_MS, Arc::from([1u8, 0]))
        .unwrap()
        .with_nonce(0)
        .with_time_epoch(1);
    let rel = ReliableHeader {
        flags: 0,
        seq: 42,
        ack: 0,
    };
    rows.push((
        "reliable command u8x2 (hop seq 42)",
        pack_packet_with_reliable(&cmd, rel).len(),
        2,
    ));
    rows.push((
        "reliable command u8x2 (e2e, unsequenced)",
        pack_packet(&cmd).len(),
        2,
    ));
    rows.push((
        "hop ACK",
        pack_reliable_ack("NODE_A", s.command, NOW_MS, 42).len(),
        0,
    ));
    let announce = timesync_packet(DataType::TimeSyncAnnounce, words(&[0x8000_0000_0001_0203, NOW_MS]));
    rows.push(("time sync announce", pack_packet(&announce).len(), 16));
    let request = timesync_packet(DataType::TimeSyncRequest, words(&[17, 123_456]));
    rows.push(("time sync request", pack_packet(&request).len(), 16));
    let response = timesync_packet(
        DataType::TimeSyncResponse,
        words(&[17, 123_456, (1 << 63) | (NOW_MS * 1000 - 3), (5 << 56) | (NOW_MS * 1000 - 900)]),
    );
    rows.push(("time sync response", pack_packet(&response).len(), 32));
    rows
}

struct Pair {
    clock: Arc<AtomicU64>,
    a: Arc<Router>,
    b: Arc<Router>,
    a_out: Arc<Mutex<VecDeque<Vec<u8>>>>,
    b_out: Arc<Mutex<VecDeque<Vec<u8>>>>,
    a_tap: Arc<Mutex<Vec<Vec<u8>>>>,
    a_side: RouterSideId,
    b_side: RouterSideId,
}

fn pair(opts: RouterSideOptions) -> Pair {
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let sink = schema().sink;
    let mk = |name: &str| {
        let tick = clock.clone();
        let handlers = if name == "NODE_B" {
            vec![EndpointHandler::new_packet_handler(sink, |_pkt| Ok(()))]
        } else {
            Vec::new()
        };
        Arc::new(Router::new_with_clock(
            RouterConfig::new(handlers).with_sender(name),
            Box::new(move || tick.load(Ordering::Relaxed)),
        ))
    };
    let a = mk("NODE_A");
    let b = mk("NODE_B");
    let a_out = Arc::new(Mutex::new(VecDeque::new()));
    let b_out = Arc::new(Mutex::new(VecDeque::new()));
    let a_tap = Arc::new(Mutex::new(Vec::new()));
    let (q, tap) = (a_out.clone(), a_tap.clone());
    let a_side = a.add_side_packed_with_priority_and_options(
        "link",
        move |bytes: &[u8], _priority| {
            tap.lock().unwrap().push(bytes.to_vec());
            q.lock().unwrap().push_back(bytes.to_vec());
            Ok(())
        },
        opts.clone(),
    );
    let q = b_out.clone();
    let b_side = b.add_side_packed_with_priority_and_options(
        "link",
        move |bytes: &[u8], _priority| {
            q.lock().unwrap().push_back(bytes.to_vec());
            Ok(())
        },
        opts,
    );
    Pair {
        clock,
        a,
        b,
        a_out,
        b_out,
        a_tap,
        a_side,
        b_side,
    }
}

impl Pair {
    fn pump(&self, ms: u64, discovery: bool) {
        for _ in 0..ms {
            self.clock.fetch_add(1, Ordering::Relaxed);
            loop {
                let Some(frame) = self.a_out.lock().unwrap().pop_front() else { break };
                let _ = self.b.rx_packed_from_side(&frame, self.b_side);
            }
            loop {
                let Some(frame) = self.b_out.lock().unwrap().pop_front() else { break };
                let _ = self.a.rx_packed_from_side(&frame, self.a_side);
            }
            for r in [&self.a, &self.b] {
                if discovery {
                    r.poll_discovery().unwrap();
                }
                r.process_all_queues().unwrap();
            }
        }
    }
}

/// Mean bytes per telemetry packet on a point-to-point templated link, over
/// `count` packets at 10 Hz (template refreshes included).
fn templated_bytes_per_packet(count: usize) -> (f64, usize, usize) {
    let s = schema();
    let opts = RouterSideOptions {
        reliable_enabled: false,
        max_side_transport_templates: 16,
        side_transport_profile: SideTransportProfile::Ipv6Like,
        ..RouterSideOptions::default()
    }
    .with_small_packet_transport(RADIO_FRAME);
    let p = pair(opts);
    for r in [&p.a, &p.b] {
        r.announce_discovery().unwrap();
    }
    p.pump(3_000, true);
    p.a_tap.lock().unwrap().clear();
    let payload: Vec<u8> = [1.5f32, -2.25, 9.80665]
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect();
    let mut sent = 0;
    for _ in 0..count {
        let pkt = Packet::new(s.vector, &[s.sink], "NODE_A", p.clock.load(Ordering::Relaxed), Arc::from(payload.clone()))
            .unwrap();
        p.a.tx(pkt).unwrap();
        sent += 1;
        p.pump(100, false);
    }
    let frames = p.a_tap.lock().unwrap();
    let bytes: usize = frames.iter().map(Vec::len).sum();
    let largest = frames.iter().map(Vec::len).max().unwrap_or(0);
    (bytes as f64 / sent as f64, frames.len(), largest)
}

fn bundle_sizes() -> Vec<(usize, usize)> {
    (1..=24)
        .map(|n| {
            let frames: Vec<Vec<u8>> = (0..n)
                .map(|i| pack_packet(&vector_packet(NOW_MS + 20 * i as u64)).to_vec())
                .collect();
            let refs: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
            (n, sedsnet::wire_bundle::pack_bundle(&refs).unwrap().len())
        })
        .collect()
}

/// Discovery frames on a canonical point-to-point link: (type name, count, mean bytes).
fn discovery_rows() -> Vec<(String, usize, f64)> {
    let p = pair(RouterSideOptions::default());
    for r in [&p.a, &p.b] {
        r.announce_discovery().unwrap();
    }
    p.pump(3_000, true);
    let mut by_type: std::collections::BTreeMap<String, (usize, usize)> = Default::default();
    for frame in p.a_tap.lock().unwrap().iter() {
        let name = match sedsnet::wire_format::unpack_packet(frame) {
            Ok(pkt) => format!("{:?}", pkt.data_type()),
            Err(_) => "control/other".to_string(),
        };
        let e = by_type.entry(name).or_default();
        e.0 += 1;
        e.1 += frame.len();
    }
    by_type
        .into_iter()
        .map(|(k, (n, b))| (k, n, b as f64 / n as f64))
        .collect()
}

#[test]
fn wire_overhead_table() {
    println!("--- discovery frames, first 3 s (canonical link) ---");
    for (name, n, mean) in discovery_rows() {
        println!("{name:44} {n:3} frames, mean {mean:6.1} B");
    }
    println!("--- canonical frames (shared CAN bus) ---");
    for (name, len, payload) in canonical_rows() {
        println!("{name:44} {len:4} B  (payload {payload:3}, overhead {:3})", len - payload);
    }
    let (templated, frames, largest) = templated_bytes_per_packet(90);
    println!("--- point-to-point templated link (UART / radio frames) ---");
    println!(
        "telemetry f32x3: {templated:.2} B per packet ({frames} frames for 90 packets, largest {largest} B), overhead {:.2} B",
        templated - 12.0
    );
    println!("--- compact bundles ---");
    let bundles = bundle_sizes();
    for (n, len) in &bundles {
        if [1usize, 2, 4, 8, 16, 24].contains(n) {
            println!(
                "{n:2} x telemetry f32x3: {len:4} B, {:.2} B per packet ({:.2} overhead)",
                *len as f64 / *n as f64,
                *len as f64 / *n as f64 - 12.0
            );
        }
    }
    let per_record = (bundles[23].1 - bundles[15].1) as f64 / 8.0;
    let single = (RADIO_TURN_BYTES as f64 / templated).floor();
    // One bundle per turn, filled by the budgeted writer.
    let fill = |record_crc: bool| {
        let mut writer = sedsnet::wire_bundle::BundleWriter::new(RADIO_TURN_BYTES, record_crc);
        let mut i = 0u64;
        while writer
            .try_push(&pack_packet(&vector_packet(NOW_MS + 20 * i)))
            .unwrap()
        {
            i += 1;
        }
        (writer.count(), writer.len())
    };
    let (bundled, bundle_len) = fill(false);
    let (bundled_crc, bundle_crc_len) = fill(true);
    println!("--- radio turn budget {RADIO_TURN_BYTES} B / 200 ms ---");
    println!(
        "templated frames: {single} packets per turn ({:.0} packets/s); marginal bundle record {per_record:.2} B",
        single * 5.0
    );
    println!(
        "one bundle per turn: {bundled} packets ({bundle_len} B, {:.0} packets/s); per-record CRC: {bundled_crc} packets ({bundle_crc_len} B, {:.0} packets/s)",
        bundled as f64 * 5.0,
        bundled_crc as f64 * 5.0
    );
    // Budgets (SEDSnet 7): fail on a regression.
    let rows = canonical_rows();
    assert!(rows[0].1 <= 37, "telemetry canonical frame grew: {}", rows[0].1);
    assert!(templated <= 23.0, "templated telemetry grew: {templated:.2} B");
    assert!(per_record <= 15.5, "bundle record grew: {per_record:.2} B");
    assert!(bundled >= 42, "radio turn holds only {bundled} bundled packets");
}
