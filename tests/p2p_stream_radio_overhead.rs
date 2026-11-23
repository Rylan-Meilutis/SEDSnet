#![cfg(all(feature = "std", feature = "discovery"))]
//! Bytes on air for bulk P2P stream messages over a constrained radio path.
//!
//! Models a leaf node (`LEAF`) behind a two-sided bridge (`BRIDGE`) that
//! forwards over a 192-byte-frame radio to a station (`STATION`):
//!
//! ```text
//! LEAF --(packed, ipv6_like, 64 B frames)--> BRIDGE --(packed, ipv6_like, 192 B frames)--> STATION
//! ```
//!
//! The station opens a P2P stream to the leaf; the leaf then sends N stream
//! messages back to back. Every radio frame is charged a 4-byte link header
//! (a typical UART framing). Run with
//! `cargo test --test p2p_stream_radio_overhead -- --nocapture` to print the
//! table; the test asserts budgets so regressions fail.

use sedsnet::config::DataType;
use sedsnet::router::{
    P2pStreamEventKind, Router, RouterConfig, RouterSideId, RouterSideOptions,
    SideTransportProfile,
};
use std::collections::{HashMap, VecDeque};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};

const LINK_HEADER: usize = 4;
const RADIO_FRAME: usize = 192;
const CAN_FRAME: usize = 64;
const PORT: u16 = 4000;
const CLIENT_PORT: u16 = 49152;

#[derive(Default, Clone, Debug)]
struct Tally {
    frames: usize,
    bytes: usize,
    chunk_frames: usize,
    chunk_header_bytes: usize,
    /// Reassembled or single canonical frames, by type.
    canonical: Vec<(Option<DataType>, usize, usize)>,
}

struct Link {
    to: usize,
    side: RouterSideId,
    radio: Option<&'static str>,
}

struct Net {
    clock: Arc<AtomicU64>,
    routers: Vec<Arc<Router>>,
    queues: Vec<Arc<Mutex<VecDeque<Vec<u8>>>>>,
    links: Vec<Link>,
    taps: HashMap<&'static str, Arc<Mutex<Vec<Vec<u8>>>>>,
}

fn side_opts(max_frame: usize) -> RouterSideOptions {
    // seds_router_add_side_packed_profile_with_priority(.., false,
    // SEDS_SIDE_TRANSPORT_PROFILE_IPV6_LIKE, max_frame, 0, 16)
    RouterSideOptions {
        reliable_enabled: false,
        link_local_enabled: false,
        max_side_transport_templates: 16,
        side_transport_profile: SideTransportProfile::Ipv6Like,
        ..RouterSideOptions::default()
    }
    .with_small_packet_transport(max_frame)
}

impl Net {
    fn new() -> Self {
        let clock = Arc::new(AtomicU64::new(1_000));
        let routers: Vec<_> = ["LEAF", "BRIDGE", "STATION"]
            .into_iter()
            .map(|name| {
                let tick = clock.clone();
                Arc::new(Router::new_with_clock(
                    RouterConfig::new([]).with_sender(name),
                    Box::new(move || tick.load(Ordering::Relaxed)),
                ))
            })
            .collect();
        let mut net = Net {
            clock,
            routers,
            queues: Vec::new(),
            links: Vec::new(),
            taps: HashMap::new(),
        };
        // (from, to, options, radio tap)
        let mut station = RouterSideOptions {
            reliable_enabled: false,
            ..Default::default()
        };
        #[cfg(feature = "compact-bundle")]
        {
            station.compact_bundle = true;
        }
        station = station.with_small_packet_transport(RADIO_FRAME);
        let plan: [(usize, usize, RouterSideOptions, Option<&'static str>); 4] = [
            (0, 1, side_opts(CAN_FRAME), None),
            (1, 0, side_opts(CAN_FRAME), None),
            (1, 2, side_opts(RADIO_FRAME), Some("down")),
            (2, 1, station, Some("up")),
        ];
        let mut sides = Vec::new();
        for (from, _to, opts, radio) in plan.iter().cloned() {
            let queue = Arc::new(Mutex::new(VecDeque::<Vec<u8>>::new()));
            let q = queue.clone();
            let tap = radio.map(|name| {
                net.taps
                    .entry(name)
                    .or_insert_with(|| Arc::new(Mutex::new(Vec::new())))
                    .clone()
            });
            let side = net.routers[from].add_side_packed_with_priority_and_options(
                "link",
                move |bytes, _priority| {
                    if let Some(tap) = &tap {
                        tap.lock().unwrap().push(bytes.to_vec());
                    }
                    q.lock().unwrap().push_back(bytes.to_vec());
                    Ok(())
                },
                opts,
            );
            sides.push(side);
            net.queues.push(queue);
        }
        // A frame queued on link i arrives on the peer's side for the reverse link.
        for (i, (_from, to, _opts, radio)) in plan.iter().enumerate() {
            let reverse = plan
                .iter()
                .position(|(f, t, _, _)| *f == *to && *t == plan[i].0)
                .unwrap();
            net.links.push(Link {
                to: *to,
                side: sides[reverse],
                radio: *radio,
            });
        }
        net
    }

    /// Deliver every queued frame and run every router until quiet.
    fn pump(&self, max_ms: u64) {
        let mut quiet = 0;
        for _ in 0..max_ms {
            self.clock.fetch_add(1, Ordering::Relaxed);
            let mut delivered = false;
            for (i, link) in self.links.iter().enumerate() {
                loop {
                    let frame = self.queues[i].lock().unwrap().pop_front();
                    let Some(frame) = frame else { break };
                    let _ = link.radio;
                    self.routers[link.to]
                        .rx_packed_from_side(&frame, link.side)
                        .unwrap();
                    delivered = true;
                }
            }
            for router in &self.routers {
                router.poll_discovery().unwrap();
                router.process_all_queues().unwrap();
            }
            let pending = self.queues.iter().any(|q| !q.lock().unwrap().is_empty());
            if !delivered && !pending {
                quiet += 1;
                if quiet > 20 {
                    return;
                }
            } else {
                quiet = 0;
            }
        }
    }

    fn take(&self, tap: &str) -> Vec<Vec<u8>> {
        core::mem::take(&mut *self.taps[tap].lock().unwrap())
    }
}

fn uleb(buf: &[u8], off: &mut usize) -> u64 {
    let mut value = 0u64;
    let mut shift = 0;
    loop {
        let byte = buf[*off];
        *off += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return value;
        }
        shift += 7;
    }
}

/// Parse one side-transport chunk: (transfer, index, total, header bytes, body).
fn parse_chunk(frame: &[u8]) -> Option<(u32, usize, usize, usize, &[u8])> {
    if !frame.starts_with(b"SDT") || frame.get(3) != Some(&0x03) {
        return None;
    }
    let body = &frame[4..frame.len() - 4];

    // Transfer id u16 LE, then one ULEB128 position naming index and total:
    // total * (total - 1) / 2 + index.
    let transfer = u32::from(u16::from_le_bytes([body[0], body[1]]));
    let mut off = 2;
    let position = uleb(body, &mut off) as usize;
    let mut total = 1;
    while total * (total + 1) / 2 <= position {
        total += 1;
    }
    let index = position - total * (total - 1) / 2;
    Some((transfer, index, total, 4 + off + 4, &body[off..]))
}

fn tally(frames: &[Vec<u8>]) -> Tally {
    let mut t = Tally::default();
    let mut parts: HashMap<u32, Vec<Option<Vec<u8>>>> = HashMap::new();
    for frame in frames {
        t.frames += 1;
        t.bytes += frame.len() + LINK_HEADER;
        if let Some((transfer, index, total, header, body)) = parse_chunk(frame) {
            t.chunk_frames += 1;
            t.chunk_header_bytes += header;
            let slots = parts.entry(transfer).or_insert_with(|| vec![None; total]);
            slots[index] = Some(body.to_vec());
            if slots.iter().all(Option::is_some) {
                let whole: Vec<u8> = parts
                    .remove(&transfer)
                    .unwrap()
                    .into_iter()
                    .flatten()
                    .flatten()
                    .collect();
                let packet = sedsnet::wire_format::unpack_packet(&whole).unwrap();
                t.canonical
                    .push((Some(packet.data_type()), whole.len(), packet.payload().len()));
            }
        } else if let Ok(packet) = sedsnet::wire_format::unpack_packet(frame) {
            t.canonical
                .push((Some(packet.data_type()), frame.len(), packet.payload().len()));
        } else {
            t.canonical.push((None, frame.len(), 0));
        }
    }
    t
}

struct Row {
    body: usize,
    count: usize,
    down: Tally,
    up: Tally,
}

fn run(body: usize, count: usize) -> Row {
    let net = Net::new();
    for router in &net.routers {
        router.announce_discovery().unwrap();
    }
    net.pump(5_000);
    let leaf = net.routers[0].clone();
    let station = net.routers[2].clone();
    assert!(station.resolve_hostname("LEAF").is_some(), "discovery");

    let accepted = Arc::new(Mutex::new(None));
    let a = accepted.clone();
    leaf.bind_p2p_stream_port(PORT, move |event| {
        if event.kind == P2pStreamEventKind::Accepted {
            *a.lock().unwrap() = Some(event.stream_id);
        }
        Ok(())
    })
    .unwrap();
    let received = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let r = received.clone();
    station
        .bind_p2p_stream_port(CLIENT_PORT, move |event| {
            if event.kind == P2pStreamEventKind::Data {
                r.lock().unwrap().push(event.payload.to_vec());
            }
            Ok(())
        })
        .unwrap();
    station
        .open_p2p_stream_to_hostname("LEAF", PORT, CLIENT_PORT)
        .unwrap();
    net.pump(5_000);
    let stream = accepted.lock().unwrap().expect("stream accepted");
    net.take("down");
    net.take("up");

    // Incompressible payloads (the application compresses its own data).
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let mut messages = Vec::new();
    for _ in 0..count {
        let message: Vec<u8> = (0..body)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed as u8
            })
            .collect();
        leaf.send_p2p_stream(stream, &message).unwrap();
        messages.push(message);
    }
    net.pump(20_000);
    assert_eq!(*received.lock().unwrap(), messages, "stream delivery");
    Row {
        body,
        count,
        down: tally(&net.take("down")),
        up: tally(&net.take("up")),
    }
}

fn per(n: usize, count: usize) -> f64 {
    n as f64 / count as f64
}

fn report(row: &Row) {
    let n = row.count;
    let d = &row.down;
    let u = &row.up;
    let p2p: Vec<_> = d
        .canonical
        .iter()
        .filter(|(ty, _, _)| *ty == Some(DataType::P2pMessage))
        .collect();
    assert_eq!(p2p.len(), n, "one canonical P2P frame per message");
    let canonical: usize = p2p.iter().map(|(_, len, _)| len).sum();
    let payload: usize = p2p.iter().map(|(_, _, payload)| payload).sum();
    let envelope = canonical - payload;
    let p2p_headers = payload - n * row.body;
    let acks: Vec<_> = u
        .canonical
        .iter()
        .filter(|(ty, _, _)| *ty == Some(DataType::ReliableAck))
        .collect();
    let ack_bytes: usize = acks.iter().map(|(_, len, _)| len + LINK_HEADER).sum();
    println!("--- {} x {} B stream messages ---", n, row.body);
    println!(
        "down: {:.1} B on air / msg ({:.1} frames), efficiency {:.1}%",
        per(d.bytes, n),
        per(d.frames, n),
        100.0 * (n * row.body) as f64 / d.bytes as f64
    );
    println!(
        "  canonical envelope+CRC {:.1} B | P2P message+stream headers {:.1} B | SDT chunk headers {:.1} B ({:.1}/chunk) | link headers {:.1} B",
        per(envelope, n),
        per(p2p_headers, n),
        per(d.chunk_header_bytes, n),
        if d.chunk_frames == 0 { 0.0 } else { per(d.chunk_header_bytes, d.chunk_frames) },
        per(d.frames * LINK_HEADER, n),
    );
    // Largest body that fits k radio frames with this per-message overhead.
    let fixed = per(envelope + p2p_headers, n);
    let chunk_header = if d.chunk_frames == 0 { 0.0 } else { per(d.chunk_header_bytes, d.chunk_frames) };
    let fits: Vec<String> = (2..=7)
        .map(|k| format!("{k}:{:.0}", k as f64 * (RADIO_FRAME as f64 - chunk_header) - fixed))
        .collect();
    println!("  largest body per k radio frames: {}", fits.join(" "));
    println!(
        "up:   {:.1} B on air / msg ({:.1} frames); end-to-end ACKs {} frames, {:.1} B each on air",
        per(u.bytes, n),
        per(u.frames, n),
        acks.len(),
        if acks.is_empty() { 0.0 } else { per(ack_bytes, acks.len()) },
    );
}

#[test]
fn bulk_p2p_stream_bytes_on_air() {
    let rows: Vec<Row> = [(512usize, 16usize), (1000, 16), (2000, 4)]
        .into_iter()
        .map(|(body, count)| run(body, count))
        .collect();
    for row in &rows {
        report(row);
    }
    // Budgets (bytes on air per message, both directions).
    for row in &rows {
        let n = row.count;
        let overhead = per(row.down.bytes, n) - row.body as f64;
        // Measured: 108.7, 138.8 and 229.0 bytes (666.7/1214.8/2315.0 B on
        // air before the compact P2P and chunk formats).
        let budget = match row.body {
            512 => 112.0,
            1000 => 142.0,
            _ => 235.0,
        };
        assert!(
            overhead <= budget,
            "{} B: {overhead:.1} B of overhead per message exceeds {budget}",
            row.body
        );
        assert!(
            per(row.up.bytes, n) <= 52.0,
            "{} B: {:.1} B up per message",
            row.body,
            per(row.up.bytes, n)
        );
    }
}
