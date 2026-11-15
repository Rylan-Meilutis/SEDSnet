//! Compact bundles: round trip, negotiation, mixed old/new routers, fuzzing.
use super::*;
use crate::wire_bundle::{BUNDLE_MARKER, frame_bundleable, pack_bundle, unpack_bundle_frames};
use crate::router::{RouterItem, RouterSideId};
use crate::wire_format::{self, ReliableHeader};
use crate::{MessageClass, MessageDataType, MessageElement, ReliableMode, discovery};
use std::sync::Mutex;

fn ty(name: &str, element: MessageElement, reliable: ReliableMode) -> DataType {
    crate::tests::ensure_common_test_schema();
    let ep = DataEndpoint::named("RADIO");
    DataType::try_named(name).unwrap_or_else(|| {
        crate::config::register_data_type(name, element, &[ep], reliable, 10).unwrap()
    })
}
fn imu() -> DataType {
    ty(
        "CB_TEST_IMU",
        MessageElement::Static(6, MessageDataType::Float32, MessageClass::Data),
        ReliableMode::None,
    )
}
fn battery() -> DataType {
    ty(
        "CB_TEST_BATTERY",
        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
        ReliableMode::Ordered,
    )
}
fn blob() -> DataType {
    ty(
        "CB_TEST_BLOB",
        MessageElement::Dynamic(MessageDataType::Binary, MessageClass::Data),
        ReliableMode::None,
    )
}
fn packet(t: DataType, sender: &str, ts: u64, payload: Vec<u8>) -> Packet {
    Packet::new(t, &[DataEndpoint::named("RADIO")], sender, ts, Arc::<[u8]>::from(payload)).unwrap()
}

/// A realistic mix: templated-type telemetry, reliable headers, frozen
/// contracts with targets, ACK-only frames, discovery, explicit endpoint
/// lists, compressed payloads, several sources and backwards timestamps.
fn mixed_frames() -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let ts0 = 1_767_225_607_518u64;
    for i in 0..3u64 {
        out.push(wire_format::pack_packet(&packet(imu(), "FC", ts0 + i * 20, vec![i as u8; 24])).to_vec());
    }
    out.push(
        wire_format::pack_packet_with_reliable(
            &packet(battery(), "PB", ts0 + 5, vec![1, 2, 3, 4]),
            ReliableHeader { flags: 0, seq: 77, ack: 3 },
        )
        .to_vec(),
    );
    let targeted = packet(battery(), "PB", ts0 - 40, vec![9, 9, 9, 9]);
    out.push(
        wire_format::pack_packet_with_wire_contract(
            &targeted,
            Some(ReliableHeader { flags: 0, seq: 78, ack: 0 }),
            None,
            &[0x1122_3344_5566_7788, 0x99AA_BBCC_DDEE_FF00],
        )
        .unwrap()
        .to_vec(),
    );
    out.push(
        wire_format::pack_packet_with_wire_contract(
            &packet(battery(), "PB", ts0 - 39, vec![8, 8, 8, 8]),
            Some(ReliableHeader { flags: 0, seq: 79, ack: 0 }),
            None,
            &[0x1122_3344_5566_7788, 0x99AA_BBCC_DDEE_FF00],
        )
        .unwrap()
        .to_vec(),
    );
    out.push(wire_format::pack_reliable_ack("GS", battery(), ts0 + 1, 77).to_vec());
    out.push(
        wire_format::pack_packet(&discovery::build_discovery_announce("RF", ts0, &[DataEndpoint::named("RADIO")]).unwrap())
            .to_vec(),
    );
    // Explicit endpoint list (not the schema default) and a large compressible payload.
    let multi = Packet::new(
        blob(),
        &[DataEndpoint::named("RADIO"), DataEndpoint::named("SD_CARD")],
        "RF",
        ts0 + 1_000_000,
        Arc::<[u8]>::from(vec![b'A'; 600]),
    )
    .unwrap();
    out.push(wire_format::pack_packet(&multi).to_vec());
    out.push(wire_format::pack_packet(&packet(blob(), "RF", 0, vec![])).to_vec());
    out
}

#[test]
fn round_trip_rebuilds_every_canonical_frame_byte_for_byte() {
    let frames = mixed_frames();
    assert!(frames.iter().any(|f| f[0] & 0x01 != 0), "fixture needs a compressed frame");
    assert!(frames.iter().any(|f| f[0] & 0x80 != 0), "fixture needs an endpoint list");
    for f in &frames {
        assert!(frame_bundleable(f));
    }
    // Every prefix and every single frame, so first/elided paths are both hit.
    for n in 1..=frames.len() {
        let refs: Vec<&[u8]> = frames[..n].iter().map(Vec::as_slice).collect();
        let bundle = pack_bundle(&refs).unwrap();
        assert!(crate::wire_bundle::is_bundle(&bundle));
        assert_eq!(unpack_bundle_frames(&bundle).unwrap(), frames[..n].to_vec());
    }
    for f in &frames {
        let bundle = pack_bundle(&[f]).unwrap();
        assert_eq!(unpack_bundle_frames(&bundle).unwrap(), vec![f.clone()]);
        let packet = wire_format::unpack_packet(&unpack_bundle_frames(&bundle).unwrap()[0]);
        assert_eq!(packet.is_ok(), wire_format::unpack_packet(f).is_ok());
    }
}

#[test]
fn bundling_shrinks_a_telemetry_train() {
    let ts0 = 1_767_225_607_518u64;
    let frames: Vec<Vec<u8>> = (0..4u64)
        .map(|i| wire_format::pack_packet(&packet(imu(), "FC", ts0 + i * 20, vec![i as u8; 24])).to_vec())
        .collect();
    let refs: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
    let legacy: usize = frames.iter().map(|f| f.len() + 4).sum(); // + UART header each
    let bundled = pack_bundle(&refs).unwrap().len() + 4;
    assert!(bundled * 10 < legacy * 7, "bundle {bundled} vs legacy {legacy}");
    // Per record after the first: len, flags, elide, ts delta, nonce delta, payload.
    let one = pack_bundle(&refs[..1]).unwrap().len();
    let two = pack_bundle(&refs[..2]).unwrap().len();
    assert!(two - one <= 24 + 8, "second record costs {} B", two - one);
}

#[test]
fn side_wrapped_sealed_and_damaged_frames_stay_standalone() {
    let frame = wire_format::pack_packet(&packet(imu(), "FC", 5, vec![0; 24])).to_vec();
    let mut damaged = frame.clone();
    damaged[4] ^= 0x40;
    assert!(!frame_bundleable(&damaged));
    assert!(pack_bundle(&[&damaged]).is_err());
    let mut sdt = b"SDT\x01".to_vec();
    sdt.extend_from_slice(&frame);
    assert!(!frame_bundleable(&sdt));
    let mut sealed = frame.clone();
    sealed[0] |= 0x10;
    let n = sealed.len() - 4;
    let crc = crc32fast::hash(&sealed[..n]).to_le_bytes();
    sealed[n..].copy_from_slice(&crc);
    assert!(!frame_bundleable(&sealed));
    assert!(pack_bundle(&[]).is_err());
}

#[test]
fn every_single_byte_corruption_is_rejected_whole() {
    let frames = mixed_frames();
    let refs: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
    let bundle = pack_bundle(&refs).unwrap();
    for i in 0..bundle.len() {
        for bit in [0x01u8, 0x80] {
            let mut bad = bundle.clone();
            bad[i] ^= bit;
            assert!(unpack_bundle_frames(&bad).is_err(), "flip at {i} accepted");
        }
    }
    for cut in 0..bundle.len() {
        assert!(unpack_bundle_frames(&bundle[..cut]).is_err());
    }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}
fn with_crc(mut body: Vec<u8>) -> Vec<u8> {
    let crc = crc32fast::hash(&body).to_le_bytes();
    body.extend_from_slice(&crc);
    body
}

/// The CRC stops random damage, so fuzz behind a valid CRC: structured
/// mutations of real bundles and random bodies must never panic, never
/// return more than the record bound, and anything accepted must re-pack.
#[test]
fn fuzz_decoder_behind_a_valid_crc() {
    let frames = mixed_frames();
    let refs: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
    let good = pack_bundle(&refs).unwrap();
    let body = &good[..good.len() - 4];
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut accepted = 0usize;
    for round in 0..200_000u32 {
        let candidate = match round % 4 {
            0 => {
                let mut b = body.to_vec();
                for _ in 0..1 + rng.next() % 4 {
                    let i = (rng.next() as usize) % b.len();
                    b[i] = rng.next() as u8;
                }
                b
            }
            1 => {
                let mut b = body.to_vec();
                let i = 1 + (rng.next() as usize) % (b.len() - 1);
                let n = (rng.next() as usize) % 8;
                if rng.next() & 1 == 0 {
                    b.drain(i..(i + n).min(b.len()));
                } else {
                    for _ in 0..n {
                        b.insert(i, rng.next() as u8);
                    }
                }
                b
            }
            _ => {
                let len = (rng.next() as usize) % 96;
                let mut b = vec![BUNDLE_MARKER];
                b.extend((0..len).map(|_| rng.next() as u8));
                b
            }
        };
        let candidate = with_crc(candidate);
        if let Ok(out) = unpack_bundle_frames(&candidate) {
            accepted += 1;
            assert!(!out.is_empty() && out.len() <= crate::wire_bundle::MAX_BUNDLE_RECORDS);
            for frame in &out {
                // Rebuilt frames always carry their own valid CRC; the router
                // still validates them like any received canonical frame.
                let n = frame.len() - 4;
                assert_eq!(crc32fast::hash(&frame[..n]).to_le_bytes(), frame[n..]);
                let _ = wire_format::unpack_packet(frame);
            }
        }
    }
    assert!(accepted > 0, "fuzz never reached the record parser's accept path");
}

// ---------------------------------------------------------------- node table

/// The node table every SEDS build shares (order matters).
static NODES: [&str; 9] = ["GS", "RRLS", "RF", "FC", "PB", "AB", "VB", "GB", "DAQ"];

fn with_table() {
    crate::wire_bundle::set_node_table(&NODES);
}

fn ack_and_battery_frames() -> Vec<Vec<u8>> {
    let ts0 = 1_767_225_607_518u64;
    let gs = Router::sender_hash("GS");
    let pb = Router::sender_hash("PB");
    let mut out = Vec::new();
    for i in 0..3u64 {
        let ack = Packet::new(
            DataType::ReliableAck,
            &[DataEndpoint::named("RADIO")],
            "E2EACK:GS",
            ts0 + i,
            Arc::<[u8]>::from((1000 + i).to_le_bytes().to_vec()),
        )
        .unwrap();
        out.push(
            wire_format::pack_packet_with_wire_contract(&ack, None, None, &[gs, if i == 1 { 0x55AA } else { pb }])
                .unwrap()
                .to_vec(),
        );
    }
    out.push(wire_format::pack_packet(&packet(imu(), "PB", ts0 + 9, vec![3; 24])).to_vec());
    out
}

/// With the shared table, sources and frozen targets travel as 1-byte node
/// indices, unknown ones in full, and every frame rebuilds byte for byte.
#[test]
fn node_table_indices_round_trip_and_shrink_acks() {
    with_table();
    let frames = ack_and_battery_frames();
    let refs: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
    let bundle = pack_bundle(&refs).unwrap();
    assert_eq!(bundle[0], crate::wire_bundle::BUNDLE_MARKER_TABLE);
    assert_eq!(unpack_bundle_frames(&bundle).unwrap(), frames);
    // Each indexed ACK record: no 16-byte target list, no 5-byte source.
    let one = pack_bundle(&refs[..1]).unwrap().len();
    let legacy = frames[0].len() + 4;
    assert!(one + 16 <= legacy, "indexed ACK bundle {one} B vs {legacy} B");
}

/// A receiver whose node table differs drops the bundle; it never guesses.
#[test]
fn a_different_node_table_drops_the_bundle() {
    with_table();
    let frames = ack_and_battery_frames();
    let refs: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
    let mut bundle = pack_bundle(&refs).unwrap();
    bundle[1] ^= 0x5A; // as packed by a node with another table
    let n = bundle.len() - 4;
    let crc = crc32fast::hash(&bundle[..n]).to_le_bytes();
    bundle[n..].copy_from_slice(&crc);
    assert!(unpack_bundle_frames(&bundle).is_err());
    // Index bits inside a bundle that carries no table check are refused too.
    let mut plain = pack_bundle(&refs).unwrap();
    plain.remove(1);
    plain[0] = BUNDLE_MARKER;
    let n = plain.len() - 4;
    let crc = crc32fast::hash(&plain[..n]).to_le_bytes();
    plain[n..].copy_from_slice(&crc);
    assert!(unpack_bundle_frames(&plain).is_err());
}

// ---------------------------------------------------------------- routers

type Frames = Arc<Mutex<Vec<Vec<u8>>>>;

fn opts(bundle: bool) -> RouterSideOptions {
    let mut o = RouterSideOptions::default().with_small_packet_transport(1024);
    o.compact_bundle = bundle;
    o
}

fn sender_node(side_bundle: bool) -> (Router, RouterSideId, Frames) {
    crate::tests::ensure_common_test_schema();
    let out: Frames = Arc::new(Mutex::new(Vec::new()));
    let cap = out.clone();
    let node = Router::new_with_clock(RouterConfig::new([]).with_sender("RF"), Box::new(|| 100));
    let side = node.add_side_packed_with_options(
        "radio",
        move |f| {
            cap.lock().unwrap().push(f.to_vec());
            Ok(())
        },
        opts(side_bundle),
    );
    (node, side, out)
}

type Received = Arc<Mutex<Vec<(DataType, Vec<u8>)>>>;

fn receiver_node() -> (Router, RouterSideId, Received) {
    crate::tests::ensure_common_test_schema();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    let cfg = RouterConfig::new([EndpointHandler::new_packet_handler(
        DataEndpoint::named("RADIO"),
        move |p: &Packet| {
            log.lock().unwrap().push((p.data_type(), p.payload().to_vec()));
            Ok(())
        },
    )])
    .with_sender("GS");
    let node = Router::new_with_clock(cfg, Box::new(|| 100));
    let side = node.add_side_packed_with_options("radio", |_| Ok(()), opts(true));
    (node, side, seen)
}

fn emit(node: &Router, side: RouterSideId, item: &RouterItem) {
    let handler = node.state.lock().sides[side].as_ref().unwrap().tx_handler.clone();
    node.call_side_tx_handler(side, &handler, item, false).unwrap();
}

/// The writer the boards and GS run: bundle consecutive bundleable frames.
fn writer(frames: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut run: Vec<&[u8]> = Vec::new();
    for f in frames {
        if frame_bundleable(f) {
            run.push(f);
        } else {
            if !run.is_empty() {
                out.push(pack_bundle(&run).unwrap());
                run.clear();
            }
            out.push(f.clone());
        }
    }
    if !run.is_empty() {
        out.push(pack_bundle(&run).unwrap());
    }
    out
}

#[test]
fn a_bundle_side_hands_its_writer_canonical_frames() {
    for bundle in [false, true] {
        let (tx, side, out) = sender_node(bundle);
        assert_eq!(tx.side_compact_bundle_active(side), bundle);
        out.lock().unwrap().clear();
        for i in 0..4u64 {
            emit(&tx, side, &RouterItem::Packet(packet(imu(), "RF", 100 + i, vec![1; 24])));
        }
        let frames = out.lock().unwrap().clone();
        assert_eq!(frames.len(), 4);
        assert_eq!(frames.iter().all(|f| frame_bundleable(f)), bundle);
        assert_eq!(frames.iter().any(|f| f.starts_with(b"SDT")), !bundle);
    }
    let (tx, side, _) = sender_node(false);
    tx.set_side_compact_bundle(side, true).unwrap();
    assert!(tx.side_compact_bundle_active(side));
}

/// Whole new stack: a bundle-side RF router's stream reaches a bundle-side GS
/// router through bundles (direct and queued receive) with every packet.
#[test]
fn routers_deliver_every_packet_through_bundles() {
    with_table();
    let stream: Vec<Packet> = (0..12u64)
        .map(|i| match i % 3 {
            0 => packet(imu(), "RF", 1_000 + i * 20, vec![i as u8; 24]),
            1 => packet(blob(), "FC", 1_000 + i * 20, vec![i as u8; 7]),
            _ => packet(imu(), "PB", 1_000 + i * 20 - 50, vec![0xEE; 24]),
        })
        .collect();
    let mut want: Vec<(DataType, Vec<u8>)> = stream.iter().map(|p| (p.data_type(), p.payload().to_vec())).collect();
    want.sort();
    for queued in [false, true] {
        let (tx, tx_side, out) = sender_node(true);
        let (rx, rx_side, seen) = receiver_node();
        let mut wire_frames = Vec::new();
        for (i, p) in stream.iter().enumerate() {
            emit(&tx, tx_side, &RouterItem::Packet(p.clone()));
            if i % 3 == 2 {
                let frames: Vec<Vec<u8>> = out.lock().unwrap().drain(..).collect();
                wire_frames.extend(writer(&frames));
            }
        }
        assert_eq!(wire_frames.len(), 4);
        assert!(wire_frames.iter().all(|w| crate::wire_bundle::is_bundle(w)));
        for w in &wire_frames {
            if queued {
                rx.rx_packed_queue_from_side(w, rx_side).unwrap();
            } else {
                rx.rx_packed_from_side(w, rx_side).unwrap();
            }
        }
        rx.process_all_queues().unwrap();
        let mut got = seen.lock().unwrap().clone();
        got.sort();
        assert_eq!(got, want, "queued={queued}");
        let mut bad = wire_frames[0].clone();
        let last = bad.len() - 6;
        bad[last] ^= 1;
        assert!(rx.rx_packed_from_side(&bad, rx_side).is_err());
    }
}

/// An ABORT is never bundled by the writers; as a canonical frame it decodes
/// on a node that has never seen any bundle or node table.
#[test]
fn a_canonical_abort_decodes_with_no_prior_state() {
    let abort = ty(
        "CB_TEST_ABORT",
        MessageElement::Dynamic(MessageDataType::String, MessageClass::Error),
        ReliableMode::None,
    );
    let frame = wire_format::pack_packet(&packet(abort, "GS", 5, b"ABORT".to_vec())).to_vec();
    let (rx, rx_side, seen) = receiver_node();
    rx.rx_packed_from_side(&frame, rx_side).unwrap();
    rx.process_all_queues().unwrap();
    assert_eq!(seen.lock().unwrap().len(), 1);
}
