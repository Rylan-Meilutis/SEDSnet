//! Compact bundles: round trip, negotiation, mixed old/new routers, fuzzing.
use super::*;
use crate::wire_bundle::{BUNDLE_MARKER, frame_bundleable, pack_bundle, unpack_bundle_frames};
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
        assert_eq!(bundle[0], BUNDLE_MARKER);
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

// ---------------------------------------------------------------- routers

type Frames = Arc<Mutex<Vec<Vec<u8>>>>;

fn opts(bundle: bool) -> RouterSideOptions {
    let mut o = RouterSideOptions::default().with_small_packet_transport(1024);
    o.compact_bundle = bundle;
    o
}

/// Tell `node` that peer `name` on `side` advertises `peer_opts`' real link
/// capabilities, through the same discovery path a radio peer uses.
fn hear_peer(node: &Router, side: RouterSideId, name: &str, peer_opts: &RouterSideOptions) {
    let ad = discovery::AddressAdvertisement {
        hostname: name.into(),
        address: crate::packet::sender_address_u32(name),
        requested_address: 0,
        mode: discovery::ADDRESS_MODE_STATIC,
        state: discovery::ADDRESS_STATE_APPROVED,
        birth_ms: 1,
        owner_hash: crate::packet::sender_address_u32(name) as u64,
        reachable_endpoints: vec![DataEndpoint::named("RADIO")],
        reachable_network_variables: vec![],
        reachable_timesync_sources: vec![],
        link_capabilities: peer_opts.link_capabilities(),
    };
    let pkt = discovery::build_discovery_address(name, 100, &ad).unwrap();
    node.rx_from_side(&pkt, side).unwrap();
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

fn receiver_node(side_bundle: bool) -> (Router, RouterSideId, Arc<Mutex<Vec<(DataType, Vec<u8>)>>>) {
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
    let side = node.add_side_packed_with_options("radio", |_| Ok(()), opts(side_bundle));
    (node, side, seen)
}

fn emit(node: &Router, side: RouterSideId, item: &RouterItem) {
    let handler = node.state.lock().sides[side].as_ref().unwrap().tx_handler.clone();
    node.call_side_tx_handler(side, &handler, item, false).unwrap();
}

/// The writer the boards and GS run: bundle consecutive bundleable frames
/// when the side is active, otherwise write each frame as it is.
fn writer(active: bool, frames: &[Vec<u8>]) -> Vec<Vec<u8>> {
    if !active {
        return frames.to_vec();
    }
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
fn negotiation_needs_every_live_peer_and_the_local_offer() {
    let new_peer = opts(true);
    let old_peer = opts(false);
    for (local, peers, expect) in [
        (true, vec![], false),
        (true, vec![("GS", &new_peer)], true),
        (false, vec![("GS", &new_peer)], false),
        (true, vec![("GS", &new_peer), ("RRLS", &old_peer)], false),
        (true, vec![("GS", &new_peer), ("RRLS", &new_peer)], true),
    ] {
        let (node, side, _) = sender_node(local);
        for (name, o) in &peers {
            hear_peer(&node, side, name, o);
        }
        assert_eq!(node.side_compact_bundle_active(side), expect, "local={local} peers={}", peers.len());
    }
    assert_eq!(new_peer.link_capabilities().flags & discovery::LINK_CAPABILITY_COMPACT_BUNDLE, discovery::LINK_CAPABILITY_COMPACT_BUNDLE);
    assert_eq!(old_peer.link_capabilities().flags & discovery::LINK_CAPABILITY_COMPACT_BUNDLE, 0);
}

#[test]
fn a_late_old_peer_or_withdrawn_offer_turns_bundles_off() {
    let (node, side, _) = sender_node(true);
    hear_peer(&node, side, "GS", &opts(true));
    assert!(node.side_compact_bundle_active(side));
    hear_peer(&node, side, "RRLS", &opts(false));
    assert!(!node.side_compact_bundle_active(side));
    let (node, side, _) = sender_node(true);
    hear_peer(&node, side, "GS", &opts(true));
    node.set_side_compact_bundle(side, false).unwrap();
    assert!(!node.side_compact_bundle_active(side));
    node.set_side_compact_bundle(side, true).unwrap();
    assert!(node.side_compact_bundle_active(side));
}

/// Mixed old/new interop with real routers: the same telemetry stream from a
/// bundling RF router reaches (a) a new receiver as bundles, (b) an old-style
/// receiver (no offer) as legacy templated frames, and (c) a new receiver
/// across a mid-stream switch, with identical delivered packets every time.
#[test]
fn mixed_old_and_new_routers_deliver_identical_packets() {
    let stream: Vec<Packet> = (0..12u64)
        .map(|i| match i % 3 {
            0 => packet(imu(), "RF", 1_000 + i * 20, vec![i as u8; 24]),
            1 => packet(blob(), "RF", 1_000 + i * 20, vec![i as u8; 7]),
            _ => packet(imu(), "RF", 1_000 + i * 20 - 50, vec![0xEE; 24]),
        })
        .collect();
    let expected: Vec<(DataType, Vec<u8>)> =
        stream.iter().map(|p| (p.data_type(), p.payload().to_vec())).collect();

    for (receiver_offers, switch_at) in [(true, None), (false, None), (true, Some(5usize))] {
        let (tx, tx_side, out) = sender_node(true);
        let (rx, rx_side, seen) = receiver_node(receiver_offers);
        let rx_opts = opts(receiver_offers);
        let mut wire_frames = Vec::new();
        let mut bundles = 0;
        for (i, p) in stream.iter().enumerate() {
            if i == switch_at.unwrap_or(0) {
                hear_peer(&tx, tx_side, "GS", &rx_opts);
            }
            emit(&tx, tx_side, &RouterItem::Packet(p.clone()));
            // Deliver in writes of 3 frames, like a turn's burst.
            if i % 3 == 2 {
                let frames: Vec<Vec<u8>> = out.lock().unwrap().drain(..).collect();
                let active = tx.side_compact_bundle_active(tx_side);
                for w in writer(active, &frames) {
                    bundles += usize::from(w[0] == BUNDLE_MARKER);
                    wire_frames.push(w);
                }
            }
        }
        for w in &wire_frames {
            rx.rx_packed_from_side(w, rx_side).unwrap();
        }
        rx.process_all_queues().unwrap();
        let mut got = seen.lock().unwrap().clone();
        let mut want = expected.clone();
        got.sort();
        want.sort();
        assert_eq!(got, want, "receiver_offers={receiver_offers} switch={switch_at:?}");
        match (receiver_offers, switch_at) {
            (true, None) => assert_eq!(bundles, 4),
            (false, _) => assert_eq!(bundles, 0),
            (true, Some(_)) => assert!(bundles >= 2 && wire_frames.len() > bundles),
        }
    }
}

/// A queued receive (the GS path) and a reliable stream through bundles.
#[test]
fn queued_receive_and_reliable_frames_survive_bundling() {
    let (rx, rx_side, seen) = receiver_node(true);
    let frames: Vec<Vec<u8>> = (0..4u32)
        .map(|i| {
            wire_format::pack_packet_with_reliable(
                &packet(battery(), "PB", 2_000 + u64::from(i), vec![i as u8; 4]),
                ReliableHeader { flags: wire_format::RELIABLE_FLAG_UNSEQUENCED, seq: 0, ack: 0 },
            )
            .to_vec()
        })
        .collect();
    let refs: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
    let bundle = pack_bundle(&refs).unwrap();
    rx.rx_packed_queue_from_side(&bundle, rx_side).unwrap();
    rx.process_all_queues().unwrap();
    let got: Vec<Vec<u8>> = seen.lock().unwrap().iter().map(|(_, p)| p.clone()).collect();
    assert_eq!(got.len(), 4);
    let mut bad = bundle.clone();
    let last = bad.len() - 6;
    bad[last] ^= 1;
    assert!(rx.rx_packed_from_side(&bad, rx_side).is_err());
}

/// With bundles active the router hands its writer canonical frames (no
/// template wrapper); without, the existing templated format is unchanged.
#[test]
fn active_side_emits_canonical_frames_for_the_writer() {
    for active in [false, true] {
        let (tx, side, out) = sender_node(true);
        hear_peer(&tx, side, "GS", &opts(active));
        out.lock().unwrap().clear();
        for i in 0..4u64 {
            emit(&tx, side, &RouterItem::Packet(packet(imu(), "RF", 100 + i, vec![1; 24])));
        }
        let frames = out.lock().unwrap().clone();
        assert_eq!(frames.len(), 4);
        assert_eq!(frames.iter().all(|f| frame_bundleable(f)), active);
        assert_eq!(frames.iter().any(|f| f.starts_with(b"SDT")), !active);
    }
}
