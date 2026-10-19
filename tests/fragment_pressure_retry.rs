#![cfg(all(feature = "std", feature = "discovery"))]
use sedsnet::{
    MessageClass, MessageDataType, MessageElement, ReliableMode,
    config::{self, DataEndpoint, DataType},
    discovery::{TopologyBoardNode, build_discovery_topology},
    packet::Packet,
    relay::{Relay, RelayConfig, RelaySideOptions},
    router::{Router, RouterConfig, RouterSideOptions},
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
static LOCK: Mutex<()> = Mutex::new(());
static ALLOW: AtomicBool = AtomicBool::new(true);
extern "C" fn probe(_: usize, _: usize) -> bool {
    ALLOW.load(Ordering::SeqCst)
}
struct Reset;
impl Drop for Reset {
    fn drop(&mut self) {
        sedsnet::memory_admission::set_probe(None);
        ALLOW.store(true, Ordering::SeqCst);
        #[cfg(feature = "compact-packet-store")]
        sedsnet::packet_store::set_default_store(None);
    }
}
fn fixture(suffix: &str) -> (DataEndpoint, DataType, Packet) {
    #[cfg(feature = "compact-packet-store")]
    sedsnet::packet_store::set_default_store(Some(
        sedsnet::packet_store::PacketStore::new(65536, 512, 4096).unwrap(),
    ));
    let ep = config::register_endpoint(&format!("FRAGMENT_PRESSURE_{suffix}"), false).unwrap();
    let ty = config::register_data_type(
        &format!("FRAGMENT_PRESSURE_VALUE_{suffix}"),
        MessageElement::Static(1024, MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        0,
    )
    .unwrap();
    let mut rng = 19u32;
    let bytes = (0..1024)
        .map(|_| {
            rng ^= rng << 13;
            rng ^= rng >> 17;
            rng ^= rng << 5;
            rng as u8
        })
        .collect::<Vec<_>>();
    let packet = Packet::new(ty, &[ep], "GB", 1, Arc::<[u8]>::from(bytes)).unwrap();
    (ep, ty, packet)
}
fn baseline(ep: DataEndpoint) -> Packet {
    build_discovery_topology(
        "GS",
        0,
        &[TopologyBoardNode {
            sender_id: "GS".into(),
            reachable_endpoints: vec![ep],
            reachable_timesync_sources: vec![],
            connections: vec!["GB".into()],
        }],
    )
    .unwrap()
}
fn check_fragments(frames: &[Vec<u8>], packet: &Packet) {
    assert!(frames.len() > 2, "test must exercise fragmented transfer");
    let mut bytes = Vec::new();
    for (i, frame) in frames.iter().enumerate() {
        assert_eq!(&frame[..4], b"SDT\x03");
        assert_eq!(
            u16::from_le_bytes([frame[8], frame[9]]) as usize,
            i,
            "accepted fragments were retransmitted or skipped"
        );
        assert_eq!(
            u16::from_le_bytes([frame[10], frame[11]]) as usize,
            frames.len()
        );
        assert_eq!(
            &frame[4..8],
            &frames[0][4..8],
            "transfer identity changed while deferred"
        );
        assert_eq!(
            crc32fast::hash(&frame[..frame.len() - 4]),
            u32::from_le_bytes(frame[frame.len() - 4..].try_into().unwrap())
        );
        bytes.extend_from_slice(&frame[12..frame.len() - 4]);
    }
    let decoded = sedsnet::wire_format::unpack_packet(&bytes).unwrap();
    assert_eq!(decoded.data_type(), packet.data_type());
    assert_eq!(decoded.payload(), packet.payload());
}
#[test]
fn router_retains_a_transfer_when_next_fragment_cannot_be_admitted() {
    let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _reset = Reset;
    let (ep, _, packet) = fixture("ROUTER");
    let clock = Arc::new(AtomicU64::new(0));
    let now = clock.clone();
    let router = Router::new_with_clock(
        RouterConfig::new([]).with_sender("GB"),
        Box::new(move || now.load(Ordering::SeqCst)),
    );
    let frames = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let output = frames.clone();
    let stopped = Arc::new(AtomicBool::new(false));
    let once = stopped.clone();
    let mut opts = RouterSideOptions::default().with_small_packet_transport(64);
    opts.header_template_enabled = false;
    let side = router.add_side_packed_with_options(
        "uart",
        move |frame| {
            output.lock().unwrap().push(frame.to_vec());
            if !once.swap(true, Ordering::SeqCst) {
                ALLOW.store(false, Ordering::SeqCst);
            }
            Ok(())
        },
        opts,
    );
    router.rx_from_side(&baseline(ep), side).unwrap();
    router.clear_queues();
    frames.lock().unwrap().clear();
    stopped.store(false, Ordering::SeqCst);
    ALLOW.store(true, Ordering::SeqCst);
    router.tx_queue(packet.clone()).unwrap();
    sedsnet::memory_admission::set_probe(Some(probe));
    let result = router.dispatch_tx_queue_with_timeout(0);
    assert!(
        result.is_ok(),
        "workspace pressure must defer transmission, not become a handler failure: {result:?}"
    );
    assert_eq!(frames.lock().unwrap().len(), 1);
    assert_eq!(router.export_runtime_stats().queues.tx_len, 1);
    ALLOW.store(true, Ordering::SeqCst);
    clock.store(1, Ordering::SeqCst);
    router.dispatch_tx_queue_with_timeout(0).unwrap();
    assert_eq!(router.export_runtime_stats().queues.tx_len, 0);
    check_fragments(&frames.lock().unwrap(), &packet);
}
#[test]
fn relay_retains_a_transfer_when_next_fragment_cannot_be_admitted() {
    let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _reset = Reset;
    let (ep, _, packet) = fixture("RELAY");
    let clock = Arc::new(AtomicU64::new(0));
    let now = clock.clone();
    let relay = Relay::new_with_config(
        RelayConfig::default().with_sender("GB"),
        Box::new(move || now.load(Ordering::SeqCst)),
    );
    let ingress = relay.add_side_packed("can", |_| Ok(()));
    let frames = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let output = frames.clone();
    let stopped = Arc::new(AtomicBool::new(false));
    let once = stopped.clone();
    let mut opts = RelaySideOptions::default().with_small_packet_transport(64);
    opts.header_template_enabled = false;
    let side = relay.add_side_packed_with_options(
        "uart",
        move |frame| {
            output.lock().unwrap().push(frame.to_vec());
            if !once.swap(true, Ordering::SeqCst) {
                ALLOW.store(false, Ordering::SeqCst);
            }
            Ok(())
        },
        opts,
    );
    relay.rx_from_side(side, baseline(ep)).unwrap();
    relay.process_rx_queue().unwrap();
    relay.clear_queues();
    frames.lock().unwrap().clear();
    stopped.store(false, Ordering::SeqCst);
    ALLOW.store(true, Ordering::SeqCst);
    relay.rx_from_side(ingress, packet.clone()).unwrap();
    sedsnet::memory_admission::set_probe(Some(probe));
    let result = relay.drain_queues_with_timeout(0);
    assert!(
        result.is_ok(),
        "workspace pressure must preserve the relay's pending transfer: {result:?}"
    );
    assert_eq!(frames.lock().unwrap().len(), 1);
    assert_eq!(relay.export_runtime_stats().queues.tx_len, 1);
    ALLOW.store(true, Ordering::SeqCst);
    clock.store(1, Ordering::SeqCst);
    relay.drain_queues_with_timeout(0).unwrap();
    assert_eq!(relay.export_runtime_stats().queues.tx_len, 0);
    check_fragments(&frames.lock().unwrap(), &packet);
}
