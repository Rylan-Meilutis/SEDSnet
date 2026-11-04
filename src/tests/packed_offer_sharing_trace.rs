//! Identical old/new leaf inputs; clocks and actual callback facts are compared.
use super::*;
use std::sync::{Mutex, atomic::{AtomicBool, AtomicUsize, Ordering}};

#[derive(Clone, Copy)]
enum Path { Fresh, Replay, Packed, Packet }
impl Path {
    fn name(self) -> &'static str {
        match self { Self::Fresh => "fresh", Self::Replay => "replay", Self::Packed => "packed", Self::Packet => "packet" }
    }
}
#[derive(Default)]
struct Trace { calls: usize, accepted: Vec<Vec<u8>>, refused: Vec<Vec<u8>> }

fn observe(path: Path) -> serde_json::Value {
    let name = path.name();
    let endpoint = crate::config::register_endpoint_with_description(&format!("PACKED_SHARE_{name}_EP"), "fixture", false).unwrap();
    let reliable = matches!(path, Path::Fresh | Path::Replay);
    let ty = crate::config::register_data_type_with_description(
        &format!("PACKED_SHARE_{name}"), "actual frame trace",
        MessageElement::Static(64, crate::MessageDataType::UInt32, crate::MessageClass::Data),
        &[endpoint], if reliable { crate::ReliableMode::Unordered } else { crate::ReliableMode::None }, 80,
    ).unwrap();
    let clock_reads = Arc::new(AtomicUsize::new(0));
    let reads = clock_reads.clone();
    let router = Router::new_with_clock(RouterConfig::new([]).with_sender("PACKED_SHARE_NODE"), Box::new(move || {
        reads.fetch_add(1, Ordering::SeqCst); 1000
    }));
    let busy = Arc::new(AtomicBool::new(true));
    let reject = busy.clone();
    let trace = Arc::new(Mutex::new(Trace::default()));
    let seen = trace.clone();
    let side = router.add_side_packed_with_options("frames", move |bytes| {
        let mut trace = seen.lock().unwrap();
        trace.calls += 1;
        if reject.load(Ordering::SeqCst) && trace.calls == 2 {
            trace.refused.push(bytes.to_vec());
            return Err(TelemetryError::Io("side tx busy"));
        }
        trace.accepted.push(bytes.to_vec()); Ok(())
    }, RouterSideOptions { reliable_enabled: true, max_frame_bytes: 96, ..Default::default() });
    router.clear_queues();
    *trace.lock().unwrap() = Trace::default();
    let packet = Packet::new(ty, &[endpoint], "PACKED_SHARE_NODE", 1001, Arc::<[u8]>::from([9u8; 256])).unwrap();
    let packed = if matches!(path, Path::Replay) {
        router.pack_packet_for_router(&packet, Some(wire_format::ReliableHeader { flags: wire_format::RELIABLE_FLAG_UNORDERED, seq: 1, ack: 0 })).unwrap()
    } else { crate::shared_bytes::convert(wire_format::pack_packet(&packet)) };
    let handler = Router::side_ref(&router.state.lock(), side).unwrap().tx_handler.clone();
    clock_reads.store(0, Ordering::SeqCst);
    let mut admitted = false;
    let first = match path {
        Path::Fresh => router.send_reliable_to_side_with_progress(side, RouterItem::Packet(packet.clone()), false, &mut admitted),
        Path::Replay => {
            let gate = router.admit_side_tx(side).unwrap();
            router.send_reliable_raw_to_admitted_side(&gate, packed.clone(), false, &mut admitted)
        }
        Path::Packed => router.call_side_tx_handler_with_progress(side, &handler, &RouterItem::Packed(packed.clone()), false, &mut admitted),
        Path::Packet => router.call_side_tx_handler_with_progress(side, &handler, &RouterItem::Packet(packet.clone()), false, &mut admitted),
    };
    assert!(admitted, "first actual fragment was accepted");
    if matches!(path, Path::Fresh) { assert!(first.is_ok()); }
    else { assert!(matches!(first, Err(TelemetryError::Io("side tx busy")))); }
    let first_reads = clock_reads.load(Ordering::SeqCst);
    let first_callbacks = trace.lock().unwrap().calls;
    busy.store(false, Ordering::SeqCst);
    let second = match path {
        Path::Fresh => router.queue_reliable_retransmit(side, ty, 1, false),
        Path::Replay => {
            let gate = router.admit_side_tx(side).unwrap();
            router.send_reliable_raw_to_admitted_side(&gate, packed.clone(), false, &mut admitted)
        }
        Path::Packed => router.call_side_tx_handler_with_progress(side, &handler, &RouterItem::Packed(packed), false, &mut admitted),
        Path::Packet => router.call_side_tx_handler_with_progress(side, &handler, &RouterItem::Packet(packet), false, &mut admitted),
    };
    assert!(second.is_ok());
    let final_reads = clock_reads.load(Ordering::SeqCst);
    let statistics = format!("{:?}", router.export_runtime_stats());
    let trace = trace.lock().unwrap();
    assert_eq!(trace.refused.len(), 1);
    assert!(trace.accepted.len() > 1);
    assert!(trace.accepted[1..].iter().all(|bytes| bytes != &trace.accepted[0]), "accepted prefix must not be offered again");
    serde_json::json!({"path":name,"first_result":format!("{first:?}"),"first_clock_reads":first_reads,"first_callbacks":first_callbacks,
        "final_clock_reads":final_reads,"callbacks":trace.calls,"accepted":trace.accepted,"refused":trace.refused,"statistics":statistics})
}

#[test]
fn four_actual_paths_preserve_callback_bytes_clock_reads_and_statistics() {
    crate::tests::ensure_common_test_schema();
    for path in [Path::Fresh, Path::Replay, Path::Packed, Path::Packet] {
        println!("PACKED_OFFER_TRACE {}", observe(path));
    }
}
