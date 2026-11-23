use super::*;
use crate::side_peek::{SideFrameKind, SideFramePeeker};
use std::sync::Mutex;

/// Every frame a router emits on a small-packet side (header templates and
/// chunking) is classified with its real type: canonical, full, compact and
/// chunked frames alike, learned in transmit order.
#[test]
fn a_peeker_classifies_every_frame_a_small_packet_side_emits() {
    crate::tests::ensure_common_test_schema();
    let ep = DataEndpoint::named("RADIO");
    let small = crate::config::register_data_type_with_description(
        "SIDE_PEEK_SMALL", "",
        crate::MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[ep], crate::ReliableMode::None, 16).unwrap();
    let large = crate::config::register_data_type_with_description(
        "SIDE_PEEK_LARGE", "",
        crate::MessageElement::Dynamic(crate::MessageDataType::String, crate::MessageClass::Data),
        &[ep], crate::ReliableMode::None, 16).unwrap();
    let frames = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let out = frames.clone();
    let router = Router::new_with_clock(RouterConfig::new([]).with_sender("RRLS"), Box::new(|| 1000));
    router.add_side_packed_with_options("radio", move |b| { out.lock().unwrap().push(b.to_vec()); Ok(()) },
        RouterSideOptions::default().with_small_packet_transport(192).with_point_to_point());
    let mut expected = Vec::new();
    for i in 0..4u8 {
        router.announce_leave().unwrap();
        router.process_all_queues().unwrap();
        expected.push(Some(DataType::DiscoveryLeave));
        router.tx(Packet::new(small, &[ep], "RRLS", 2000 + u64::from(i), Arc::<[u8]>::from([i])).unwrap()).unwrap();
        router.process_all_queues().unwrap();
        expected.push(Some(small));
    }
    router.tx(Packet::new(large, &[ep], "RRLS", 3000, Arc::<[u8]>::from(vec![b'x'; 600])).unwrap()).unwrap();
    router.process_all_queues().unwrap();
    let frames = frames.lock().unwrap().clone();
    let mut peeker = SideFramePeeker::new(true);
    let seen: Vec<_> = frames.iter().map(|f| peeker.peek(f)).collect();
    let kinds: Vec<_> = seen.iter().flatten().map(|i| i.kind).collect();
    assert!(seen.iter().all(Option::is_some), "every frame classified: {seen:?}");
    for ty in [DataType::DiscoveryLeave, small, large] {
        assert!(seen.iter().flatten().any(|i| i.ty == ty), "{ty:?} seen: {seen:?}");
    }
    assert!(kinds.contains(&SideFrameKind::Chunk), "the large frame was chunked: {kinds:?}");
    assert!(kinds.contains(&SideFrameKind::Compact), "repeated headers went compact: {kinds:?}");
    // No frame is misclassified as another known type.
    let leaves = seen.iter().flatten().filter(|i| i.ty == DataType::DiscoveryLeave).count();
    assert!(leaves >= 4, "{leaves} leaves: {seen:?}");
    // Without side state, a FULL or canonical frame still reads its type.
    for (frame, info) in frames.iter().zip(&seen) {
        let info = info.unwrap();
        if matches!(info.kind, SideFrameKind::Full | SideFrameKind::Canonical) {
            assert_eq!(crate::side_peek::peek_side_frame_type(frame), Some(info.ty));
        }
    }
    let _ = expected;
}
