#![cfg(feature = "std")]
use sedsnet::config::{register_data_type, register_endpoint};
use sedsnet::packet::Packet;
use sedsnet::router::{Router, RouterConfig, RouterSideOptions};
use sedsnet::{MessageClass, MessageDataType, MessageElement, ReliableMode};
use std::sync::{Arc, Mutex};

#[test]
fn side_labels_do_not_select_codec_mtu_priority_or_routing() {
    let endpoint = register_endpoint("GENERIC_SIDE_DESTINATION", false).unwrap();
    let ty = register_data_type(
        "GENERIC_SIDE_VALUE",
        MessageElement::Dynamic(MessageDataType::Binary, MessageClass::Data),
        &[endpoint],
        ReliableMode::None,
        37,
    )
    .unwrap();
    let packet = Packet::new(
        ty,
        &[endpoint],
        "FIXED_SOURCE",
        100,
        Arc::<[u8]>::from(vec![42; 160]),
    )
    .unwrap();
    let mut expected = None;
    for label in [
        "RADIO",
        "SD_CARD",
        "SOFTWARE_BUS",
        "IMU",
        "GPS",
        "entirely arbitrary label",
    ] {
        let seen = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let capture = seen.clone();
        let node = Router::new_with_clock(
            RouterConfig::new([]).with_sender("GENERIC_LOCAL"),
            Box::new(|| 100),
        );
        let mut options = RouterSideOptions::default().with_ipv6_like_compact_header_target();
        options.max_frame_bytes = 80;
        let side = node.add_side_packed_with_priority_and_options(
            label,
            move |frame, priority| {
                // Compare the fixed application's exact wire frames. Separate
                // discovery owner nonces are intentionally not comparable.
                if priority == 37 {
                    capture.lock().unwrap().push(frame.to_vec());
                }
                Ok(())
            },
            options,
        );
        node.clear_queues();
        seen.lock().unwrap().clear();
        node.set_typed_route(None, ty, side, true).unwrap();
        node.tx(packet.clone()).unwrap();
        node.process_all_queues().unwrap();
        let frames = seen.lock().unwrap().clone();
        assert!(!frames.is_empty());
        assert!(frames.iter().all(|frame| frame.len() <= 80));
        if let Some(expected) = &expected {
            assert_eq!(&frames, expected, "label {label} changed wire behavior");
        } else {
            expected = Some(frames);
        }
    }
}
