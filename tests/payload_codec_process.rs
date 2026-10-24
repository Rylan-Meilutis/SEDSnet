#![cfg(feature = "discovery")]
#[cfg(not(feature = "std"))]
#[unsafe(no_mangle)]
extern "C" fn telemetry_lock() {}
#[cfg(not(feature = "std"))]
#[unsafe(no_mangle)]
extern "C" fn telemetry_unlock() {}

#[test]
#[ignore = "orchestrated across independently compiled codec profiles"]
fn isolated_router_codec_node() {
    use sedsnet::config::*;
    use sedsnet::packet::Packet;
    use sedsnet::router::{Router, RouterConfig, RouterSideOptions};
    use sedsnet::{MessageClass, MessageDataType, MessageElement, ReliableMode};
    use std::sync::{Arc, Mutex};
    if std::env::var_os("CODEC_PROCESS_ROLE").is_none() {
        let directory = std::env::temp_dir().join(format!(
            "sedsnet-codec-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        for role in ["produce", "receive"] {
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact", "isolated_router_codec_node"])
                .env("CODEC_PROCESS_ROLE", role)
                .env("CODEC_PROCESS_DIR", &directory)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stdout)
            );
        }
        std::fs::remove_dir_all(directory).unwrap();
        return;
    }
    let directory = std::path::PathBuf::from(std::env::var_os("CODEC_PROCESS_DIR").unwrap());
    let endpoint = register_endpoint("ISOLATED_CODEC_DATA", false).unwrap();
    let ty = register_data_type(
        "ISOLATED_CODEC_BYTES",
        MessageElement::Dynamic(MessageDataType::Binary, MessageClass::Data),
        &[endpoint],
        ReliableMode::None,
        10,
    )
    .unwrap();
    let expected = vec![b'A'; 4096];
    if std::env::var("CODEC_PROCESS_ROLE").unwrap() == "produce" {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let output = captured.clone();
        let node =
            Router::new_with_clock(RouterConfig::new([]).with_sender("HOST"), Box::new(|| 100));
        let side = node.add_side_packed_with_options(
            "unknown-or-legacy",
            move |frame| {
                if sedsnet::wire_format::peek_frame_info(frame)?.envelope.ty == ty {
                    *output.lock().unwrap() = frame.to_vec();
                }
                Ok(())
            },
            RouterSideOptions::default(),
        );
        node.set_route(None, side, true).unwrap();
        let packet = Packet::new(ty, &[endpoint], "HOST", 123, Arc::from(expected)).unwrap();
        let receipt = packet.packet_id();
        node.tx(packet).unwrap();
        let frame = captured.lock().unwrap();
        assert!(!frame.is_empty(), "router did not emit ordinary data");
        std::fs::write(directory.join("data.packet"), &*frame).unwrap();
        std::fs::write(directory.join("receipt"), receipt.to_le_bytes()).unwrap();
    } else {
        let frame = std::fs::read(directory.join("data.packet")).unwrap();
        let packet = sedsnet::wire_format::unpack_packet(&frame).unwrap();
        assert_eq!(packet.payload(), expected);
        assert_eq!(packet.data_type(), ty);
        let receipt = u64::from_le_bytes(
            std::fs::read(directory.join("receipt"))
                .unwrap()
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            packet.packet_id(),
            receipt,
            "transcoding must preserve delivery identity"
        );
    }
}
