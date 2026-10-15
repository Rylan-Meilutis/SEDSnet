#![cfg(feature = "discovery")]

#[cfg(not(feature = "std"))]
#[unsafe(no_mangle)]
extern "C" fn telemetry_lock() {}
#[cfg(not(feature = "std"))]
#[unsafe(no_mangle)]
extern "C" fn telemetry_unlock() {}

#[test]
#[ignore = "run by test_runtime_schema_process.py across isolated std/embedded binaries"]
fn isolated_schema_node() {
    use sedsnet::config::*;
    use sedsnet::discovery::{build_discovery_schema, decode_discovery_schema};
    use sedsnet::packet::Packet;
    use sedsnet::wire_format::{pack_packet, unpack_packet};
    use sedsnet::{MessageClass, MessageDataType, MessageElement, ReliableMode};
    // Full release gates also run ignored tests directly. Without external
    // fixtures, exercise the same binary in three independent registries.
    // The Python driver additionally crosses hosted and embedded profiles.
    if std::env::var_os("SEDSNET_PROCESS_SCHEMA_DIR").is_none()
        && std::env::var_os("SEDSNET_PROCESS_SCHEMA_ROLE").is_none()
    {
        let directory = std::env::temp_dir().join(format!(
            "sedsnet-schema-process-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        for role in ["a", "b", "receive"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact", "isolated_schema_node"])
                .env("SEDSNET_PROCESS_SCHEMA_DIR", &directory)
                .env("SEDSNET_PROCESS_SCHEMA_ROLE", role)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "role {role}: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::fs::remove_dir_all(directory).unwrap();
        return;
    }
    let directory =
        std::path::PathBuf::from(std::env::var_os("SEDSNET_PROCESS_SCHEMA_DIR").unwrap());
    let role = std::env::var("SEDSNET_PROCESS_SCHEMA_ROLE").unwrap();
    if let Ok(name) = std::env::var("SEDSNET_EXPECT_BUNDLED_ENDPOINT") {
        assert_eq!(
            DataEndpoint::try_named(&name),
            Some(DataEndpoint::identity(&name))
        );
    }
    let a = DataEndpoint::identity("PROCESS_SCHEMA_A");
    let b = DataEndpoint::identity("PROCESS_SCHEMA_B");
    let ty = DataType::identity("PROCESS_SCHEMA_FLOW");
    let element = MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data);
    if role == "a" || role == "b" {
        let (name, endpoints, priority) = if role == "a" {
            ("PROCESS_SCHEMA_A", vec![a], 10)
        } else {
            ("PROCESS_SCHEMA_B", vec![b], 20)
        };
        register_endpoint(name, false).unwrap();
        register_data_type(
            "PROCESS_SCHEMA_FLOW",
            element,
            &endpoints,
            ReliableMode::None,
            priority,
        )
        .unwrap();
        let snapshot = build_discovery_schema(&role, 0).unwrap();
        std::fs::write(
            directory.join(format!("{role}.schema")),
            pack_packet(&snapshot),
        )
        .unwrap();
        if role == "a" {
            assert!(!endpoint_exists(b));
            let packet = Packet::from_f32_slice(ty, &[7.5], &[b], 123).unwrap();
            std::fs::write(directory.join("data.packet"), pack_packet(&packet)).unwrap();
            std::fs::write(
                directory.join("data.receipt"),
                packet.packet_id().to_le_bytes(),
            )
            .unwrap();
        }
        return;
    }
    assert_eq!(role, "receive");
    assert!(!data_type_exists(ty));
    let receive_schema = |name| {
        let wire = std::fs::read(directory.join(format!("{name}.schema"))).unwrap();
        let snapshot = decode_discovery_schema(&unpack_packet(&wire).unwrap()).unwrap();
        merge_owned_schema_snapshot_with_budget(snapshot, 65536).unwrap();
    };
    receive_schema("a");
    assert!(!endpoint_exists(b));
    let bytes = std::fs::read(directory.join("data.packet")).unwrap();
    let expected = u64::from_le_bytes(
        std::fs::read(directory.join("data.receipt"))
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let before = unpack_packet(&bytes).unwrap();
    assert_eq!(before.endpoints(), &[b]);
    assert_eq!(before.packet_id(), expected);
    receive_schema("b");
    let definition = data_type_definition(ty).unwrap();
    assert_eq!(definition.priority, 20);
    assert!(definition.endpoints.contains(&a) && definition.endpoints.contains(&b));
    assert_eq!(definition.endpoints.len(), 2);
    assert_eq!(unpack_packet(&bytes).unwrap().packet_id(), expected);
    let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let delivered = count.clone();
    let router = sedsnet::router::Router::new_with_clock(
        sedsnet::router::RouterConfig::new(vec![
            sedsnet::router::EndpointHandler::new_packet_handler(b, move |packet| {
                assert_eq!(packet.data_as_f32().unwrap(), vec![7.5]);
                delivered.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }),
        ]),
        Box::new(|| 0),
    );
    let side = router.add_side_packed("peer", |_| Ok(()));
    router.rx_packed_from_side(&bytes, side).unwrap();
    assert_eq!(count.load(std::sync::atomic::Ordering::Relaxed), 1);
}
