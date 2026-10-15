#![cfg(all(not(feature = "std"), feature = "discovery"))]

#[unsafe(no_mangle)]
extern "C" fn telemetry_lock() {}
#[unsafe(no_mangle)]
extern "C" fn telemetry_unlock() {}

#[test]
fn existing_firmware_learns_schema_additions_from_router_and_relay() {
    use sedsnet::config::*;
    use sedsnet::discovery::{
        build_discovery_schema, build_discovery_schema_from_owned_snapshot, decode_discovery_schema,
    };
    use sedsnet::{
        E2eEncryptionPolicy, MessageClass, MessageDataType, MessageElement, ReliableMode,
    };

    assert_eq!(schema_bytes_used(), 0);
    let compiled = export_schema();
    let router = sedsnet::router::Router::new_with_clock(
        sedsnet::router::RouterConfig::new(vec![]),
        Box::new(|| 0),
    );
    let side = router.add_side_packet("dynamic-schema", |_| Ok(()));
    let relay = sedsnet::relay::Relay::new(Box::new(|| 0));
    let relay_side = relay.add_side_packet("dynamic-schema", |_| Ok(()));

    // Sender schemas grow while both forwarding instances and their firmware
    // remain unchanged. None of these IDs/names exist in generated tables.
    for (index, name) in ["FUTURE_ANALOG_A", "FUTURE_ANALOG_B"]
        .into_iter()
        .enumerate()
    {
        let ep = DataEndpoint(9000 + index as u32);
        let ty = DataType(9000 + index as u32);
        let snapshot = OwnedRuntimeSchemaSnapshot {
            endpoints: vec![OwnedEndpointDefinition {
                id: ep,
                name: format!("FUTURE_DEST_{index}"),
                description: String::new(),
                link_local_only: false,
            }],
            types: vec![OwnedDataTypeDefinition {
                id: ty,
                name: name.into(),
                description: String::new(),
                element: MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
                endpoints: vec![ep],
                reliable: ReliableMode::None,
                priority: 10,
                e2e_encryption: E2eEncryptionPolicy::PreferOff,
            }],
        };
        assert!(!data_type_exists(ty));
        let packet = build_discovery_schema_from_owned_snapshot(
            "future-board",
            index as u64,
            snapshot.clone(),
        )
        .unwrap();
        if index == 0 {
            router.rx_from_side(&packet, side).unwrap();
        } else {
            relay.rx_from_side(relay_side, packet).unwrap();
            relay.process_rx_queue().unwrap();
        }
        assert_eq!(data_type_definition(ty).unwrap(), snapshot.types[0]);
        assert_eq!(endpoint_definition(ep).unwrap(), snapshot.endpoints[0]);
        assert_eq!(DataType::try_named(name), Some(ty));
        let retained = schema_bytes_used();
        assert!(retained > 0 && retained < 8192);
        // Repeated advertisements do not consume more retained memory.
        let report = merge_owned_schema_snapshot_with_budget(snapshot.clone(), retained).unwrap();
        assert!(!report.changed());
        assert_eq!(schema_bytes_used(), retained);
        let mut rejected = snapshot;
        rejected.endpoints[0].id = DataEndpoint(9100 + index as u32);
        rejected.endpoints[0].name.push_str("_REJECTED");
        assert!(merge_owned_schema_snapshot_with_budget(rejected, retained).is_err());
        assert!(!endpoint_exists(DataEndpoint(9100 + index as u32)));
        assert_eq!(schema_bytes_used(), retained);
    }
    // Learned fields are advertised onward, together with the original schema.
    let advertised = decode_discovery_schema(&build_discovery_schema("GB", 10).unwrap()).unwrap();
    for original in compiled.types {
        assert!(advertised.types.contains(&original));
    }
    assert!(
        advertised
            .types
            .iter()
            .any(|def| def.name == "FUTURE_ANALOG_A")
    );
    assert!(
        advertised
            .types
            .iter()
            .any(|def| def.name == "FUTURE_ANALOG_B")
    );
    // A conflict winner must hide every old flash alias, in both ID and
    // name-based APIs. Export and packet lookup must describe one catalog.
    let original = compiled
        .endpoints
        .into_iter()
        .find(|def| def.id.0 > 202)
        .unwrap();
    let mut replaced = false;
    for index in 0..64 {
        let mut incoming = original.clone();
        incoming.name = format!("COMPILED_ENDPOINT_REPLACEMENT_{index}");
        merge_owned_schema_snapshot_with_budget(
            OwnedRuntimeSchemaSnapshot {
                endpoints: vec![incoming.clone()],
                types: vec![],
            },
            8192,
        )
        .unwrap();
        if endpoint_definition(original.id).unwrap().name == incoming.name {
            assert_eq!(DataEndpoint::try_named(&original.name), None);
            assert_eq!(endpoint_definition_by_name(&original.name), None);
            assert_eq!(DataEndpoint::try_named(&incoming.name), Some(original.id));
            replaced = true;
            break;
        }
    }
    assert!(replaced, "fixture must exercise a learned conflict winner");
    let original = export_schema()
        .types
        .into_iter()
        .find(|def| def.id.0 > 18)
        .unwrap();
    let mut replaced = false;
    for index in 0..64 {
        let mut incoming = original.clone();
        incoming.name = format!("COMPILED_TYPE_REPLACEMENT_{index}");
        merge_owned_schema_snapshot_with_budget(
            OwnedRuntimeSchemaSnapshot {
                endpoints: vec![],
                types: vec![incoming.clone()],
            },
            8192,
        )
        .unwrap();
        if data_type_definition(original.id).unwrap().name == incoming.name {
            assert_eq!(DataType::try_named(&original.name), None);
            assert_eq!(data_type_definition_by_name(&original.name), None);
            assert_eq!(DataType::try_named(&incoming.name), Some(original.id));
            replaced = true;
            break;
        }
    }
    assert!(
        replaced,
        "fixture must exercise a learned type conflict winner"
    );
}
