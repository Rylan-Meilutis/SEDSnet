use alloc::sync::Arc;

use crate::{
    DataEndpoint, DataType, E2eEncryptionPolicy, MessageClass, MessageDataType, MessageElement,
    ReliableMode, TelemetryError,
    config::{
        DataTypeDefinition, EndpointDefinition, MAX_QUEUE_BUDGET, OwnedDataTypeDefinition,
        OwnedEndpointDefinition, OwnedRuntimeSchemaSnapshot, RuntimeSchemaSnapshot,
        data_type_definition_by_name, data_type_exists, endpoint_definition_by_name,
        endpoint_exists, export_schema, merge_owned_schema_snapshot,
        merge_owned_schema_snapshot_with_budget, merge_schema_snapshot, owned_schema_byte_cost,
        register_data_type_id, register_data_type_id_with_description,
        register_data_type_with_description, register_endpoint_id_with_description,
        register_endpoint_with_description, register_schema_json_bytes, register_schema_json_file,
        remove_data_type_by_name, remove_endpoint, remove_endpoint_by_name, schema_bytes_used,
    },
    discovery::{build_discovery_schema_from_snapshot, decode_discovery_schema},
    message_meta,
    packet::Packet,
    router::EndpointHandler,
};

#[test]
fn discovery_schema_packet_roundtrips_and_merges_new_entries() {
    static ENDPOINTS_230: [DataEndpoint; 1] = [DataEndpoint(230)];
    let endpoint = EndpointDefinition {
        id: DataEndpoint(230),
        name: "SCHEMA_SYNC_EP_230",
        description: "",
        link_local_only: false,
    };
    let ty = DataTypeDefinition {
        id: DataType(3001),
        name: "SCHEMA_SYNC_TYPE_3001",
        description: "",
        element: MessageElement::Static(2, MessageDataType::UInt16, MessageClass::Data),
        endpoints: &ENDPOINTS_230,
        reliable: ReliableMode::None,
        priority: 17,
        e2e_encryption: E2eEncryptionPolicy::PreferOn,
    };
    let snapshot = RuntimeSchemaSnapshot {
        endpoints: vec![endpoint],
        types: vec![ty],
    };
    let pkt = build_discovery_schema_from_snapshot("REMOTE", 10, snapshot).unwrap();
    let decoded = decode_discovery_schema(&pkt).unwrap();
    assert_eq!(
        decoded.types[0].e2e_encryption,
        E2eEncryptionPolicy::PreferOn
    );
    let report = merge_owned_schema_snapshot(decoded);
    assert!(report.changed() || DataType::try_from_u32(3001).is_some());
    assert_eq!(message_meta(DataType(3001)).element, ty.element);
}

#[test]
fn decoded_schema_is_owned_until_it_fits_the_registry_budget() {
    let endpoint = OwnedEndpointDefinition {
        id: DataEndpoint(250),
        name: "SCHEMA_SYNC_BUDGET_EP_250".to_string(),
        description: String::new(),
        link_local_only: false,
    };
    let ty = OwnedDataTypeDefinition {
        id: DataType(4090),
        name: "X".repeat(MAX_QUEUE_BUDGET),
        description: String::new(),
        element: MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
        endpoints: vec![endpoint.id],
        reliable: ReliableMode::None,
        priority: 1,
        e2e_encryption: E2eEncryptionPolicy::PreferOff,
    };
    let snapshot = OwnedRuntimeSchemaSnapshot {
        endpoints: vec![endpoint],
        types: vec![ty],
    };
    assert!(owned_schema_byte_cost(&snapshot) > MAX_QUEUE_BUDGET);

    let err = merge_owned_schema_snapshot_with_budget(snapshot, MAX_QUEUE_BUDGET).unwrap_err();
    assert!(matches!(err, TelemetryError::PacketTooLarge(_)));
    assert!(schema_bytes_used() <= MAX_QUEUE_BUDGET);
    assert!(DataType::try_from_u32(4090).is_none());
}

#[test]
fn schema_registry_counts_against_router_shared_queue_budget() {
    use crate::router::{Router, RouterConfig};

    let router = Router::new(RouterConfig::default());
    let schema_bytes = schema_bytes_used();
    assert!(schema_bytes > 0);
    assert!(router.debug_shared_queue_bytes_used() >= schema_bytes);
    assert!(router.debug_shared_queue_bytes_used() <= MAX_QUEUE_BUDGET);
}

#[test]
fn endpoint_handler_registration_creates_missing_endpoint() {
    let endpoint = DataEndpoint(249);
    assert!(!endpoint_exists(endpoint));
    let _handler = EndpointHandler::new_packet_handler(endpoint, |_pkt: &Packet| Ok(()));
    assert!(endpoint_exists(endpoint));
    assert_eq!(endpoint.as_str().as_ref(), "ENDPOINT_249");
}

#[test]
fn runtime_schema_auto_ids_are_searchable_exported_and_removable() {
    let ep_name = "SCHEMA_AUTO_EP_UNIQUE_9000";
    let ty_name = "SCHEMA_AUTO_TYPE_UNIQUE_9000";
    let _ = remove_data_type_by_name(ty_name);
    let _ = remove_endpoint_by_name(ep_name);

    assert!(DataEndpoint::try_named("SCHEMA_AUTO_EP_MISSING_9000").is_none());
    assert!(DataType::try_named("SCHEMA_AUTO_TYPE_MISSING_9000").is_none());

    let endpoint = register_endpoint_with_description(ep_name, "auto id endpoint", false).unwrap();
    let ty = register_data_type_with_description(
        ty_name,
        "auto id data type",
        MessageElement::Dynamic(MessageDataType::Binary, MessageClass::Warning),
        &[endpoint],
        ReliableMode::Unordered,
        42,
    )
    .unwrap();

    assert_eq!(DataEndpoint::try_named(ep_name), Some(endpoint));
    assert_eq!(DataType::try_named(ty_name), Some(ty));

    let endpoint_ref = endpoint_definition_by_name(ep_name).unwrap();
    assert_eq!(endpoint_ref.id, endpoint);
    assert_eq!(endpoint_ref.description, "auto id endpoint");

    let ty_ref = data_type_definition_by_name(ty_name).unwrap();
    assert_eq!(ty_ref.id, ty);
    assert_eq!(ty_ref.description, "auto id data type");
    assert_eq!(ty_ref.endpoints, &[endpoint]);
    assert_eq!(message_meta(ty).reliable, ReliableMode::Unordered);
    assert_eq!(message_meta(ty).priority, 42);

    let snapshot = export_schema();
    assert!(
        snapshot
            .endpoints
            .iter()
            .any(|def| def.id == endpoint && def.name == ep_name)
    );
    assert!(
        snapshot
            .types
            .iter()
            .any(|def| def.id == ty && def.name == ty_name)
    );

    assert!(remove_data_type_by_name(ty_name).unwrap());
    assert!(remove_endpoint_by_name(ep_name).unwrap());
    assert!(DataEndpoint::try_named(ep_name).is_none());
    assert!(DataType::try_named(ty_name).is_none());
}

#[test]
fn runtime_json_bytes_and_file_seed_schema_metadata() {
    let bytes_ep = "SCHEMA_JSON_BYTES_EP_9001";
    let bytes_ty = "SCHEMA_JSON_BYTES_TYPE_9001";
    let file_ep = "SCHEMA_JSON_FILE_EP_9002";
    let file_ty = "SCHEMA_JSON_FILE_TYPE_9002";
    for name in [bytes_ty, file_ty] {
        let _ = remove_data_type_by_name(name);
    }
    for name in [bytes_ep, file_ep] {
        let _ = remove_endpoint_by_name(name);
    }

    let bytes_json = br#"{
                "endpoints": [
                    {
                        "rust": "SchemaJsonBytesEp9001",
                        "name": "SCHEMA_JSON_BYTES_EP_9001",
                        "description": "json bytes endpoint",
                        "broadcast_mode": "Never"
                    }
                ],
                "types": [
                    {
                        "rust": "SchemaJsonBytesType9001",
                        "name": "SCHEMA_JSON_BYTES_TYPE_9001",
                        "description": "json bytes type",
                        "priority": 77,
                        "reliable": true,
                        "class": "Data",
                        "element": { "kind": "Static", "data_type": "UInt8", "count": 4 },
                        "endpoints": ["SchemaJsonBytesEp9001"]
                    }
                ]
            }"#;
    register_schema_json_bytes(bytes_json).unwrap();

    let ep = endpoint_definition_by_name(bytes_ep).unwrap();
    assert_eq!(ep.description, "json bytes endpoint");
    assert!(ep.link_local_only);
    let ty = data_type_definition_by_name(bytes_ty).unwrap();
    assert_eq!(ty.description, "json bytes type");
    assert_eq!(
        ty.element,
        MessageElement::Static(4, MessageDataType::UInt8, MessageClass::Data)
    );
    assert_eq!(ty.reliable, ReliableMode::Ordered);
    assert_eq!(ty.priority, 77);
    assert_eq!(ty.endpoints, &[ep.id]);

    let file_json = br#"{
                "endpoints": [
                    {
                        "rust": "SchemaJsonFileEp9002",
                        "name": "SCHEMA_JSON_FILE_EP_9002",
                        "doc": "json file endpoint",
                        "link_local_only": true
                    }
                ],
                "types": [
                    {
                        "rust": "SchemaJsonFileType9002",
                        "name": "SCHEMA_JSON_FILE_TYPE_9002",
                        "doc": "json file type",
                        "priority": 12,
                        "reliable_mode": "Unordered",
                        "class": "Error",
                        "element": { "kind": "Dynamic", "data_type": "String" },
                        "endpoints": ["SchemaJsonFileEp9002"]
                    }
                ]
            }"#;
    let path = std::env::temp_dir().join(format!(
        "sedsnet_runtime_schema_{}_{}.json",
        std::process::id(),
        9002
    ));
    std::fs::write(&path, file_json).unwrap();
    register_schema_json_file(&path).unwrap();
    let _ = std::fs::remove_file(&path);

    let ep = endpoint_definition_by_name(file_ep).unwrap();
    assert_eq!(ep.description, "json file endpoint");
    assert!(ep.link_local_only);
    let ty = data_type_definition_by_name(file_ty).unwrap();
    assert_eq!(ty.description, "json file type");
    assert_eq!(
        ty.element,
        MessageElement::Dynamic(MessageDataType::String, MessageClass::Error)
    );
    assert_eq!(ty.reliable, ReliableMode::Unordered);
    assert_eq!(ty.priority, 12);
    assert_eq!(ty.endpoints, &[ep.id]);

    for name in [bytes_ty, file_ty] {
        assert!(remove_data_type_by_name(name).unwrap());
    }
    for name in [bytes_ep, file_ep] {
        assert!(remove_endpoint_by_name(name).unwrap());
    }
}

#[test]
fn endpoint_registration_conflicts_and_endpoint_removal_are_validated() {
    let endpoint = DataEndpoint(9003);
    let ty = DataType(9003);
    let ep_name = "SCHEMA_CONFLICT_EP_9003";
    let ty_name = "SCHEMA_CONFLICT_TYPE_9003";
    let _ = remove_data_type_by_name(ty_name);
    let _ = remove_endpoint(endpoint);
    let _ = remove_endpoint_by_name(ep_name);

    register_endpoint_id_with_description(endpoint, ep_name, "first endpoint", false).unwrap();
    assert_eq!(
        register_endpoint_id_with_description(
            endpoint,
            "SCHEMA_CONFLICT_EP_OTHER_9003",
            "first endpoint",
            false,
        )
        .unwrap_err(),
        TelemetryError::BadArg
    );
    assert_eq!(
                register_endpoint_id_with_description(
                    DataEndpoint(9004),
                    ep_name,
                    "first endpoint",
                    false,
                )
                .unwrap_err(),
                TelemetryError::BadArg
            );

    register_data_type_id_with_description(
        ty,
        ty_name,
        "dependent type",
        MessageElement::Static(1, MessageDataType::UInt16, MessageClass::Data),
        &[endpoint],
        ReliableMode::None,
        1,
    )
    .unwrap();
    assert!(data_type_exists(ty));

    assert!(remove_endpoint(endpoint).unwrap());
    assert!(!endpoint_exists(endpoint));
    assert!(!data_type_exists(ty));
}

#[test]
fn schema_entries_can_be_named_described_used_by_handlers_and_removed() {
    let endpoint = DataEndpoint(247);
    let ty = DataType(4088);
    let ep_name = "SCHEMA_LOOKUP_EP_247";
    let ty_name = "SCHEMA_LOOKUP_TYPE_4088";
    let _ = remove_data_type_by_name(ty_name);
    let _ = remove_endpoint_by_name(ep_name);

    register_endpoint_id_with_description(endpoint, ep_name, "lookup test endpoint", false)
        .unwrap();
    register_data_type_id_with_description(
        ty,
        ty_name,
        "lookup test type",
        MessageElement::Static(1, MessageDataType::UInt32, MessageClass::Data),
        &[endpoint],
        ReliableMode::None,
        9,
    )
    .unwrap();

    let endpoint_ref = endpoint_definition_by_name(ep_name).unwrap();
    assert_eq!(endpoint_ref.id, endpoint);
    assert_eq!(endpoint_ref.description, "lookup test endpoint");
    let _handler = EndpointHandler::new_packet_handler_for(endpoint_ref, |_pkt: &Packet| Ok(()));

    let ty_ref = data_type_definition_by_name(ty_name).unwrap();
    assert_eq!(ty_ref.id, ty);
    assert_eq!(ty_ref.description, "lookup test type");
    assert_eq!(message_meta(ty).priority, 9);

    assert!(remove_data_type_by_name(ty_name).unwrap());
    assert!(!data_type_exists(ty));
    assert!(remove_endpoint_by_name(ep_name).unwrap());
    assert!(!endpoint_exists(endpoint));
}

#[test]
fn data_type_registration_rejects_different_shape_for_existing_id() {
    let endpoint = DataEndpoint(248);
    let _handler = EndpointHandler::new_packet_handler(endpoint, |_pkt: &Packet| Ok(()));
    let ty = DataType(4089);
    let first = register_data_type_id(
        ty,
        "SCHEMA_SYNC_EXPLICIT_TYPE_4089",
        MessageElement::Static(1, MessageDataType::UInt16, MessageClass::Data),
        &[endpoint],
        ReliableMode::None,
        3,
    );
    assert!(first.is_ok() || data_type_exists(ty));
    let err = register_data_type_id(
        ty,
        "SCHEMA_SYNC_EXPLICIT_TYPE_4089",
        MessageElement::Static(2, MessageDataType::UInt16, MessageClass::Data),
        &[endpoint],
        ReliableMode::None,
        3,
    )
    .unwrap_err();
    assert_eq!(err, TelemetryError::BadArg);
}

#[test]
fn conflicting_schema_type_layout_resolves_deterministically() {
    static ENDPOINTS_231: [DataEndpoint; 1] = [DataEndpoint(231)];
    let endpoint = EndpointDefinition {
        id: DataEndpoint(231),
        name: "SCHEMA_SYNC_EP_231",
        description: "",
        link_local_only: false,
    };
    let a = DataTypeDefinition {
        id: DataType(3002),
        name: "SCHEMA_SYNC_TYPE_3002",
        description: "",
        element: MessageElement::Static(1, MessageDataType::UInt16, MessageClass::Data),
        endpoints: &ENDPOINTS_231,
        reliable: ReliableMode::None,
        priority: 1,
        e2e_encryption: E2eEncryptionPolicy::PreferOff,
    };
    let b = DataTypeDefinition {
        id: DataType(3002),
        name: "SCHEMA_SYNC_TYPE_3002",
        description: "",
        element: MessageElement::Static(2, MessageDataType::UInt16, MessageClass::Data),
        endpoints: &ENDPOINTS_231,
        reliable: ReliableMode::None,
        priority: 1,
        e2e_encryption: E2eEncryptionPolicy::PreferOff,
    };

    let _ = merge_schema_snapshot(RuntimeSchemaSnapshot {
        endpoints: vec![endpoint],
        types: vec![a],
    });
    let _ = merge_schema_snapshot(RuntimeSchemaSnapshot {
        endpoints: vec![endpoint],
        types: vec![b],
    });
    let first = message_meta(DataType(3002)).element;
    let _ = merge_schema_snapshot(RuntimeSchemaSnapshot {
        endpoints: vec![endpoint],
        types: vec![a],
    });
    let second = message_meta(DataType(3002)).element;
    assert_eq!(first, second);
    assert!(export_schema().types.iter().any(|def| {
        def.id == DataType(3002) && (def.element == a.element || def.element == b.element)
    }));
}

#[test]
fn inline_wire_shape_keeps_old_payload_decodable_after_layout_change() {
    crate::tests::ensure_common_test_schema();
    let endpoint = DataEndpoint::named("RADIO");
    let ty = (13..=crate::MAX_VALUE_DATA_TYPE)
        .find_map(|id| (!data_type_exists(DataType(id))).then_some(DataType(id)))
        .expect("free runtime data type id");
    let ty_name = "SCHEMA_WIRE_TYPE_4090";
    let _ = remove_data_type_by_name(ty_name);
    register_data_type_id_with_description(
        ty,
        ty_name,
        "wire shape type v1",
        MessageElement::Static(1, MessageDataType::UInt16, MessageClass::Data),
        &[endpoint],
        ReliableMode::None,
        1,
    )
    .unwrap();

    let pkt = Packet::new(
        ty,
        &[endpoint],
        "SRC",
        0,
        Arc::<[u8]>::from(7u16.to_le_bytes().to_vec()),
    )
    .unwrap();
    let wire = crate::wire_format::pack_packet_with_wire_contract(
        &pkt,
        None,
        Some(message_meta(ty).element),
        &[],
    )
    .unwrap();

    assert!(remove_data_type_by_name(ty_name).unwrap());
    register_data_type_id_with_description(
        ty,
        ty_name,
        "wire shape type v2",
        MessageElement::Static(2, MessageDataType::UInt16, MessageClass::Data),
        &[endpoint],
        ReliableMode::None,
        1,
    )
    .unwrap();

    let decoded = crate::wire_format::unpack_packet(&wire).unwrap();
    decoded.validate().unwrap();
    assert_eq!(decoded.data_as_u16().unwrap(), vec![7u16]);
}

#[test]
fn conflicting_schema_endpoint_metadata_resolves_deterministically() {
    let a = EndpointDefinition {
        id: DataEndpoint(9005),
        name: "SCHEMA_SYNC_EP_9005_A",
        description: "a",
        link_local_only: false,
    };
    let b = EndpointDefinition {
        id: DataEndpoint(9005),
        name: "SCHEMA_SYNC_EP_9005_B",
        description: "b",
        link_local_only: true,
    };

    let _ = merge_schema_snapshot(RuntimeSchemaSnapshot {
        endpoints: vec![a],
        types: vec![],
    });
    let _ = merge_schema_snapshot(RuntimeSchemaSnapshot {
        endpoints: vec![b],
        types: vec![],
    });
    let first = endpoint_definition_by_name("SCHEMA_SYNC_EP_9005_A")
        .or_else(|| endpoint_definition_by_name("SCHEMA_SYNC_EP_9005_B"))
        .unwrap();
    let _ = merge_schema_snapshot(RuntimeSchemaSnapshot {
        endpoints: vec![a],
        types: vec![],
    });
    let second = endpoint_definition_by_name("SCHEMA_SYNC_EP_9005_A")
        .or_else(|| endpoint_definition_by_name("SCHEMA_SYNC_EP_9005_B"))
        .unwrap();

    assert_eq!(first.id, second.id);
    assert_eq!(first.name, second.name);
    assert_eq!(first.description, second.description);
    assert_eq!(first.link_local_only, second.link_local_only);
    assert!(first == a || first == b);
}
