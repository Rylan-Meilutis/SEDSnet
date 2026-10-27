#![cfg(all(not(feature = "std"), feature = "discovery", feature = "serde"))]
use sedsnet::config::{self, DataEndpoint, DataType};
#[unsafe(no_mangle)]
extern "C" fn telemetry_lock() {}
#[unsafe(no_mangle)]
extern "C" fn telemetry_unlock() {}

#[test]
fn compiled_catalog_and_runtime_parser_preserve_explicit_application_ids() {
    // build.py supplies the explicit-ID test catalog to the flash generator.
    assert_eq!(DataEndpoint::named("RADIO"), DataEndpoint(101));
    assert_eq!(DataType::named("GPS_DATA"), DataType(100));
    assert_ne!(DataEndpoint::identity("RADIO"), DataEndpoint(101));
    assert_ne!(DataType::identity("GPS_DATA"), DataType(100));
    let snapshot =
        config::schema_snapshot_from_json_bytes(include_bytes!("../telemetry_config.test.json"))
            .unwrap();
    for endpoint in snapshot.endpoints {
        assert_eq!(DataEndpoint::named(&endpoint.name), endpoint.id);
    }
    for ty in snapshot.types {
        assert_eq!(DataType::named(&ty.name), ty.id);
    }
    let arbitrary = config::schema_snapshot_from_json_bytes(br#"{"endpoints":[{"name":"ANY_DESTINATION","id":100}],"types":[{"name":"ANY_READING","id":101,"class":"Data","element":{"kind":"Dynamic","data_type":"Binary"},"endpoints":["ANY_DESTINATION"],"reliable":"Off"}]}"#).unwrap();
    assert_eq!(arbitrary.endpoints[0].id, DataEndpoint(100));
    assert_eq!(arbitrary.types[0].id, DataType(101));
    assert_eq!(arbitrary.types[0].endpoints, [DataEndpoint(100)]);
}

#[test]
fn embedded_registration_and_merge_reject_reserved_ids_without_partial_mutation() {
    use sedsnet::{MessageClass, MessageDataType, MessageElement, ReliableMode};
    let before = config::schema_bytes_used();
    assert!(config::register_endpoint_id(DataEndpoint(200), "APP_DESTINATION", false).is_err());
    assert!(
        config::register_data_type_id(
            DataType(1),
            "APP_READING",
            MessageElement::Dynamic(MessageDataType::Binary, MessageClass::Data),
            &[],
            ReliableMode::None,
            0
        )
        .is_err()
    );
    let snapshot = config::OwnedRuntimeSchemaSnapshot {
        endpoints: vec![config::OwnedEndpointDefinition {
            id: DataEndpoint(645_321),
            name: "SHOULD_NOT_REGISTER".into(),
            description: String::new(),
            link_local_only: false,
        }],
        types: vec![config::OwnedDataTypeDefinition {
            id: DataType(1),
            name: "FORGED_PROTOCOL".into(),
            description: String::new(),
            element: MessageElement::Dynamic(MessageDataType::Binary, MessageClass::Data),
            endpoints: vec![],
            reliable: ReliableMode::None,
            priority: 0,
            e2e_encryption: sedsnet::E2eEncryptionPolicy::PreferOff,
        }],
    };
    assert!(config::merge_owned_schema_snapshot_with_budget(snapshot, usize::MAX).is_err());
    assert!(DataEndpoint::try_named("SHOULD_NOT_REGISTER").is_none());
    assert_eq!(before, config::schema_bytes_used());
}
