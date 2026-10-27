#![cfg(feature = "std")]
use sedsnet::config::{self, DataEndpoint, DataType};
use sedsnet::packet::Packet;
use sedsnet::wire_format::{pack_packet, unpack_packet};
use std::sync::Arc;

#[test]
fn small_application_ids_and_endpoint_zero_keep_application_semantics() {
    let schema = br#"{"endpoints":[{"name":"ZERO_DESTINATION","id":0},{"name":"HUNDRED_DESTINATION","id":100},{"name":"OTHER_DESTINATION","id":101}],"types":[{"name":"OPAQUE_READING","id":50,"class":"Data","element":{"kind":"Dynamic","data_type":"Binary"},"endpoints":["ZERO_DESTINATION","HUNDRED_DESTINATION","OTHER_DESTINATION"],"reliable":"Off","priority":7},{"name":"LOW_APPLICATION","id":19,"class":"Data","element":{"kind":"Dynamic","data_type":"Binary"},"endpoints":[],"reliable":"Off","priority":255},{"name":"HIGH_APPLICATION","id":99,"class":"Data","element":{"kind":"Dynamic","data_type":"Binary"},"endpoints":[],"reliable":"Off","priority":2}]}"#;
    // This process owns a private application schema; no standard test schema
    // is preloaded by this integration test's call site.
    let snapshot = config::schema_snapshot_from_json_bytes(schema).unwrap();
    for endpoint in snapshot.endpoints {
        // build.py may preload its application test fixture in this private
        // process. Replace only these non-protocol test destinations.
        if config::endpoint_exists(endpoint.id) {
            config::remove_endpoint(endpoint.id).unwrap();
        }
        config::register_endpoint_id(endpoint.id, &endpoint.name, false).unwrap();
    }
    for ty in snapshot.types {
        config::register_data_type_id(
            ty.id,
            &ty.name,
            ty.element,
            &ty.endpoints,
            ty.reliable,
            ty.priority,
        )
        .unwrap();
    }
    let packet = Packet::new(
        DataType(50),
        &[DataEndpoint(0), DataEndpoint(100), DataEndpoint(101)],
        "CUSTOM_SOURCE",
        77,
        Arc::<[u8]>::from([1, 2, 3, 4]),
    )
    .unwrap();
    let decoded = unpack_packet(&pack_packet(&packet)).unwrap();
    assert_eq!(decoded.data_type(), DataType(50));
    assert_eq!(
        decoded.endpoints(),
        &[DataEndpoint(0), DataEndpoint(100), DataEndpoint(101)]
    );
    assert_eq!(decoded.payload(), &[1, 2, 3, 4]);
    assert_eq!(sedsnet::transport_priority(DataType(50)), 7);
    assert_eq!(
        sedsnet::transport_priority(DataType(19)),
        253,
        "application priority remains capped below protocol control"
    );
    assert_eq!(sedsnet::transport_priority(DataType(99)), 2);
    assert!(!sedsnet::is_reliable_type(DataType(50)));
}

#[test]
fn later_schema_resolves_an_unclaimed_endpoint_placeholder() {
    let id = DataEndpoint(645_999);
    config::ensure_endpoint_id(id, false).unwrap();
    let snapshot = config::OwnedRuntimeSchemaSnapshot {
        endpoints: vec![config::OwnedEndpointDefinition {
            id,
            name: "ACTUAL_GENERIC_DESTINATION".into(),
            description: "learned after its numeric ID".into(),
            link_local_only: false,
        }],
        types: vec![],
    };
    config::merge_owned_schema_snapshot_with_budget(snapshot, usize::MAX).unwrap();
    assert_eq!(DataEndpoint::named("ACTUAL_GENERIC_DESTINATION"), id);
    let conflict = config::OwnedRuntimeSchemaSnapshot {
        endpoints: vec![config::OwnedEndpointDefinition {
            id,
            name: "ANOTHER_REAL_CLAIM".into(),
            description: String::new(),
            link_local_only: false,
        }],
        types: vec![],
    };
    assert!(config::merge_owned_schema_snapshot_with_budget(conflict, usize::MAX).is_err());
    assert_eq!(DataEndpoint::named("ACTUAL_GENERIC_DESTINATION"), id);
}
