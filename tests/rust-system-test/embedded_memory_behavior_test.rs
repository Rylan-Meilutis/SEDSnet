#![cfg(not(feature = "std"))]

use sedsnet::config::{
    DataEndpoint, DataType, OwnedDataTypeDefinition, OwnedEndpointDefinition,
    OwnedRuntimeSchemaSnapshot, data_type_definition, endpoint_definition,
    merge_owned_schema_snapshot_with_budget, schema_bytes_used,
};
use sedsnet::discovery::build_discovery_schema_from_owned_snapshot;
use sedsnet::router::{Router, RouterConfig};
use sedsnet::{E2eEncryptionPolicy, MessageClass, MessageDataType, MessageElement, ReliableMode};

use std::sync::Arc;
use std::sync::Mutex;

static TEST_LOCK: Mutex<()> = Mutex::new(());

// The no_std library delegates synchronization to the platform. This test is
// single-threaded, so no-op host shims are sufficient to execute that path.
#[unsafe(no_mangle)]
extern "C" fn telemetry_lock() {}

#[unsafe(no_mangle)]
extern "C" fn telemetry_unlock() {}

#[test]
fn embedded_router_merges_remote_schema_into_its_bounded_overlay() {
    let _guard = TEST_LOCK.lock().unwrap();
    let router = Router::new_with_clock(RouterConfig::default(), Box::new(|| 0));
    let side = router.add_side_packed("embedded-link", |_bytes| Ok(()));

    let endpoint = DataEndpoint(28_001);
    let data_type = DataType(28_002);
    let packet = build_discovery_schema_from_owned_snapshot(
        "REMOTE_NODE",
        1,
        OwnedRuntimeSchemaSnapshot {
            endpoints: vec![OwnedEndpointDefinition {
                id: endpoint,
                name: "DYNAMIC_REMOTE_ENDPOINT".into(),
                description: String::new(),
                link_local_only: false,
            }],
            types: vec![OwnedDataTypeDefinition {
                id: data_type,
                name: "DYNAMIC_REMOTE_VALUE".into(),
                description: String::new(),
                element: MessageElement::Static(1, MessageDataType::UInt32, MessageClass::Data),
                endpoints: vec![endpoint],
                reliable: ReliableMode::Ordered,
                priority: 42,
                e2e_encryption: E2eEncryptionPolicy::PreferOff,
            }],
        },
    )
    .unwrap();

    router.rx_from_side(&packet, side).unwrap();

    assert_eq!(
        endpoint_definition(endpoint).unwrap().name,
        "DYNAMIC_REMOTE_ENDPOINT"
    );
    assert_eq!(
        data_type_definition(data_type).unwrap().name,
        "DYNAMIC_REMOTE_VALUE"
    );
}

#[test]
fn embedded_router_advertises_its_merged_schema() {
    let _guard = TEST_LOCK.lock().unwrap();
    let router = Router::new_with_clock(RouterConfig::default(), Box::new(|| 0));
    let frames = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let captured = frames.clone();
    router.add_side_packed("embedded-link", move |bytes| {
        captured.lock().unwrap().push(bytes.to_vec());
        Ok(())
    });

    router.announce_discovery().unwrap();
    router.process_tx_queue().unwrap();

    let frames = frames.lock().unwrap();
    assert!(!frames.is_empty());
    assert!(frames.iter().any(|bytes| {
        sedsnet::wire_format::unpack_packet(bytes)
            .map(|packet| packet.data_type() == DataType::DiscoverySchema)
            .unwrap_or(false)
    }));
}

#[test]
fn embedded_schema_budget_failure_is_atomic() {
    let _guard = TEST_LOCK.lock().unwrap();
    let endpoint = DataEndpoint(28_101);
    let before = schema_bytes_used();
    let oversized = OwnedRuntimeSchemaSnapshot {
        endpoints: vec![OwnedEndpointDefinition {
            id: endpoint,
            name: "X".repeat(1024),
            description: String::new(),
            link_local_only: false,
        }],
        types: Vec::new(),
    };

    assert!(merge_owned_schema_snapshot_with_budget(oversized, before + 64).is_err());
    assert!(endpoint_definition(endpoint).is_none());
    assert_eq!(schema_bytes_used(), before);
}
