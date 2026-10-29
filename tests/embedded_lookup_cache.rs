#![cfg(all(not(feature = "std"), feature = "discovery"))]
use sedsnet::config::{self, DataType};
#[unsafe(no_mangle)]
extern "C" fn telemetry_lock() {}
#[unsafe(no_mangle)]
extern "C" fn telemetry_unlock() {}
#[test]
fn compiled_lookup_warmup_does_not_hide_overlay_metadata_updates() {
    let id = DataType::named("GPS_DATA");
    let original = config::data_type_definition(id).unwrap();
    for _ in 0..100 {
        assert_eq!(config::data_type_definition(id), Some(original.clone()));
        assert!(config::data_type_exists(id));
        // Warm other compiled definitions, including direct-mapped slot collisions.
        for definition in config::export_schema().types {
            assert!(config::data_type_exists(definition.id));
        }
    }
    let mut changed = original.clone();
    changed.priority = original.priority.wrapping_add(1);
    changed.description.push_str(" learned overlay");
    let report = config::merge_owned_schema_snapshot_with_budget(
        config::OwnedRuntimeSchemaSnapshot {
            endpoints: vec![],
            types: vec![changed.clone()],
        },
        usize::MAX,
    )
    .unwrap();
    assert_eq!(report.types_replaced, 1);
    let merged = config::data_type_definition(id).unwrap();
    assert_eq!(merged.priority, changed.priority);
    for _ in 0..100 {
        assert_eq!(config::data_type_definition(id), Some(merged.clone()));
        assert_eq!(sedsnet::message_priority(id), changed.priority);
        assert!(config::data_type_exists(id));
    }
}
