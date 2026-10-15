#![cfg(feature = "std")]
use sedsnet::{ReliableMode, config::schema_snapshot_from_json_bytes};
fn schema(mode: serde_json::Value) -> serde_json::Value {
    serde_json::json!({"endpoints": [{"rust":"SingleReliabilityEp","name":"SINGLE_RELIABILITY_EP"}],
        "types": [{"name":"SINGLE_RELIABILITY_VALUE", "class":"Data",
            "element":{"kind":"Static","data_type":"Float32","count":1},
            "endpoints":["SingleReliabilityEp"],"reliable":mode}]})
}
#[test]
fn single_reliability_enum_parses_all_three_values() {
    for (name, expected) in [
        ("Off", ReliableMode::None),
        ("Ordered", ReliableMode::Ordered),
        ("Unordered", ReliableMode::Unordered),
    ] {
        let snapshot =
            schema_snapshot_from_json_bytes(&serde_json::to_vec(&schema(name.into())).unwrap())
                .unwrap();
        assert_eq!(snapshot.types[0].reliable, expected);
        assert_eq!(serde_json::to_value(expected).unwrap(), name);
    }
}
#[test]
fn legacy_boolean_mode_pairs_and_invalid_modes_are_rejected() {
    for value in [
        serde_json::json!(true),
        serde_json::json!(false),
        serde_json::json!(0),
        serde_json::json!(null),
        serde_json::json!("None"),
        serde_json::json!("off"),
    ] {
        let mut input = schema(value);
        input["types"][0]["reliable_mode"] = "Ordered".into();
        assert!(schema_snapshot_from_json_bytes(&serde_json::to_vec(&input).unwrap()).is_err());
    }
    let mut conflicting = schema("Off".into());
    conflicting["types"][0]["reliable_mode"] = "Unordered".into();
    assert!(schema_snapshot_from_json_bytes(&serde_json::to_vec(&conflicting).unwrap()).is_err());
    let mut input = schema("Off".into());
    input["types"][0]
        .as_object_mut()
        .unwrap()
        .remove("reliable");
    input["types"][0]["reliable_mode"] = "Unordered".into();
    assert!(schema_snapshot_from_json_bytes(&serde_json::to_vec(&input).unwrap()).is_err());
}
