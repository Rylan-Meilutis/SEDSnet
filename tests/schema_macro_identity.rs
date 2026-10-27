#![cfg(feature = "std")]
use strum::EnumCount;
#[derive(Debug, Clone, Copy)]
pub enum ReliableMode {
    None,
    Ordered,
    Unordered,
}
#[derive(Debug, Clone, Copy)]
pub enum MessageClass {
    Data,
    Error,
    Warning,
}
#[derive(Debug, Clone, Copy)]
pub enum MessageDataType {
    Binary,
    NoData,
    UInt8,
    UInt32,
    UInt64,
    String,
}
#[derive(Debug, Clone, Copy)]
pub enum MessageElement {
    Static(usize, MessageDataType, MessageClass),
    Dynamic(MessageDataType, MessageClass),
}
pub struct EndpointMeta {
    pub name: &'static str,
    pub link_local_only: bool,
}
pub struct MessageMeta {
    pub name: &'static str,
    pub element: MessageElement,
    pub endpoints: &'static [DataEndpoint],
    pub reliable: ReliableMode,
    pub priority: u8,
}
sedsnet_macros::define_telemetry_schema!(
    path = "tests/fixtures/generic-identity.json",
    timesync = true,
    discovery = true
);

#[test]
fn generated_macro_ids_match_runtime_snapshot_and_generic_hashes() {
    use sedsnet::config::schema_snapshot_from_json_bytes;
    let snapshot =
        schema_snapshot_from_json_bytes(include_bytes!("fixtures/generic-identity.json")).unwrap();
    assert_eq!(DataEndpoint::CustomStorage as u32, 100);
    assert_eq!(DataType::CustomReading as u32, 101);
    assert_eq!(
        DataEndpoint::Radio as u32,
        sedsnet::config::DataEndpoint::identity("RADIO").as_u32()
    );
    assert_eq!(
        DataType::Heartbeat as u32,
        sedsnet::config::DataType::identity("HEARTBEAT").as_u32()
    );
    assert_eq!(
        snapshot.types[0].id.as_u32(),
        DataType::CustomReading as u32
    );
    assert_eq!(snapshot.types[1].id.as_u32(), DataType::Heartbeat as u32);
    assert_eq!(DataEndpoint::TimeSync as u32, 200);
    assert_eq!(DataEndpoint::Discovery as u32, 201);
    assert_eq!(DataEndpoint::TelemetryError as u32, 202);
    assert_eq!(DataType::ReliableAck as u32, 1);
    assert_eq!(DataType::DiscoveryTopology as u32, 9);
    for ty in [
        DataType::TelemetryError,
        DataType::ReliableAck,
        DataType::ReliablePartialAck,
        DataType::ReliablePacketRequest,
        DataType::TimeSyncAnnounce,
        DataType::TimeSyncRequest,
        DataType::TimeSyncResponse,
        DataType::DiscoveryAnnounce,
        DataType::DiscoveryTimeSyncSources,
        DataType::DiscoveryTopology,
    ] {
        let generated = get_message_meta(ty);
        assert!(generated.name.starts_with("SEDSNET_"));
        let runtime =
            sedsnet::config::data_type_definition(sedsnet::config::DataType(ty as u32)).unwrap();
        assert_eq!(generated.name, runtime.name);
        assert_eq!(generated.priority, runtime.priority);
        assert_eq!(
            format!("{:?}", generated.reliable),
            format!("{:?}", runtime.reliable)
        );
        assert_eq!(
            format!("{:?}", generated.element),
            format!("{:?}", runtime.element)
        );
        assert_eq!(
            generated
                .endpoints
                .iter()
                .map(|endpoint| *endpoint as u32)
                .collect::<Vec<_>>(),
            runtime
                .endpoints
                .iter()
                .map(|endpoint| endpoint.as_u32())
                .collect::<Vec<_>>()
        );
    }
}
