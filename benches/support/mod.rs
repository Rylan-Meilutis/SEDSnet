// Benchmarks run against an empty hosted registry unless they seed it.
// Keep schema setup outside timed loops and identical across all path benches.
use sedsnet::config::{
    DataEndpoint, data_type_definition_by_name, endpoint_definition_by_name,
    register_data_type_with_description, register_endpoint_with_description,
};
use sedsnet::{MessageClass, MessageDataType, MessageElement, ReliableMode};
use std::sync::Once;
pub fn initialize_schema() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        for (name, description) in [
            (
                "RADIO",
                "Radio or external link (telemetry uplink/downlink).",
            ),
            ("SD_CARD", "On-board storage (e.g. SD card / flash)."),
        ] {
            if endpoint_definition_by_name(name).is_none() {
                register_endpoint_with_description(name, description, false).unwrap();
            }
        }
        let endpoints = [DataEndpoint::named("RADIO"), DataEndpoint::named("SD_CARD")];
        for (name, description, shape, reliable, priority) in [
            (
                "GPS_DATA",
                "GPS data (typically 3x f32: latitude, longitude, altitude).",
                MessageElement::Static(3, MessageDataType::Float32, MessageClass::Data),
                ReliableMode::Ordered,
                80,
            ),
            (
                "MESSAGE_DATA",
                "Generic string message payload.",
                MessageElement::Dynamic(MessageDataType::String, MessageClass::Data),
                ReliableMode::None,
                0,
            ),
        ] {
            if data_type_definition_by_name(name).is_none() {
                register_data_type_with_description(
                    name,
                    description,
                    shape,
                    &endpoints,
                    reliable,
                    priority,
                )
                .unwrap();
            }
        }
    });
}
