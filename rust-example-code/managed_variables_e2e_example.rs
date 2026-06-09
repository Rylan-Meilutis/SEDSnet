use sedsprintf_rs::config::{
    register_data_type_id_with_description_and_e2e_encryption,
    register_endpoint_id_with_description,
};
use sedsprintf_rs::router::{Router, RouterConfig, RouterE2eEncryptionMode};
use sedsprintf_rs::{
    DataEndpoint, DataType, E2eEncryptionPolicy, MessageClass, MessageDataType, MessageElement,
    ReliableMode, TelemetryResult,
};

fn main() -> TelemetryResult<()> {
    let radio = register_endpoint_id_with_description(
        DataEndpoint(101),
        "RADIO",
        "serialized radio link",
        false,
    )?;
    let flight_state = register_data_type_id_with_description_and_e2e_encryption(
        DataType(3100),
        "FLIGHT_STATE",
        "network-managed flight state",
        MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
        &[radio],
        ReliableMode::None,
        90,
        E2eEncryptionPolicy::RequireOn,
    )?;

    let router = Router::new(
        RouterConfig::default()
            .with_sender("FLIGHT_COMPUTER")
            .with_e2e_encryption(RouterE2eEncryptionMode::RequiredOnly)
            .with_e2e_key_id(7),
    );

    router.enable_managed_variable(flight_state)?;
    router.add_side_serialized("RADIO", |_bytes| Ok(()));

    let state = [3_u8];
    router.log(flight_state, &state)?;
    router.request_managed_variable(flight_state)?;
    router.process_all_queues()?;
    Ok(())
}
