#![cfg(feature = "std")]
use sedsnet::config::{DataEndpoint, DataType, register_data_type_id, register_endpoint_id};
use sedsnet::wire_format::{pack_packet, packet_id_from_wire, unpack_packet};
use sedsnet::{MessageClass, MessageDataType, MessageElement, ReliableMode};

#[test]
fn captured_mcu_startup_warning_keeps_canonical_receipt_identity() {
    // Exact application IDs from the captured firmware, isolated from other
    // test processes' runtime schemas.
    let endpoints = [DataEndpoint(100), DataEndpoint(101)];
    // The full test route preloads its own names/descriptions at these IDs.
    // Preserve that fixture; with an empty registry use the hardware names.
    for (endpoint, name) in endpoints.iter().zip(["SD_CARD", "GROUND_STATION"]) {
        if DataEndpoint::try_from_u32(endpoint.as_u32()).is_none() {
            register_endpoint_id(*endpoint, name, false).unwrap();
        }
    }
    register_data_type_id(
        DataType(114),
        "WARNING",
        MessageElement::Dynamic(MessageDataType::String, MessageClass::Warning),
        &endpoints,
        ReliableMode::Ordered,
        0,
    )
    .unwrap();
    let hex = "6c027227f903e7d80296fde8e10300000000000000000000000030000000000000000000000000000000000000000b072d015f43929e12bbfca78400534420756e617661696c61626c653b20666c696768742f6e6574776f726b20636f6e74696e7565138cf220";
    let bytes: Vec<u8> = hex
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    let packet = unpack_packet(&bytes).unwrap();
    assert_eq!(packet.payload(), b"SD unavailable; flight/network continue");
    let canonical = packet_id_from_wire(&bytes).unwrap();
    assert_eq!(packet.packet_id(), canonical);
    assert_eq!(
        packet_id_from_wire(&pack_packet(&packet)).unwrap(),
        canonical
    );
}

#[test]
fn endpoint_order_and_duplicates_do_not_change_wire_receipt_identity() {
    use sedsnet::packet::Packet;
    let endpoints = [DataEndpoint(180), DataEndpoint(181), DataEndpoint(182)];
    for (ep, name) in endpoints
        .iter()
        .zip(["ID_CANON_A", "ID_CANON_B", "ID_CANON_C"])
    {
        register_endpoint_id(*ep, name, false).unwrap();
    }
    let ty = DataType(180);
    register_data_type_id(
        ty,
        "ID_CANON_VALUE",
        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
        &endpoints,
        ReliableMode::Ordered,
        0,
    )
    .unwrap();
    let reference = Packet::from_f32_slice(ty, &[1.25], &endpoints, 123).unwrap();
    for selection in [
        vec![endpoints[2], endpoints[0], endpoints[1]],
        vec![endpoints[1], endpoints[2], endpoints[0], endpoints[1]],
    ] {
        let packet = Packet::new_with_nonce(
            ty,
            &selection,
            reference.sender(),
            reference.timestamp(),
            reference.nonce(),
            std::sync::Arc::from(reference.payload()),
        )
        .unwrap();
        let wire = pack_packet(&packet);
        assert_eq!(packet.packet_id(), reference.packet_id());
        assert_eq!(packet_id_from_wire(&wire).unwrap(), reference.packet_id());
        assert_eq!(
            unpack_packet(&wire).unwrap().packet_id(),
            reference.packet_id()
        );
    }
}
