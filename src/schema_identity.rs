// Shared by the build-time generator and runtime registration. IDs must not
// depend on which subset of a schema a node knows, or registration order.
pub const fn endpoint_id(name: &str) -> u32 {
    let hashed = name_id(name, 0x4550);
    let (reserved_name, id) = match hashed {
        110065665 => ("SD_CARD", 100),
        200499620 => ("RADIO", 101),
        97321777 => ("SOFTWARE_BUS", 102),
        179412986 => ("SEDSNET_ERROR", 202),
        108886069 => ("SEDSNET_TIME_SYNC", 200),
        216355494 => ("SEDSNET_DISCOVERY", 201),
        _ => return hashed,
    };
    // A hash collision with a reserved name must remain an application ID.
    if equal(name, reserved_name) {
        id
    } else {
        hashed
    }
}
pub const fn type_id(name: &str) -> u32 {
    let hashed = name_id(name, 0x5459);
    let (reserved_name, id) = match hashed {
        116203261 => ("GPS_DATA", 100),
        138392882 => ("IMU_DATA", 101),
        196339676 => ("BATTERY_STATUS", 102),
        11224736 => ("SYSTEM_STATUS", 103),
        101531372 => ("BAROMETER_DATA", 104),
        27869908 => ("MESSAGE_DATA", 105),
        258974484 => ("HEARTBEAT", 106),
        240639630 => ("IPC_MESSAGE", 107),
        58436129 => ("SEDSNET_ERROR", 0),
        106117325 => ("SEDSNET_RELIABLE_ACK", 1),
        196062750 => ("SEDSNET_RELIABLE_PACKET_REQUEST", 2),
        148884243 => ("SEDSNET_RELIABLE_PARTIAL_ACK", 3),
        109685708 => ("SEDSNET_TIME_SYNC_ANNOUNCE", 4),
        170500828 => ("SEDSNET_TIME_SYNC_REQUEST", 5),
        205765904 => ("SEDSNET_TIME_SYNC_RESPONSE", 6),
        30659965 => ("SEDSNET_DISCOVERY_ANNOUNCE", 7),
        235996729 => ("SEDSNET_DISCOVERY_TIMESYNC_SOURCES", 8),
        240880835 => ("SEDSNET_DISCOVERY_TOPOLOGY", 9),
        180082409 => ("SEDSNET_DISCOVERY_SCHEMA", 10),
        9124173 => ("SEDSNET_DISCOVERY_TOPOLOGY_REQUEST", 11),
        259220559 => ("SEDSNET_DISCOVERY_SCHEMA_REQUEST", 12),
        190130393 => ("SEDSNET_MANAGED_VARIABLE_REQUEST", 13),
        148495321 => ("SEDSNET_MANAGED_VARIABLE_VALUE", 14),
        79804237 => ("SEDSNET_DISCOVERY_LEAVE", 15),
        155796665 => ("SEDSNET_DISCOVERY_LINK_CAPABILITIES", 16),
        133165958 => ("SEDSNET_DISCOVERY_ADDRESS", 17),
        32457485 => ("SEDSNET_P2P_MESSAGE", 18),
        _ => return hashed,
    };
    // A hash collision with a reserved name must remain an application ID.
    if equal(name, reserved_name) {
        id
    } else {
        hashed
    }
}
const fn equal(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut index = 0;
    while index < a.len() {
        if a[index] != b[index] {
            return false;
        }
        index += 1;
    }
    true
}
const fn name_id(name: &str, namespace: u32) -> u32 {
    let mut hash = 0x811c9dc5u32 ^ namespace;
    let bytes = name.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        hash = (hash ^ bytes[index] as u32).wrapping_mul(0x01000193);
        index += 1;
    }
    // Keep internal/legacy IDs reserved. Registration checks collisions;
    // a conflicting name must never silently acquire an existing identity.
    0x10000 | (hash & 0x0fff_ffff)
}
