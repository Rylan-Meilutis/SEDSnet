// Generated mirror of src/schema_identity.rs; run scripts/sync-schema-identity.py.
// Shared by the build-time generator and runtime registration. IDs must not
// depend on which subset of a schema a node knows, or registration order.
pub const fn endpoint_id(name: &str) -> u32 {
    let hashed = name_id(name, 0x4550);
    let (reserved_name, id) = match hashed {
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
    // Keep generated application IDs outside the small protocol namespace.
    // Explicit application IDs are configured independently. Registration checks collisions;
    // a conflicting name must never silently acquire an existing identity.
    0x10000 | (hash & 0x0fff_ffff)
}

/// Resolve an optional wire ID without assigning application semantics to names.
/// Only the SDK protocol IDs and their exact names are reserved.
pub fn resolve_endpoint(name: &str, explicit: Option<u32>) -> Result<u32, &'static str> {
    resolve(
        name,
        explicit,
        endpoint_id(name),
        matches!(endpoint_id(name), 200..=202),
        true,
    )
}
pub fn resolve_type(name: &str, explicit: Option<u32>) -> Result<u32, &'static str> {
    resolve(name, explicit, type_id(name), type_id(name) <= 18, false)
}
fn resolve(
    name: &str,
    explicit: Option<u32>,
    default: u32,
    protocol_name: bool,
    endpoint: bool,
) -> Result<u32, &'static str> {
    if name.is_empty() {
        return Err("schema name must not be empty");
    }
    let id = explicit.unwrap_or(default);
    let protocol_id = if endpoint {
        matches!(id, 200..=202)
    } else {
        id <= 18
    };
    if (protocol_name && id != default) || (protocol_id && (!protocol_name || id != default)) {
        return Err("schema ID conflicts with a reserved SEDSNET protocol identity");
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn application_names_have_no_reserved_meaning() {
        for (name, old) in [
            ("GPS_DATA", 100),
            ("IMU_DATA", 101),
            ("BATTERY_STATUS", 102),
            ("SYSTEM_STATUS", 103),
            ("BAROMETER_DATA", 104),
            ("MESSAGE_DATA", 105),
            ("HEARTBEAT", 106),
            ("IPC_MESSAGE", 107),
        ] {
            assert_eq!(type_id(name), name_id(name, 0x5459));
            assert_ne!(type_id(name), old);
            assert_eq!(resolve_type(name, Some(old)), Ok(old));
        }
        for (name, old) in [("SD_CARD", 100), ("RADIO", 101), ("SOFTWARE_BUS", 102)] {
            assert_eq!(endpoint_id(name), name_id(name, 0x4550));
            assert_ne!(endpoint_id(name), old);
        }
        assert_eq!(resolve_type("ANY_APPLICATION", Some(100)), Ok(100));
        assert_eq!(resolve_endpoint("ANY_DESTINATION", Some(100)), Ok(100));
    }

    #[test]
    fn only_exact_protocol_identities_are_reserved() {
        let names = [
            "SEDSNET_ERROR",
            "SEDSNET_RELIABLE_ACK",
            "SEDSNET_RELIABLE_PACKET_REQUEST",
            "SEDSNET_RELIABLE_PARTIAL_ACK",
            "SEDSNET_TIME_SYNC_ANNOUNCE",
            "SEDSNET_TIME_SYNC_REQUEST",
            "SEDSNET_TIME_SYNC_RESPONSE",
            "SEDSNET_DISCOVERY_ANNOUNCE",
            "SEDSNET_DISCOVERY_TIMESYNC_SOURCES",
            "SEDSNET_DISCOVERY_TOPOLOGY",
            "SEDSNET_DISCOVERY_SCHEMA",
            "SEDSNET_DISCOVERY_TOPOLOGY_REQUEST",
            "SEDSNET_DISCOVERY_SCHEMA_REQUEST",
            "SEDSNET_MANAGED_VARIABLE_REQUEST",
            "SEDSNET_MANAGED_VARIABLE_VALUE",
            "SEDSNET_DISCOVERY_LEAVE",
            "SEDSNET_DISCOVERY_LINK_CAPABILITIES",
            "SEDSNET_DISCOVERY_ADDRESS",
            "SEDSNET_P2P_MESSAGE",
        ];
        for (id, name) in names.into_iter().enumerate() {
            assert_eq!(resolve_type(name, None), Ok(id as u32));
            assert_eq!(resolve_type(name, Some(id as u32)), Ok(id as u32));
            assert!(resolve_type(name, Some(100)).is_err());
            assert!(resolve_type("ARBITRARY", Some(id as u32)).is_err());
        }
        for (id, name) in [
            (200, "SEDSNET_TIME_SYNC"),
            (201, "SEDSNET_DISCOVERY"),
            (202, "SEDSNET_ERROR"),
        ] {
            assert_eq!(resolve_endpoint(name, None), Ok(id));
            assert!(resolve_endpoint("ARBITRARY", Some(id)).is_err());
            assert!(resolve_endpoint(name, Some(100)).is_err());
        }
    }
}
