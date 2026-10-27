# Generated from src/schema_identity.rs by scripts/sync-schema-identity.py.
# No application or test identity belongs in the protocol tables.
ENDPOINT_PROTOCOL = {'SEDSNET_ERROR': 202, 'SEDSNET_TIME_SYNC': 200, 'SEDSNET_DISCOVERY': 201}
TYPE_PROTOCOL = {'SEDSNET_ERROR': 0, 'SEDSNET_RELIABLE_ACK': 1, 'SEDSNET_RELIABLE_PACKET_REQUEST': 2, 'SEDSNET_RELIABLE_PARTIAL_ACK': 3, 'SEDSNET_TIME_SYNC_ANNOUNCE': 4, 'SEDSNET_TIME_SYNC_REQUEST': 5, 'SEDSNET_TIME_SYNC_RESPONSE': 6, 'SEDSNET_DISCOVERY_ANNOUNCE': 7, 'SEDSNET_DISCOVERY_TIMESYNC_SOURCES': 8, 'SEDSNET_DISCOVERY_TOPOLOGY': 9, 'SEDSNET_DISCOVERY_SCHEMA': 10, 'SEDSNET_DISCOVERY_TOPOLOGY_REQUEST': 11, 'SEDSNET_DISCOVERY_SCHEMA_REQUEST': 12, 'SEDSNET_MANAGED_VARIABLE_REQUEST': 13, 'SEDSNET_MANAGED_VARIABLE_VALUE': 14, 'SEDSNET_DISCOVERY_LEAVE': 15, 'SEDSNET_DISCOVERY_LINK_CAPABILITIES': 16, 'SEDSNET_DISCOVERY_ADDRESS': 17}


def resolve_id(name, explicit=None, *, endpoint=False):
    if not isinstance(name, str) or not name:
        raise ValueError("schema name must not be empty")
    table = ENDPOINT_PROTOCOL if endpoint else TYPE_PROTOCOL
    value = 0x811C9DC5 ^ (0x4550 if endpoint else 0x5459)
    for byte in name.encode("utf-8"):
        value = ((value ^ byte) * 0x01000193) & 0xFFFFFFFF
    default = table.get(name, 0x10000 | (value & 0x0FFFFFFF))
    if explicit is not None and (type(explicit) is not int or not 0 <= explicit <= 0xFFFFFFFF):
        raise ValueError("schema id must be a u32 integer")
    value = default if explicit is None else explicit
    reserved = 200 <= value <= 202 if endpoint else 0 <= value <= 18
    if (name in table and value != default) or (reserved and table.get(name) != value):
        raise ValueError("schema ID conflicts with a reserved SEDSNET protocol identity")
    return value
