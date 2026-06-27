# Discovery and Internal Formats (Technical)

This page documents the payload formats used by discovery and router-owned internal packet types.
The outer packet frame is still the compact wire frame described in
[Technical-Wire-Format](Technical-Wire-Format). The layouts below describe the `PAYLOAD_BYTES`
section for built-in control `DataType` values.

All integer fields in these payloads are little-endian fixed-width integers unless the layout says
otherwise. Strings are UTF-8 bytes preceded by a `u32` byte length.

## Built-In Control IDs

Built-in router endpoints:

| ID | Name |
| --- | --- |
| `200` | `SEDSNET_TIME_SYNC` |
| `201` | `SEDSNET_DISCOVERY` |
| `202` | `SEDSNET_ERROR` |

Built-in router data types:

| ID | Name | Endpoint |
| --- | --- | --- |
| `0` | `SEDSNET_ERROR` | `SEDSNET_ERROR` |
| `1` | `SEDSNET_RELIABLE_ACK` | `SEDSNET_ERROR` |
| `2` | `SEDSNET_RELIABLE_PACKET_REQUEST` | `SEDSNET_ERROR` |
| `3` | `SEDSNET_RELIABLE_PARTIAL_ACK` | `SEDSNET_ERROR` |
| `4` | `SEDSNET_TIME_SYNC_ANNOUNCE` | `SEDSNET_TIME_SYNC` |
| `5` | `SEDSNET_TIME_SYNC_REQUEST` | `SEDSNET_TIME_SYNC` |
| `6` | `SEDSNET_TIME_SYNC_RESPONSE` | `SEDSNET_TIME_SYNC` |
| `7` | `SEDSNET_DISCOVERY_ANNOUNCE` | `SEDSNET_DISCOVERY` |
| `8` | `SEDSNET_DISCOVERY_TIMESYNC_SOURCES` | `SEDSNET_DISCOVERY` |
| `9` | `SEDSNET_DISCOVERY_TOPOLOGY` | `SEDSNET_DISCOVERY` |
| `10` | `SEDSNET_DISCOVERY_SCHEMA` | `SEDSNET_DISCOVERY` |
| `11` | `SEDSNET_DISCOVERY_TOPOLOGY_REQUEST` | `SEDSNET_DISCOVERY` |
| `12` | `SEDSNET_DISCOVERY_SCHEMA_REQUEST` | `SEDSNET_DISCOVERY` |
| `13` | `SEDSNET_MANAGED_VARIABLE_REQUEST` | `SEDSNET_DISCOVERY` |
| `14` | `SEDSNET_MANAGED_VARIABLE_VALUE` | `SEDSNET_DISCOVERY` |
| `15` | `SEDSNET_DISCOVERY_LEAVE` | `SEDSNET_DISCOVERY` |
| `16` | `SEDSNET_DISCOVERY_LINK_CAPABILITIES` | `SEDSNET_DISCOVERY` |
| `17` | `SEDSNET_DISCOVERY_ADDRESS` | `SEDSNET_DISCOVERY` |
| `18` | `SEDSNET_P2P_MESSAGE` | `SEDSNET_DISCOVERY` |

Discovery, reliable-control, managed-variable request, and P2P packets are router-owned control
traffic. Applications should not register normal user handlers on the discovery endpoint.

## Common String Encoding

Discovery payload strings use this fixed format:

```text
[len: u32 LE]
[utf8 bytes: len]
```

Decoders reject truncated strings and invalid UTF-8.

## Discovery Announce

`SEDSNET_DISCOVERY_ANNOUNCE` advertises directly reachable non-discovery endpoints.

```text
[endpoint id 0: u32 LE]
[endpoint id 1: u32 LE]
...
```

The payload length must be a multiple of 4. Decoding sorts and deduplicates endpoint IDs and drops
the discovery endpoint.

## Discovery Time-Sync Sources

`SEDSNET_DISCOVERY_TIMESYNC_SOURCES` advertises source identifiers that can answer time-sync
requests through this router or relay.

```text
[source_count: u32 LE]
repeat source_count:
    [source_id: string]
```

Empty source IDs are ignored. Decoding sorts and deduplicates source IDs.

## Discovery Topology

`SEDSNET_DISCOVERY_TOPOLOGY` carries a normalized board graph.

```text
[board_count: u32 LE]
repeat board_count:
    [sender_id: string]
    [endpoint_count: u32 LE]
    repeat endpoint_count:
        [endpoint id: u32 LE]
    [timesync_source_count: u32 LE]
    repeat timesync_source_count:
        [source_id: string]
    [connection_count: u32 LE]
    repeat connection_count:
        [peer_sender_id: string]
```

Each board record describes one sender ID, the user endpoints reachable behind it, the time-sync
sources reachable behind it, and neighboring sender IDs in the router graph. Normalization removes
self-connections, sorts and deduplicates endpoints, sources, boards, and links, and drops discovery
endpoint IDs.

## Discovery Schema

`SEDSNET_DISCOVERY_SCHEMA` carries the runtime schema snapshot. Version 3 is emitted by current
builds; decoders still accept versions 1 and 2.

```text
[version: u32 LE]                 // current: 3
[endpoint_count: u32 LE]
repeat endpoint_count:
    [endpoint_id: u32 LE]
    [link_local_only: u8]          // 0 or 1
    [name: string]
    [description: string]          // version >= 2
[type_count: u32 LE]
repeat type_count:
    [type_id: u32 LE]
    [name: string]
    [description: string]          // version >= 2
    [element_kind: u8]             // 0 static, 1 dynamic
    [static_count: u32 LE]         // 0 for dynamic
    [message_data_type_code: u8]
    [message_class_code: u8]
    [reliable_code: u8]
    [priority: u8]
    [e2e_encryption_policy_code: u8] // version >= 3
    [endpoint_count: u32 LE]
    repeat endpoint_count:
        [endpoint_id: u32 LE]
```

Version compatibility:

| Version | Fields |
| --- | --- |
| `1` | IDs, names, element shape, reliability, priority, endpoint lists |
| `2` | Adds endpoint/type descriptions |
| `3` | Adds E2E encryption policy |

## Discovery Requests And Leave

These packets have empty payloads:

| Data type | Meaning |
| --- | --- |
| `SEDSNET_DISCOVERY_TOPOLOGY_REQUEST` | Ask eligible peers for a topology snapshot |
| `SEDSNET_DISCOVERY_SCHEMA_REQUEST` | Ask eligible peers for a schema snapshot |
| `SEDSNET_DISCOVERY_LEAVE` | Planned shutdown/removal announcement |

Routers answer discovery requests only when the current topology view says they should answer that
requester, which limits duplicate replies after the network has converged.

## Link Capabilities

`SEDSNET_DISCOVERY_LINK_CAPABILITIES` advertises the side transport profile seen on the announcing
side.

```text
[version: u8]
[capability_flags: u32 LE]
[profile_code: u8]
[max_frame_bytes: u32 LE]
[compact_header_target_bytes: u32 LE]
[max_side_transport_templates: u32 LE]
```

Capability flags:

| Bit | Mask | Meaning |
| --- | --- | --- |
| `0` | `0x00000001` | Header templates supported |
| `1` | `0x00000002` | Side-transport chunking supported |
| `2` | `0x00000004` | Hop reliability supported on the side |
| `3` | `0x00000008` | E2E cryptography support is present |
| `4` | `0x00000010` | End-to-end reliability support is present |
| `5` | `0x00000020` | Unchanged compact timestamp omission supported |

Profile codes:

| Code | Profile |
| --- | --- |
| `0` | canonical |
| `1` | template |
| `2` | IPv6-like |
| `3` | IPv4-like |

## Discovery Address

`SEDSNET_DISCOVERY_ADDRESS` is the unified node identity and address advertisement. It carries the
requested/current address, hostname, reachable endpoints, time-sync sources, and link capabilities
as one packet.

```text
[version: u8]                     // current: 1
[mode: u8]                        // 0 dynamic, 1 requested, 2 static
[state: u8]                       // 0 request, 1 approved
[address: u32 LE]                 // current assigned node address
[requested_address: u32 LE]       // requested/static address, or 0 for dynamic
[birth_ms: u64 LE]
[owner_hash: u64 LE]
[hostname: string]
[endpoint_count: u32 LE]
repeat endpoint_count:
    [endpoint_id: u32 LE]
[timesync_source_count: u32 LE]
repeat timesync_source_count:
    [source_id: string]
[link_version: u8]
[link_capability_flags: u32 LE]
[link_profile_code: u8]
[link_max_frame_bytes: u32 LE]
[link_compact_header_target_bytes: u32 LE]
[link_max_side_transport_templates: u32 LE]
```

Address modes:

| Code | Mode |
| --- | --- |
| `0` | Dynamic address assigned by the network |
| `1` | Requested address, shifted if it conflicts |
| `2` | Static address, preserved unless another static node has the same address |

Address states:

| Code | State |
| --- | --- |
| `0` | Request |
| `1` | Approved |

The address advertisement is also the hostname advertisement. Routers keep hostnames unique. If a
partition heals and duplicate addresses or hostnames are learned, deterministic deconfliction uses
the address mode, `birth_ms`, and `owner_hash`. Dynamic and requested nodes move before static
nodes. If two static nodes conflict, the oldest owner keeps the address and newer owners are shifted
and notified through address-change callbacks.

## P2P Message

`SEDSNET_P2P_MESSAGE` carries byte-stream style service traffic over SEDSnet. The destination node
is selected by the outer packet's target-sender wire contract, which is learned from discovery. The
destination address or hostname is not repeated inside the P2P payload.

```text
[version: u8]                     // current: 1
[destination_port: u16 LE]
[source_port: u16 LE]
[source_address: u32 LE]
[source_hostname_len: u16 LE]
[payload_len: u32 LE]
[source_hostname_utf8: source_hostname_len]
[payload: payload_len]
```

Routers dispatch the decoded payload to handlers registered with `bind_p2p_port(...)`. Senders can
target by discovered hostname or by current node address. Hostname targeting survives address
changes because the router resolves the current address book entry before sending.

## Managed Variable Control

`SEDSNET_MANAGED_VARIABLE_REQUEST` asks a peer for its cached latest value for one data type.

```text
[data_type_id: u32 LE]
```

`SEDSNET_MANAGED_VARIABLE_VALUE` is the built-in schema entry reserved for managed-variable control,
but the current response path replays the cached original value packet. User endpoint handlers see
the same packet shape as a normal update. Permission checks happen before a router responds to a
request or accepts a write.

## Reliable Control Payloads

The hop-reliable control data types use the same payload shape:

```text
[data_type_id: u32 LE]
[sequence: u32 LE]
```

| Data type | Meaning |
| --- | --- |
| `SEDSNET_RELIABLE_ACK` | Cumulative ACK for a side/type sequence |
| `SEDSNET_RELIABLE_PARTIAL_ACK` | Receiver has buffered a later sequence but is missing an earlier one |
| `SEDSNET_RELIABLE_PACKET_REQUEST` | Receiver asks the sender to replay a specific sequence |

End-to-end reliable delivery also uses `SEDSNET_RELIABLE_ACK`, but the payload is:

```text
[packet_id: u64 LE]
```

End-to-end ACK packets are generated by routers after local delivery and are routed back over the
learned return path for that packet ID.

## Time-Sync Payloads

Time-sync packets are built-in control traffic on `SEDSNET_TIME_SYNC`. The packet types are:

| Data type | Role |
| --- | --- |
| `SEDSNET_TIME_SYNC_ANNOUNCE` | Advertise an available clock source |
| `SEDSNET_TIME_SYNC_REQUEST` | Request a sample exchange with a source |
| `SEDSNET_TIME_SYNC_RESPONSE` | Return the timing sample used for offset estimation |

See [Time-Sync](Time-Sync) for the timing model, convergence behavior, and slow-link throttling.

## Queue And Memory Accounting

Discovery and internal router state share the dynamic `MAX_QUEUE_BUDGET` with RX/TX queues,
recent-ID caches, reliable replay/out-of-order buffers, and topology state. See
[Technical-Queues-and-Memory](Technical-Queues-and-Memory) for the budget model and eviction
behavior.
