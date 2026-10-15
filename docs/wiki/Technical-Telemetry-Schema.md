# Telemetry Schema

As of v4.0.0, user telemetry schema is runtime state. `DataEndpoint` and
`DataType` are stable numeric IDs on the wire, but the library no longer
generates application-specific Rust enum variants or binding constants at
compile time.

The default registry contains only built-in internal entries:

- telemetry error endpoint/type
- reliable-control packet types
- discovery endpoint/types
- time-sync endpoint/types when the `timesync` feature is enabled

Applications add user endpoints and data types at runtime through APIs, JSON
seeding, or discovery schema sync.

## Runtime IDs and Names

`DataEndpoint(pub u32)` and `DataType(pub u32)` are transparent runtime IDs.
Use names for readability and only use raw IDs where you are assigning a wire
ID intentionally.

```rust
let radio = DataEndpoint::named("RADIO");
let gps = DataType::named("GPS_DATA");

let maybe_radio = DataEndpoint::try_named("RADIO");
let maybe_gps = DataType::try_named("GPS_DATA");
```

Definitions carry:

- numeric ID
- string name
- human-readable description
- endpoint link-local flag
- data type shape, allowed endpoints, reliability mode, queue priority, and E2E cryptography policy

Lookup/export APIs include:

- `endpoint_definition(...)`
- `endpoint_definition_by_name(...)`
- `data_type_definition(...)`
- `data_type_definition_by_name(...)`
- `known_endpoints()`
- `known_data_types()`
- `export_schema()`

## Registering Schema

Rust:

```rust
let radio = register_endpoint_id_with_description(
    DataEndpoint(100),
    "RADIO",
    "Downlink radio",
    false,
)?;

register_data_type_id_with_description(
    DataType(100),
    "GPS_DATA",
    "Latitude, longitude, altitude",
    MessageElement::Static(3, MessageDataType::Float32, MessageClass::Data),
    &[radio],
    ReliableMode::Ordered,
    80,
)?;
```

Use `register_data_type_id_with_description_and_e2e_encryption(...)` when a type should prefer or
require E2E encrypted payloads.

Direct registration rejects conflicts:

- same endpoint ID/name with different endpoint metadata
- same data type ID/name with a different shape, endpoint set, reliability mode, priority, or E2E
  policy
- data types referencing endpoints that do not exist

Endpoint handler registration also creates missing endpoints in `std` builds:

```rust
EndpointHandler::new_packet_handler(DataEndpoint(250), |_pkt| Ok(()));
```

If that endpoint ID did not exist, it is registered as `ENDPOINT_250` and can be
advertised through schema discovery.

## Removing Schema

User endpoints and data types can be removed at runtime:

- `remove_endpoint(...)`
- `remove_endpoint_by_name(...)`
- `remove_data_type(...)`
- `remove_data_type_by_name(...)`

Removing an endpoint also removes user data types that reference it. Built-in
internal entries cannot be removed.

## JSON Runtime Seeding

JSON is optional runtime input. It is not used to generate user schema constants.

Host/std builds can seed from:

- `SEDSNET_STATIC_SCHEMA_PATH`
- `SEDSNET_STATIC_IPC_SCHEMA_PATH`
- Rust `register_schema_json_path(...)` / `register_schema_json_bytes(...)`
- C `seds_schema_register_json_file(...)` / `seds_schema_register_json_bytes(...)`
- Python `register_schema_json_file(...)` / `register_schema_json_bytes(...)`

Host file registration decodes entries incrementally through a fixed-size 512-byte read buffer; it
does not keep a second full copy of the document in memory. Set `SCHEMA_JSON_CHUNK_BYTES` at build
time to use a smaller or larger buffer. Input size and retained schema memory are bounded, and a
parse, validation, or budget failure atomically removes everything added by that load. Rust callers
can select a tighter per-load retained-memory limit with
`register_schema_json_file_with_budget(...)` or
`register_schema_json_bytes_with_budget(...)`.

For `no_std` embedded builds, an application-provided `telemetry_config.json` is converted at build
time into static endpoint and data-type definitions. Those definitions stay in flash and require no
runtime JSON parser, file-read buffer, or intentionally leaked metadata. Embedded discovery omits
documentation-only descriptions to reduce its memory footprint. The crate remains
buildable/publishable without an application JSON file.

JSON shape:

```json
{
  "endpoints": [
    {
      "rust": "Radio",
      "name": "RADIO",
      "description": "Downlink radio"
    }
  ],
  "types": [
    {
      "rust": "GpsData",
      "name": "GPS_DATA",
      "description": "GPS data",
      "reliable": "Ordered",
      "priority": 80,
      "class": "Data",
      "element": { "kind": "Static", "data_type": "Float32", "count": 3 },
      "endpoints": ["Radio"]
    }
  ]
}
```

Notes:

- `description` is preferred.
- Legacy `doc` is still accepted as an alias.
- Legacy `broadcast_mode = "Never"` is accepted and maps to link-local behavior.
- IPC JSON loaded through the IPC seed path is applied as link-local overlay data.

## Network Schema Sync

A schema file is an optional seed. Hosted and embedded nodes can register
endpoints and data types at runtime, announce their definitions, and learn
complementary catalogs through routers or relays. A gateway does not need a
compiled copy of a new application's schema to forward it.

Automatic identities derive from canonical wire names, independently of file
order, local catalog subsets, or registration order. Rust callers can use
`DataEndpoint::identity(name)` and `DataType::identity(name)` before the referenced
definition arrives. C callers use `seds_endpoint_identity` and
`seds_dtype_identity`, then the registration APIs. Explicit numeric registrations
must use consistent identities across nodes. Name/hash collisions are detected
rather than treated as two equivalent definitions.

Compatible definitions contribute the union of destinations and the higher
priority. Link-local restrictions are preserved. Incompatible definitions use
the same deterministic conflict rule in hosted and embedded contexts; optional
descriptions do not decide functional conflicts. A new incompatible application
message layout should use a distinct versioned wire name. References to remote
endpoints may arrive before their endpoint definitions. External JSON references
use canonical wire names; Rust aliases apply within their defining document.

Application frames retain explicit destination lists, so a partial sender's
one-destination packet is not reinterpreted as a receiver's larger merged list.
Sparse lists use variable-length numeric IDs rather than a fixed 32-byte bitmap;
dense legacy-range sets can still use the bitmap representation. Reliable-header
presence is carried in the frame. Receipt identity uses numeric wire identities
and remains stable when missing names/definitions are subsequently learned.

Embedded nodes retain generated definitions in flash and learned/updated
immutable overlays in RAM. Only retained RAM consumes the shared schema budget.
The entire proposed merge is budget checked before publication; queue pressure
must not remove existing schema definitions. Superseded immutable records remain
charged to that budget until reboot so borrowed readers remain safe. Repeated
identical or already-covered schema fragments do not grow retained memory.

The identity and header changes require an initial coordinated rebuild of network
participants. Subsequent compatible schema additions and destination changes are
learned at runtime without reflashing existing gateways. The mixed-system linked
qualification and long soak remain required before release.

## Memory Budgeting

Runtime schema memory counts against the shared router/relay `MAX_QUEUE_BUDGET`.
That same budget also covers RX/TX queues, reliable replay/out-of-order state,
recent packet ID caches, and discovery topology.

If a received schema snapshot would exceed the budget, the merge is rejected and
the current registry is left unchanged.

Runtime-owned endpoint/type names, descriptions, endpoint lists, and C/Python side names are freed
when their owning definitions or router/relay instances are removed or replaced. Failed JSON loads
also roll back their allocations rather than leaving partially registered schema behind.

## Payload Layouts

Schema shape still controls packet validation:

- **Static + numeric/bool**: payload size must equal `count * element_width`.
- **Dynamic + numeric/bool**: payload size must be a multiple of element width.
- **String**: dynamic UTF-8 bytes; trailing NULs are ignored for validation.
- **Binary**: raw bytes.
- **NoData**: zero-length payload.

For static `String` or `Binary` payloads, the configured limits are:

- runtime `static_string_length`, defaulting to the packaged `STATIC_STRING_LENGTH`
- runtime `static_hex_length`, defaulting to the packaged `STATIC_HEX_LENGTH`

## Compatibility Checklist

For v4 deployments:

- Prefer named runtime lookup in application code: `DataEndpoint::named(...)` and
  `DataType::named(...)`.
- Seed required endpoints/types at router startup if they must always exist.
- Let discovery sync optional or peer-defined schema over time.
- Treat data type shape changes as incompatible unless you intentionally create
  a new type ID/name.
- Budget for schema memory if you expect many dynamic endpoints/types.

### Reliability declaration

Every type declares one required field: `"reliable": "Off"`, `"Ordered"`, or
`"Unordered"`. `Off` sends best-effort samples; `Ordered` acknowledges delivery
and preserves sequence; `Unordered` acknowledges delivery without ordering.
Boolean `reliable` values and `reliable_mode` declarations are no longer accepted.
Update application, board, and host schema files together. Runtime metadata
stores one enum; the binary discovery schema and packet wire format are unchanged.
