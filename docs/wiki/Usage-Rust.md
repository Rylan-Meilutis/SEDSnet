# Rust Usage

This is the primary API and the source of truth for the Rust-facing behavior.

## Add as a dependency

```toml
sedsnet = { path = "path/to/sedsnet" }
```

Or from git:

```toml
sedsnet = { git = "https://github.com/Rylan-Meilutis/sedsnet.git", branch = "main" }
```

## Minimal router example

```rust
use sedsnet::config::{
    register_data_type_id_with_description, register_endpoint_id_with_description,
};
use sedsnet::router::{EndpointHandler, Router, RouterConfig};
use sedsnet::{
    DataEndpoint, DataType, MessageClass, MessageDataType, MessageElement, ReliableMode,
    TelemetryResult,
};

fn main() -> TelemetryResult<()> {
    let sd_card = register_endpoint_id_with_description(
        DataEndpoint(100),
        "SD_CARD",
        "Local storage endpoint",
        false,
    )?;
    let radio = register_endpoint_id_with_description(
        DataEndpoint(101),
        "RADIO",
        "External radio link",
        false,
    )?;
    register_data_type_id_with_description(
        DataType(100),
        "GPS_DATA",
        "Three f32 GPS values",
        MessageElement::Static(3, MessageDataType::Float32, MessageClass::Data),
        &[sd_card, radio],
        ReliableMode::None,
        80,
    )?;

    let handler = EndpointHandler::new_packet_handler(DataEndpoint::named("SD_CARD"), |pkt| {
        println!("rx: {pkt}");
        Ok(())
    });

    let router = Router::new(RouterConfig::new([handler]));

    router.add_side_serialized("RADIO", |bytes| {
        let _ = bytes;
        Ok(())
    });

    router.log(DataType::named("GPS_DATA"), &[1.0_f32, 2.0, 3.0])?;
    router.process_all_queues()?;
    Ok(())
}
```

On `std` builds, `Router::new(...)` uses an internal monotonic clock. For tests, simulation, or
`no_std`, use `Router::new_with_clock(...)`.

## Runtime schema

User endpoints and data types are registered at runtime. There are no generated Rust variants for
application schema entries in v4.0.0.

Common options:

- call `register_endpoint(...)` / `register_data_type(...)` when the process starts
- call the `_id` variants when you need stable numeric IDs on the wire
- load a JSON seed with `register_schema_json_file(...)`, `register_schema_json_path(...)`, or
  `register_schema_json_bytes(...)`
- use `DataEndpoint::named("GROUNDSTATION")` and `DataType::named("GPS_DATA")` after registration
- use `try_named(...)` or `endpoint_definition_by_name(...)` / `data_type_definition_by_name(...)`
  when missing schema should be handled as a normal error path

Registering an endpoint handler for a missing endpoint auto-creates that endpoint in `std` builds
and broadcasts the new schema through discovery. Registering a data type or endpoint with the same
name/ID and a different shape returns an error.

## Network Variables and E2E Payloads

Network variables are latest-value caches for user data types. A router that enables a network
variable remembers the newest local or received packet for that type. User code uses a setter and
getter rather than registering a special endpoint: the setter commits the value to the network when
permissions allow, and the getter returns the cached value while internally requesting a refresh if
the value has never been seen or is stale. Caches are tiered: any router that has enabled or seen the
variable can answer the refresh from its local cache, so reconnecting boards can resync from a nearby
node instead of always reaching the original producer/master.

Data types can also advertise an E2E cryptography preference:

```rust
use sedsnet::config::register_data_type_id_with_description_and_e2e_encryption;
use sedsnet::router::{
    NetworkVariablePermissions, Router, RouterConfig, RouterE2eEncryptionMode,
};
use sedsnet::{
    DataEndpoint, DataType, E2eEncryptionPolicy, MessageClass, MessageDataType, MessageElement,
    ReliableMode,
};

let flight_state = register_data_type_id_with_description_and_e2e_encryption(
    DataType(3100),
    "FLIGHT_STATE",
    "network-managed flight state",
    MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
    &[DataEndpoint::named("RADIO")],
    ReliableMode::None,
    90,
    E2eEncryptionPolicy::RequireOn,
)?;

let router = Router::new(
    RouterConfig::default()
        .with_e2e_encryption(RouterE2eEncryptionMode::RequiredOnly)
        .with_e2e_key_id(7),
);
router.enable_network_variable(flight_state, NetworkVariablePermissions::READ_WRITE)?;
router.on_network_variable_update(flight_state, |pkt| {
    let state = pkt.data_as_u8()?;
    Ok(())
})?;
router.set_network_variable(pkt)?;
let cached = router.get_network_variable(flight_state, Some(1_000))?;
```

When a refresh request finds a peer with the value, the original value packet is replayed through
normal endpoint handlers. If the local router lacks read or write permission, the getter/setter
returns `TelemetryError::PermissionDenied` and peers answer refresh requests with a permission
error packet. `on_network_variable_update(...)` runs only for inbound updates and refresh replies
that change the local cache; local setters/seeds update the cache without firing that callback.

Router modes are:

- `Disabled`: never encrypt; reject data types marked `RequireOn`
- `RequiredOnly`: encrypt only required data types
- `Preferred`: encrypt required and preferred data types
- `ForceAll`: encrypt every non-control user data type

`RouterConfig::default()` and `RouterConfig::new(...)` use `Preferred` automatically with the
default `cryptography` feature; minimal builds that explicitly omit `cryptography` default to
`Disabled`.

The `cryptography` feature uses this provider order:

- registered C provider, for C firmware, OS crypto, secure elements, or hardware accelerators
- registered Rust provider, for Rust-only firmware or std applications wrapping OS crypto
- built-in software fallback, only after the application registers a key for the packet `key_id`

Serialized side traffic carries visible routing metadata and an encrypted payload; the visible
header is authenticated as AAD so header tampering fails during open. The built-in fallback uses the
provisioned key for authenticated cryptography, but it does not create identity by itself.

```rust
#[cfg(feature = "cryptography")]
sedsnet::crypto::register_software_key(
    7,
    b"32-byte minimum deployment secret....",
)?;
```

For MITM resistance, boards must authenticate the key source. Common deployments use either
factory-provisioned PSKs or a network master that acts as the root authority. In the master-root
model, boards ship with the master public key or a join PSK, the master signs short-lived board
credentials, and peer/session keys are accepted only when the key exchange transcript validates back
to that root. Without that authenticated root, an active attacker can substitute keys before the
AEAD layer ever sees a packet.

The `cryptography` feature includes a compact 80-byte managed credential helper for this
master-root model. The master issues a `ManagedCredential` containing subject id, key id, epoch,
validity window, and permission bits; peers verify it against the provisioned root key before
accepting issued session/group keys.

For board-to-board deployments, run your board-owned quantum-resistant asynchronous key exchange
when discovery learns a peer, derive a low-cost symmetric traffic key, and pass that key through the
provider by `key_id`. Multi-drop endpoint traffic can use a shared group traffic key when every holder of
that endpoint must decode the same message; AEAD authentication still prevents a receiver from
modifying the frame for downstream boards without detection.

Fragmented links should encrypt the original message before splitting it. Fragments then carry a
message id, fragment index/count, source epoch, and route metadata; the receiver reassembles and
opens the original authenticated payload. On reconnect, routers should discard incomplete fragments
from older master epochs, refresh time/topology, and use network-variable getters to refresh any
state that is missing or stale. If the master epoch changed, resync from the current snapshot.

Discovery-enabled routers do not flood unknown user-data routes by fallback. They forward user data
only when discovery or explicit route policy identifies a path; discovery/control traffic still
propagates so the network can recover after partitions. For time-sliced radios, have the TX callback
return `TelemetryError::Io("side tx busy")` while the radio is in an RX window. Queued work will be
retried later, and measured bring-up/slot throughput can be fed into
`note_side_link_probe_sample(side, bytes, duration_ms)` to seed adaptive path selection and
control-plane throttling. Once a side is measured as slow, discovery sends minimal reachability
pings between infrequent full schema/topology/time-source refreshes, and router-managed time sync
throttles only that measured slow side while fast sides keep the configured normal cadence.

## Sides and routing

Routers and relays use named sides such as `UART`, `CAN`, or `RADIO`.

- `add_side_serialized(...)` and `add_side_packet(...)` register egress handlers
- `remove_side(...)` tombstones a side without renumbering the remaining side ids
- `set_side_ingress_enabled(...)` and `set_side_egress_enabled(...)` control directional policy
- `set_route(...)` and `set_typed_route(...)` define runtime forwarding rules

There is no `RouterMode` anymore.

- `Router` now defaults to rule-driven full-mesh forwarding between eligible sides
- `Relay` keeps the same full-mesh default
- if you want sink-like behavior, disable the specific routes you do not want rather than choosing a
  separate constructor mode

Example:

```rust
use sedsnet::router::Router;

let router = Router::new(RouterConfig::default());
let side_a = router.add_side_serialized("A", tx_a);
let side_b = router.add_side_serialized("B", tx_b);
let side_c = router.add_side_serialized("C", tx_c);

router.set_route(None, side_b, false)?;        // local TX does not go to B
router.set_route(Some(side_a), side_b, true)?; // allow A -> B
router.set_route(Some(side_b), side_a, false)?;// block B -> A
router.set_typed_route(None, DataType::named("GPS_DATA"), side_c, true)?;
router.set_side_egress_enabled(side_c, false)?; // ingress only
```

## Discovery and multi-path routing

With the `discovery` feature enabled, routers and relays learn which endpoints are reachable
through which sides.

- known paths are used directly
- unknown user-data paths are not flooded by fallback; discovery/control traffic still bootstraps
  route learning
- measured slow links receive minimal discovery pings most of the time, with full refreshes spaced
  out to preserve bandwidth
- link-local-only endpoints stay on sides marked `link_local_enabled`
- local plus source-side route rules still gate what discovery is allowed to use
- discovery also carries a transitive router graph, so exported topology keeps sender ownership and
  router-to-router connections instead of only flattening reachability per side

When discovery reports multiple candidate paths:

- normal traffic defaults to adaptive load balancing based on observed transmit bandwidth
- reliable traffic still fans out across all discovered candidates so one weak path does not hide a
  successful delivery on another path
- `set_source_route_mode(...)`, `set_route_weight(...)`, and `set_route_priority(...)` can still
  override the defaults

Packets already in flight also carry a compact internal wire contract: a frozen destination holder set
and enough payload-shape metadata to stay decodable while schema and topology updates are still propagating.
Applications do not build that contract manually; routers and relays attach and honor it automatically.

## Reliable delivery

Reliable delivery has two switches:

- the schema type itself must be marked reliable
- the router/relay side must opt in with `reliable_enabled: true`

That side option is per hop, not global. It controls what happens between the router/relay and
that side's TX callback.

```rust
use sedsnet::router::{Router, RouterConfig, RouterSideOptions};

let router = Router::new(RouterConfig::default());
router.add_side_serialized_with_options(
    "RADIO",
    tx,
    RouterSideOptions {
        reliable_enabled: true,
        link_local_enabled: false,
        ..RouterSideOptions::default()
    },
);
```

If the underlying transport is already reliable, disable the router-level reliable layer with
`RouterConfig::with_reliable_enabled(false)`.

What `reliable_enabled` means on a side:

- `reliable_enabled: true` on a serialized side wraps reliable schema traffic in the router/relay's
  hop-level reliable framing for that side only
- that hop-level framing adds sequence numbers, ACKs, packet requests, and retransmits
- `reliable_enabled: false` sends the application packet once on that side without the router's
  hop-level reliable wrapper
- packet-output sides (`add_side_packet*`) receive decoded `Packet` values, so they cannot carry
  the serialized hop-level reliable wrapper even if `reliable_enabled` is set

For routers specifically:

- hop-level side reliability is separate from the source router's end-to-end reliable tracking
- a reliable packet can still be tracked end-to-end across the network even if one specific egress
  side is configured without hop-level reliability
- when discovery reports multiple candidate holders, reliable traffic still fans out across all of
  them unless you explicitly restrict routes

As of `3.11.0`, reliability has two layers:

- per-link reliable sequencing, ACKs, packet requests, and retransmits
- end-to-end verification from the source router to every currently discovered destination holder

The end-to-end path works like this:

- the source router tracks reliable packets it originated
- when a destination router delivers a reliable packet to a local handler, it emits an end-to-end
  acknowledgement tagged with its identity
- routers and relays learn the return path from the reliable packet’s ingress side and route that
  acknowledgement only where it needs to go
- the source keeps the packet in flight until all currently discovered holders have acknowledged
- if one end-to-end acknowledgement is lost, the source retransmits only toward the holders that
  are still outstanding until they respond or the retry limit is reached
- if discovery later expires one holder, the source removes that holder from the pending set and
  finishes once the remaining discovered holders are satisfied

That means reliable delivery is now verified at the application-destination boundary, not just per
hop, while still keeping reliable send non-blocking for newer packets on the same side/type lane.

For ordered reliable links, a receiver that gets packets after a gap buffers those later packets,
emits partial ACKs for them, and requests the missing sequence. Partial ACKs stop timeout-based
retransmits for packets the receiver already has, but explicit packet requests can still replay
them. When the missing sequence arrives, the buffered packets are dispatched immediately in order.

## Receiving packets

Common receive APIs:

- `rx_serialized(bytes)`
- `rx_serialized_queue(bytes)`
- `rx(packet)`
- `rx_queue(packet)`

Meaning of the variants:

- `rx_*` processes immediately in the current call
- `rx_*_queue` only enqueues work for a later `process_*` / `periodic` call
- `*_from_side(..., side_id)` tags the ingress with an explicit side id for route/discovery logic
- the non-`from_side` variants treat the input as locally-originated rather than arriving from a
  registered side

If an immediate router receive/transmit API is called from inside a side TX callback, the router
now defers that work onto its queue instead of recursively re-entering forwarding on the same
stack. Internal `SEDSNET_DISCOVERY` and `SEDSNET_TIME_SYNC` traffic stays router-owned;
applications should use the public discovery/time-sync APIs instead of constructing those packets
directly.

Use side-aware ingress only when you need to override the ingress side explicitly:

- `rx_serialized_from_side(bytes, side_id)`
- `rx_from_side(packet, side_id)`

## Queue processing

The common maintenance calls are:

- `process_rx_queue()`
- `process_tx_queue()`
- `process_all_queues()`
- `periodic(timeout_ms)`
- `periodic_no_timesync(timeout_ms)` when `timesync` is enabled but you want to skip it for one
  loop

What each one does:

- `process_rx_queue()` drains queued receives only
- `process_tx_queue()` drains queued transmits only
- `process_all_queues()` drains both queues without a time budget
- `process_*_with_timeout(timeout_ms)` runs the same phase with a millisecond budget; `0` means
  drain fully
- `periodic(timeout_ms)` is the normal main-loop entry point because it also polls built-in
  discovery and, when enabled, time sync before draining queues

For relays, nested `process_tx_queue*` / `process_all_queues*` calls made from inside a side TX
callback are intentionally turned into no-ops so a side callback cannot recursively drive relay TX
on the same stack.

Router and relay queue-backed state shares the compile-time `MAX_QUEUE_BUDGET` dynamically.
That includes RX work, TX work, recent packet IDs, reliable buffers/replay state, and discovery
topology. Recent packet ID caches preallocate their final storage and reserve that byte cost
immediately. If the remaining budget is exhausted, older queued state is evicted; discovery
topology eviction emits a warning in `std` builds.

Use `router.export_memory_layout_json()` or `relay.export_memory_layout_json()` when profiling a
running node. The JSON reports shared allocated/used bytes plus per-area used/allocated bytes for
RX, ISR RX, TX, replay queues, reliable buffers, discovery, schema, and the network-variable cache.

Use `router.export_runtime_stats()` / `relay.export_runtime_stats()` or the matching C/Python
exports when profiling constrained links. Each side reports whether header-template compaction is
enabled, its effective side-transport profile, fixed-frame size, the compact-header target,
full/compact/chunk side-transport frame counts, emitted bytes, bytes saved versus canonical frames,
timestamp-delta and unchanged-timestamp compact frame counts, and the observed compact follow-up
overhead. Small-packet transport defaults to a 40-byte IPv6-like overhead target; call
`with_ipv4_like_compact_header_target()` on the side options when a stable tiny telemetry stream
should be held to a 20-byte IPv4-like target with unchanged compact timestamps omitted. Python
exposes the same profile selection with `add_side_serialized_profile(..., profile="ipv4_like")`; C
callers use `seds_router_add_side_serialized_profile(...)` or
`seds_relay_add_side_serialized_profile(...)` with `SEDS_SIDE_TRANSPORT_PROFILE_IPV4_LIKE`.

For mixed links, keep absolute/delta timestamps for most traffic and omit unchanged timestamps only
for selected data types:

```rust
let opts = RouterSideOptions::default()
    .with_ipv6_like_compact_header_target()
    .with_omitted_unchanged_compact_timestamps_for_type(DataType::named("GPS_DATA"));
```

## Topology export

With discovery enabled, `export_topology()` returns the router's current learned view.

- `topology.routers` contains the top-level discovered router graph
- each router entry includes the sender ID, owned endpoints, owned time-sync source IDs, and
  connected router sender IDs
- `topology.links` is a deduplicated board-to-board edge list (`source`, `target`) for direct graph
  rendering
- exported JSON/Python dictionaries use `reachable_endpoints` and `advertised_endpoints` for
  schema-advertised names, with `reachable_endpoint_ids` and `advertised_endpoint_ids` available
  when code needs stable numeric validation
- SEDSnet-owned control endpoints (`SEDSNET_TIME_SYNC`, `SEDSNET_DISCOVERY`, `SEDSNET_ERROR`) are
  filtered out of user endpoint reachability fields
- each side route also includes `announcers`, so you can see which upstream router advertised the
  exported topology

Use `router.client_stats("BOARD_ID")` or `relay.client_stats("BOARD_ID")` to inspect one
discovered client. The snapshot includes connected/disconnected state, side IDs and side names,
last-seen/age timing, named reachable endpoints, reachable time-sync sources, and packet/byte
counters aggregated from the side(s) currently reaching that client.

Use `router.announce_leave()` or `relay.announce_leave()` before a planned shutdown or disconnect.
That queues a `SEDSNET_DISCOVERY_LEAVE` control packet so peers can prune topology immediately
instead of waiting for the discovery TTL. The C ABI also attempts this on router/relay free, but an
explicit leave is preferred when shutdown order matters.

## Reserved internal endpoints

Do not register user handlers for:

- `DataEndpoint::Discovery`
- `DataEndpoint::TimeSync` when the `timesync` feature is enabled

Those endpoints are owned by the router’s built-in control traffic.

## Time sync

When the `timesync` feature is enabled, the router maintains an internal network clock and handles
`SEDSNET_TIME_SYNC` traffic internally.

For ordinary loops, prefer `periodic(timeout_ms)` so time sync, discovery, and queue draining run
together.

See [Time-Sync](Time-Sync) for the protocol details.
