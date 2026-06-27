# Python Usage

Python bindings are built with `pyo3` and `maturin`. The module name is `sedsnet`.

## Build and install

Recommended in this repo:

```bash
./build.py python
```

Direct `maturin` is also supported:

```bash
maturin develop
```

## Minimal example

```python
import sedsnet as seds


def tx(bytes_buf):
    pass


def on_packet(pkt):
    print(pkt)


schema = b"""
{
  "endpoints": [
    {"rust": "SdCard", "name": "SD_CARD", "description": "Local storage endpoint"},
    {"rust": "Radio", "name": "RADIO", "description": "External radio link"}
  ],
  "types": [
    {
      "rust": "GpsData",
      "name": "GPS_DATA",
      "description": "Three f32 GPS values",
      "priority": 80,
      "class": "Data",
      "element": {"kind": "Static", "data_type": "Float32", "count": 3},
      "endpoints": ["Radio", "SdCard"]
    }
  ]
}
"""
seds.register_schema_json_bytes(schema)
sd_card = seds.endpoint_info_by_name("SD_CARD")["id"]
gps_data = seds.data_type_info_by_name("GPS_DATA")["id"]

router = seds.Router(
    handlers=[(sd_card, on_packet, None)],
)

router.add_side_packed("RADIO", tx, reliable_enabled=True)
router.log_f32(gps_data, [1.0, 2.0, 3.0])
router.process_all_queues()
```

If you need a custom monotonic source for tests or simulation, pass `now_ms=...`.

## Runtime schema

Python exposes the same runtime registry as Rust and C:

- `register_endpoint(...)` and `register_data_type(...)` add explicit entries
- `register_schema_json_file(...)` and `register_schema_json_bytes(...)` seed entries from JSON
- `endpoint_info_by_name(...)` and `data_type_info_by_name(...)` return IDs and metadata
- `remove_endpoint_by_name(...)` and `remove_data_type_by_name(...)` remove user entries

The `DataType` and `DataEndpoint` enums only contain built-in control IDs. Application schema IDs
should be looked up by string name after registration or JSON seeding.

## Network Variables and E2E Policy

Network variables cache the latest value packet for a data type. User code uses a setter and getter;
the getter returns the cached value and internally requests a refresh when the value has never been
seen or is stale. No separate endpoint registration is needed for the network-variable machinery.
Caches are tiered: any router that has enabled or seen the variable can answer the refresh from its
local cache, so reconnecting boards can resync from a nearby node instead of always reaching the
original producer/master.

```python
import sedsnet as seds

RADIO = 101
FLIGHT_STATE = 3100

seds.register_endpoint(RADIO, "RADIO")
seds.register_data_type(
    FLIGHT_STATE,
    "FLIGHT_STATE",
    True,
    1,
    0,  # UInt8
    0,  # Data
    [RADIO],
    priority=90,
    e2e_encryption=2,  # RequireOn
)

router = seds.Router(e2e_mode=1, e2e_key_id=7)  # RequiredOnly
router.enable_network_variable(FLIGHT_STATE, True, True)
router.on_network_variable_update(FLIGHT_STATE, on_flight_state_update)
router.set_network_variable(packet)
cached = router.get_network_variable(FLIGHT_STATE, 1000)
router.process_all_queues()
```

If the router lacks read or write permission, getters/setters raise the normal SEDSnet Python
exception for `PermissionDenied`. Peers answer denied refreshes with a telemetry error packet. The
update callback runs only for inbound updates and refresh replies that change the local cache; local
setters/seeds update the cache without firing that callback.

E2E policy values are `0=PreferOff`, `1=PreferOn`, and `2=RequireOn`. Router E2E modes are
`0=Disabled`, `1=RequiredOnly`, `2=Preferred`, and `3=ForceAll`. The constructor default
`e2e_mode=255` means "build default": `Preferred` for normal Python builds because `cryptography`
is part of the `python` feature. Custom extensions built without cryptography default to `Disabled`
and reject `RequireOn` traffic instead of silently downgrading it.

Key exchange is board/application owned. Run your quantum-resistant asynchronous exchange when
discovery learns a peer, derive symmetric traffic keys, and have the cryptography provider select those keys by
`e2e_key_id`. For three boards advertising the same endpoint, use an endpoint/group traffic key so
all intended boards can open the same message; authenticated payloads reject header or ciphertext
changes before handlers see data.

## Routing model

There is no Python `RouterMode` anymore.

- `Router` now uses the same rule-driven forwarding model as the Rust API
- routers and relays both default to a full forwarding mesh across eligible sides
- runtime route rules are how you restrict forwarding

Useful controls:

- `set_side_ingress_enabled(...)`
- `set_side_egress_enabled(...)`
- `set_route(...)`
- `clear_route(...)`
- `set_typed_route(...)`
- `clear_typed_route(...)`
- `set_source_route_mode(...)`
- `set_route_weight(...)`
- `set_route_priority(...)`

Use `None` for `src_side_id` when controlling locally-originated traffic.

## Discovery and reliability

With `discovery` enabled:

- routers and relays learn endpoint reachability per side
- discovery also propagates a transitive router graph, not just flattened endpoint sets
- normal traffic defaults to adaptive discovered-path load balancing
- reliable traffic still fans out across all known discovered candidates

`export_topology()` is available on both `Router` and `Relay`.

- it returns a Python `dict`
- the top-level `routers` key lists each discovered router, the endpoint names/source IDs it owns,
  and its connected router sender IDs
- the top-level `links` key lists deduplicated board-to-board graph edges as `{source, target}`
- graph-facing endpoint fields such as `reachable_endpoints` and `advertised_endpoints` contain
  schema-advertised names; companion fields such as `reachable_endpoint_ids` and
  `advertised_endpoint_ids` preserve the numeric IDs
- SEDSnet-owned control endpoints (`SEDSNET_TIME_SYNC`, `SEDSNET_DISCOVERY`, `SEDSNET_ERROR`) are
  not included in user endpoint reachability fields
- each route entry also includes `announcers` so you can see which upstream router advertised each
  piece of topology

`Router.client_stats("BOARD_ID")` and `Relay.client_stats("BOARD_ID")` return a dictionary for one
discovered client or `None` if that sender is unknown. The dictionary includes connected state,
side IDs/names, last-seen/age timing, named reachable endpoints, reachable time-sync sources, and
packet/byte counters aggregated from the side(s) currently reaching that client.

Call `announce_leave()` before a planned shutdown or disconnect so peers receive
`SEDSNET_DISCOVERY_LEAVE` and remove that sender from topology immediately instead of waiting for
the discovery TTL.

Reliable delivery is enabled on a per-side basis with `reliable_enabled=True` for packed
sides. Packets already in flight also carry a compact internal wire contract so topology or
runtime-schema changes do not redirect them to the wrong holder or make them undecodable mid-flight.
Applications do not construct that contract directly; routers and relays manage it internally.

As of `3.11.0`, reliable delivery is end-to-end verified:

- the source router tracks reliable packets it originated
- each discovered destination holder emits an end-to-end acknowledgement after local delivery
- routers and relays route that acknowledgement back only along the learned return path
- unrelated sides do not receive those end-to-end acknowledgements
- the source keeps retransmitting only toward holders that are still missing an acknowledgement
- if a discovered holder ages out of topology, the source removes it from the pending holder set
- newer reliable packets on the same side still do not block while those end-to-end ACKs are pending

For ordered reliable links, later packets that arrive after a missing sequence are buffered and
partial-ACKed. Partial ACKs suppress timeout retransmit for packets already received, but explicit
packet requests can still replay them. The buffered packets are dispatched as soon as the missing
sequence arrives.

## Queue processing

Useful maintenance calls:

- `process_rx_queue()`
- `process_tx_queue()`
- `process_all_queues()`
- `periodic(timeout_ms)`
- `periodic_no_timesync(timeout_ms)` when time sync is enabled but should be skipped for one loop

Router and relay queue-backed state shares one dynamic `MAX_QUEUE_BUDGET`. RX work, TX work,
recent packet IDs, reliable buffers/replay state, discovery topology, and runtime schema registry
memory all count against it.
Recent packet ID caches preallocate their final storage and reserve that byte cost immediately.
Discovery topology eviction emits a warning in `std` builds.

Use `export_memory_layout_json()` on a router or relay to profile queue pressure. The JSON includes
shared allocated/used bytes plus per-area queue, reliable-buffer, schema, discovery, and
network-variable-cache breakdowns.

Use `add_side_packed_profile(...)` to select a compact side-wire profile from Python:

```python
router.add_side_packed_profile(
    "RADIO",
    tx,
    reliable_enabled=True,
    profile="ipv4_like",
    max_frame_bytes=0,
    max_side_transport_templates=64,
)
```

Profiles are `canonical`, `template`, `ipv6_like`, and `ipv4_like`. A
`compact_header_target_bytes` value of `0` uses the IPv6-like 40-byte or IPv4-like 20-byte default
target for the selected profile. The `ipv4_like` profile also omits unchanged compact timestamps.
The same method is available on `Relay`. Per-data-type timestamp omission policy is currently a
Rust-side option; Python callers use profile-wide timestamp omission through `ipv4_like`.

## P2P Service Ports

Routers expose discovery-backed service ports for byte protocols that should run over SEDSnet
instead of IP:

```python
router.bind_p2p_port(80, lambda meta, payload: handle_http(payload))
client.send_p2p_to_hostname("http-service", 80, 49152, b"GET / HTTP/1.1\r\n\r\n")
client.send_p2p_to_address(0x10203040, 80, 49152, b"GET / HTTP/1.1\r\n\r\n")
```

`router.current_address` returns the current compact address, and
`router.resolve_hostname("name")` returns discovered address metadata when known.

## Time sync

When built with `timesync`, `Router` keeps an internal network clock and handles `SEDSNET_TIME_SYNC`
traffic internally.

Construct `Router(..., timesync_enabled=False)` if the extension was built with `timesync` but you
do not want time sync for a particular instance. `SEDSNET_TIME_SYNC`, `SEDSNET_DISCOVERY`, and
`SEDSNET_ERROR` remain reserved internal endpoints; do not register handlers for them or try to emit
those packets manually.

See [Time-Sync](Time-Sync) for protocol details.
