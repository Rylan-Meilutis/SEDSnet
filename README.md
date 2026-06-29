# SEDSnet

A Rust networking stack with compact packets, runtime schema, discovery, routing, reliability,
managed state sync, P2P service ports/streams, optional E2E payload cryptography, and C/Python
bindings for distributed embedded and host systems.

Crate API docs are published on [docs.rs](https://docs.rs/SEDSnet). The implementation-level wiki,
including wire/discovery formats and binding guides, is mirrored in
[docs/wiki](./docs/wiki/Home.md) and on the project wiki.

---

## Authors

- [@Rylan-Meilutis](https://github.com/rylan-meilutis) (Original Author, Maintainer, and co-creator of the protocol)
- [@origami-yoda](https://github.com/origami-yoda) (Co-creator of the protocol and co-author of the original C++
  implementation)

---

## About

This library started out as a Rust rewrite of the earlier SEDS telemetry C++ implementation.

After the initial rewrite, many improvements were made to the rust implementation including better safety, easier
extension, and improved performance.
This caused the C++ implementation to be rewritten to keep feature parity with the rust version.
After about of month of this, we decided that we were no longer going to use the C++ version, and thus the project was
archived and is no longer being maintained.
With the Rust version being the sole implementation, we have continued to improve it and add new features like python
bindings, packet compression, and a bitmap for endpoints to further reduce packet size.
This library is now being used in multiple projects including embedded code on the rocket and on the rust based ground
station. SEDSnet is now capable of acting as a new network, passing telemetry data to endpoints across hardware
and software networks (uart, can ethernet, etc.) and across differing platforms and protocols (tcp, udp, etc.).

---

## Overview

This library provides a safe and efficient way to handle telemetry data including serializing, routing, and converting
into strings for logging. The purpose of this library is to provide an easy and consistent way to create and transport
any data to any destination without needing to implement the core routing on every platform, the library handles the
creation and routing of the data while allowing for easy extension to support new data types and destinations. The user
of the library is responsible for implementing 2 core functions and one function per local data endpoint.
The core functions are as follows:

- A function to send raw bytes to the all other nodes (e.g. UART, SPI, I2C, CAN, etc.)
- A function to receive raw bytes from all other nodes and passes the packet to the router
  (e.g. UART, SPI, I2C, CAN, etc.)
- A function to handle local data endpoints (e.g. logging to console, writing to file, sending over radio, etc.)
  (Note: each local endpoint needs its own function)

SEDSnet also provides helpers to convert the telemetry data into strings for logging purposes.
The library also handles packing telemetry packets to wire frames and unpacking received frames.

SEDSnet is platform-agnostic and can be used on any platform that supports Rust. The library is primarily designed
to be used in embedded systems and used by a C program, but can also be used in desktop applications and other rust
codebases.

SEDSnet also supports python bindings via pyo3. to use you need maturin installed to build the python package.

With the optional `discovery` feature, routers and relays can exchange built-in discovery packets, learn which
endpoints are reachable through which sides, adapt the announce rate as the topology changes, and export a live topology
snapshot for inspection. When `timesync` is also enabled, discovery can advertise concrete time source sender IDs so
`SEDSNET_TIME_SYNC` requests prefer exact source paths instead of generic endpoint flooding. Once discovery topology exists,
unknown user-data routes are not blindly flooded across low-bandwidth links; discovery/control traffic still propagates,
and explicit route policy can intentionally select a side. `SEDSNET_DISCOVERY` and `SEDSNET_TIME_SYNC` are reserved internal router
endpoints: applications can use the discovery and time-sync APIs, but must not register local endpoint handlers for
those endpoints or try to override their built-in handling.

Discovery and time-sync maintenance also throttle themselves across measured slow links. Link-probe
or driver timing samples mark constrained sides, after which routers and relays send mostly minimal
reachability pings across those sides and reserve full schema/topology/time-source refreshes for a
much slower cadence. Router-managed time sync keeps its normal cadence on fast sides while each
measured slow side independently receives sparse time-sync traffic, keeping asymmetric or
time-sliced radio links available for user payloads.

Discovery also assigns and advertises compact node addresses and hostnames for point-to-point
service traffic. A router can bind a SEDSnet service port and receive opaque byte payloads targeted
by hostname or address, or open a P2P stream with connect/accept/data/close events. Protocols such
as HTTP can be carried over SEDSnet links without IP being the underlying transport. Broadcast
endpoint delivery remains available for telemetry data types; P2P service frames use discovery
identity and ports for board-to-board traffic.

Queue memory is bounded per router/relay instance. Packaged values such as `MAX_QUEUE_BUDGET`
provide defaults, and Rust, C, and Python constructors can override the active budget at runtime.
Router and relay internals share that budget dynamically across RX work, TX work, reliable
replay/out-of-order buffers, recent packet ID tracking, and learned discovery topology state. The
recent packet ID cache preallocates its final storage because it is expected to fill during normal
operation, so its reserved bytes come out of the shared budget immediately. If one active queue area
is idle, another can use more of the remaining budget; if several areas fill at once, older queued
state is evicted so total queue-owned memory stays bounded.

Reliable delivery uses internal ACK/request control packets. Ordered reliable receivers buffer out-of-order packets,
partial-ACK packets that arrived after a gap, request the missing sequence, and then release the buffered run as soon as
the gap is filled. A partial ACK suppresses timeout retransmission for that exact packet, but an explicit packet request
can still retransmit it later.

Routers can also cache selected data types as managed network variables. A board that restarts can request the current
cached value and receive it through the normal endpoint handler path instead of waiting for the next publisher update.
For sensitive state or commands, the default `cryptography` feature lets data types prefer or require end-to-end payload
cryptography while the application supplies a C provider, Rust provider, OS/hardware crypto wrapper, or registered software key.

When topology or schema changes are propagating, packets already on the wire now carry a compact frozen delivery and
decode contract. New packets immediately use the latest schema-default endpoint view, while in-flight packets continue to
route only to their original intended holders and remain decodable against the shape they were packed with. The
contract is encoded compactly with bitmap-oriented metadata and sender hashes so header growth stays small.

Packed packets use compact varint fields, schema-derived endpoints, a compact source address instead of a repeated
sender hostname, and optional per-side header templates. Hostnames and endpoint holders are learned through discovery
and network configuration; the packet header carries only the source address needed for identity/routing. Per-side
templates can then replace repeated header fields with a compact template ID on small-packet transports, keeping the
header-to-payload ratio reasonable for small payloads such as three floats or a few `u8` values.

---

## Recent changelog milestones

## Version 4.0.1 highlights

- Prebuilt/host packages can configure active device identity, runtime tuning, time sync, address
  assignment, and memory budgets without rebuilding the crate.
- C and Python bindings now expose the runtime tuning, default device identifier, memory, and
  router address APIs documented for v4.
- Added router and relay regression tests that stress small runtime memory budgets and assert
  memory-layout exports stay within the configured shared queue budget.

## Version 4.0.0 highlights

- User telemetry schema is now runtime-only. `build.rs` no longer generates Rust enum variants or
  binding constants from `telemetry_config.json`.
- Endpoints and data types can be registered, looked up by name, exported, synced through
  discovery, and removed at runtime.
- Rust code can use readable runtime references such as `DataEndpoint::named("RADIO")` and
  `DataType::named("GPS_DATA")` instead of raw numeric IDs.
- C and Python expose matching schema register/info/info-by-name/remove APIs.
- Managed network variables let restarted boards request the latest cached state through normal
  endpoint handlers, and update callbacks can run when an inbound network update changes the cache.
- Discovery-backed P2P service ports support datagrams and lightweight stream sessions with
  connect/accept/data/close/reset events for byte protocols that need board-to-board sessions.
- End-to-end payload cryptography is enabled by default and can be preferred or required per data type;
  routers choose whether to encrypt required, preferred, or all user data.
- Crypto providers can be supplied as C callbacks, Rust providers, or registered software fallback
  keys, and compact managed credentials support master-root deployments without user-managed cert
  files.
- Fixed-size packed sides transparently split/reassemble packets for CAN, I2C, and fixed-frame
  radios, while link-probe samples seed adaptive routing for asymmetric or time-sliced links.
- Discovery-aware forwarding avoids blind unknown-route user-data flooding once topology exists,
  protecting low-bandwidth sides unless explicit route policy selects them.
- Discovery and time-sync control traffic is dynamically throttled per measured slow link, using
  minimal reachability pings between infrequent full topology/schema refreshes.
- Routers and relays export topology as a board graph with named endpoint fields, side names,
  deduplicated `links`, and filtered SEDSnet control endpoints. They also expose memory-layout and
  per-client stats snapshots for profiling and diagnostics.
- Routers and relays announce `SEDSNET_DISCOVERY_LEAVE` during explicit leave/shutdown so peers can
  prune topology immediately instead of waiting for expiry.
- Optional JSON config is applied at runtime through env/path/bytes APIs. The repo does not carry a
  default user schema. Embedded users that want compiled-in seed bytes must provide their own local
  `telemetry_config.json` before building.
- Schema registry memory counts against the same shared `MAX_QUEUE_BUDGET` as other router/relay
  queue-backed state.
- Optional C and C++ convenience wrappers can be enabled from CMake, while raw-ABI users can keep
  the static runtime-schema header only.
- Full changelog: [CHANGELOG.md](./CHANGELOG.md)

## Version 3.12.0 highlights

- Router and relay queue-backed state now shares one dynamic `MAX_QUEUE_BUDGET` instead of using
  isolated per-queue caps.
- `MAX_QUEUE_SIZE` has been renamed to `MAX_QUEUE_BUDGET`; the old environment name remains
  accepted as a legacy alias.
- Recent packet ID caches, reliable replay/out-of-order buffers, and discovery topology state now
  count against the same shared budget, with topology eviction warnings in `std` builds.
- Ordered reliable receive paths now partial-ACK out-of-order packets to reduce timeout
  retransmission traffic while still allowing explicit packet requests.
- Router and relay side-TX contention is now retried as transient backpressure instead of surfacing
  intermittent handler failures.
- Full changelog: [CHANGELOG.md](./CHANGELOG.md)

## Version 3.11.1 highlights

- Discovery now propagates a full router graph with `SEDSNET_DISCOVERY_TOPOLOGY`, so routers and relays
  keep track of which sender IDs own which endpoints and how remote routers connect to each other.
- `export_topology()` now includes router-level topology plus per-side announcer detail instead of
  only aggregated reachable endpoint lists.
- Topology export is now available to clients across all supported surfaces:
  Rust `export_topology()`, Python `Router.export_topology()` / `Relay.export_topology()`, and C
  JSON exports via `seds_router_export_topology*` / `seds_relay_export_topology*`.
- Full changelog: [CHANGELOG.md](./CHANGELOG.md)

## Version 3.11.0 highlights

- Removed `RouterMode` from the active router model. Routers now use the same runtime routing-rule
  model as relays, and with no explicit route rules they default to a full forwarding mesh.
- Discovery-driven multi-path routing now defaults to adaptive load balancing for normal traffic,
  while reliable discovered traffic still fans out across all known candidate paths.
- Reliable delivery is now end-to-end verified in addition to the existing per-link ACK/retransmit
  layer. Destination routers emit directed end-to-end acknowledgements, and discovery-informed
  return-path learning routes those ACKs only toward the source instead of flooding them.
- When a discovered destination holder disappears from topology, the source retires that holder
  from the in-flight obligation set instead of replaying forever toward a vanished board.
- Relays also prune their learned holder-ACK state against discovery expiry so stale confirmations
  do not keep affecting later discovered routing choices.
- Reliable streams still stay non-blocking while those end-to-end acknowledgements are outstanding.
- Added expanded testing documentation covering unit tests, Rust system tests, C system tests,
  local coverage reporting, and the new end-to-end reliability regression tests.
- Full changelog: [CHANGELOG.md](./CHANGELOG.md)

## Version 3.10.0 highlights

- Reliable delivery in both `Router` and `Relay` now uses built-in internal
  `RELIABLE_ACK` and `RELIABLE_PACKET_REQUEST` packet types instead of wire-only ACK-only frames.
- Reliable streams no longer block on one missing reliable packet. Ordered gaps are requested
  explicitly, out-of-order packets are buffered, and retransmits are requeued with elevated
  priority.
- This improves recovery on asymmetric links and multi-destination fanout where different boards
  progress at different rates.
- Full changelog: [CHANGELOG.md](./CHANGELOG.md)

## Version 3.9.1 highlights

- Reserved the built-in `SEDSNET_DISCOVERY` and `SEDSNET_TIME_SYNC` endpoints for router-owned control traffic.
- User handlers can no longer shadow internal discovery or time-sync behavior through Rust or C
  configuration APIs.
- Queue timeout handling was tightened so TX/RX work shares nonzero budgets more predictably.
- Full changelog: [CHANGELOG.md](./CHANGELOG.md)

## Version 3.0.0 highlights

- Introduced internal router-side tracking so most applications can use the plain RX APIs and only
  opt into side-aware ingress when they actually need it.
- Added TCP-like reliable delivery for schema types marked `reliable` or `reliable_mode`, with
  ACKs, retransmits, and optional ordering.
- This established the modern router/reliability model that later releases expanded.
- Full changelog: [v2.4.0...v3.0.0](https://github.com/Rylan-Meilutis/sedsnet/compare/v2.4.0...v3.0.0)

## Version 1.0.0 highlights

- First stable release with routing, packet packing, and packet creation across Rust, C, and Python.
- Marked the API as stable and established the base wire-format and packet model the later versions
  built on.

---

## Building

To build the library in a C project, just include the library as a submodule or subtree and link it in your
cmakelists.txt as shown below.
For other build systems, you can build the library as a static or dynamic library using cargo and link it to your
project.

Building with python bindings can be done with the build script on posix systems:

```
./build.py release maturin-develop
```

When building in an embedded environment the library will compile to a static library that can be linked to your C code.
this library takes up about 100kb of flash and does require heap allocation to be available through either freertos, or
by creating providers that expose pvPortMalloc and vPortFree.


## Embedded hooks

For embedded integrations, treat the router or relay as a single owner context. The normal application loop should call
`periodic(...)` and feed ingress bytes into the queued RX APIs.

Rules that matter in practice:

- Do not call router, relay, or packet-to-string APIs from an ISR. Queue the bytes and hand them to a task or worker.
- If you wrap router calls with a lock, that lock must be recursive-safe because side TX callbacks can trigger deferred
  queue work in the same logical call chain.
- `SEDSNET_DISCOVERY` and `SEDSNET_TIME_SYNC` are reserved internal endpoints. Do not register local handlers for them and do not emit
  those packets manually from application code. Use the time-sync and discovery APIs instead.
- When the `timesync` feature is enabled, `periodic(...)` is the expected maintenance entry point. Only use
  `poll_timesync(...)` / `poll_discovery(...)` directly when you intentionally need manual phase control.

### build.py usage

```
./build.py [OPTIONS]

Options:
  release                 Build in release mode.
  check                   Run cargo clippy with -D warnings for default, python, and embedded builds.
  test                    Run the clippy checks, nextest/cargo tests, a stable Criterion benchmark smoke pass, and also validate python plus embedded builds when the cross C toolchain exists.
  embedded                Build for the embedded target (enables embedded feature).
  python                  Build with Python bindings (enables python feature).
  timesync                Build with time sync helpers (enables timesync feature).
  maturin-build           Run maturin build while including the static .pyi stub.
  maturin-develop         Run maturin develop while including the static .pyi stub.
  maturin-install         Build wheel and install it with uv pip install.
  target=<triple>         Set Rust compilation target (e.g. target=thumbv7em-none-eabihf).
  device_id=<id>          Set the packaged DEVICE_IDENTIFIER default for the build.
  static_schema_path=<path>      Set SEDSNET_STATIC_SCHEMA_PATH for runtime registry seeding.
  static_ipc_schema_path=<path>  Set SEDSNET_STATIC_IPC_SCHEMA_PATH for a runtime IPC/link-local seed.
  max_queue_budget=<n>    Set MAX_QUEUE_BUDGET for the shared router/relay queue budget.
  max_recent_rx_ids=<n>   Set MAX_RECENT_RX_IDS for the preallocated recent-ID cache.
  max_stack_payload=<n>   Set MAX_STACK_PAYLOAD for define_stack_payload!(env="MAX_STACK_PAYLOAD", ...).
  env:KEY=VALUE           Set arbitrary environment variable(s) for the build (repeatable).
```

Examples:

```
./build.py release
./build.py check
./build.py check release
./build.py embedded release target=thumbv7em-none-eabihf device_id=FC
./build.py python
./build.py test release
./build.py maturin-install max_recent_rx_ids=256 env:MAX_STACK_PAYLOAD=128
```

## Dependencies

- Rust → https://rustup.rs/
- CMake
- A C++ compiler
- A C compiler

## Performance benchmarking

Criterion benchmarks are available through Cargo benches. The current benchmark targets exercise packet construction,
packing, header peeking, unpacking, and router/relay flows that mirror the Rust system-test path under the
default host feature set.

Run:

```bash
cargo bench --bench packet_paths
cargo bench --bench router_system_paths
```

If you want profiler-friendly output while iterating locally:

```bash
cargo bench --bench packet_paths -- --profile-time=5
```

`./build.py test` now starts with the same strict clippy checks as `./build.py check`, then runs:

- `cargo nextest run --features timesync` when `cargo-nextest` is installed, otherwise
  `cargo test --features timesync`, covering the unit tests in `src/tests.rs`, the Rust system tests under
  `tests/rust-system-test/`, and the C integration tests under `tests/c-system-test/`
- `cargo test --doc --features timesync` when nextest is used, since nextest does not run doctests
- a stable Criterion smoke pass for `packet_paths` and `router_system_paths`
- a `cargo build` validation for the `python` feature
- a `cargo build` validation for the `embedded` feature when a matching cross C toolchain is available

The benchmark smoke pass uses Cargo `--profile release`, saves into a dedicated `sedsnet_smoke` baseline, disables
plot generation, and uses a longer timing window plus a wider smoke-test noise threshold so host variance does not print
alternating regression/improvement noise. The C system-test harness waits for all asserted endpoint hits before exiting,
so it does not fail early while one side is still draining forwarded traffic.

Coverage is regression-oriented rather than percentage-gated in CI today. If you want a local line/branch coverage
number, the supported path is:

```bash
cargo llvm-cov --features timesync --workspace --html
```

That writes an HTML report under `target/llvm-cov/html/` when `cargo-llvm-cov` is installed.

More detail on the test layers, what each suite covers, and the intended commands is in
[docs/wiki/Testing.md](./docs/wiki/Testing.md).

## Usage

### Linking from a C/C++ CMake project

```
# Example: building for an embedded target
set(SEDSNET_TARGET "thumbv7m-none-eabi" CACHE STRING "" FORCE)
set(SEDSNET_EMBEDDED_BUILD ON CACHE BOOL "" FORCE)

# Optional: always build the Rust crate in release mode, even if the parent CMake
# configuration is Debug. Useful when your top-level project stays Debug but you
# want an optimized telemetry library.
# set(SEDSNET_FORCE_RELEASE ON CACHE BOOL "" FORCE)

# set the packaged default sender name
set(SEDSNET_DEVICE_IDENTIFIER "FC26_MAIN" CACHE STRING "" FORCE)

# optional compile-time env overrides
set(SEDSNET_MAX_STACK_PAYLOAD "256" CACHE STRING "" FORCE)
set(SEDSNET_MAX_QUEUE_BUDGET "65536" CACHE STRING "" FORCE)
set(SEDSNET_MAX_RECENT_RX_IDS "256" CACHE STRING "" FORCE)
set(SEDSNET_ENABLE_CRYPTOGRAPHY ON CACHE BOOL "" FORCE)

# optional wrapper targets; leave both OFF to use only the raw static ABI header
set(SEDSNET_ENABLE_C_WRAPPER ON CACHE BOOL "" FORCE)
set(SEDSNET_ENABLE_CPP_WRAPPER OFF CACHE BOOL "" FORCE)

# Use the provided CMake glue
add_subdirectory(${CMAKE_SOURCE_DIR}/sedsnet sedsnet_build)

# Optional: prefer static linking even on host builds
# set(SEDSNET_PREFER_DYNAMIC OFF CACHE BOOL "" FORCE)

# Link against the imported target
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE sedsnet::sedsnet)

# Optional convenience wrappers when enabled above:
# target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE sedsnet::c_wrapper)
# target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE sedsnet::cpp_wrapper)
```

### Pulling SEDSnet from GitHub without a submodule

CMake projects can use `FetchContent` to download SEDSnet during configure instead of storing it
as a submodule or subtree. Set SEDSnet options before `FetchContent_MakeAvailable(...)`; they are
CMake cache variables consumed by the fetched project.

```cmake
cmake_minimum_required(VERSION 3.20)
project(my_board C)

include(FetchContent)

set(SEDSNET_EMBEDDED_BUILD ON CACHE BOOL "" FORCE)
set(SEDSNET_TARGET "thumbv7em-none-eabihf" CACHE STRING "" FORCE)
set(SEDSNET_FORCE_RELEASE ON CACHE BOOL "" FORCE)
set(SEDSNET_DEVICE_IDENTIFIER "FC26_MAIN" CACHE STRING "" FORCE)
set(SEDSNET_MAX_STACK_PAYLOAD "256" CACHE STRING "" FORCE)
set(SEDSNET_ENABLE_C_WRAPPER ON CACHE BOOL "" FORCE)

FetchContent_Declare(
    sedsnet
    GIT_REPOSITORY https://github.com/Rylan-Meilutis/SEDSnet.git
    GIT_TAG v4.0.2
)
FetchContent_MakeAvailable(sedsnet)

add_executable(my_board src/main.c)
target_link_libraries(my_board PRIVATE sedsnet::sedsnet)

# Optional when SEDSNET_ENABLE_C_WRAPPER is ON:
# target_link_libraries(my_board PRIVATE sedsnet::c_wrapper)
```

Pin `GIT_TAG` to a release tag or commit SHA for reproducible builds. Use `main` or `dev` only
when you intentionally want the parent project to track a moving branch.

Host CMake builds now prefer the shared Rust library when supported. Embedded builds still use the static library.
If you want the Rust crate to use the release profile regardless of the parent CMake config,
set `SEDSNET_FORCE_RELEASE=ON` before `add_subdirectory(...)`. Otherwise the wrapper follows
`CMAKE_BUILD_TYPE` for single-config generators and defaults to debug for Debug builds.

- Configure telemetry schema at runtime. The default build contains only built-in internal
  endpoints/types for telemetry errors, reliable control, discovery, and time sync. Applications
  add user endpoints/types through the runtime APIs, by passing a JSON schema path/bytes to the
  registry, or by letting discovery sync schema entries from peers.
- The raw C ABI is always available through the static runtime-schema header. The C and C++
  convenience wrappers are opt-in CMake targets for projects that want global router/relay helper
  APIs without passing raw handles through every application function.

---

## Setting the device / platform name

Each build of `sedsnet` embeds a **default device identifier**. In v4 packet routing uses compact
addresses on the wire; hostnames/sender names are discovery/config metadata instead of repeated in
every packed frame. Applications can still override the active identifier at runtime.

Rust resolves it using:

```
pub const DEVICE_IDENTIFIER: &str = match option_env!("DEVICE_IDENTIFIER") {
    Some(v) => v,
    None => "TEST_PLATFORM",
};
```

### Set it globally using `.cargo/config.toml` (recommended)

Create:

```
# .cargo/config.toml
[env]
DEVICE_IDENTIFIER = "GROUND_STATION_26"
```

After this, any `cargo build`, `cargo run`, or CI build will package `"GROUND_STATION_26"` as the default.

No build script changes required.

---

### Setting the name from CMake

```
set(SEDSNET_DEVICE_IDENTIFIER "FC26_MAIN" CACHE STRING "" FORCE)
```

Note: This must be set **before** including the sedsnet CMake as a subdirectory.

Runtime overrides are available in every host binding:

```rust
use sedsnet::config::set_runtime_device_identifier;

set_runtime_device_identifier("GROUND_STATION_26")?;
let router = sedsnet::router::Router::new_with_config(
    sedsnet::router::RouterConfig::new().with_sender("FC26_MAIN"),
    Box::new(clock),
);
```

```c
seds_set_runtime_device_identifier("GROUND_STATION_26", 17);
seds_router_set_sender_id(router, "FC26_MAIN", 9);
seds_router_configure_address(router, 2, 0x10203040); /* 0=dynamic, 1=requested, 2=static */
```

```python
import sedsnet as seds

seds.set_runtime_device_identifier("GROUND_STATION_26")
router = seds.Router(hostname="FC26_MAIN", address_mode=2, requested_address=0x10203040)
router.configure_address(address_mode=1, requested_address=0x10203041)
```

Typical examples:

```cmake
# Flight computer firmware
set(SEDSNET_DEVICE_IDENTIFIER "FC26_MAIN" CACHE STRING "" FORCE)
set(SEDSNET_TARGET "thumbv7em-none-eabihf" CACHE STRING "" FORCE)
set(SEDSNET_EMBEDDED_BUILD ON CACHE BOOL "" FORCE)
set(SEDSNET_MAX_STACK_PAYLOAD "256" CACHE STRING "" FORCE)
set(SEDSNET_MAX_QUEUE_BUDGET "65536" CACHE STRING "" FORCE)
set(SEDSNET_MAX_RECENT_RX_IDS "256" CACHE STRING "" FORCE)

# or

# Ground station app
set(SEDSNET_DEVICE_IDENTIFIER "GS26" CACHE STRING "" FORCE)
set(SEDSNET_TARGET "" CACHE STRING "" FORCE)
set(SEDSNET_EMBEDDED_BUILD OFF CACHE BOOL "" FORCE)
set(SEDSNET_MAX_QUEUE_BUDGET "65536" CACHE STRING "" FORCE)
set(SEDSNET_MAX_RECENT_RX_IDS "256" CACHE STRING "" FORCE)
```

### Manually via build.py

```bash
# Host build
./build.py release device_id=GROUND_STATION
# Embedded build
./build.py embedded release target=thumbv7em-none-eabihf device_id=FC
```

---

## Runtime telemetry schema

In v4, user telemetry schema is runtime state. `DataEndpoint` and `DataType` are stable numeric IDs
on the wire, but applications should normally look them up by string:

```rust
use sedsnet::{DataEndpoint, DataType};

let radio = DataEndpoint::named("RADIO");
let gps = DataType::named("GPS_DATA");
```

You can add schema entries directly:

```rust
use sedsnet::{
    config::{register_data_type_id_with_description, register_endpoint_id_with_description},
    DataEndpoint, DataType, MessageClass, MessageDataType, MessageElement, ReliableMode,
};

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

Or seed from JSON at runtime. Host builds can use:

- `SEDSNET_STATIC_SCHEMA_PATH=/path/to/telemetry_config.json`
- `SEDSNET_STATIC_IPC_SCHEMA_PATH=/path/to/ipc_config.json`
- Rust `register_schema_json_path(...)` / `register_schema_json_bytes(...)`
- C `seds_schema_register_json_file(...)` / `seds_schema_register_json_bytes(...)`
- Python `register_schema_json_file(...)` / `register_schema_json_bytes(...)`

Default builds do not compile application JSON into the crate. Embedded builds can include
`telemetry_config.json` bytes only when the application provides that file locally before building;
those bytes are decoded through the normal runtime JSON parser.

The GUI editor still edits JSON schema files:

```bash
./telemetry_config_editor.py
```

For board-local IPC/software-bus endpoints, seed a second JSON file with
`SEDSNET_STATIC_IPC_SCHEMA_PATH` or the explicit JSON registration API. IPC seed entries are
applied at runtime and treated as link-local when loaded through the IPC path.

Built-in internal endpoint/type names for telemetry errors, reliable control, discovery, and time
sync are reserved. Do not register user handlers for `SEDSNET_DISCOVERY` or `SEDSNET_TIME_SYNC`.

### Network variables and E2E payloads

Network variables are latest-value caches keyed by data type. After registering or seeding schema,
enable a type on the router and use the getter/setter pair:

```rust
let flight_state = DataType::named("FLIGHT_STATE");
router.enable_network_variable(flight_state, NetworkVariablePermissions::READ_WRITE)?;
router.set_network_variable(pkt)?;
let cached = router.get_network_variable(flight_state, Some(1_000))?;
```

The setter commits the value to the network when permissions allow. The getter reads the cached copy
and internally requests the value if the cache has never seen it or is stale; user code does not
register a separate endpoint for network variables. Caches are tiered: any router that has enabled
or seen the variable can answer the refresh from its local cache, so reconnecting boards can resync
from a nearby node instead of always reaching the original producer/master. If a peer has the value,
the current packet is replayed through the normal endpoint handler so resync still looks like an
ordinary update. Register `on_network_variable_update(...)` when code needs a callback whenever an
inbound network update changes a variable cache.

Data types can also choose an E2E payload cryptography policy:

- `PreferOff`: plaintext unless the router forces cryptography
- `PreferOn`: encrypt when router crypto support is available
- `RequireOn`: reject send/subscribe paths unless cryptography support is available

Router E2E modes are `Disabled`, `RequiredOnly`, `Preferred`, and `ForceAll`. With the default
`cryptography` feature, the default is `Preferred`; minimal builds that explicitly omit it default
to `Disabled`. Crypto providers are tried in this order: registered C provider, registered Rust provider, then
registered software fallback key. The provider path is intended for OS crypto, hardware accelerators,
secure elements, and Rust-only embedded projects. Compact managed credential helpers are available
for deployments where a master/root node issues short-lived board credentials instead of users
managing certificate files.

Routers and relays can export JSON memory-layout snapshots to profile queue pressure at runtime,
including shared allocation, per-queue used/allocated bytes, reliable buffers, schema/discovery
state, and network-variable cache bytes.

Topology exports describe the board graph directly: `routers` contains each discovered board and
its connected peers, while `links` contains deduplicated `{source, target}` edges for visual graph
rendering. SEDSnet-owned control endpoints such as `SEDSNET_TIME_SYNC`, `SEDSNET_DISCOVERY`, and
`SEDSNET_ERROR` are filtered out of user endpoint reachability fields.

Routers and relays can also export per-client stats by sender ID. The snapshot reports whether the
client is still connected, which sides currently reach it, last-seen/age timing, named reachable
endpoints, and packet/byte counters aggregated from the side(s) used to reach that client.
Explicit `announce_leave(...)` calls, and best-effort C `free` paths, send a
`SEDSNET_DISCOVERY_LEAVE` control packet so peers can remove a departing sender from topology right
away.

Note: The editor uses Tkinter. On some Linux distros you may need to install it
(e.g. `sudo apt install python3-tk`).

Example application schema JSON:

```json
{
  "endpoints": [
    {
      "rust": "Radio",
      "name": "RADIO",
      "doc": "Downlink radio"
    },
    {
      "rust": "SdCard",
      "name": "SD_CARD",
      "doc": "Onboard logging"
    }
  ],
  "types": [
    {
      "rust": "GpsData",
      "name": "GPS_DATA",
      "doc": "Lat/Lon/Alt",
      "class": "Data",
      "element": {
        "kind": "Static",
        "data_type": "Float32",
        "count": 3
      },
      "endpoints": [
        "Radio",
        "SdCard"
      ]
    }
  ]
}
```

---

## Example CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.22)
project(my_app C CXX)

add_executable(my_app
    src/main.c
)

# ---- sedsnet configuration ----
set(SEDSNET_DEVICE_IDENTIFIER "FC26_MAIN" CACHE STRING "" FORCE)
set(SEDSNET_TARGET "thumbv7em-none-eabihf" CACHE STRING "" FORCE)
set(SEDSNET_EMBEDDED_BUILD ON CACHE BOOL "" FORCE)
set(SEDSNET_MAX_STACK_PAYLOAD "256" CACHE STRING "" FORCE)
set(SEDSNET_MAX_QUEUE_BUDGET "65536" CACHE STRING "" FORCE)
set(SEDSNET_MAX_RECENT_RX_IDS "256" CACHE STRING "" FORCE)

# Add the submodule/subtree root (adjust path as needed)
add_subdirectory(${CMAKE_SOURCE_DIR}/sedsnet sedsnet_build)

target_link_libraries(my_app PRIVATE sedsnet::sedsnet)
```

---

## Using this repo as a subtree

```
git remote add sedsnet-upstream https://github.com/Rylan-Meilutis/sedsnet.git
git fetch sedsnet-upstream

git config subtree.sedsnet.remote sedsnet-upstream
git config subtree.sedsnet.branch main

git subtree add --prefix=sedsnet sedsnet-upstream main
```

To Switch branches:

```bash
git config subtree.sedsnet.branch <the-new-branch>
```

Update:

```bash
git subtree pull --prefix=sedsnet sedsnet-upstream main \
    -m "Merge sedsnet upstream main"
```

Helper scripts:

```bash
./scripts/subtree_update_no_stash.py
./scripts/subtree_update.py            # stash → update → stash-pop
```

---

## Using this repo as a submodule

If you prefer a **submodule** instead of a subtree:

```bash
git submodule add -b main https://github.com/Rylan-Meilutis/sedsnet.git sedsnet

git config submodule.sedsnet.branch main   # (or dev, etc.)
```

Initialize:

```bash
git submodule update --init --recursive
```

Update using helper scripts:

The scripts:

- read `submodule.sedsnet.branch`
- fetch `origin/<branch>`
- fast-forward the submodule repo
- stage & commit the updated submodule pointer in the parent repo

---

## Embedded allocator + lock hook examples (C)

For embedded (`--features embedded`) builds, provide these symbols:

- `void *telemetryMalloc(size_t)`
- `void telemetryFree(void *)`
- `void telemetry_lock(void)`
- `void telemetry_unlock(void)`
- `void seds_error_msg(const char *, size_t)`
- `void telemetry_panic_hook(const char *, size_t)`

Notes:

- `telemetry_lock`/`telemetry_unlock` must be recursive-safe.
- Do not call router/logging APIs from ISR context (hooks may block).
- Keep allocator non-blocking/fail-fast on RTOS targets (`NO_WAIT` style).

```C
// telemetry_hooks.c
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

/*
 * Rust expects these functions to exist for heap allocations:
 *
 *   void *telemetryMalloc(size_t);
 *   void telemetryFree(void *);
 *   void telemetry_lock(void);
 *   void telemetry_unlock(void);
 *   void seds_error_msg(const char *, const size_t);
 *   void telemetry_panic_hook(const char *, const size_t);
 *
 */

void telemetry_lock(void)
{
    /* Optional on bare metal / single-threaded targets. */
}

void telemetry_unlock(void)
{
    /* Optional on bare metal / single-threaded targets. */
}

void *telemetryMalloc(size_t xSize)
{
    if (xSize == 0) {
        xSize = 1;
    }
    return malloc(xSize);
}

void telemetryFree(void *pv)
{
    free(pv);
}

void seds_error_msg(const char *str, const size_t len)
{
    // Implement your logging mechanism here, for example:
    fwrite(str, 1, len, stderr);
    fwrite("\n", 1, 1, stderr);
}

void telemetry_panic_hook(const char *str, const size_t len)
{
    // Called from Rust panic handler in embedded/no_std builds.
    fwrite("PANIC: ", 1, 7, stderr);
    fwrite(str, 1, len, stderr);
    fwrite("\n", 1, 1, stderr);
}
```

### FreeRTOS example

```C
// telemetry_hooks_freertos.c
#include "FreeRTOS.h"
#include "semphr.h"
#include <stddef.h>
#include <stdio.h>

/* Example allocator backend; replace with heap_4/5 or your own allocator. */
void *pvPortMalloc(size_t xSize);
void vPortFree(void *pv);

static SemaphoreHandle_t g_telemetry_lock = NULL;

void telemetry_init_lock(void)
{
    if (g_telemetry_lock == NULL) {
        g_telemetry_lock = xSemaphoreCreateRecursiveMutex();
    }
}

void telemetry_lock(void)
{
    if (g_telemetry_lock != NULL && xPortIsInsideInterrupt() == pdFALSE) {
        (void)xSemaphoreTakeRecursive(g_telemetry_lock, portMAX_DELAY);
    }
}

void telemetry_unlock(void)
{
    if (g_telemetry_lock != NULL && xPortIsInsideInterrupt() == pdFALSE) {
        (void)xSemaphoreGiveRecursive(g_telemetry_lock);
    }
}

void *telemetryMalloc(size_t xSize)
{
    if (xSize == 0) {
        xSize = 1;
    }
    return pvPortMalloc(xSize);
}

void telemetryFree(void *pv)
{
    vPortFree(pv);
}

void seds_error_msg(const char *str, size_t len)
{
    (void)len;
    printf("%s\r\n", str);
}

void telemetry_panic_hook(const char *str, size_t len)
{
    (void)len;
    printf("PANIC: %s\r\n", str ? str : "(null)");
    taskDISABLE_INTERRUPTS();
    for (;;)
    {
    }
}
```

### ThreadX example

```C
// telemetry_hooks_threadx.c
#include "tx_api.h"
#include <stddef.h>
#include <stdio.h>

static TX_BYTE_POOL *rust_byte_pool_external = NULL;
static TX_MUTEX g_telemetry_mutex;
static UINT g_telemetry_mutex_ready = 0U;
static TX_THREAD *g_telemetry_mutex_owner = TX_NULL;
static UINT g_telemetry_mutex_recursion = 0U;

void telemetry_set_byte_pool(TX_BYTE_POOL *pool)
{
    rust_byte_pool_external = pool;
}

void telemetry_init_lock(void)
{
    if (g_telemetry_mutex_ready == 0U) {
        if (tx_mutex_create(&g_telemetry_mutex, "telemetry_mutex", TX_INHERIT) == TX_SUCCESS) {
            g_telemetry_mutex_ready = 1U;
        }
    }
}

void telemetry_lock(void)
{
    if (g_telemetry_mutex_ready == 0U) {
        return;
    }

    TX_THREAD *self = tx_thread_identify();
    if (self == TX_NULL) {
        /* Not in thread context; do not block in ISR/startup contexts. */
        return;
    }

    if (g_telemetry_mutex_owner == self) {
        g_telemetry_mutex_recursion++;
        return;
    }

    if (tx_mutex_get(&g_telemetry_mutex, TX_WAIT_FOREVER) == TX_SUCCESS) {
        g_telemetry_mutex_owner = self;
        g_telemetry_mutex_recursion = 1U;
    }
}

void telemetry_unlock(void)
{
    if (g_telemetry_mutex_ready == 0U) {
        return;
    }

    TX_THREAD *self = tx_thread_identify();
    if (self == TX_NULL) {
        return;
    }

    if (g_telemetry_mutex_owner != self) {
        return;
    }

    if (g_telemetry_mutex_recursion > 1U) {
        g_telemetry_mutex_recursion--;
        return;
    }

    g_telemetry_mutex_owner = TX_NULL;
    g_telemetry_mutex_recursion = 0U;
    (void)tx_mutex_put(&g_telemetry_mutex);
}

void *telemetryMalloc(size_t xSize)
{
    void *ptr = NULL;
    if (rust_byte_pool_external == NULL) {
        return NULL;
    }

    if (xSize == 0U) {
        xSize = 1U;
    }

    if (tx_byte_allocate(rust_byte_pool_external, &ptr, xSize, TX_NO_WAIT) != TX_SUCCESS) {
        return NULL;
    }
    return ptr;
}

void telemetryFree(void *pv)
{
    if (pv != NULL) {
        (void)tx_byte_release(pv);
    }
}

void seds_error_msg(const char *str, size_t len)
{
    (void)len;
    printf("%s\r\n", str);
}

void telemetry_panic_hook(const char *str, size_t len)
{
    (void)len;
    printf("PANIC: %s\r\n", str ? str : "(null)");
    for (;;)
    {
    }
}
```

Call `telemetry_init_lock()` and `telemetry_set_byte_pool(...)` before any telemetry/router API usage.
