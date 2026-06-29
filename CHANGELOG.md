# Changelog

## 4.0.2

- Made `pyproject.toml` use maturin's dynamic version metadata so the Python package version is
  derived from the root Cargo package version instead of being edited separately.
- Hardened `publish_crates.py` for crates.io release retries: an already-published macro crate no
  longer waits for delayed index propagation, and index lag after a successful macro upload can be
  treated as a non-fatal publish warning when `--ignore-publish-errors` is used.

## 4.0.1

- Made the remaining prebuilt/host tuning knobs runtime configurable across Rust, C, and Python:
  device identifier, compression threshold, static string/binary sizing, float string precision,
  handler retries, reliable retransmit timing, and reliable cache limits.
- Added runtime router address configuration across bindings, including dynamic, requested, and
  static address modes for discovery-backed P2P routing.
- Updated the checked-in C ABI header and Python type stub so packaged users see the new runtime
  memory, tuning, device identity, and address APIs.
- Added router and relay regression tests that stress small runtime memory budgets and assert the
  exported memory-layout usage never exceeds the configured shared queue budget.
- Updated README and wiki docs for the v4.0.1 release, clarifying that build-time values are
  packaged defaults while runtime APIs configure active nodes. `MAX_STACK_PAYLOAD` remains the
  compile-time inline payload capacity because it changes type layout.

## 4.0.0

- Removed compile-time user schema generation. `build.rs` no longer turns
  `telemetry_config.json` into Rust `DataType` / `DataEndpoint` variants or generated schema
  constants. User endpoints and data types are runtime registry entries.
- Added runtime schema registration and lookup APIs:
    - Rust: `register_endpoint*`, `register_data_type*`, `endpoint_definition_by_name`,
      `data_type_definition_by_name`, `DataEndpoint::named(...)`, and `DataType::named(...)`.
    - C ABI: endpoint/type register, info, info-by-name, JSON registration, and removal functions.
    - Python: matching register, info, info-by-name, JSON registration, and removal functions.
- Endpoint and data type definitions now include human-readable `description` metadata. Runtime
  JSON accepts both `description` and legacy `doc` fields.
- Handler registration now auto-creates missing runtime endpoints. If an endpoint handler is
  registered for an unknown endpoint ID, the registry creates a named placeholder and advertises it
  through schema discovery.
- Added schema discovery sync. Nodes now advertise the current runtime schema, merge compatible
  endpoint/type definitions, and resolve conflicts deterministically when IDs or names collide.
  Type shape conflicts remain rejected by direct registration.
- Schema registry memory is now part of the same shared router/relay queue budget used for RX/TX
  queues, reliable state, recent packet IDs, discovery topology, and other queue-backed state.
- Added network-variable latest-value caching. Routers can mark a data type as network-managed with
  local read/write permissions, set the value for the network, read the cached value, and
  internally request a refresh when the cache is missing or stale. Refreshes can be answered by any
  nearby router that has enabled or seen the variable, and applications can register update
  callbacks for inbound cache changes.
- Added discovery-backed P2P service ports. Routers now advertise compact node addresses and
  hostnames, deconflict duplicate static/requested/dynamic addresses after partitions merge, and
  notify local code when identity changes. Applications can bind a SEDSnet service port and send
  opaque byte payloads to a hostname or address, enabling protocols such as HTTP to run over
  SEDSnet instead of IP while normal endpoint broadcast telemetry remains unchanged.
- Added lightweight P2P stream sessions on top of service ports. Streams exchange local/peer stream
  IDs and expose connect/accept/data/close/reset events while continuing to use discovery-targeted
  ordered `SEDSNET_P2P_MESSAGE` frames.
- Added end-to-end payload encryption policy hooks under the `cryptography` feature:
    - Data types can declare `PreferOff`, `PreferOn`, or `RequireOn`.
    - Routers can run in `Disabled`, `RequiredOnly`, `Preferred`, or `ForceAll` mode.
    - Builds without crypto support reject required encrypted traffic instead of silently
      downgrading it.
- Added process-wide crypto provider support. The provider order is C provider, Rust provider, then a
  software fallback key, so std applications can wrap OS crypto APIs and embedded applications can
  use secure elements or hardware accelerators without changing the router API.
- Added compact 80-byte managed credential helpers for master-root deployments. A master/root key
  can issue short-lived board credentials containing subject, key, epoch, validity window, and
  permission bits; peers verify them before accepting issued session or group keys.
- Added runtime sender ID update APIs and reduced packed header overhead. Canonical packet frames
  now carry a compact source address instead of repeating sender hostnames; sender names are
  discovery/config metadata, and packed sides can still cache header templates for follow-up frames.
- Added fixed-size packed side splitting/reassembly for transports such as CAN, I2C, and
  fixed-frame radio links. Router and relay sides can cap outbound packed chunks without
  changing the user packet/logging API.
- Added link-probe sample APIs for routers and relays so transport bring-up or driver-measured
  throughput can seed adaptive path selection.
- Tightened discovery-aware forwarding for low-bandwidth links. Once topology exists, unknown
  user-data routes are not blindly flooded; discovery/control traffic still propagates and explicit
  route policy can still intentionally select a side.
- Added dynamic control-plane throttling for measured slow links. Routers and relays use recent
  link-probe or driver timing samples to send minimal discovery reachability pings across slow
  sides between infrequent full schema/topology/time-source refreshes, and router-managed time sync
  throttles only the measured slow egress while fast sides keep the configured normal cadence.
- Time-sync source/grandmaster role selection is runtime configuration across bindings. Rust can
  set `TimeSyncConfig` at construction or later, C can call `seds_router_configure_timesync(...)`,
  and Python can pass time-sync role/priority/interval keywords or call
  `router.configure_timesync(...)`.
- Router and relay memory limits are now runtime constructor options as well as compile-time
  defaults. Rust exposes `RuntimeMemoryConfig` through router/relay configs, C exposes
  `seds_router_new_with_memory(...)` and `seds_relay_new_with_memory(...)`, and Python `Router`/
  `Relay` constructors accept queue budget, recent-ID, starting-size, and growth overrides.
- The remaining host/prebuilt tuning defaults are runtime configurable. Rust exposes
  `RuntimeTuningConfig`, `runtime_tuning_config(...)`, `set_runtime_tuning_config(...)`, and
  `set_runtime_device_identifier(...)`; C exposes `SedsRuntimeTuningConfig` plus matching get/set
  functions; Python exposes `runtime_tuning_config(...)`, `set_runtime_tuning_config(...)`, and
  runtime device identifier helpers. These cover compression threshold, static string/binary
  sizing, float string precision, handler retries, reliable retransmit timing, and reliable cache
  limits.
- Router identity/address assignment can be configured at runtime across bindings. Python
  constructors accept `hostname`, `address_mode`, and `requested_address`, and C exposes
  `seds_router_configure_address(...)` for dynamic/requested/static address mode changes.
- Topology exports now include a deduplicated `links` graph, named endpoint fields, side names, and
  filtered SEDSnet control endpoints so graphing tools see user-facing network structure instead of
  router-only internals.
- Added explicit leave announcements. Routers and relays can queue `SEDSNET_DISCOVERY_LEAVE` so
  peers prune topology and client stats immediately during planned shutdown or disconnect.
- Added per-client stats snapshots for routers and relays. Rust exposes typed snapshots, Python
  returns dictionaries, and C/C++ expose JSON exports keyed by sender ID. Packet and byte counters
  are aggregated from the side(s) currently reaching the client.
- Added memory-layout JSON exports for routers and relays, including shared allocation/used bytes,
  queue breakdowns, reliable buffers, schema/discovery state, and network-variable cache usage.
- Static JSON config is now runtime seeding only. `SEDSNET_STATIC_SCHEMA_PATH` and
  `SEDSNET_STATIC_IPC_SCHEMA_PATH` can seed the registry at startup, and explicit path/bytes
  APIs are available for Rust/C/Python. Default `build.py` builds do not include application JSON.
- Embedded builds include `telemetry_config.json` bytes only when an application provides that file
  locally before building, then decode those bytes through the normal runtime JSON parser. Builds
  remain publishable without a required local JSON file, and the repo no longer carries a default
  user schema. Downstream applications can still add and package their own schema files
  intentionally.
- Runtime removal APIs can remove user endpoints or data types by ID or name. Built-in internal
  discovery, time-sync, telemetry-error, and reliable-control entries remain protected.
- The checked-in C header is now static for the runtime-schema ABI. Optional reusable C and C++
  convenience wrappers can be selected from upstream CMake without forcing wrapper code into
  projects that only want the raw ABI.
- Built-in runtime endpoint/type names now use the `SEDSNET_*` prefix for router-owned control
  traffic such as `SEDSNET_DISCOVERY`, `SEDSNET_TIME_SYNC`, and `SEDSNET_ERROR`.
- C API coverage now includes router/relay global helper wrappers, network variables, update
  callbacks, cryptography provider registration, software fallback keys, managed credentials,
  runtime sender IDs, fixed-size packed sides, link-probe samples, leave announcements, memory
  layout, client stats, and topology/runtime-stat exports.
- `./build.py test` now auto-detects `cargo-nextest` for non-doctest Rust suites when installed,
  falls back to `cargo test` when it is not, and keeps doctests covered with Cargo's built-in test
  runner.
- Added release automation for crates.io and PyPI. `publish_crates.py` can dry-run or publish the
  ordered `sedsnet_macros`/`SEDSnet` crates, build Python wheels and sdists, build Linux/macOS/
  Windows wheels through Docker or local macOS tooling, and tolerate already-published artifacts so
  rerunning a release does not fail only because an upload previously succeeded.
- PyPI uploads now use Twine instead of maturin's deprecated upload/publish commands. The release
  helper can validate and reuse ignored local PyPI credentials, checks wheel/sdist artifacts before
  upload, and keeps CI and local release paths on the same upload mechanism.
- Updated package metadata for crates.io and PyPI, including package descriptions, README-backed
  long descriptions, keywords, project URLs, license metadata, and release checklist guidance for
  GitHub/GitLab tag builds.
- Benchmark smoke validation still executes Criterion benchmarks, but now uses a dedicated
  `sedsnet_smoke` baseline, longer timing windows, disabled plots, and a wider smoke-test noise
  threshold so normal host variance does not print alternating regression/improvement noise.
- Updated Rust tests and benches to use readable runtime names such as
  `DataEndpoint::named("RADIO")` and `DataType::named("GPS_DATA")` instead of raw legacy IDs.
- Added regression coverage for schema sync, deterministic conflict resolution, budget accounting,
  runtime string lookups, description metadata, handler construction from endpoint definitions,
  runtime schema removal, network-variable getter/setter/cache/callback behavior, crypto
  credentials/providers, topology graph exports, leave pruning, client stats, memory layout,
  fixed-size side splitting, link probing, slow-link discovery/time-sync throttling, and
  nextest-aware test execution.

## 3.12.0

- Queue sizing now uses one shared dynamic `MAX_QUEUE_BUDGET` across router and relay internals
  instead of fixed per-queue caps.
- The compile-time queue knob has been renamed from `MAX_QUEUE_SIZE` to `MAX_QUEUE_BUDGET` to
  match its current meaning; the old environment name remains accepted as a legacy alias.
- Router and relay receive queues, transmit queues, reliable replay/out-of-order buffers, recent
  packet ID tracking, and discovery topology state now all draw from that same budget.
- Recent packet ID caches now preallocate their final storage at construction and reserve
  `min(MAX_RECENT_RX_IDS * sizeof(u64), MAX_QUEUE_BUDGET)` bytes from the shared queue budget.
- Discovery topology growth is bounded by the shared queue budget, and `std` builds emit a warning
  when topology state has to be evicted because the budget is exhausted.
- Ordered reliable receive paths now partial-ACK out-of-order packets so those packets do not get
  timeout-retransmitted while a gap is being recovered.
- Explicit `RELIABLE_PACKET_REQUEST` retransmits still work for partial-ACKed packets, so a packet
  can be held back from timeout traffic without becoming impossible to request again.
- Buffered reliable packets after a missing sequence are retained under the shared queue budget and
  released immediately once the missing packet arrives.
- Router and relay side-TX contention is now treated as transient backpressure: pending work is
  requeued and retried instead of surfacing an intermittent handler failure.
- Added regression coverage for shared queue-budget accounting, discovery topology budget pressure,
  partial reliable ACK behavior, side-TX busy retry handling, and the previously flaky threaded
  system flow.

## 3.11.1

- Discovery now carries a full transitive router graph with the built-in
  `DISCOVERY_TOPOLOGY` control packet instead of exporting only flattened side reachability.
- Routers and relays now preserve which sender IDs own which endpoints, which time-sync source IDs
  belong to which router, and which routers are connected to each other when that topology is
  forwarded across the network.
- `export_topology()` now exposes:
    - a top-level `routers` list with per-router endpoints, time-sync source IDs, and connections
    - per-side announcer detail so applications can see which upstream router advertised each
      portion of the graph
- Added client-facing topology export parity:
    - Python `Router.export_topology()` / `Relay.export_topology()`
    - C `seds_router_export_topology[_len]` / `seds_relay_export_topology[_len]` JSON exports
- Updated discovery, time-sync, Rust, Python, and C/C++ documentation to describe the richer
  topology model and export surfaces.

## 3.11.0

- Removed `RouterMode` from the active router model and moved router forwarding fully onto the
  same runtime route-rule system already used by `Relay`.
- Routers now default to a full forwarding mesh when no explicit route rules are installed, and
  discovery-driven multi-path routing now defaults to adaptive load balancing for normal traffic.
- Reliable delivery is now end-to-end verified in addition to the existing per-link reliable
  transport. Source routers retain locally-originated reliable packets until every currently
  discovered destination holder confirms local delivery.
- Destination routers now emit directed end-to-end reliable acknowledgements, and routers/relays
  learn return paths from reliable ingress traffic so those acknowledgements are routed only to the
  side that needs them instead of flooding unrelated links.
- When one discovered destination holder has already acknowledged, retries are narrowed to only the
  holders that are still outstanding instead of replaying to all holders again.
- If discovery later ages out one of those holders, the source drops that holder from the
  in-flight obligation set so the transaction completes instead of replaying forever toward a board
  that has disappeared from the topology view.
- Relays now prune their learned per-packet holder-ACK state against the same discovery view, so
  stale holder confirmations do not survive topology expiry or distort later route decisions.
- The end-to-end layer keeps the non-blocking reliable-stream behavior from `3.10.0`: waiting for
  holder ACKs does not stall the side/type lane for newer reliable packets.
- Added regression coverage for the new default routing model, adaptive discovery balancing, route
  disabling in place of sink-mode behavior, end-to-end reliable acknowledgement recovery for both
  single-destination and multi-holder delivery in the Rust system tests, and holder-expiry cleanup
  in both router and relay unit tests.
- Expanded documentation for testing, including unit tests, Rust system tests, C system tests, and
  local code-coverage reporting with `cargo llvm-cov`.

## 3.10.0

- Reworked reliable delivery in both `Router` and `Relay` to use built-in internal
  `RELIABLE_ACK` and `RELIABLE_PACKET_REQUEST` packet types instead of wire-only ACK-only frames.
- Reliable senders no longer block a side/type lane on one inflight packet. New reliable packets can
  continue sending while missing ordered packets are requested and retransmitted.
- Ordered reliable receive paths now buffer out-of-order frames, request the specific missing
  sequence, and release buffered packets once the gap is filled.
- Retransmits are now requeued with temporarily elevated priority instead of being sent as an
  exclusive inflight retry path, which improves recovery under mixed traffic and multi-destination
  fanout.
- Added regression coverage for non-blocking reliable send, router and relay retransmit recovery,
  and the new internal reliable control flow in both unit and system-style tests.
- Updated README and technical docs to describe the new internal reliable control packets and
  non-blocking retransmit behavior.

## 3.9.1

- Reserved the built-in `DISCOVERY` and `TIME_SYNC` endpoints for router-owned control traffic so
  user code can no longer register local handlers that shadow or distort internal discovery and
  time-sync behavior.
- `RouterConfig`, `EndpointHandler`, and the C router constructor now reject attempts to register
  handlers on those internal endpoints.
- Tightened combined queue processing so nonzero timeout budgets are split across TX and RX work,
  while `timeout_ms == 0` still drains both queues fully.
- Added regression coverage for queued discovery route learning, time-sync source learning, queue
  starvation prevention, and reserved-endpoint rejection in both Rust and the C ABI.
- Updated Rust and C/C++ docs to document that discovery and time sync are router-internal and
  not user-overridable.

## 3.9.0

- Added manual `DataType`-specific routing controls for both `Router` and `Relay` across Rust, C,
  and Python.
- Typed route rules now let a deployment restrict a given `(local TX or source side, data type)`
  to one or many explicitly selected destination sides, enabling dedicated links for commands,
  aborts, or other special traffic classes.
- Typed route allowlists layer on top of the existing side-level route policy, ingress/egress
  policy, and discovery/path-selection logic rather than bypassing them.
- Added regression coverage for router and relay typed-route fanout, fallback after clearing typed
  rules, precedence against base route disables, and matching C ABI coverage.
- Updated Rust, Python, C/C++, and technical routing documentation to describe the new typed-route
  APIs and routing precedence.

## 3.8.0

- Added path-selection policies for both `Router` and `Relay` across Rust, C, and Python.
- New source-side route modes let traffic keep current fanout behavior, split across multiple
  discovered paths with weighted round-robin, or use single-active failover routing.
- Per-route weights and priorities can now be configured at runtime, so deployments can do
  non-50/50 load balancing or choose a preferred primary link with ordered backups.
- Path failover now follows discovery liveness, side removal, and side disable state, so traffic
  automatically shifts to remaining eligible paths when a discovered path disappears.
- Added regression coverage for weighted split and failover behavior in both router and relay
  paths, including C ABI coverage.

## 3.7.0

- Added runtime side routing controls for both `Router` and `Relay` across Rust, C, and Python.
- `Relay` now also supports `remove_side(...)`, bringing side lifecycle parity with `Router`
  across Rust, C, and Python while preserving stable side IDs.
- Routers and relays now support per-side `ingress_enabled` and `egress_enabled` policy, so a
  deployment can use many RX sides while limiting TX to one or a selected subset of sides.
- Added runtime route overrides for `(local TX or source side) -> destination side`, enabling
  one-way relay paths such as `A -> B` while blocking `B -> A`, plus selective exclusion of
  specific sides from locally-originated traffic on both routers and relays.
- Default routing behavior still matched the older router model at this point: `RouterMode::Relay`
  initialized as a full side-to-side mesh, while `RouterMode::Sink` kept RX-side forwarding
  disabled unless routing was explicitly enabled.
- Discovery announcements now respect the active per-side egress policy and local route overrides,
  so advertised topology follows the currently allowed output links for both routers and relays.
- Added regression coverage for asymmetric routing, ingress-disabled sides, and the new C ABI
  runtime routing controls, including relay coverage.

## 3.6.0

- Added router-side removal APIs across Rust, C, and Python with stable side IDs preserved for
  surviving sides.
- Removed router sides are now tombstoned internally so stale side IDs stop routing traffic
  without forcing side ID renumbering.
- Removing a side now purges queued ingress/egress work plus reliable/discovery state associated
  with that side.
- Discovery topology changes caused by router side add/remove now immediately reschedule discovery
  announcements so peers learn newly available or remaining endpoint mappings faster.
- Added regression coverage for router-side removal, discovery topology export after removal, and
  the C ABI side-removal path.

## 3.5.2

- Fixed router-managed time sync failover so a consumer clears stale pending sync requests when
  the selected remote source disappears or leadership changes.
- This resolves a reconnection case where a consumer could continue holding over on an old source
  and fail to issue a new `TIME_SYNC_REQUEST` to the replacement source until rebooted.
- Added regression coverage for remote-source failover to ensure the replacement source is
  re-requested and accepted after timeout-driven re-election.

## 3.5.1

- Added consolidated router maintenance helpers: `periodic(timeout_ms)` and
  `periodic_no_timesync(timeout_ms)`. These bundle discovery polling and queue draining, and the
  latter lets applications skip time-sync maintenance for a loop iteration without disabling the
  feature globally.
- Added relay `periodic(timeout_ms)` to bundle discovery polling and queue draining into one main
  loop call.
- Exposed the new periodic APIs through the C ABI and Python bindings so Rust, C, and Python users
  have matching main-loop maintenance entry points.
- Updated Rust, C/C++, Python, and time-sync documentation to prefer the periodic helpers for
  ordinary application loops while keeping `poll_timesync()` / `poll_discovery()` documented as
  lower-level hooks.

## 3.5.0

- Removed schema-level `broadcast_mode` from the active telemetry schema model. Routing is now determined by discovery
  state and link-local scope instead of a per-endpoint broadcast policy.
- Added automatic upgrade handling for older schemas that still include `broadcast_mode`. `Never` now normalizes to
  `link_local_only = true`, while `Default` and `Always` are accepted as legacy no-ops.
- Kept proc-macro schema loading and `build.rs` schema loading behavior aligned so Rust codegen and generated bindings
  interpret legacy schemas the same way.
- Updated relay routing so discovered remote endpoint matches are targeted selectively, while non-local traffic can
  still bootstrap through fallback flooding before discovery converges.
- Restored release-test coverage for the discovery plus timesync path after the routing change;
  `./build.py test release` passes with the new behavior.
- Added `./build.py check`, which runs `cargo clippy -D warnings` across the default, python, and embedded builds, and
  folded that clippy coverage into `./build.py test`.
- Fixed the static C ABI header so the checked-in header includes the current logging entry points, including
  `seds_router_log_typed`, `seds_router_log_queue_typed`, `seds_router_log_bytes`, and `seds_router_log_f32`.
- Moved `C-Headers/sedsnet.h` to a static runtime-schema ABI header so user data types and endpoints are resolved
  by runtime registration instead of generated schema constants.
- Updated Python stub generation and example telemetry code to match the current public ABI and discovery helpers.
