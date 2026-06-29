# Build and Configure

This page explains how to build the library and how build-time/runtime configuration works across Rust, C/C++, and
Python.

## Build tooling (build.py)

The repo includes
build.py ([source](https://github.com/Rylan-Meilutis/sedsnet/blob/main/build.py)),
a wrapper around Cargo and Maturin that:

- Sets packaged default environment variables (e.g., `DEVICE_IDENTIFIER`).
- Enables feature flags (`embedded`, `python`).
- Optionally installs missing Rust targets via `rustup`.
- Produces consistent output for CI and local builds.

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

Useful options:

- `check` runs `cargo clippy -D warnings` for the default, python, and embedded builds.
- `test` runs the same clippy checks, then:
    - `cargo nextest run --features timesync` when cargo-nextest is installed, otherwise
      `cargo test --features timesync`
    - `cargo test --doc --features timesync` when nextest is used, since nextest does not run doctests
    - a stable Criterion smoke pass for `packet_paths` and `router_system_paths`
    - `cargo build --features python`
    - `cargo build --no-default-features --target <embedded-target> --features embedded` when a matching cross C
      toolchain is available
- `device_id=<id>` sets the packaged `DEVICE_IDENTIFIER` default for the build.
- `static_schema_path=<path>` sets `SEDSNET_STATIC_SCHEMA_PATH` for runtime registry seeding.
- `static_ipc_schema_path=<path>` sets `SEDSNET_STATIC_IPC_SCHEMA_PATH` for a runtime IPC/link-local seed.
- `max_stack_payload=<n>` sets `MAX_STACK_PAYLOAD` for inline payload storage.
- `cryptography` is enabled by default and provides the cryptography provider APIs.
- `env:KEY=VALUE` passes any compile-time env var used by
  src/config.rs ([source](https://github.com/Rylan-Meilutis/sedsnet/blob/main/src/config.rs)).
- `target=<triple>` sets the Rust target triple for embedded builds.

## Cargo features

From
Cargo.toml ([source](https://github.com/Rylan-Meilutis/sedsnet/blob/main/Cargo.toml)):

- `std` (default): host build with std.
- `embedded`: enables embedded defaults, `timesync`, and no_std-friendly behavior.
- `python`: enables pyo3 bindings.
- `compression` (default): enables payload compression (implemented with `zstd-safe`).
- `timesync`: enables time sync helpers and built-in time sync packet types.
- `cryptography` (default): enables Rust cryptography provider helpers plus optional C callback registration APIs.

Examples:

- Disable compression: `default-features = false` and omit `compression`.
- Embedded + compression: enable both `embedded` and `compression`.

Compression notes:

- Compression is opportunistic (only used when it reduces size).
- Backend is fixed to `zstd-safe` for simplicity/consistency across builds.
- There is no compression-level build option.
- For cross-target embedded builds, enabling `compression` requires a usable target C toolchain
  (for `zstd-sys`, e.g. `arm-none-eabi-gcc` or `CC_<target>` override).

When `timesync` is enabled, the build adds the `SEDSNET_TIME_SYNC` endpoint and
`SEDSNET_TIME_SYNC_*` packet types directly in code (like `SEDSNET_ERROR`), plus the router-managed
internal network clock and FFI accessors for current network time. See [Time-Sync](Time-Sync)
for roles, packet fields, internal clock behavior, and master-side setter APIs.

Python builds via `maturin` in this repo enable `timesync` by default (see
pyproject.toml ([source](https://github.com/Rylan-Meilutis/sedsnet/blob/main/pyproject.toml))).

## Test coverage and what runs

`./build.py test` is the intended top-level validation command for local development and CI-style checks in this repo.
It covers four layers:

- Static analysis: strict `cargo clippy -D warnings` for default, `python`, and embedded variants.
- Rust unit and integration tests: `cargo nextest run --features timesync` when available, otherwise
  `cargo test --features timesync`, including `src/tests.rs`, Rust system tests in `tests/rust-system-test/`,
  and the Rust harness that configures and runs the C system tests in `tests/c-system-test/c_system_test.rs`.
- Benchmark smoke: run Criterion benchmarks into a dedicated `sedsnet_smoke` baseline, with plot generation
  disabled, longer timing than the old fast path, and a wider smoke-test noise threshold so validation exercises
  benchmark code without treating normal workstation variance as a regression.
- Build validation: host `python` feature build and embedded-feature build when an embedded cross C toolchain is
  present.

The C system tests exercise the static C ABI, multi-endpoint routing, relay forwarding, discovery, and time-sync
behavior through compiled executables in `c-system-test/`. The main multi-node C test now waits for every asserted
endpoint count before shutdown so it does not fail early when one simulated board drains slightly slower than another.

The Rust system tests under `tests/rust-system-test/` cover the higher-level multi-node behaviors that matter most for
regressions:

- router-to-router and router-to-relay forwarding
- discovery route learning and selective forwarding
- adaptive multi-path routing
- reliable dropped-frame recovery
- end-to-end reliable verification and directed ACK return-path routing
- time-sync election, failover, and multi-node convergence

`src/tests.rs` also includes a combined multi-node memory exhaustion regression. It constructs
multiple routers with small `RuntimeMemoryConfig` pools, injects large discovery topology updates,
queues telemetry RX/TX work, and asserts each router's exported memory layout remains within its
configured shared queue budget throughout the pressure run.

This repo does not currently publish or gate on a single required coverage percentage in `build.py test`. Coverage is
tracked primarily through regression tests across unit, Rust system, and C system layers. If you want a local
percentage/HTML report, use `cargo-llvm-cov`:

```bash
cargo llvm-cov --features timesync --workspace --html
```

That produces a local report under `target/llvm-cov/html/`.

For a fuller description of the test layers and recommended commands, see [Testing](Testing).

## Device identifier

Every build embeds a default `DEVICE_IDENTIFIER`. In v4 that name is discovery/config metadata; packed frames route by
compact address and do not repeat the hostname on every packet. Runtime APIs can override the active default or an
individual router/relay identity.

Recommended (Rust):

```
# .cargo/config.toml
[env]
DEVICE_IDENTIFIER = "GROUND_STATION_26"
```

CMake:

```
set(SEDSNET_DEVICE_IDENTIFIER "FC26_MAIN" CACHE STRING "" FORCE)
```

build.py ([source](https://github.com/Rylan-Meilutis/sedsnet/blob/main/build.py)):

```
./build.py release device_id=GROUND_STATION
```

Runtime overrides:

- Rust: `set_runtime_device_identifier("GROUND_STATION")`, `RouterConfig::with_sender(...)`, and
  `RelayConfig::with_sender(...)`.
- C: `seds_set_runtime_device_identifier(...)`, `seds_router_set_sender_id(...)`,
  `seds_relay_set_sender_id(...)`, and `seds_router_configure_address(...)`.
- Python: `sedsnet.set_runtime_device_identifier(...)`, `Router(hostname=..., address_mode=...,
  requested_address=...)`, `router.set_sender_id(...)`, and `router.configure_address(...)`.

## Runtime and compile-time configuration

Configuration values are read via `option_env!` in
src/config.rs ([source](https://github.com/Rylan-Meilutis/sedsnet/blob/main/src/config.rs)).
You can set them via `.cargo/config.toml`,
`build.py env:KEY=VALUE`, or CMake `SEDSNET_ENV_<KEY>` variables.

These values are packaged defaults, not fixed board behavior for host/prebuilt builds. The active node can change
identity, time-sync role, memory pool limits, retry/reliable queue limits, string/binary static sizing, float string
precision, and compression threshold at runtime. `MAX_STACK_PAYLOAD` is the exception: it defines the compiled inline
payload capacity used by the stack-backed payload type, so runtime configuration can choose behavior up to that compiled
capacity but cannot enlarge the type layout after compilation.

Supported keys (defaults shown):

- `DEVICE_IDENTIFIER` (TEST_PLATFORM)
- `MAX_RECENT_RX_IDS` (128)
- `STARTING_QUEUE_SIZE` (128 bytes)
- `MAX_QUEUE_BUDGET` (102400 bytes)
- `QUEUE_GROW_STEP` (3.2)
- `PAYLOAD_COMPRESS_THRESHOLD` (16 bytes)
- `STATIC_STRING_LENGTH` (1024)
- `STATIC_HEX_LENGTH` (1024)
- `STRING_PRECISION` (8)
- `MAX_STACK_PAYLOAD` (64, via `define_stack_payload!`)
- `MAX_HANDLER_RETRIES` (3)
- `RELIABLE_RETRANSMIT_MS` (250)
- `RELIABLE_MAX_RETRIES` (8)
- `RELIABLE_MAX_PENDING` (64)
- `RELIABLE_MAX_RETURN_ROUTES` (64)
- `RELIABLE_MAX_END_TO_END_PENDING` (`RELIABLE_MAX_PENDING`)
- `RELIABLE_MAX_END_TO_END_ACK_CACHE` (`MAX_RECENT_RX_IDS`)

`MAX_QUEUE_BUDGET`, `MAX_RECENT_RX_IDS`, `STARTING_QUEUE_SIZE`, and `QUEUE_GROW_STEP` are defaults,
not the only way to size a node. Rust can pass `RuntimeMemoryConfig` through
`RouterConfig::with_memory_config(...)` or `RelayConfig::with_memory_config(...)`. C can use
`seds_router_new_with_memory(...)` and `seds_relay_new_with_memory(...)`. Python can pass
`max_queue_budget`, `max_recent_rx_ids`, `starting_queue_size`, and `queue_grow_step` to
`Router(...)` or `Relay(...)`.

The remaining active tuning values are process-wide runtime settings:

- Rust: `runtime_tuning_config()` and `set_runtime_tuning_config(RuntimeTuningConfig { ... })`.
- C: `seds_get_runtime_tuning_config(...)` and `seds_set_runtime_tuning_config(...)`.
- Python: `sedsnet.runtime_tuning_config()` and `sedsnet.set_runtime_tuning_config(...)`.

The active queue budget is the shared queue-owned memory budget for each router or relay. RX queues,
TX queues, reliable replay/out-of-order buffers, and discovery topology state draw from this budget
dynamically. The recent packet ID cache preallocates
`min(max_recent_rx_ids * sizeof(u64), max_queue_budget)` bytes at construction and reserves that
amount from the same budget.

`MAX_QUEUE_SIZE` is still accepted as a legacy environment alias for the default budget, but new
builds should use `MAX_QUEUE_BUDGET`, `build.py max_queue_budget=<n>`, or CMake
`SEDSNET_MAX_QUEUE_BUDGET` only when they want to change the packaged default.

## Runtime telemetry schema

v4 removes compile-time user schema generation. `build.rs` no longer turns
`telemetry_config.json` into application-specific Rust enum variants or binding constants.

Default builds start with only built-in internal entries:

- telemetry error endpoint/type
- reliable-control packet types
- discovery endpoint/types
- time-sync endpoint/types when `timesync` is enabled

Applications add user endpoints and data types at runtime:

- Rust registration APIs in `config`
- C ABI registration APIs
- Python registration APIs
- JSON seeding through env, path, or bytes
- discovery schema sync from peers

Runtime JSON seeding options:

- `SEDSNET_STATIC_SCHEMA_PATH=/path/to/telemetry_config.json`
- `SEDSNET_STATIC_IPC_SCHEMA_PATH=/path/to/ipc_config.json`
- Rust `register_schema_json_path(...)` / `register_schema_json_bytes(...)`
- C `seds_schema_register_json_file(...)` / `seds_schema_register_json_bytes(...)`
- Python `register_schema_json_file(...)` / `register_schema_json_bytes(...)`

Embedded builds include `telemetry_config.json` bytes only when an application provides that file
locally before building, then parse those bytes at runtime. The default crate build does not require
or include application JSON.

## CMake integration

CMakeLists.txt ([source](https://github.com/Rylan-Meilutis/sedsnet/blob/main/CMakeLists.txt))
invokes
build.py ([source](https://github.com/Rylan-Meilutis/sedsnet/blob/main/build.py))
and exposes variables for embedded builds.

Common CMake variables:

- `SEDSNET_EMBEDDED_BUILD` (ON/OFF)
- `SEDSNET_FORCE_RELEASE` (ON/OFF, forces Cargo release profile even under a Debug parent build)
- `SEDSNET_TARGET` (Rust target triple)
- `SEDSNET_DEVICE_IDENTIFIER`
- `SEDSNET_MAX_STACK_PAYLOAD`
- `SEDSNET_ENABLE_C_WRAPPER` (ON/OFF, builds `sedsnet::c_wrapper`)
- `SEDSNET_ENABLE_CPP_WRAPPER` (ON/OFF, exposes `sedsnet::cpp_wrapper`)
- `SEDSNET_ENABLE_CRYPTOGRAPHY` (ON/OFF, enables `cryptography` and defines `SEDS_ENABLE_CRYPTOGRAPHY`)
- `SEDSNET_ENV_<KEY>` for any config env var

After `add_subdirectory`, link the target:

```
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE sedsnet::sedsnet)
```

Projects that do not want a git submodule can fetch SEDSnet directly from GitHub with CMake
`FetchContent`:

```cmake
include(FetchContent)

set(SEDSNET_EMBEDDED_BUILD ON CACHE BOOL "" FORCE)
set(SEDSNET_TARGET "thumbv7em-none-eabihf" CACHE STRING "" FORCE)
set(SEDSNET_FORCE_RELEASE ON CACHE BOOL "" FORCE)
set(SEDSNET_ENABLE_C_WRAPPER ON CACHE BOOL "" FORCE)

FetchContent_Declare(
    sedsnet
    GIT_REPOSITORY https://github.com/Rylan-Meilutis/SEDSnet.git
    GIT_TAG v4.0.2
)
FetchContent_MakeAvailable(sedsnet)

target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE sedsnet::sedsnet)
```

Set all `SEDSNET_*` cache variables before `FetchContent_MakeAvailable(sedsnet)`. Pin
`GIT_TAG` to a release tag or commit SHA for repeatable builds.

## Python builds

Python bindings are built with `maturin`.

Options:

- `./build.py python` (develop build)
- `./build.py maturin-build` (wheel)
- `./build.py maturin-install` (build + install)

If you use `maturin develop` directly, ensure you are in the correct virtualenv.

## Build.rs behavior (advanced)

build.rs ([source](https://github.com/Rylan-Meilutis/sedsnet/blob/main/build.rs))
is intentionally minimal in v4. It tracks build environment keys and whether optional embedded
JSON bytes are available. It does not generate user schema constants.

Use runtime JSON seeding for schema paths instead of build-script schema overrides.

## Embedded allocator hooks

Bare-metal builds expect the following symbols to be provided by the host environment:

- `void *telemetryMalloc(size_t)`
- `void telemetryFree(void *)`
- `void telemetry_lock(void)`
- `void telemetry_unlock(void)`
- `void seds_error_msg(const char *, size_t)`
- `void telemetry_panic_hook(const char *, size_t)`

See [Usage-C-Cpp](Usage-C-Cpp) for an example stub implementation.
