# Testing

This page describes the test layers in this repo, what each layer covers, and how to collect local
coverage numbers.

## Recommended top-level command

For normal local validation, use:

```bash
./build.py test
```

That runs:

- strict `cargo clippy -D warnings` checks for the default host build, the `python` feature build,
  and the embedded-feature build when the matching cross toolchain exists
- `cargo nextest run --features timesync` when cargo-nextest is installed, otherwise
  `cargo test --features timesync`
- `cargo test --doc --features timesync` when nextest is used
- a stable Criterion smoke pass for benchmark target validation
- `cargo build --features python`
- embedded build validation when the target toolchain is available

## Test layers

The repo intentionally uses several layers instead of relying on one giant end-to-end test.

### Unit tests

The unit tests live primarily in `src/tests.rs`.

They cover:

- packet construction, validation, packing, and unpacking
- queue behavior, timeout budgeting, and dedupe
- runtime routing policy, typed routes, route selection modes, and discovery-informed forwarding
- network-variable getter/setter permissions, tiered cache refresh, and update callbacks
- topology graph export, control-endpoint filtering, leave-announcement pruning, client stats, and
  memory-layout snapshots
- fixed-size packed side splitting/reassembly and side-local header-template compaction
- E2E payload cryptography policies, software fallback crypto, multi-holder encrypted fanout, and
  tamper rejection
- router and relay reliable-delivery internals
- C ABI behavior that can be exercised directly from Rust tests
- time-sync internals when the `timesync` feature is enabled

These are the fastest feedback loop and are the main regression net for routing/reliability logic.

### Rust system tests

The Rust system tests live under `tests/rust-system-test/`.

They exercise multi-node flows that are awkward to validate in a single unit test, including:

- router-to-router packed links
- router-to-relay-to-router forwarding
- discovery convergence and multi-hop routing
- reliable delivery under dropped frames and retransmit recovery
- end-to-end reliable acknowledgement routing without flooding unrelated sides
- time-sync election, failover, and multi-node clock behavior
- time-sync convergence across constrained scheduler models such as RFBOARD26-style TDMA slots,
  high-latency FIFO radios, bursty shared serial links, and CAN-FD tick scheduling, with assertions
  that each modeled board converges to an accurate clock and that slow links are not monopolized by
  time-sync traffic
- compression and memory-pool behavior
- runtime router/relay memory-budget enforcement, including exported memory-layout checks that
  queued state stays within the configured shared queue budget under pressure

These tests validate behavior closer to how the crate is actually embedded into larger systems.

### C system tests

The C system test harness lives in `tests/c-system-test/` and executes the static C ABI through
compiled test binaries.

It covers:

- C API construction and teardown
- handler registration and logging APIs
- router and relay side registration
- multi-node forwarding through the exported ABI
- discovery and time-sync behavior from the C caller’s point of view

This is the compatibility net for the C interface, not just the Rust core.

### Benchmark smoke tests

`./build.py test` also runs stable Criterion benchmark smoke passes for:

- `benches/packet_paths.rs`
- `benches/router_system_paths.rs`

These are not pass/fail performance gates today. They are there to catch obvious pathological
regressions in hot paths while still keeping the test command practical for local use. The smoke
runner saves into a dedicated `sedsnet_smoke` baseline, disables plots, uses a longer measurement
window than the old fast smoke path, and applies a wider noise threshold so normal host variance
does not show up as alternating regression/improvement noise against the default benchmark baseline.

## Reliability coverage

Reliable delivery is covered at multiple levels:

- unit tests validate per-link ACK/retransmit ordering, unordered delivery, and retransmit queueing
- relay tests validate multi-hop reliable forwarding
- Rust system tests validate dropped-frame recovery and end-to-end acknowledgement routing

As of `3.11.0`, reliable delivery also includes an end-to-end verification layer on top of the
existing per-link reliable transport:

- the source router keeps an in-flight record for reliable packets it originated
- each discovered destination holder emits a directed end-to-end acknowledgement when a reliable
  packet reaches a local handler
- routers and relays learn reliable return paths from reliable ingress traffic and route those
  acknowledgements only toward the source side that needs them
- unrelated sides do not receive those end-to-end acknowledgements
- system coverage includes a multi-holder regression where one destination ACK is dropped and the
  source keeps retransmitting only toward that still-outstanding holder
- unit coverage also verifies that when discovery later ages out a holder, the router drops that
  holder from the in-flight obligation set and stops treating it as pending
- relay unit coverage verifies that stale learned holder-ACK state is also removed when discovery
  expires that holder from the topology view

## Coverage numbers

This repo does not currently fail CI on a minimum percentage threshold. Coverage is regression
driven rather than percentage gated.

If you want a local HTML report, use:

```bash
cargo llvm-cov --features timesync --workspace --html
```

That writes the report under `target/llvm-cov/html/`.

If you want a summary in the terminal:

```bash
cargo llvm-cov --features timesync --workspace
```

## Useful commands

Fast local loops:

```bash
cargo test --lib
cargo test --test reliable_drop_test
cargo test --test rust-system-test
```

If installed, nextest is the preferred fast runner for non-doctest suites:

```bash
cargo nextest run --features timesync
```

`./build.py test` auto-detects nextest. Set `SEDSNET_TEST_RUNNER=cargo` to force Cargo's
built-in runner, or `SEDSNET_TEST_RUNNER=nextest` to require nextest.

Ignored long-form soak:

```bash
cargo test --test reliable_drop_test comprehensive_multinode_churn_soak_exercises_stack_features -- --ignored --nocapture
```

This deterministic multi-node soak is intentionally ignored by default because the normal settings
simulate several virtual minutes of unreliable network behavior. It exercises gateway and RF relay
paths, links with different bandwidth budgets, random disconnect/reconnect windows, planned side
disable/enable windows, temporary side add/remove operations, discovery and topology export,
source and typed route policies, reliable recovery, network-variable cache propagation, large
dynamic payload forwarding, side-transport compaction/chunking, time-sync configuration, runtime
stats, memory-layout export, and E2E crypto when the `cryptography` feature is enabled.

The soak can be shortened for local iteration:

```bash
SEDSNET_SOAK_TICKS=160 SEDSNET_SOAK_TICK_MS=250 cargo test --test reliable_drop_test comprehensive_multinode_churn_soak_exercises_stack_features -- --ignored --nocapture
```

`SEDSNET_SOAK_TICKS` controls how many virtual ticks run before the recovery drain, and
`SEDSNET_SOAK_TICK_MS` controls the virtual milliseconds advanced per tick.

Broader validation:

```bash
cargo test
./build.py test
```
