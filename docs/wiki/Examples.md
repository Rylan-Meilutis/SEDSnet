# Examples (Easy)

This page points to runnable examples and suggests a learning path.
For protocol details and role behavior, see [Time-Sync](Time-Sync).

## C/C++ example

- [C example directory](https://github.com/Rylan-Meilutis/sedsnet/tree/main/c-example-code)
- [Main router example](https://github.com/Rylan-Meilutis/sedsnet/blob/main/c-example-code/src/main.c)
- [Time-sync example](https://github.com/Rylan-Meilutis/sedsnet/blob/main/c-example-code/src/timesync_example.c)
- [Load-balancing example](https://github.com/Rylan-Meilutis/sedsnet/blob/main/c-example-code/src/load_balancing_example.c)
- [Managed-variable and E2E C example](https://github.com/Rylan-Meilutis/sedsnet/blob/main/c-example-code/src/managed_variables_e2e_example.c)
- [Managed-variable and E2E C++ example](https://github.com/Rylan-Meilutis/sedsnet/blob/main/c-example-code/src/managed_variables_e2e_example.cpp)

What it demonstrates:

- Building and linking the staticlib.
- Creating and sending packets.
- Receiving and dispatching to handlers.
- Time sync announce/request/response and offset math.
- Managed-variable latest-value resync, bounded packed sides, and E2E policy configuration.
- Runtime memory, tuning, device identity, time-sync role, and address configuration through the C
  ABI.

Suggested first steps:

1. Build the library with [build.py](https://github.com/Rylan-Meilutis/sedsnet/blob/main/build.py)
   or CMake.
2. Compile the example and run it locally.
3. Watch the output to see packet creation and handling.

## Python example

- [Python example directory](https://github.com/Rylan-Meilutis/sedsnet/tree/main/python-example)
- [Main example](https://github.com/Rylan-Meilutis/sedsnet/blob/main/python-example/main.py)
- [Time-sync example](https://github.com/Rylan-Meilutis/sedsnet/blob/main/python-example/timesync_example.py)
- [Load-balancing example](https://github.com/Rylan-Meilutis/sedsnet/blob/main/python-example/load_balancing_example.py)
- [Typed-routing example](https://github.com/Rylan-Meilutis/sedsnet/blob/main/python-example/typed_routing_example.py)
- [Managed-variable and E2E example](https://github.com/Rylan-Meilutis/sedsnet/blob/main/python-example/managed_variables_e2e_example.py)
- [P2P service example](https://github.com/Rylan-Meilutis/sedsnet/blob/main/python-example/p2p_service_example.py)
- [Manual system-suite entry point](https://github.com/Rylan-Meilutis/sedsnet/blob/main/python-example/test.py)
- [System-suite implementation](https://github.com/Rylan-Meilutis/sedsnet/blob/main/python-example/system_suite.py)
- [Shared schema helpers](https://github.com/Rylan-Meilutis/sedsnet/blob/main/python-example/schema_helpers.py)

What it demonstrates:

- Installing the Python package.
- Logging packets and decoding values.
- Looking up runtime schema names and using the returned IDs.
- Type-specific routing to two dedicated command links without weighted or failover path selection.
- Time sync announce/request/response and offset math.
- P2P service delivery by hostname and assigned address.
- A manual Python system suite covering runtime schema, discovery, route weights, side replacement,
  P2P, network variables, and memory-budget reporting.
- Managed-variable latest-value resync and E2E router/type policy settings.
- Runtime tuning, device identifier, memory budget, time-sync role, and address configuration.

Suggested first steps:

1. Build Python bindings with `./build.py python` or `./build.py maturin-install`; see
   [build.py](https://github.com/Rylan-Meilutis/sedsnet/blob/main/build.py).
2. Run the example script.
3. Inspect printed packets to see decoded values.

## Rust example (minimal)

If you want a minimal Rust example, start with [Usage-Rust](Usage-Rust) and build a small router with one endpoint
handler. The files are standalone sources to copy or register as Cargo examples; see the
[Rust example index](https://github.com/Rylan-Meilutis/sedsnet/blob/main/rust-example-code/README.md)
for the complete inventory and run instructions.

The runtime-config example shows how to configure active device identity, process-wide tuning,
router/relay memory budgets, time-sync roles, and address assignment without rebuilding the crate.
The typed-routing example shows one practical pattern: ordinary telemetry stays on its normal link,
while a command-like packet type is manually fanned out to two dedicated sides that both reach the
same remote destination. It uses `set_typed_route(...)` only, so there is no load balancing or
failover policy involved.

## RTOS time sync examples

- [FreeRTOS time-sync example](https://github.com/Rylan-Meilutis/sedsnet/blob/main/rtos-example-code/freertos_timesync.c)
- [ThreadX time-sync example](https://github.com/Rylan-Meilutis/sedsnet/blob/main/rtos-example-code/threadx_timesync.c)
- [ThreadX telemetry example](https://github.com/Rylan-Meilutis/sedsnet/blob/main/rtos-example-code/threadx_telemetry.c)

Recommended structure:

- Define one `EndpointHandler` for a single `DataEndpoint`.
- Create a router with no remote sides for local-only logging, or add sides and control forwarding
  with runtime route rules.
- Call `log_*` with a typed payload.
- Call `rx_packed` with the bytes you just sent (loopback).

## Recommended path

1. Read [Overview](Overview).
2. Read [Concepts](Concepts).
3. Try one example in your target language.
4. Read [Technical-Architecture](Technical-Architecture) for the implementation details.
