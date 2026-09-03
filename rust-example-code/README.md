# Rust Examples

These files are standalone examples rather than registered Cargo targets. Copy or symlink the one
you want into an application's `examples/` directory, then build it with the features it needs. For
example, after copying `timesync_example.rs` to `examples/timesync_example.rs`:

- `cargo run --features timesync --example timesync_example`

The examples in this directory are:

- `runtime_config_example.rs`: runtime device identity, tuning, memory budget, time-sync role,
  address assignment, and relay/router config.
- `load_balancing_example.rs`: weighted split and failover route selection.
- `typed_routing_example.rs`: route one packet type through two dedicated sides without load balancing.
- `relay_example.rs`: basic relay side wiring.
- `multinode_sim_example.rs`: multi-node simulation.
- `reliable_example.rs`: packed-side reliability and retransmission behavior.
- `queue_timeout_example.rs`: bounded queue processing with timeout budgets.
- `timesync_example.rs`: time-sync packet creation and offset/delay calculation.
- `managed_variables_e2e_example.rs`: managed-variable resync plus E2E router/type policy.
