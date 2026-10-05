# Compact packet store development validation

The optional arena and indexed codec shipped in 4.1.0 as experimental features.
The development results below are not a hardware qualification.

On 2026-10-05 the default, compact arena, and compact compression Rust suites
passed, along with minimal std, ARM embedded (plain and codec), and Python
build checks. Regression coverage includes pinned addresses during compaction,
shared ownership, arena/handle exhaustion, partial range reads, fixed workspace
budgets, no compression expansion, and no post-startup allocation in plain
store/read/compact operations. Router and Relay pressure tests verify that
refused admission does not prevent retained frames from draining and retrying.

Jupiter ran `bounded_codec_pressure_soak` for 600 wall-clock seconds: 14,674,011
rounds, 229,282 deliberate oversized-request refusals, and zero live bytes or
handles after draining. Scratch/context reservation stayed fixed at 126,895
bytes for 128-byte chunks on the native host. This is a substantial startup cost;
measure the ARM configuration against Gateway's 112 KiB total RAM before
enabling the codec. No Gateway compression configuration is qualified.
Ordinary arena queue parking does not enable compression.

The existing multi-node churn soak, with the compact arena actually installed,
passed 2,400 ticks of 250 ms (600 seconds of simulated protocol time). It
injected loss and route outages and checked post-recovery reliable delivery,
network variables, discovery/schema, streams, and packet transport. This is a
native network test, not 600 seconds of ARM instruction execution.

The latest seven-board ARM/Renode qualification remains incomplete. The
simulator needed byte UART DMA support, request pacing, G4 DMA completion IRQs,
allocator-specific probes, and build-selected Pico UART baud. The initial
115200-baud baseline failed queue/ring limits; the corrected 1 Mbaud baseline
still reported UART queue refusals. The compact candidate cleared that gateway
check but failed DAQ's zero-overrun bound with one startup overrun. Neither
linked attempt qualifies as a ten-minute pass. No throughput improvement or
indefinite OOM immunity is established by these partial results.

Evidence is retained in Jupiter's isolated `/home/rylan/seds-codec-20261005`
and `/home/rylan/seds-codec-arena-20261005` workspaces. Source snapshots and
build variants must be recorded with each subsequent run.

Repeat the native pressure and churn soaks explicitly:

```sh
cargo test --release --features compact-packet-compression \
  --test compact_packet_store bounded_codec_pressure_soak -- --ignored --nocapture
SEDSNET_SOAK_TICKS=2400 cargo test --release --features compact-packet-compression \
  --test reliable_drop_test comprehensive_multinode_churn_soak_exercises_stack_features \
  -- --ignored --nocapture
```
