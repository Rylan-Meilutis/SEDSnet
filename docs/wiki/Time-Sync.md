# Time Sync

This page explains the built-in time sync support that ships with the `timesync` feature.

## Enabling time sync

- Enable the `timesync` Cargo feature.
- Python builds in this repo enable it by default; see
  [pyproject.toml](https://github.com/Rylan-Meilutis/sedsnet/blob/main/pyproject.toml).

When enabled, the build adds the `SEDSNET_TIME_SYNC` endpoint (broadcast mode `Always`) plus built-in
time sync packet types in code.

The current model is router-owned:

- The router keeps an internal non-monotonic network clock separate from the monotonic clock you
  use for router timing (`Router::new(...)` on `std`, or `Router::new_with_clock(...)` when you
  provide a custom clock).
- The monotonic clock drives scheduling, request timestamps, holdover, and slew; it is not treated
  as UTC.
- `SEDSNET_TIME_SYNC` traffic is consumed internally by the router. It does not dispatch to normal local
  endpoint handlers.
- Packet timestamps prefer the internal network clock when one is available.
- The internal clock can merge partial sources, for example date from one source and time-of-day
  or subsecond precision from another.

If a router transmits a time sync packet and the same frame loops back into that router, it is
normally ignored by RX dedupe before internal time sync processing runs.

## Packet types and fields

All payload fields are `u64` values in little-endian order. Timestamps are in milliseconds.

- `TimeSyncAnnounce`: `[priority, time_ms]`
- `TimeSyncRequest`: `[seq, t1_ms]`
- `TimeSyncResponse`: `[seq, t1_ms, t2_ms, t3_ms]`

Since 4.3.13 the announce `priority` word also carries time quality (`TimeSyncQuality`):

| Bits | Meaning |
| --- | --- |
| 63 | 1 for a qualified announce |
| 62 | 1 when the time is unanchored (uptime or otherwise not traceable to UTC) |
| 36..62 | priority of the reference, saturated to 26 bits |
| 32..36 | stratum: 0 for a reference, plus one per re-serving hop |
| 0..32 | `timesync_sender_tag` of the announcer's own source, 0 for a reference |

Times before `TIMESYNC_UTC_FLOOR_MS` (2020-01-01T00:00:00Z) are never anchored. A legacy announce
(bit 63 clear) is anchored only when its time is plausible, and is then treated as stratum
`TIMESYNC_LEGACY_STRATUM` (8). Older decoders compare the whole word, so they still rank anchored before
unanchored, then priority, then stratum, but rank every qualified source behind legacy sources.
Use `encode_timesync_priority` / `decode_timesync_quality` or `TimeSyncSource::quality()`.

A request sent to a source learned on a known side carries that source's tag in the upper 32 bits of
`seq`. Servers answer only untargeted requests or requests naming them; legacy servers echo the word.

With the `discovery` feature enabled, discovery also adds a built-in
`SEDSNET_DISCOVERY_TIMESYNC_SOURCES` control packet that advertises concrete time source sender IDs.
The richer `SEDSNET_DISCOVERY_TOPOLOGY` packet then attributes those source IDs to specific remote routers
and carries their inter-router connections.

`t4_ms` is captured locally when the response is received; it is not part of the packet payload.

## Internal router behavior

The router handles the built-in time sync packet types internally:

- `TimeSyncAnnounce` updates per-remote-source state; the router does not collapse all remotes into
  one shared slot.
- Time sync is hop by hop: a router with time sync configured consumes announces, requests and
  responses instead of relaying them. While following a remote it re-serves that remote at the next
  stratum on every side except the one the remote announces from, so a board with a single side never
  announces. Requests go to the side the elected source announces from.
- `TimeSyncRequest` may cause the router to queue an internal response when it is acting as a
  source.
- `TimeSyncResponse` updates the leader's remote sample and steers the local network clock using
  the local monotonic receive time.
- When discovery is enabled, outbound `SEDSNET_TIME_SYNC` traffic prefers exact discovered source paths
  over generic `SEDSNET_TIME_SYNC` endpoint reachability.
- Internally generated `TimeSyncResponse` packets are returned to the requesting ingress side
  instead of being broadcast to every side.

Applications can read the resulting network time through:

- Rust: `router.network_time()` / `router.network_time_ms()`
- C: `seds_router_get_network_time()` / `seds_router_get_network_time_ms()`
- Python: `router.network_time()` / `router.network_time_ms()`

## Roles and source selection

`TimeSyncTracker` maintains the current best source and exposes a small state machine:

- `Consumer`: follows the elected producer. If `consumer_promotion_enabled` is set and there are no
  active producers, a consumer that already has non-uptime-based network time may temporarily
  promote itself to keep the network aligned.
- `Source`: participates in election as a producer. It announces and serves only while it is the
  elected leader; otherwise it follows the leader like a consumer.
- `Auto`: acts like an opportunistic producer. It only enters the election when no active producer
  is present and it has usable network time.

Sources are chosen by quality first: anchored UTC always outranks unanchored time, whatever the
configured priority or arrival order. Among sources of equal quality the lower priority wins, then the
lower stratum (the nearest hop to the same reference), then the sender ID (lexicographic). A source
whose announce names this node as its own source, or whose stratum exceeds `TIMESYNC_MAX_STRATUM` (15),
is never selected, so two relays cannot keep each other alive after their reference disappears: they
fall back to unanchored time (or consumer promotion) after `source_timeout_ms`.

A router's local candidate is anchored when a local time source (the local setters or
`update_network_time_source`) reads plausible UTC. An `Auto` node, or a promotable consumer, with
anchored local time also takes over from an unanchored remote. Standalone `TimeSyncTracker` users
declare local quality with `set_local_time_anchored`.
When several producers have the same configured priority, the elected leader advertises a boosted
priority for as long as it remains leader so the tie resolves consistently without changing the
standby producers' configured priorities. If no announce is seen within `source_timeout_ms`, a
source is considered inactive.

These roles are runtime configuration, not compile-time board roles. Use `Source` for a
grandmaster/source node, `Consumer` for a follower, and `Auto` for a node that should become a
source only when no better source is active and it already has usable time.

Discovery-master preference is independent from these roles. For example, a vehicle can prefer
GroundStation (`GS`) as discovery master while configuring RF as time source priority `1`,
GroundStation as source priority `50`, and other boards as promotable consumers. RF then wins while
present with time of the same quality, GroundStation takes over after RF's source timeout, and ordinary
consumer promotion remains the final fallback when neither configured source is available. An RF
board without a GPS fix announces unanchored uptime, so it follows a GroundStation that has UTC and
re-serves that time to the vehicle.

Runtime configuration entry points:

- Rust: `RouterConfig::with_timesync(TimeSyncConfig { ... })` at construction, or
  `router.set_timesync_config(Some(...))` / `None` after construction.
- C: `seds_router_configure_timesync(router, enabled, role, priority, source_timeout_ms,
  announce_interval_ms, request_interval_ms)`, where role `0` is consumer, `1` is source, and `2`
  is auto.
- Python: pass `timesync_role`, `timesync_priority`, interval, timeout, promotion, and slew keyword
  arguments to `Router(...)`, or call `router.configure_timesync(...)` later. Python uses the same
  role codes as C.

Failover uses holdover plus slew:

- the network clock keeps running monotonically during producer loss or producer change
- a new leader does not step an anchored clock backward or forward immediately
- instead, the router slews toward the new leader at the configured `max_slew_ppm` rate
- a fresh, matched response from the elected source may step an anchored clock forward by more than
  five seconds
- a clock holding unanchored time steps onto UTC from the first anchored announce, verified response
  or local reference, and a clock reading plausible UTC is never steered toward unanchored time

The internal clock also supports merging partial absolute sources:

- complete date from one source
- time-of-day from another source
- subsecond precision from another source

When a complete date+time base exists, the router advances it forward using the monotonic clock.

## Discovery integration

With both `timesync` and `discovery` enabled:

- discovery advertisements include `SEDSNET_TIME_SYNC` endpoint reachability
- routers and relays also advertise reachable time source sender IDs
- `export_topology()` includes both reachable endpoints and reachable time source IDs per side,
  plus a top-level `routers` graph showing which router owns each source ID and how routers are
  connected
- a consumer can route requests toward the exact side that leads to its selected source instead of
  sending requests to every side that merely exposes `SEDSNET_TIME_SYNC`

If no exact source route is known yet, routing still falls back to ordinary endpoint-based
discovery or flooding.

## Typical flow

1) A source periodically sends `TimeSyncAnnounce`.
2) The elected follower sends `TimeSyncRequest` with monotonic `t1_ms`.
3) The elected source replies with `TimeSyncResponse` and timestamps `t2_ms`/`t3_ms` in network
   time.
4) The consumer captures `t4_ms` and calls `compute_offset_delay(t1, t2, t3, t4)`.

The returned `offset_ms` and `delay_ms` mirror the standard NTP-style round trip calculation.

For most applications using router-managed timesync, you do not need to manually send or decode
these packets. The router can announce, request, respond, and maintain the internal network clock
itself once time sync is configured.

Drive that runtime with `periodic(timeout_ms)` in normal application loops. That runs time sync,
discovery, and queue draining together. If you need to skip time sync for a cycle while keeping the
feature enabled, use `periodic_no_timesync(timeout_ms)`.
`poll_timesync()` remains available as a lower-level hook when you want to queue only due
announce/request traffic and manage the surrounding queue processing yourself.

When discovery has measured a side as slow through link-probe or driver timing samples,
router-managed time sync throttles only that slow egress. Local high-speed segments keep the
configured normal sync cadence while slow bridge links carry only occasional master-to-master timing
traffic.

If you want a producer to advertise real UTC, inject that absolute time through the local network
time setters. The router's timing callback remains monotonic-only.

## Master / local clock injection

In addition to packet-driven sync, a source/master can set its local network time directly.

Rust router APIs:

- `set_local_network_time(PartialNetworkTime)`
- `set_local_network_date(...)`
- `set_local_network_time_hm(...)`
- `set_local_network_time_hms(...)`
- `set_local_network_time_hms_millis(...)`
- `set_local_network_time_hms_nanos(...)`
- `set_local_network_datetime(...)`
- `set_local_network_datetime_millis(...)`
- `set_local_network_datetime_nanos(...)`

C APIs:

- `seds_router_set_local_network_time(...)`
- `seds_router_set_local_network_date(...)`
- `seds_router_set_local_network_time_hm(...)`
- `seds_router_set_local_network_time_hms(...)`
- `seds_router_set_local_network_time_hms_millis(...)`
- `seds_router_set_local_network_time_hms_nanos(...)`
- `seds_router_set_local_network_datetime(...)`
- `seds_router_set_local_network_datetime_millis(...)`
- `seds_router_set_local_network_datetime_nanos(...)`

Python APIs:

- `router.set_local_network_time(...)`
- `router.set_local_network_date(...)`
- `router.set_local_network_time_hm(...)`
- `router.set_local_network_time_hms(...)`
- `router.set_local_network_time_hms_millis(...)`
- `router.set_local_network_time_hms_nanos(...)`
- `router.set_local_network_datetime(...)`
- `router.set_local_network_datetime_millis(...)`
- `router.set_local_network_datetime_nanos(...)`

These setters are safe to call from multiple threads because the internal clock update is
packed by the router. For complete date+time values, the implementation re-samples the
monotonic clock at commit so short context switches during the call do not leave the stored time
stale.

## API entry points

Rust helpers live in `sedsnet::timesync`:

- `TimeSyncConfig`, `TimeSyncRole`, `TimeSyncTracker`
- `send_timesync_announce`, `send_timesync_request`, `send_timesync_response`
- `build_timesync_*`, `decode_timesync_*`, `compute_offset_delay`

Router-managed APIs live on `Router` and the C/Python FFI surfaces described above.

Example implementations:

- [Rust](https://github.com/Rylan-Meilutis/sedsnet/blob/main/rust-example-code/timesync_example.rs)
- [C](https://github.com/Rylan-Meilutis/sedsnet/blob/main/c-example-code/src/timesync_example.c)
- [Python](https://github.com/Rylan-Meilutis/sedsnet/blob/main/python-example/timesync_example.py)
- [FreeRTOS](https://github.com/Rylan-Meilutis/sedsnet/blob/main/rtos-example-code/freertos_timesync.c)
- [ThreadX](https://github.com/Rylan-Meilutis/sedsnet/blob/main/rtos-example-code/threadx_timesync.c)
