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
- a clock holding unanchored time steps onto UTC from the first anchored announce, verified response
  or local reference, and a clock reading plausible UTC is never steered toward unanchored time

## Steps, slews and the time-base epoch (SEDSnet 6)

A leading node (the elected reference, for example the GS) corrects its own clock from local time
sources (`try_set_local_network_time` and the other local setters, `update_network_time_source`)
like this:

| Error vs the local source | Steps allowed (default) | Steps inhibited |
| --- | --- | --- |
| at most `step_threshold_ms` (default 1000 ms) | slew at `reference_slew_ppm` (default 20 ppm) | slew at `reference_slew_ppm` |
| above `step_threshold_ms` | **step**, start a new epoch | slew at `reference_slew_ppm` |

`step_local_network_time_ns` always steps (a new epoch) unless steps are inhibited.

#### Step policy (`set_timesync_steps_allowed`)

`Router::set_timesync_steps_allowed(false)` (C `seds_router_set_timesync_steps_allowed`, Python
`set_timesync_steps_allowed`) is the safety hook: the application that owns flight state (the GS)
inhibits steps from Armed until Recovery. The policy acts where steps originate, on the leading
node; followers always follow their source, so the network as a whole steps only when its leader's
policy allows it.

| While steps are inhibited | What happens |
| --- | --- |
| a local source disagrees by any amount | slewed at `reference_slew_ppm` (20 ppm, 72 ms per hour); followers stay locked; no epoch starts; `status.offset_ns` shows what is still to slew |
| `step_local_network_time_ns` | refused (returns `false`), nothing changes |
| steps are allowed again | the next local-source update still more than `step_threshold_ms` away steps (one new epoch) |
| the leader restarted (no follower shares its epoch yet) and its clock disagrees with a follower's fresh request stamp in a newer epoch | the leader **joins** the network's time base and epoch (reason `Joined`): no follower steps; its local sources then correct it under this policy |
| a follower diverged (named a newer epoch on another base) from a leader it was following | the leader names a still newer epoch and the follower steps back onto the leader |

#### Authority

The elected source is deterministic: anchored UTC beats unanchored time, then the lower priority
(GS 50, RRLS 60, RF with a GPS fix 70), then the lower stratum, then the sender ID. Time-base
epochs never override the election; they only decide how a node moves onto its elected source:
a newer source epoch is adopted with a step, an older one is held for until the source adopts the
follower's epoch, and two bases under one epoch number (partitions that stepped on their own) are
separated by the follower naming a newer epoch. A standby source that takes over (RRLS during a GS
outage) keeps its followers' time base, so a hand-over between agreeing sources steps no one.

#### Restarts and persisted marks

A restarted node starts in epoch 0 with no time and adopts the network's epoch within about one
exchange (a follower steps onto its source; a leader adopts a newer epoch whose stamp agrees with
its clock from the first packet it hears, otherwise names a newer one). An application that
persists an ordering mark as `(epoch, timestamp)` (a replay floor) calls
`Router::raise_network_time_epoch(mark_epoch)` (C `seds_router_raise_time_epoch`) at boot: the
network's epoch then never falls below an epoch any node remembers, even after every node
restarted, so new commands order after the mark while replays of older ones stay refused. A relay
that passes a follower's newer epoch upstream stamps its request 0, because its own clock is not in
that epoch's time base.

The reference slew is deliberately slow. Followers see it as a change of their source's frequency,
which their exchange discipline tracks and bounds honestly only within its drift allowance
(`TIMESYNC_DRIFT_ALLOWANCE_PPB`, 50 ppm). Before SEDSnet 6 local corrections slewed at
`max_slew_ppm` (5%): a 3 h 49 min correction took 76 h, and followers, whose frequency range is 3%,
fell seconds behind and dropped to Acquiring. `max_slew_ppm` now only limits the slew of a
follower's own small, measured phase corrections.

### Epochs

Every packet a router originates carries the **time-base epoch** its timestamp was taken in
(`Packet::time_epoch`, 0 until a step was ever seen; on the wire in the contract, see
[Technical-Wire-Format](Technical-Wire-Format)). An epoch names one continuous time base:

- a leading node starts a new epoch, newer than every epoch it has seen, on each step of its own
  clock;
- a follower adopts its source's newer epoch at once from the first announce or response that
  carries it, steps to the source (any size, either direction) and proves lock again; a relay
  then announces the new epoch downstream at once, and every node that changes epoch sends its
  next four announces 150 ms apart so lossy links learn of the change within a fraction of a
  second;
- a follower never steps back inside an epoch: if it finds itself ahead of its source by more than
  the step threshold (plus the exchange's own error bound) in the same epoch, it names a newer
  epoch and holds its clock; its requests carry that epoch upstream (relays pass the newest epoch
  their followers carry), the leader adopts a newer epoch (the same number when the follower's
  stamp agrees with its clock within the step threshold, otherwise one more) and the follower then
  steps onto it;
- a follower whose source is in an older epoch (a restarted station) holds its clock until the
  source adopts the network's epoch from its requests, normally within one round trip;
- any received packet from a newer epoch makes a follower ask its source at once.

So one sender's packets are always ordered by `(time_epoch, timestamp)`, across steps in either
direction. The router uses that order for managed network variables: a write made after a 4 h
step back supersedes the writer's earlier ones, and a late copy stamped before the step never
re-applies (before SEDSnet 6 every write for the next 4 h was refused as "older"). Latest-value
egress replacement uses the same order.

Freshness checks must not compare a raw timestamp with `network_time_ms()` across a step. Use
`Router::network_stamp_age_ms(epoch, timestamp)` (C `seds_router_network_stamp_age_ms`, Python
`network_stamp_age_ms`): it translates the stamp across the last four epoch changes this node
remembers and returns its age, `NewerEpoch { since_ms }` (this node has not re-anchored yet and is
doing so; `since_ms` is how long ago it first heard of a newer epoch, which bounds the stamp's age)
or `OlderEpoch` (stamped before a step no longer remembered: stale). A command stamped 2 s before a
4 h step back is 2 s old, not 4 h in the future.

Command-validity windows (for example an actuator accepting a quick-disconnect command only within
5 s of its stamp) use `Router::network_stamp_is_fresh(epoch, timestamp, max_age_ms, max_ahead_ms)`
(C `seds_router_network_stamp_fresh`, Python `network_stamp_is_fresh`): a translated age inside the
window passes; a newer-epoch stamp passes while `since_ms <= max_age_ms`, so a command sent right
after a step is not refused by a board that is a few milliseconds from re-anchoring; an
untranslatable older epoch and a node without network time never pass. Ordering marks (replay
floors, last accepted command) store `(epoch, timestamp)` and compare with
`sedsnet::timesync::compare_network_stamps` (C `seds_stamp_cmp`). Receipt dedupe keys include the
epoch, so a post-step packet that happens to repeat a pre-step stamp and nonce is never dropped as
a duplicate. Applications that stamp packets themselves read
`network_time_ms_with_epoch()` and set `Packet::with_time_epoch`; packets a router originates
with epoch 0 and its own sender are stamped with its current epoch automatically.

### Status

`timesync_status()` (C `seds_router_get_timesync_status`, Python `timesync_status()`) reports, in
addition to state, error bound, pending offset and rate: `epoch`, `newest_seen_epoch` (above
`epoch`: this node is re-anchoring), `holding`, `steps`, `steps_allowed` and `last_step` (delta,
reason, epochs, age). Reasons: `LocalSource`, `Explicit`, `UtcAnchor`, `SourceEpoch`, `Resync`
(followed forward beyond the threshold in the same epoch), `Diverged`, `Renamed`, `Joined` (a
restarted leader with steps inhibited joined the network's base) and `Raised`
(`raise_network_time_epoch`). A node
holding for its source reports Acquiring. A station should show and alarm on: state not Locked,
`holding`, `newest_seen_epoch > epoch`, and a recent `last_step`.

### Scenarios covered by tests

`src/tests/timesync_step_epoch.rs` and `tests/timesync_station_step.rs` simulate the field network
(GS, gateway, actuator over Wi-Fi/CAN; RF over a radio; FC behind RF) and check: jumps of seconds to
hours both ways from an operator set, a host/NTP source and a GPS-led RF; a station restart (clock
agreeing or not, steps allowed or inhibited); a board restart and a late joiner; a relay hop over a
45 ms radio at 0-50% loss; two sources (GS and RRLS) handing over without steps; partition and
re-merge with both sides stepping under one epoch number; repeated steps; a command sequence judged
with the validity window through steps both ways; the managed-variable cache across a step back;
a whole-stack restart raised by a persisted epoch; and that every node's own packets order by
`(epoch, timestamp)`.

### Configuration

| `TimeSyncConfig` field | Default | Meaning |
| --- | --- | --- |
| `step_threshold_ms` | 1000 | local corrections above it step a leading clock; followers more than this behind step forward |
| `reference_slew_ppm` | 20 | slew of a leading clock toward its local source; keep below 50 ppm |
| `max_slew_ppm` | 50000 | slew of a follower's own small phase corrections |

`Router::set_timesync_step_policy(threshold, slew)` (C `seds_router_set_timesync_step_policy`,
Python `set_timesync_step_policy`) changes the first two without resetting time sync state.

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
