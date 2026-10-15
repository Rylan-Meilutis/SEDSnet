# Discovery liveness and pending acknowledgements

Discovery retains endpoint ownership and downstream topology between updates.
A peer's discovery lease is refreshed by validated frames from that known
sender, including ordinary application data and empty keepalives. Traffic from
one CAN peer does not renew a different peer. A bridge's retained downstream
routes change through explicit advertisements and withdrawals. The current
lease is 30 seconds of the router's monotonic clock, not network UTC.

Stable networks do not periodically retransmit route summaries, schemas, or
full topology snapshots. Bootstrap, a new peer, changed reachability, and explicit
recovery requests trigger advertisements. Missing baselines and schemas retain
bounded recovery retries; topology changes retain bounded incremental repeats.

A pending reliable topology/schema packet must not suppress liveness on that
side. Routers and relays send an unreliable, empty discovery keepalive at a
bounded 15-second interval (subject to the normal discovery polling cadence). Empty keepalives refresh
the announcer's lease without clearing its learned endpoints. They do not
resend the topology baseline, acknowledge it, or trigger application fanout.
Explicit topology withdrawals and actual peer silence still remove routes.

No-op polls check pending work and liveness deadlines before requesting snapshot
scratch memory. They do not reserve metadata scratch or evict queued telemetry.
Compact frames can renew a known sender from their validated wrapper and retained
header without expanding the payload; allocation refusal does not erase that
liveness. Unknown templates and corrupt wrappers do not renew a peer. Keepalive
deadlines also account for successful transmission, preventing catch-up bursts
after a link delays queued work.

This matters on shared CAN: a leaf can keep hearing Power Board while losing
RF's GroundStation route. The bus is live, but Power's advertisement does not
substitute for RF's reachability. Extending all route leases would only delay
detecting that condition.

Regression coverage in `src/tests/discovery_liveness.rs` withholds a topology
ACK for 60 seconds, checks bounded keepalives, keeps another CAN peer alive,
and verifies that every sensor submission invokes the outbound callback—not
merely that the logging API returns success. It also checks that RF's route
expires after genuine silence. The relay equivalent is covered in
`src/tests/relay_restart_transport.rs`.

These deterministic tests cover the ACK-gated discovery failure mode. They do
not replace hardware measurement of radio/CAN delivery or a full-system soak.

## Chunk loss must not poison later discovery

Side-transport transfer IDs use a sender-seeded content hash of the complete
wrapped frame, folded to 32 bits. Do not use CRC32 over the complete frame for
this: because it includes the appended CRC, valid frames have a constant CRC
residue. Different packets from one producer would reuse the same assembly and
could combine stale and new fragments after loss. A final CRC check rejects the
mixture, but repeated failures can starve discovery until its route expires.

Both router and relay implementations use content-derived IDs. Exact duplicate
frames retain the same ID; changed content changes it. The wire format has not
changed, and old receivers can accept frames from updated senders. As with any
32-bit ID, collisions are possible; the complete-frame CRC remains mandatory.

Receivers retain at most four incomplete transfers per side, expire inactive
assemblies after two seconds when new chunks arrive, validate chunk indexes,
and bound accumulated payload plus a per-entry overhead allowance by the runtime
queue budget. These are separate bounded assembly buffers, not additions to the
shared RX/TX queue accounting. Under loss or exhaustion, partial frames may be
discarded; completed frames must never be fabricated from mixed transfers.

Regression tests drop a first packet's tail, deliver a different complete packet
from that sender, and verify exact decoding. A repeated-loss test checks the
assembly-count bound over 1,000 transfers. Update senders to correct IDs and
receivers for bounded partial-transfer retention.
