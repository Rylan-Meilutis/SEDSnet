# Discovery keepalive ownership

An empty DiscoveryAnnounce is the existing slow-link keepalive. It refreshes
the announcing peer timestamp without replacing its learned endpoint ownership
or triggering a topology-change advertisement. Nonempty announcements retain
their endpoint-update behavior. Explicit topology updates, leave messages, and
route expiry remain responsible for withdrawals.

The v4.0.30 regression covers both Router and Relay receivers, including an
explicit empty topology update after a keepalive. Previously the keepalive
erased the sender endpoint list while an address summary could still advertise
aggregate reachability. That inconsistency is independently reproducible;
it is not yet proof that every observed hardware status-delivery gap has the
same cause. This fix was published in v4.0.30.

## Compact transport and packet identity

Compact transmitters now carry absolute timestamps, while still reusing header
templates. A delta against the last transmitted frame is unsafe on a lossy
transport: the receiver may have a different base and reconstruct a different
packet identity. That can also prevent reliable delivery acknowledgements from
matching pending packets. Timestamp omission has the same dependency and is
disabled on transmit. Existing receive formats remain supported for compatibility;
old transmitters must be updated to remove the unsafe dependency.

Regression tests cover loss for routers and loss, reordering, and duplicates
for relays. Hardware validation remains pending.

Discovery advertisements now always carry a self-describing transport header.
A restarted receiver or one that missed a header must be able to process the
next discovery update without first recovering a compact-template dictionary.
Ordinary application traffic still uses compact headers. A regression drops
the first discovery header and verifies that the next update decodes.
This change was published in v4.0.30; hardware validation remains separate.

Reliable application submission with a remote destination now returns an I/O
error when discovery provides no route, rather than returning success while
discarding the packet. Failed submission no longer poisons duplicate tracking:
the same packet can be retried after a route is learned. Managed-variable writes
that are retained in the local cache keep their existing successful behavior.
Callers must distinguish submission success from a remote protocol ACK.

## Peer restart and application headers (v4.0.31)

Self-describing discovery alone does not restore an application dictionary. A
peer can restart with the same identity and endpoints, request topology, and
then receive compact state reports whose headers it no longer knows. Waiting
for the periodic full header can exceed the command-response latency bound.

Routers and relays now refresh only their transmit dictionary on the ingress
link of a topology/schema request. The next application header is complete.
Receive dictionaries and learned routes stay intact, and other links retain
compression. This does not flood application traffic or reset discovery.
The focused router regression fails before the fix; router and relay tests
cover both request types and dictionary isolation. Full-system qualification
with the new fix is pending; v4.0.30 does not contain this restart recovery.

Reliability-control frames (ACK, partial ACK, and retransmission request) also
carry complete headers in v4.0.31. These controls must remain
decodable after header loss; otherwise recovery of one ordered data stream can
itself depend on a missing dictionary. Router and relay regressions drop the
initial header and require the next control frame to decode correctly.

Reliable application frames are also self-describing on every forwarding hop.
Previously, after a lost first header, the initial send plus eight reliable
retries could all finish before the next periodic complete header. A retry
therefore repeated an undecodable compact frame. Commands and ordered state
reports now trade a small fixed header overhead for independent decoding; bulk
best-effort telemetry remains compressed. The tests preserve compact recovery,
dictionary-capacity and bytes-saved coverage using explicit best-effort fixtures.
No routing fanout is added.

Transmit refresh retains dictionary entries and marks them to send a complete
header on their next use. Previously, clearing TX while retaining RX changed
their bounded eviction histories. The smaller-peer capacity test exposed a
lost best-effort packet after negotiation. Retaining TX entries restores that
test without changing its packet-count or capacity assertions; all 20 compact
transport/deduplication tests pass with the aligned dictionaries.

Reliable packets use the existing native wire format rather than retaining
unused compression templates. Normal link chunking still applies, and old
decoders already accept these self-describing packets. Regressions require zero
TX/RX template retention for this path.

The memory audit also reproduced timestamp-cache growth at zero template
capacity, including shared CAN links where discovery disables compression.
Both encoders and decoders now retain timestamps only for retained templates.
The router and relay zero-capacity tests fail before this fix and pass after it.
These tests supplement, not replace, the seven-board memory/latency soak.
