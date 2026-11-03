# Prepared queued admission

The hosted (`std`) APIs separate work that may wait or allocate from final queue ownership. They do not make the router realtime or lock-free, and local SDK ownership does not prove peer delivery, physical application or an empty external transport/modem.

## Decoded packets and a pending-type fence

`Router::prepare_tx_queue(packet)` retains the supplied Packet's payload, endpoints, sender, nonce, packet ID and timestamp. Call preparation outside application dispatch, Stop or Launch guards. Preparation can acquire schema/storage locks, park compact payload storage and allocate. A `PrepareQueuedPacketFailure` returns both the error and original Packet. Arena pressure follows the existing heap-Arc fallback behavior.

`Router::try_tx_queue_unless_pending_reliable_type(&mut prepared, blocked_type)` checks retained ownership for the caller-selected generic DataType under the same router-core owner that admits the prepared Packet. Pending inspection includes queued and active claims, replay and reliable owners. Unknown Packed/type metadata and inconsistent active counts conservatively block. The API never infers application authority or assigns application message IDs.

The commit tries core and schema locks, validates the captured schema, and checks preallocated queue slots and complete queue/shared byte budgets. It performs no clock/provider/user/transport callbacks and never grows, evicts or replaces an existing queue entry. Managed-variable priority, small frozen-control priority, ordered-tail priority and reliable/disposable classification retain ordinary scheduling semantics.

`CoreBusy`, `SchemaBusy`, `BlockedPendingReliableType`, `Capacity`, `StalePreparation` and `OriginNotAllowed` retain an unadmitted preparation and create no candidate SDK owner. `AlreadyAdmitted` creates no new owner but does not undo the earlier successful admission. Only success transfers the Packet to the SDK once. `PreparedQueuedPacket::into_packet()` returns the original Packet before admission and None afterward. Retry only while the original application's authority, epoch and deadline remain valid; never rebuild or restamp an expired intent merely because a generic preparation can be made.

`Router::try_has_pending_reliable_tx_type(type)` uses the same conservative predicate without waiting for the core mutex. `CoreBusy` is inability to prove clear, not false. This inspector can support caller-owned RAM publication guards, but a separate inspection followed by queue admission is not an atomic fence. The existing blocking inspector and ordinary queue APIs remain available.

## P2P streams

`prepare_p2p_stream_open` and `prepare_p2p_stream_control` freeze the target/session metadata, frame bytes and selected timestamp. Preparation does not create an active session, advance its stream cursor/sequence, publish a frame or call transport/handler callbacks. Preparation may wait, allocate, and sample a clock or call a crypto provider; supplying an explicit timestamp, including zero, freezes that timestamp.

`try_queue_prepared_p2p` validates the router, checked session revision, schema and complete batch capacity before ownership transfer. An unresolved-peer refresh SYN and its DATA/control frame form one local all-or-nothing batch. Busy, Stale or Capacity preserve unadmitted buffers without a partial SYN-only admission. Callbacks and wire dispatch occur later on queue workers. A successful close/reset can defer removed-session deallocation until the caller drops the preparation outside its application guard. Allocator and OS latency remain unbounded.

Incoming stream routing attribution and the bound peer tuple are validated before session progress. A topology-only route knows the remote hostname's compact routing identity, which is not its assigned source address. Its explicitly provisional address becomes bound on a valid SYNACK; early DATA cannot establish a peer ID/connection or rebind it. Once bound, the assigned address and known peer stream ID must match. Declared node address zero remains distinct from the prohibited zero source stream ID in a SYNACK. Name/tuple consistency is not cryptographic authentication.

Wire encoding and existing Rust/C event layouts are unchanged. These APIs do not cancel already admitted bytes or replace application Stop, Launch, authentication, session or freshness checks.
