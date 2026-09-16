# Discovery keepalive ownership

An empty DiscoveryAnnounce is the existing slow-link keepalive. It refreshes
the announcing peer timestamp without replacing its learned endpoint ownership
or triggering a topology-change advertisement. Nonempty announcements retain
their endpoint-update behavior. Explicit topology updates, leave messages, and
route expiry remain responsible for withdrawals.

The dev regression covers both Router and Relay receivers, including an
explicit empty topology update after a keepalive. Previously the keepalive
erased the sender endpoint list while an address summary could still advertise
aggregate reachability. That inconsistency is independently reproducible;
it is not yet proof that every observed hardware status-delivery gap has the
same cause. No new release has been published for this change.

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
This change is under hardware validation and is not yet a published release.

Reliable application submission with a remote destination now returns an I/O
error when discovery provides no route, rather than returning success while
discarding the packet. Failed submission no longer poisons duplicate tracking:
the same packet can be retried after a route is learned. Managed-variable writes
that are retained in the local cache keep their existing successful behavior.
Callers must distinguish submission success from a remote protocol ACK.
