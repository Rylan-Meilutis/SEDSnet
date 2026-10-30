# Latest-value egress

An application can explicitly select one packed-output side for newest-pending
best-effort reports. The Cargo feature `latest-value-egress` is disabled by default and omitted from
all default feature bundles. Without it, Rust methods and C setter symbols are
absent and ordinary queue/dispatch paths retain their existing behavior.
With it, the runtime policy is still disabled until a side is selected. It changes pending radio
publication, not acquisition, local handlers, SD recording, or other egresses.
No schema or application IDs change.

For Cargo, add `latest-value-egress` to the dependency features. For the SDK
CMake interface, set `SEDSNET_LATEST_VALUE_EGRESS=ON`; it forwards that Cargo
feature and defines `SEDS_ENABLE_LATEST_VALUE_EGRESS=1` for linked C/C++ targets.
When building Cargo manually for C, define that macro for the matching header
only if the library was built with the feature. Applications that need freshness
should require the feature at build time instead of silently falling back.

```rust
router.set_latest_value_side(Some(radio_side))?;
// Relay has the same setter. Disable with None.
```

```c
/* Check the returned SDK status. router/relay side IDs must already exist. */
seds_router_set_latest_value_side(router, radio_side);
seds_relay_set_latest_value_side(relay, radio_side);
/* Pass -1 to disable. */
```

The selected side must have a packed callback and an ID from 0 through 126.
Selecting another side replaces the selection. Removing the selected side clears
it before its ID can be reused. Configure the policy when constructing the link.
Disabling it retains the current pending sample; it cannot recover superseded
samples. The C API needs SDK 4.3.3 or later.

Only validated plaintext, non-contract application Data with no reliability,
managed-variable ownership, or protected priority (200 and above) is eligible.
Internal protocol traffic, discovery, P2P, reliable records and ACKs, frozen wire
contracts, compressed/encrypted input, retries and attempted transport owners are
excluded. Application commands must express protection through their schema or
protected priority; this generic policy cannot infer application intent from a
low-priority unreliable Data message.

For each source wire address, data type and endpoint multiset, a new sample with
an equal or newer source timestamp replaces the existing never-attempted sample
in its existing queue slot. Older arrivals are ignored. Priority must match.
Different sources, types, endpoint sets and other sides keep separate owners.
The timestamp comparison assumes a source clock that does not move backwards;
a rebooted or reset source may wait for its older pending owner to dispatch.
There is no per-flow map, retained cache, extra queue capacity, or larger budget.
Existing fairness and admission rules still apply to distinct flows.

Coalescing occurs on canonical samples before this egress encodes SDT templates,
compression history or chunks. Selection for dispatch permanently removes the
replaceable marker. Even a refused first callback may have advanced encoded
history; refusal never grants permission to discard that owner. Fresh latest-value
work waits before encoding while a refused or partial owner's encoding history
must remain serialized. Its never-attempted pending values can still coalesce.

Starting with 4.3.4, an SDK-owned streamed canonical discovery catalog can resume
alongside independent fresh reports. Its already-accepted prefix must match the
same catalog identity and frame size, remain within the existing transfer timeout,
and be known not to depend on the side's encoding dictionary. The catalog remains
owned and cannot be evicted. First refusals, packed or unknown owners, and
dictionary-dependent transfers keep the conservative history barrier. This does
not change discovery cadence or allocate additional transport capacity.

Retry owners and protected controls keep their normal dispatch opportunities, and
other sides and local handlers continue. Attempted owners on the opted-in side
are excluded from both fair and priority queue eviction; pressure can refuse new
admission rather than discard those owners. No transport-ready timing or CTS
signal is assumed. This is SDK ownership backpressure, not a modem timing window.

The opt-in makes this egress asynchronous. Call the normal periodic/queue service
regularly. A successful local publication can leave a replaceable radio sample
pending until that service runs.

Replacement parks compact payloads and checks both the shared budget and queue
budget before mutating the existing owner. A failed replacement returns pressure
and leaves the accepted sample and byte accounting intact. This policy does not
replace transport-side bounded admission or delivery receipts, and does not
promise lossless best-effort delivery. Applications that require every sample
must leave it disabled on that egress.
