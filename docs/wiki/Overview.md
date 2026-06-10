# Overview

This page is the shortest path to understanding what the library does and how its pieces relate. It intentionally avoids
implementation details and focuses on how you think about the system.

## What problem this solves

SEDSNet gives you a **shared telemetry schema**, a **compact wire format**, and a **router** that can deliver
messages locally and/or forward them across links. It is designed to run on embedded devices and host machines with the
**same schema** and compatible packets.

Key outcomes:

- Consistent message definitions across Rust, C/C++, and Python.
- Small, predictable packets that are easy to send over low‑bandwidth links.
- A central Router API that handles validation, dedupe, and dispatch.
- Optional TCP‑like reliability (ACKs, retransmits, ordered/unordered delivery) for types marked reliable in the schema.
- CRC32 integrity checks on all serialized frames (corrupt frames are dropped; reliable modes request retransmit via
  internal reliable control packets).
- Optional adaptive discovery that learns which endpoints are reachable on which sides and exports a live topology view.
- Managed-variable latest-value caches so restarted boards can request current network state through
  the normal endpoint handler path.
- Optional E2E encrypted payloads through C/Rust crypto shims or a registered software fallback key.
- Bounded queue memory: RX, TX, reliable buffers, preallocated dedupe caches, and discovery
  topology share one dynamic `MAX_QUEUE_BUDGET` per router or relay.

As of v3.0.0, the router manages side tracking internally. Most users call the plain RX APIs without threading a side ID
through their handlers; side-aware RX functions are only needed when you explicitly override ingress.

## The core concepts (in plain language)

- **Schema**: A shared list of endpoints (where data goes) and types (what data looks like). In v4,
  application schema is runtime state supplied by registration APIs, application-owned JSON, or
  discovery sync; the crate does not ship a default user schema.
- **Telemetry packet**: One message, with a type, destination endpoints, sender ID, timestamp, and payload bytes.
- **Router**: The switchboard. It receives packets, calls local handlers, and optionally forwards packets to other
  nodes.
- **Relay**: A simpler fan‑out component that forwards packets between sides without knowing the schema.
- **Discovery**: An optional internal control plane that advertises reachable endpoints, adapts its announce rate to
  topology changes, and helps routers/relays forward more selectively.
- **Managed variable**: A data type whose latest value is cached by the network and can be replayed
  on request after a board restart or reconnect.

## A simple mental model

Think of the router as a message bus with two kinds of consumers:

- **Local handlers** (code that runs on the same device).
- **Remote links** (radio, CAN, UART, TCP, etc.).

A packet can go to both: local handlers run, and then the router may forward the packet to remote links depending on
configuration and endpoint rules.

If discovery is enabled, forwarding becomes side-aware: known routes are used first, and unknown
user-data routes are not flooded by fallback. Discovery/control traffic still propagates so the
network can learn paths.

If reliable ordered delivery is enabled, later packets that arrive after a missing sequence are
buffered and partially acknowledged. The missing packet is requested, and the buffered run is
released immediately when the gap is filled.

## What happens when you send telemetry

1) Your code calls a log/tx API with a type and payload.
2) The router validates the payload against the schema.
3) The packet is serialized into a compact byte format.
4) The bytes are handed to a transport callback for sending.

## What happens when you receive telemetry

1) Raw bytes arrive from a link.
2) The router decodes the header and payload.
3) It drops duplicates to avoid loops.
4) It calls any local handlers for the targeted endpoints.
5) If configured to relay, it forwards the packet to other links.

With discovery enabled, step 5 becomes "forward to known matching sides when possible; otherwise
hold user data off the link until discovery or explicit route policy identifies a path."

## Typical deployment shapes

- **Single device**: router with only local handlers (no forwarding).
- **Device + ground station**: device forwards to a link; ground station receives and dispatches.
- **Multi‑hop**: routers in relay mode forward packets across several transport links.
- **Star topology**: relay fans out from one ingress to many egress links.
- **Adaptive mesh-like forwarding**: discovery lets routers and relays learn which sides lead toward which endpoints.

## A tiny example flow

```
Device A                 Link (UART)                 Device B
--------                 -----------                 --------
log(GPS_DATA)  ->  serialize -> bytes -> send -> bytes -> rx_serialized()
  |                              |                        |
  +-- local handler              |                        +-- local handler
                                 +-- remote forward
```

## What to read next

- If you want the concepts explained without code: [Concepts](Concepts)
- If you want abbreviations and terms defined: [Glossary-and-Abbreviations](Glossary-and-Abbreviations)
- If you want integration steps: [Build-and-Configure](Build-and-Configure)
- If you want routing internals: [Technical-Router-Details](Technical-Router-Details)
- If you need time sync details: [Time-Sync](Time-Sync)
- If you want implementation details: [Technical-Architecture](Technical-Architecture)
