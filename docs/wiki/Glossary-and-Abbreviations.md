# Glossary and Abbreviations

This page defines abbreviations and recurring terms used across the wiki, README, changelog, and
API docs.

## Protocol and packet terms

- **ABI**: Application Binary Interface. The stable C-callable surface exposed by
  `C-Headers/sedsnet.h`.
- **AAD**: Additional Authenticated Data. Header bytes that are not encrypted but are authenticated
  by the E2E payload wrapper so tampering is detected before handlers see the payload.
- **AEAD**: Authenticated Cryptography with Associated Data. The style of cryptography expected from
  cryptography providers: encrypt the payload and authenticate both payload and selected visible header bytes.
- **CRC**: Cyclic Redundancy Check. Packed frames include a CRC32 trailer to reject corrupted
  bytes before dispatch.
- **E2E**: End-to-end. In this project it can mean either end-to-end reliable delivery confirmation
  or end-to-end encrypted payloads, depending on context.
- **Frame**: A packed packet byte sequence ready to send over a side.
- **Packet**: The logical telemetry message before packing or after unpacking. It has a sender, time,
  data type, endpoints, and payload.
- **Payload**: The application data bytes inside a packet. With `cryptography`, these bytes can be
  wrapped by the E2E encrypted payload format.
- **ULEB**: Unsigned Little Endian Base 128. A compact variable-length integer encoding used in
  parts of the wire format.

## Routing and transport terms

- **CAN**: Controller Area Network. A fixed-frame bus that usually benefits from packed-side
  max-size splitting.
- **Endpoint**: A logical destination such as `RADIO`, `SD_CARD`, or `FLIGHT_SOFTWARE`.
- **Flooding**: Forwarding to every eligible side. Current discovery-aware routing avoids blind
  unknown-route flooding for normal user data once topology exists.
- **I2C**: Inter-Integrated Circuit. A short-distance bus that can benefit from fixed-size
  packed-side splitting.
- **Link-local**: Traffic that should stay on local software-bus or IPC sides and not be advertised
  onto normal network links.
- **LoRa**: Long Range radio. Usually low bandwidth and sometimes time-sliced, so discovery-aware
  routing, link probes, queueing, and TX-busy retry behavior matter.
- **RX**: Receive.
- **Side**: A router or relay connection to a transport, such as `UART`, `CAN`, `RADIO`, `TCP`, or
  a software bus.
- **TX**: Transmit.
- **UART**: Universal Asynchronous Receiver/Transmitter. A common serial transport.

## Runtime state terms

- **Discovery**: The internal control plane that advertises reachable endpoints, time sources,
  schema, and topology so routers and relays can route selectively.
- **Network variable**: A data type whose latest packet is cached by routers/relays with local
  read/write permissions. Getters read the local cache and request refresh when missing or stale;
  setters publish a new value for the network.
- **Managed variable**: Legacy wording for a network variable or latest-value cache. Current user
  docs prefer **network variable**.
- **Schema**: Runtime definitions for endpoints and data types. In v4, user schema is registered,
  seeded from JSON, or learned through discovery instead of generated at compile time.
- **Topology**: The discovered graph of boards, sides, reachable endpoints, time sources, and
  connections. Exported topology uses advertised endpoint and side names where available.

## Security terms

- **Credential**: A compact signed authorization record issued by a master/root key. The built-in
  managed credential helper stores subject, key id, epoch, validity window, and permission bits.
- **HMAC**: Hash-based Message Authentication Code. Used by the software fallback and managed
  credential helper for authentication.
- **Key ID**: An application-defined number used by routers and cryptography providers to select the
  symmetric key or provider context for a packet.
- **MITM**: Man in the middle. An active attacker that can intercept and modify key exchange or
  traffic. E2E cryptography resists MITM only when the key source is authenticated, for example by a
  provisioned root key, PSK, or master-issued credential.
- **PSK**: Pre-shared key. A key provisioned before deployment and used to authenticate peers,
  derive traffic keys, or verify a master/root authority.
- **Root/master node**: The authority that issues credentials or approves network state in
  deployments that avoid user-managed certificate files.

## Build and test terms

- **CMake wrapper target**: Optional CMake targets such as `sedsnet::c_wrapper` and
  `sedsnet::cpp_wrapper` that provide convenience APIs on top of the raw C ABI.
- **Criterion**: The Rust benchmarking framework used by the benchmark smoke pass.
- **Doctest**: A Rust documentation code example compiled and run as a test by `cargo test --doc`.
- **nextest**: An optional faster Rust test runner. `./build.py test` auto-detects
  `cargo-nextest` and falls back to Cargo's built-in runner when it is not installed.
- **Smoke test**: A validation run intended to catch obvious breakage, not a strict performance
  gate. The benchmark smoke pass executes Criterion benchmarks using the `sedsnet_smoke`
  baseline.
