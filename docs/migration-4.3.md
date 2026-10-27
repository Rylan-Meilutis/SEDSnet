# Migrating to 4.3

Version 4.3.0 and macros 2.2.0 are candidates under qualification. The complete
test matrix and application simulator qualification must pass before release.

## Application IDs belong to the application schema

Only network protocol types 0–18 and endpoints 200–202 are reserved. Their exact
names begin with `SEDSNET_`. All other IDs are available to application schemas,
subject to identity collision checks. Side names do not select radio, storage,
codec, priority or scheduling behavior; configure those properties explicitly.

Earlier versions assigned special IDs to several application names. In 4.3,
these names use the same stable name-derived identity rule as every other
application name unless an `id` is supplied:

| Kind | Name | Earlier implicit ID |
| --- | --- | ---: |
| Type | GPS_DATA | 100 |
| Type | IMU_DATA | 101 |
| Type | BATTERY_STATUS | 102 |
| Type | SYSTEM_STATUS | 103 |
| Type | BAROMETER_DATA | 104 |
| Type | MESSAGE_DATA | 105 |
| Type | HEARTBEAT | 106 |
| Type | IPC_MESSAGE | 107 |
| Endpoint | SD_CARD | 100 |
| Endpoint | RADIO | 101 |
| Endpoint | SOFTWARE_BUS | 102 |

To retain an existing network's wire identities, add `"id": 100` to its GPS_DATA
type definition and SD_CARD endpoint definition, and likewise configure each
other legacy identity used by the application. Keep the existing payload,
endpoints, reliability and other metadata. Apply the same schema choices to
every participating node, including host tools. These IDs are compatibility
choices in application configuration; the library does not reserve them.

`DataType::identity(name)` and `DataEndpoint::identity(name)` compute the default
identity for a name. They do not look up an explicit configured ID. Use generated
schema constants, the validated schema snapshot, or runtime `named(name)` lookup
after registration when a definition supplies an ID. Applications that generate
compile-time constants should derive them from the same schema used at runtime.

Invalid, reserved or colliding explicit IDs are rejected. A rejected runtime
schema must not leave a partially registered set of definitions. Repeated
identical definitions received on the wire remain idempotent; conflicting
definitions do not replace a registered identity.

## Protocol names and application heartbeats

SDK-owned discovery, time synchronization, reliability, managed-variable and P2P
messages use their canonical `SEDSNET_` names. Keep application names such as
HEARTBEAT separate from those protocol identities. The SDK does not originate an
application heartbeat, flood it on every side, bypass its route selection or
suppress its configured delivery tracking because of its name. Configure its
endpoints, routes, reliability and publication cadence in the application.

Regenerate macro-generated schemas with macros 2.2.0 before using them with
SEDSnet 4.3. Older 2.1-generated schemas can contain unprefixed SDK protocol
names at reserved IDs; do not register those definitions alongside the canonical
`SEDSNET_` definitions. Version 4.3 rejects conflicting names at reserved IDs.
This schema regeneration requirement does not imply wire incompatibility for
correctly formed legacy C protocol frames with the existing reserved identities.

## Router and Relay configuration

Router and Relay use one routing engine and the same side configuration type.
The existing RouterSideOptions and RelaySideOptions names remain aliases for
compatibility. Existing Relay construction and callback APIs remain available
through a facade. The relay role forwards network traffic but does not allocate
or expose the participating router's local application services or originate new
application data. Protocol control traffic still uses the common routing engine.

Recheck memory and throughput on the actual firmware configuration after an
upgrade, including TLSF and compact packet stores where enabled. Structural
object size alone does not establish peak heap usage or available board RAM.

## Package and GitHub publication

Published SEDSnet/PyPI 4.2.7 and macros 2.1.1 cannot be replaced. The new source
versions are SEDSnet/PyPI 4.3.0 and macros 2.2.0. A GitHub release will identify the
validated source commit; crates.io and PyPI uploads remain manual maintainer work.
