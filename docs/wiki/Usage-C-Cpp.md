# C/C++ Usage

The C API is exposed via
C-Headers/sedsnet.h ([source](https://github.com/Rylan-Meilutis/sedsnet/blob/main/C-Headers/sedsnet.h))
and a static library built by Cargo.

`C-Headers/sedsnet.h` is a static checked-in ABI header. Runtime data types and endpoints are
registered at runtime, so the header no longer needs to be generated for each schema. Build-time
payload storage settings such as `SEDSNET_MAX_STACK_PAYLOAD` / `MAX_STACK_PAYLOAD` are packaged
defaults or compiled capacities; active identity, memory pools, reliable limits, string sizing,
precision, compression threshold, address assignment, and time-sync behavior can be configured at
runtime.

## CMake integration (recommended)

```cmake
# Example: building for an embedded target
set(SEDSNET_TARGET "thumbv7em-none-eabihf" CACHE STRING "" FORCE)
set(SEDSNET_EMBEDDED_BUILD ON CACHE BOOL "" FORCE)

# Optional: force the Rust crate into the release profile even when the parent
# CMake build is Debug.
# set(SEDSNET_FORCE_RELEASE ON CACHE BOOL "" FORCE)

# set the sender name
set(SEDSNET_DEVICE_IDENTIFIER "FC26_MAIN" CACHE STRING "" FORCE)

# optional compile-time env overrides
set(SEDSNET_MAX_STACK_PAYLOAD "256" CACHE STRING "" FORCE)
set(SEDSNET_MAX_QUEUE_BUDGET "65536" CACHE STRING "" FORCE)
set(SEDSNET_MAX_RECENT_RX_IDS "256" CACHE STRING "" FORCE)

# Optional wrappers and feature-gated cryptography provider support.
# Leave wrappers OFF when you only want the raw ABI header/library.
set(SEDSNET_ENABLE_C_WRAPPER ON CACHE BOOL "" FORCE)
# set(SEDSNET_ENABLE_CPP_WRAPPER ON CACHE BOOL "" FORCE)
# set(SEDSNET_ENABLE_CRYPTOGRAPHY ON CACHE BOOL "" FORCE)

add_subdirectory(${CMAKE_SOURCE_DIR}/sedsnet sedsnet_build)

target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE sedsnet::sedsnet)

# If SEDSNET_ENABLE_C_WRAPPER is ON and you want the reusable C wrapper:
# target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE sedsnet::c_wrapper)
# If SEDSNET_ENABLE_CPP_WRAPPER is ON and you want the C++ header wrapper:
# target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE sedsnet::cpp_wrapper)
```

## CMake integration without a submodule

C projects can pull SEDSnet directly from GitHub at configure time with CMake
`FetchContent`. This keeps the parent project free of a submodule while still building the Rust
crate and exposing the same C ABI target.

Set SEDSnet cache variables before `FetchContent_MakeAvailable(...)`:

```cmake
cmake_minimum_required(VERSION 3.20)
project(my_board C)

include(FetchContent)

# Configure SEDSnet before it is added.
set(SEDSNET_EMBEDDED_BUILD ON CACHE BOOL "" FORCE)
set(SEDSNET_TARGET "thumbv7em-none-eabihf" CACHE STRING "" FORCE)
set(SEDSNET_FORCE_RELEASE ON CACHE BOOL "" FORCE)
set(SEDSNET_DEVICE_IDENTIFIER "FC26_MAIN" CACHE STRING "" FORCE)
set(SEDSNET_ENABLE_C_WRAPPER ON CACHE BOOL "" FORCE)

FetchContent_Declare(
    sedsnet
    GIT_REPOSITORY https://github.com/Rylan-Meilutis/SEDSnet.git
    GIT_TAG v4.0.2
)
FetchContent_MakeAvailable(sedsnet)

add_executable(my_board src/main.c)
target_link_libraries(my_board PRIVATE sedsnet::sedsnet)

# Optional wrapper target when SEDSNET_ENABLE_C_WRAPPER is ON:
# target_link_libraries(my_board PRIVATE sedsnet::c_wrapper)
```

Prefer pinning `GIT_TAG` to a release tag or commit SHA for reproducible firmware builds. Use a
branch name only when you intentionally want each configure step to follow that branch.

Important CMake variables:

- `SEDSNET_EMBEDDED_BUILD` (ON/OFF)
- `SEDSNET_FORCE_RELEASE` (ON/OFF)
- `SEDSNET_ENABLE_C_WRAPPER` (ON/OFF)
- `SEDSNET_ENABLE_CPP_WRAPPER` (ON/OFF)
- `SEDSNET_ENABLE_CRYPTOGRAPHY` (ON/OFF)
- `SEDSNET_TARGET` (Rust target triple)
- `SEDSNET_DEVICE_IDENTIFIER`
- `SEDSNET_MAX_STACK_PAYLOAD`
- `SEDSNET_MAX_QUEUE_BUDGET`
- `SEDSNET_MAX_RECENT_RX_IDS`
- `SEDSNET_ENV_<KEY>` for any config env var

`SEDSNET_FORCE_RELEASE` is useful when your top-level CMake build remains `Debug` but you
still want `sedsnet` built with Cargo's release profile. If it is left `OFF`, the wrapper
follows the parent CMake configuration for single-config generators.

## Manual build (no CMake)

If you want to call Cargo directly:

```
DEVICE_IDENTIFIER=FC26_MAIN cargo build --release
```

The static library will be under `target/release/` (or under `target/<triple>/release` for embedded targets).

## Runtime configuration

The build-time values above are defaults. C/C++ applications can configure the active runtime even
when using a prebuilt library:

```c
SedsRuntimeTuningConfig tuning;
seds_get_runtime_tuning_config(&tuning);
tuning.payload_compress_threshold = 24;
tuning.static_string_length = 512;
tuning.static_hex_length = 512;
tuning.string_precision = 6;
tuning.max_handler_retries = 4;
tuning.reliable_retransmit_ms = 300;
tuning.reliable_max_retries = 10;
tuning.reliable_max_pending = 96;
tuning.reliable_max_return_routes = 96;
tuning.reliable_max_end_to_end_pending = 96;
tuning.reliable_max_end_to_end_ack_cache = 256;
seds_set_runtime_tuning_config(&tuning);

seds_set_runtime_device_identifier("GROUND_STATION", 14);

SedsRuntimeMemoryConfig memory = {
    .max_queue_budget = 65536,
    .max_recent_rx_ids = 256,
    .starting_queue_size = 256,
    .queue_grow_step = 2.0,
};
SedsRouter * router = seds_router_new_with_memory(
    0, now_ms, user, handlers, n_handlers,
    SEDS_ROUTER_E2E_PREFERRED, 7, &memory
);
seds_router_set_sender_id(router, "FC26_MAIN", 9);
seds_router_configure_address(router, 2, 0x10203040); /* 0=dynamic, 1=requested, 2=static */
seds_router_configure_timesync(router, true, 2, 100, 5000, 2000, 2000);
```

`MAX_STACK_PAYLOAD` is the remaining compile-time capacity limit because it changes the inline
payload type layout. Runtime tuning can reduce active static string/binary sizes and other limits,
but it cannot enlarge that compiled inline capacity after the library is built.

## Header Choices

There are three intentionally separate C/C++ surfaces:

- `C-Headers/sedsnet.h`: the raw ABI header. It is always available and does not expose
  convenience macros or wrapper-owned globals.
- `c-wrapper/sedsnet_c_wrapper.h`: optional C convenience API. Enable
  `SEDSNET_ENABLE_C_WRAPPER` and link `sedsnet::c_wrapper`.
- `c-wrapper/sedsnet_cpp_wrapper.hpp`: optional header-only C++ convenience API. Enable
  `SEDSNET_ENABLE_CPP_WRAPPER` and link `sedsnet::cpp_wrapper`.

## Optional Native C Wrapper

When `SEDSNET_ENABLE_C_WRAPPER` is `ON`, CMake also builds
`sedsnet::c_wrapper`, which provides `sedsnet_c_wrapper.h`.

The wrapper has two styles:

- Global router/relay helpers for simple board firmware. The wrapper owns one global router and
  one global relay, so application code does not need to pass handles through every function.
- Explicit `SedsWrapperRouter` / `SedsWrapperRelay` structs for tests or applications that need
  more than one instance.

Minimal global-router usage:

```C
#include "sedsnet_c_wrapper.h"

static SedsResult tx_can(const uint8_t *bytes, size_t len, void *user)
{
    (void)bytes; (void)len; (void)user;
    return SEDS_OK;
}

void app_init(void)
{
    SedsWrapperRouterConfig cfg = seds_wrapper_router_default_config();
    cfg.sender = SEDS_NAME_LITERAL("FC26_MAIN");
    cfg.configure_timesync = true;

    seds_global_router_init(&cfg);
    seds_global_router_add_packed_small_side(
        SEDS_NAME_LITERAL("CAN"),
        tx_can,
        NULL,
        true,
        64);
}

void app_log_flight_state(uint8_t state)
{
    SedsTypeRef ty;
    if (seds_type_ref_by_name(SEDS_NAME_LITERAL("FLIGHT_STATE"), &ty) == SEDS_OK) {
        seds_global_router_log_typed(ty, &state, 1, sizeof(state), SEDS_EK_UNSIGNED, NULL, 0);
    }
}
```

Minimal global-relay usage:

```C
SedsWrapperRelayConfig cfg = seds_wrapper_relay_default_config();
cfg.sender = SEDS_NAME_LITERAL("RF_RELAY");
seds_global_relay_init(&cfg);

SedsSideRef can = seds_global_relay_add_packed_small_side(
    SEDS_NAME_LITERAL("CAN"), tx_can, NULL, true, 64);
SedsSideRef uart = seds_global_relay_add_packed_side(
    SEDS_NAME_LITERAL("UART"), tx_uart, NULL, true);

/* Feed bytes received from CAN. The relay owns queueing and forwarding. */
seds_global_relay_rx_packed_from_side(can, rx_bytes, rx_len);
seds_global_relay_process(0);
```

The global helpers cover side registration, fixed-size packet splitting, RX queueing, periodic
processing, discovery/time-sync polling, route controls, typed logging, and topology/runtime-stat
exports. Use `seds_global_router_handle()` or `seds_global_relay_handle()` only when you need to
drop down to a raw ABI function that is not wrapped yet.

## Minimal C example

```C
#include "sedsnet.h"
#include <string.h>

static uint64_t now_ms(void *user) { (void)user; return 0; }
static SedsResult tx_send(const uint8_t *bytes, size_t len, void *user)
{
    (void)bytes; (void)len; (void)user;
    return SEDS_OK;
}

static SedsResult on_packet(const SedsPacketView *pkt, void *user)
{
    (void)user;
    char buf[seds_pkt_to_string_len(pkt)];
    seds_pkt_to_string(pkt, buf, sizeof(buf));
    return SEDS_OK;
}

int main(void)
{
    const uint32_t sd_card = 100;
    const uint32_t radio = 101;
    const uint32_t gps_data = 100;
    const uint32_t gps_endpoints[] = {sd_card, radio};

    seds_endpoint_register_ex(
        sd_card,
        "SD_CARD",
        strlen("SD_CARD"),
        "Local storage endpoint",
        strlen("Local storage endpoint"),
        false
    );
    seds_endpoint_register_ex(
        radio,
        "RADIO",
        strlen("RADIO"),
        "External radio link",
        strlen("External radio link"),
        false
    );
    seds_dtype_register_ex(
        gps_data,
        "GPS_DATA",
        strlen("GPS_DATA"),
        "Three f32 GPS values",
        strlen("Three f32 GPS values"),
        true,
        3,
        1, /* Float32 */
        0, /* Data */
        0, /* ReliableMode::None */
        80,
        gps_endpoints,
        2
    );

    SedsEndpointInfo sd_info;
    seds_endpoint_get_info_by_name("SD_CARD", strlen("SD_CARD"), &sd_info);

    const SedsLocalEndpointDesc locals[] = {
        { .endpoint = sd_info.id, .packet_handler = on_packet, .user = NULL },
    };

    SedsRouter *r = seds_router_new(
        Seds_RM_Relay,
        NULL,
        NULL,
        locals,
        sizeof(locals) / sizeof(locals[0])
    );
    seds_router_add_side_packed(r, "TX", 2, tx_send, NULL, true);

    float data[3] = {1.0f, 2.0f, 3.0f};
    seds_router_log_typed_ex(
        r,
        gps_data,
        data,
        3,
        sizeof(float),
        SEDS_EK_FLOAT,
        NULL,
        0
    );
    seds_router_process_all_queues(r);

    seds_router_free(r);
    return 0;
}
```

On `std` builds, passing `NULL` for `now_ms_cb` makes the router use its own internal monotonic
clock. On `no_std` builds, provide a monotonic clock callback.

## Native Board Helpers

The optional `c-wrapper/` sources provide the reusable router-node wrapper pattern used by the
gateway, RF, actuator, power, valve, DAQ, and flight-computer firmware. Enable it with:

```cmake
set(SEDSNET_ENABLE_C_WRAPPER ON CACHE BOOL "" FORCE)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE sedsnet::c_wrapper)
```

Then include:

```C
#include "sedsnet_c_wrapper.h"
```

The shared helper surface includes:

- `SedsName`, `SedsTypeRef`, `SedsEndpointRef`, and `SedsSideRef` wrap runtime names, schema IDs,
  and side IDs so new code does not pass raw strings or raw integers throughout the application.
- `seds_type_ref_by_name(...)` and `seds_endpoint_ref_by_name(...)` resolve names once. Store the
  resulting typed refs and use those for logging, routing, and packet checks.
- `SedsWrapperRouter` plus `SedsWrapperRouterConfig` wraps router creation, sender setup, optional
  timesync configuration, initial discovery announce, packed side registration, RX enqueue,
  periodic queue processing, and typed/string logging.
- `seds_router_add_side_packed_small_packets(...)` and
  `seds_relay_add_side_packed_small_packets(...)` expose compact/bounded side transport from C.
  Use these for fixed-size links such as CAN or I2C.

Example:

```C
static SedsResult can_tx(const uint8_t *bytes, size_t len, void *user)
{
    (void)user;
    return board_can_send(bytes, len) == 0 ? SEDS_OK : SEDS_IO;
}

static SedsWrapperRouter telemetry;
static SedsTypeRef flight_state_ty;

void telemetry_init(void)
{
    SedsWrapperRouterConfig cfg = seds_wrapper_router_default_config();
    cfg.sender = SEDS_NAME_LITERAL("ACTUATOR");
    cfg.configure_timesync = true;
    cfg.timesync_role = 0; /* consumer */

    (void)seds_type_ref_by_name(SEDS_NAME_LITERAL("FLIGHT_STATE"), &flight_state_ty);
    (void)seds_wrapper_router_init(&telemetry, &cfg);
    (void)seds_wrapper_router_add_packed_small_side(
        &telemetry,
        SEDS_NAME_LITERAL("can"),
        can_tx,
        NULL,
        true,
        64
    );
}

void telemetry_rx_can(const uint8_t *bytes, size_t len)
{
    (void)seds_wrapper_router_rx_packed_from_side(
        &telemetry,
        telemetry.primary_side,
        bytes,
        len
    );
}

void telemetry_publish_flight_state(uint8_t state)
{
    (void)seds_wrapper_router_log_typed(
        &telemetry,
        flight_state_ty,
        &state,
        1,
        sizeof(state),
        SEDS_EK_UNSIGNED,
        NULL,
        1
    );
}
```

The helper layer is optional. The lower-level ABI remains available for firmware that needs direct
control over every router and relay call.

## Network Variables

Routers can cache the latest packet for selected user data types and expose it through a setter and
getter. The setter commits the value to the network when permissions allow. The getter reads the
cached value and internally requests a refresh when the value has never been seen or is stale; user
code does not register a separate endpoint for network variables. Caches are tiered: any router that
has enabled or seen the variable can answer the refresh from its local cache, so reconnecting boards
can resync from a nearby node instead of always reaching the original producer/master.

```C
SedsTypeRef flight_state_ty;
seds_type_ref_by_name(SEDS_NAME_LITERAL("FLIGHT_STATE"), &flight_state_ty);

seds_global_router_enable_network_variable(flight_state_ty, true, true);
seds_global_router_on_network_variable_update(flight_state_ty, on_flight_state_update, NULL);

/* If stale or missing, this queues an internal refresh and returns 0 until a value arrives. */
int32_t need = seds_global_router_get_network_variable_packed_len(flight_state_ty, 1000U);
seds_global_router_process(0);
```

Producers should also enable the same variable type. C firmware can set the network variable from a
packed packet with `seds_global_router_set_network_variable_packed(...)`, or seed only the
local cache with `seds_router_seed_managed_variable_packed(...)`. If the local router lacks read
or write permission, getters/setters return `SEDS_PERMISSION_DENIED`; peers answer denied refreshes
with a telemetry error packet. `seds_router_on_network_variable_update(...)` runs only for inbound
updates and refresh replies that change the local cache; local setters/seeds update the cache without
firing that callback.

If the managed variable carries sensitive state, mark its data type as requiring E2E cryptography and
create the router with an E2E mode:

```C
seds_dtype_set_e2e_encryption_policy((uint32_t)flight_state_ty.id, SEDS_E2E_REQUIRE_ON);

SedsWrapperRouterConfig cfg = seds_wrapper_router_default_config();
cfg.sender = SEDS_NAME_LITERAL("FLIGHT_COMPUTER");
cfg.e2e_mode = SEDS_ROUTER_E2E_REQUIRED_ONLY;
cfg.e2e_key_id = 7U;
(void)seds_global_router_init(&cfg);
```

Routers created without crypto support reject sends/subscriptions for data types marked
`SEDS_E2E_REQUIRE_ON`. `SEDS_ROUTER_E2E_PREFERRED` encrypts both preferred and required data types,
while `SEDS_ROUTER_E2E_FORCE_ALL` encrypts all non-control user data. When
`SEDS_ENABLE_CRYPTOGRAPHY` is defined, the convenience wrapper default is
`SEDS_ROUTER_E2E_PREFERRED`; builds without it default to `SEDS_ROUTER_E2E_DISABLED`.

## Optional C++ Wrapper

Enable `SEDSNET_ENABLE_CPP_WRAPPER` and include `sedsnet_cpp_wrapper.hpp` when C++ code
wants typed helpers without the C macro layer:

```cpp
#include "sedsnet_cpp_wrapper.hpp"

void publish_state(SedsRouter *router, uint8_t state)
{
    SedsTypeRef ty{};
    if (seds::type_ref_by_name(SEDS_NAME_LITERAL("FLIGHT_STATE"), ty) == SEDS_OK) {
        (void)seds::set_e2e_encryption_policy(ty, SEDS_E2E_REQUIRE_ON);
        (void)seds::router_log(router, ty, &state, 1);
    }
}
```

## Optional Cryptography Provider

Enable the cryptography provider APIs with Cargo feature `cryptography`, build.py option `cryptography`, or
CMake option `SEDSNET_ENABLE_CRYPTOGRAPHY`. C/C++ builds receive the
`SEDS_ENABLE_CRYPTOGRAPHY` define automatically when the CMake option is enabled.

For C firmware, register board-specific crypto callbacks:

```C
#if defined(SEDS_ENABLE_CRYPTOGRAPHY)
static SedsResult seal_cb(
    uint32_t key_id,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *plain, size_t plain_len,
    uint8_t *cipher_out, size_t cipher_cap, size_t *cipher_len_out,
    uint8_t *tag_out, size_t tag_cap, size_t *tag_len_out,
    void *user)
{
    (void)user;
    return board_crypto_seal(key_id, nonce, nonce_len, aad, aad_len, plain, plain_len,
                             cipher_out, cipher_cap, cipher_len_out,
                             tag_out, tag_cap, tag_len_out);
}

static SedsResult open_cb(
    uint32_t key_id,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *cipher, size_t cipher_len,
    const uint8_t *tag, size_t tag_len,
    uint8_t *plain_out, size_t plain_cap, size_t *plain_len_out,
    void *user)
{
    (void)user;
    return board_crypto_open(key_id, nonce, nonce_len, aad, aad_len, cipher, cipher_len,
                             tag, tag_len, plain_out, plain_cap, plain_len_out);
}

void crypto_init(void)
{
    (void)seds_crypto_register_provider(seal_cb, open_cb, NULL);
}
#endif
```

Registered callbacks are preferred over the built-in fallback, so std applications can wrap OS
crypto APIs and embedded applications can wrap hardware accelerators or secure elements. If no
callback is available, register a software fallback key for the `key_id` used by the router:

```C
#if defined(SEDS_ENABLE_CRYPTOGRAPHY)
static const uint8_t fallback_key[32] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
};

void crypto_fallback_init(void)
{
    (void)seds_crypto_register_software_key(7, fallback_key, sizeof(fallback_key));
}
#endif
```

For embedded Rust-only projects, implement `sedsnet::crypto::CryptographyProvider` directly and register
it globally. This avoids exporting a C ABI when the whole firmware is Rust:

```rust
#[cfg(feature = "cryptography")]
struct BoardCrypto;

#[cfg(feature = "cryptography")]
impl sedsnet::crypto::CryptographyProvider for BoardCrypto {
    fn seal(
        &self,
        key_id: u32,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext_out: &mut [u8],
        tag_out: &mut [u8],
    ) -> sedsnet::TelemetryResult<(usize, usize)> {
        board_crypto_seal(key_id, nonce, aad, plaintext, ciphertext_out, tag_out)
    }

    fn open(
        &self,
        key_id: u32,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        plaintext_out: &mut [u8],
    ) -> sedsnet::TelemetryResult<usize> {
        board_crypto_open(key_id, nonce, aad, ciphertext, tag, plaintext_out)
    }
}

#[cfg(feature = "cryptography")]
static BOARD_CRYPTO: BoardCrypto = BoardCrypto;

#[cfg(feature = "cryptography")]
fn crypto_init() {
    sedsnet::crypto::register_rust_cryptography_provider(&BOARD_CRYPTO);
}
```

The crypto layer authenticates packet bytes only after a trusted key exists. A typical secure
deployment runs a quantum-resistant asynchronous key exchange when discovery learns a peer, derives
hardware-accelerated symmetric traffic keys, and selects them through `key_id`. To avoid user-managed
certificates, deploy a master-root model: boards are provisioned with the master public key or a join
PSK, the master issues signed short-lived board credentials, and peers accept session keys only when
the exchange transcript validates to that root. Without that root or a PSK, a man-in-the-middle can
substitute keys before packet authentication begins.

For multi-drop traffic where three boards advertise the same endpoint, use a shared endpoint/group
traffic key so all intended boards can open the same payload; the authenticated header and tag
prevent a receiver from modifying that frame for another board without detection.

The first `seds_router_new(...)` mode argument is retained for ABI compatibility with older
headers. Current routers use runtime side route controls instead of sink/relay construction modes,
so local-only behavior is achieved by creating no sides or disabling the relevant routes.

Reserved internal endpoints:

- Do not register `SEDS_EP_DISCOVERY` in `SedsLocalEndpointDesc`.
- Do not register `SEDS_EP_TIME_SYNC` in `SedsLocalEndpointDesc` when `timesync` is enabled.
- Those endpoints are reserved for the router's built-in discovery and time-sync control traffic,
  and `seds_router_new(...)` rejects them.

See c-example-code/
([source](https://github.com/Rylan-Meilutis/sedsnet/tree/main/c-example-code))
for a more complete example. Time sync is demonstrated in c-example-code/src/timesync_example.c
([source](https://github.com/Rylan-Meilutis/sedsnet/blob/main/c-example-code/src/timesync_example.c)).
See [Time-Sync](Time-Sync) for the time sync packet flow and roles.

## P2P Service Ports

The C ABI exposes discovery-backed service ports for byte protocols that should run over SEDSnet
instead of IP:

- `seds_router_bind_p2p_port(...)`
- `seds_router_send_p2p_to_hostname(...)`
- `seds_router_send_p2p_to_address(...)`
- `seds_router_current_address(...)`
- `seds_router_resolve_hostname_address(...)`
- `seds_router_bind_p2p_stream_port(...)`
- `seds_router_open_p2p_stream_to_hostname(...)`
- `seds_router_open_p2p_stream_to_address(...)`
- `seds_router_send_p2p_stream(...)`
- `seds_router_close_p2p_stream(...)`
- `seds_router_reset_p2p_stream(...)`

The callback receives a `SedsP2pMessageView` containing source hostname/address, source and
destination ports, and opaque payload bytes. This is suitable for carrying protocols such as HTTP
over SEDSnet links while normal telemetry data types continue to use endpoint broadcast routing.
Stream callbacks receive `SedsP2pStreamEventView`, whose `kind` is one of
`SEDS_P2P_STREAM_ACCEPTED`, `SEDS_P2P_STREAM_CONNECTED`, `SEDS_P2P_STREAM_DATA`,
`SEDS_P2P_STREAM_CLOSED`, or `SEDS_P2P_STREAM_RESET`.

## Side reliability

Side-level reliability in the C API is controlled by the `reliable_enabled` argument passed to:

- `seds_router_add_side_packed`
- `seds_router_add_side_packet`
- `seds_relay_add_side_packed`
- `seds_relay_add_side_packet`

That flag is per hop, not global. It controls what the router/relay does on the connection between
itself and that specific side callback.

What it means in practice:

- reliable schema types only use the router/relay's hop-level reliable layer on sides where
  `reliable_enabled == true`
- on packed sides, that hop-level layer adds sequence numbers, ACKs, packet requests, and
  retransmits
- on sides where `reliable_enabled == false`, the router/relay sends the application packet once
  without that hop-level reliable wrapper
- packet-view side callbacks do not preserve the packed hop-level wrapper, so the most complete
  router/relay-managed reliable behavior is on packed sides

For routers, this side setting is separate from router-wide and end-to-end reliability:

- `RouterConfig::with_reliable_enabled(false)` on the Rust side disables the router-managed
  hop-level reliable layer entirely
- otherwise, the source router can still track reliable packets end-to-end across the network even
  if one particular egress side does not use hop-level reliable framing

For ordered reliable links, packets that arrive after a missing sequence are buffered and
partial-ACKed. Partial ACKs suppress timeout retransmit for packets already received, while
explicit packet requests can still replay them. Once the missing sequence arrives, the buffered
packets are dispatched immediately in order.

Router and relay queue-backed state shares one active memory budget. The packaged
`MAX_QUEUE_BUDGET` is only the default; C callers can pass `SedsRuntimeMemoryConfig` to
`seds_router_new_with_memory(...)` or `seds_relay_new_with_memory(...)` to choose per-instance
limits at runtime. RX work, TX work, recent packet IDs, reliable buffers/replay state, and discovery
topology all draw from the active budget. Recent packet ID caches preallocate their final storage
and reserve that byte cost immediately. Discovery topology eviction emits a warning in `std`
builds.

`seds_router_export_memory_layout(...)` and `seds_relay_export_memory_layout(...)` return JSON with
shared allocated/used bytes and per-area queue, reliable-buffer, schema, discovery, and
network-variable-cache breakdowns.

Topology JSON exports include both `routers[].connections` and a top-level `links` array with
deduplicated `{source, target}` board-to-board edges for graph rendering. SEDSnet-owned control
endpoints (`SEDSNET_TIME_SYNC`, `SEDSNET_DISCOVERY`, `SEDSNET_ERROR`) are filtered out of user
endpoint reachability fields.

Use `seds_router_export_client_stats_len(...)` / `seds_router_export_client_stats(...)` or the
matching relay functions to export one discovered client's stats as JSON. The convenience wrapper
also exposes `seds_global_router_export_client_stats*` and `seds_global_relay_export_client_stats*`.
Unknown senders export as JSON `null`. Known snapshots include connected state, side IDs/names,
last-seen/age timing, named reachable endpoints, reachable time-sync sources, and packet/byte
counters aggregated from the side(s) currently reaching that client.

Call `seds_router_announce_leave(...)` or `seds_relay_announce_leave(...)` before a planned
disconnect so peers receive `SEDSNET_DISCOVERY_LEAVE` and prune topology immediately. The raw C free
functions attempt a best-effort leave and queue flush, but explicit leave is preferred when shutdown
order matters.

With `timesync` enabled, the router owns an internal network clock and handles `SEDSNET_TIME_SYNC`
packets internally. Use `seds_router_get_network_time_ms` / `seds_router_get_network_time` to
read the current synthesized network time. Source/master nodes can seed that clock directly with
the `seds_router_set_local_network_*` functions for date-only, time-only, millisecond, or
nanosecond precision inputs.
`SEDS_EP_TIME_SYNC` remains reserved for that internal machinery and must not be registered as a
local endpoint handler.
For normal application loops, call `seds_router_periodic(...)` to run time sync, discovery, and
queue draining together. If you need to skip time sync for a cycle while keeping the feature
enabled, call `seds_router_periodic_no_timesync(...)` instead.
`seds_router_poll_timesync(...)` remains available as a lower-level non-blocking hook when you
want to manage maintenance phases manually.

With `discovery` enabled, `seds_router_poll_discovery(...)` remains available as a lower-level
hook to queue due discovery advertisements, and `seds_router_announce_discovery(...)` still forces
an immediate announce. Relays now expose `seds_relay_periodic(...)` for the normal main-loop path,
alongside the lower-level `seds_relay_poll_discovery(...)` and `seds_relay_announce_discovery(...)`
functions.

Topology export is also available in the C ABI:

- `seds_router_export_topology_len(...)` / `seds_router_export_topology(...)`
- `seds_relay_export_topology_len(...)` / `seds_relay_export_topology(...)`

These return a JSON snapshot. The top-level `routers` array contains each discovered router, the
endpoint names/time-sync source IDs it owns, and its connected router sender IDs. Graph-facing
endpoint fields such as `reachable_endpoints` and `advertised_endpoints` contain
schema-advertised names; companion fields such as `reachable_endpoint_ids` and
`advertised_endpoint_ids` preserve the numeric IDs. Per-side route entries also include their
upstream announcer detail.

Packets already in flight also carry a compact internal wire contract so topology or runtime-schema
changes do not redirect them to the wrong holder or make them undecodable mid-flight. That contract
is attached by the router or relay automatically; C callers continue to use the same public packet
and logging APIs.

## Sending and receiving

Common calls:

- `seds_router_log` / `seds_router_log_ts`: log typed payloads.
- `seds_router_transmit_packed_message`: send raw bytes.
- `seds_router_receive_packed`: receive bytes immediately.
- `seds_router_rx_packed_packet_to_queue`: enqueue for later processing.
- `seds_router_process_all_queues`: process queued RX/TX.

Immediate vs queued variants:

- `receive*` / `transmit*` act immediately in the current call
- `*_to_queue*` only enqueue work for a later queue drain
- `*_from_side*` variants tag the traffic with an explicit ingress side id
- non-`from_side` variants treat the traffic as locally-originated

Main-loop guidance:

- `seds_router_periodic(...)` is the normal router loop entry point because it polls time sync,
  polls discovery, and drains queues
- `seds_router_periodic_no_timesync(...)` does the same but skips time sync for that iteration
- `seds_relay_periodic(...)` is the normal relay loop entry point
- `seds_router_process_*` and `seds_relay_process_*` are lower-level phase helpers when you need
  manual control

As of v3.0.0, most applications should call the plain receive APIs above. Side IDs are tracked
internally by the router. If you need to explicitly override ingress (custom relay or bridge),
use the side-aware variants:

- `seds_router_receive_packed_from_side`
- `seds_router_receive_from_side`
- `seds_router_rx_packed_packet_to_queue_from_side`
- `seds_router_rx_packet_to_queue_from_side`

Runtime side policy and routing controls are also available:

- `seds_router_remove_side`
- `seds_router_set_side_ingress_enabled`
- `seds_router_set_side_egress_enabled`
- `seds_router_note_side_link_probe_sample`
- `seds_router_set_route`
- `seds_router_clear_route`
- `seds_router_set_typed_route`
- `seds_router_clear_typed_route`
- `seds_router_set_source_route_mode`
- `seds_router_set_route_weight`
- `seds_router_set_route_priority`
- `seds_relay_remove_side`
- `seds_relay_set_side_ingress_enabled`
- `seds_relay_set_side_egress_enabled`
- `seds_relay_note_side_link_probe_sample`
- `seds_relay_set_route`
- `seds_relay_clear_route`
- `seds_relay_set_typed_route`
- `seds_relay_clear_typed_route`
- `seds_relay_set_source_route_mode`
- `seds_relay_set_route_weight`
- `seds_relay_set_route_priority`

Pass `-1` as the source side to `seds_router_set_route` / `seds_router_clear_route` when you want
to control locally-originated router TX rather than traffic received from a specific side. The
same `-1` convention also applies to `seds_router_set_typed_route` /
`seds_router_clear_typed_route`. The relay route APIs use the same `-1` convention for
locally-originated discovery TX.

Typed route rules act as per-`DataType` allowlists for a given source side. If any typed rules
exist for `(src_side, ty)`, only the enabled destination sides for that type remain eligible.
That allows dedicated command, abort, or other special-purpose links while keeping ordinary
traffic on the default routing policy.

With discovery enabled, unknown user-data routes are not flooded by fallback. Discovery/control
traffic still propagates so paths can be learned; user data uses discovered paths or explicit route
policy. This keeps low-bandwidth sides such as LoRa from being saturated just because they are the
only currently eligible side.

For time-sliced radios, return the side TX error code for `TelemetryError::Io("side tx busy")` while
the radio is in an RX window or otherwise cannot accept another frame. The router/relay leaves the
work queued and retries during later queue processing. If the driver measures link speed during
bring-up or per-slot operation, call `seds_router_note_side_link_probe_sample(...)` or
`seds_relay_note_side_link_probe_sample(...)` so adaptive path selection learns that radio has less
headroom than Ethernet. Those same samples also throttle built-in control traffic: discovery sends
minimal reachability pings across measured slow sides between infrequent full refreshes, and
router-managed time sync throttles only the measured slow egress while fast sides keep the
configured normal cadence.

`SedsRouteSelectionMode` controls multi-path behavior:

- `Seds_RSM_Fanout`: send to all eligible paths.
- `Seds_RSM_Weighted`: send one packet on one eligible path using weighted round-robin.
- `Seds_RSM_Failover`: send only on the lowest-priority eligible path.

The routing parameters mean:

- `src_side_id`: the ingress side that traffic arrived from; pass `-1` for locally-originated
  router/relay traffic
- `dst_side_id`: the candidate egress side being allowed, blocked, weighted, or prioritized
- `ty`: the `DataType` affected by a typed-route override
- `enabled`: whether that route is allowed
- `weight`: relative share used by `Seds_RSM_Weighted`
- `priority`: lower values win in `Seds_RSM_Failover`

## Payload layout expectations

Payloads are little-endian. The schema defines element type and count. For dynamic payloads, sizes must be a multiple of
element width.

Strings must be valid UTF-8. For static strings, the payload is padded or truncated to the active
runtime `static_string_length` value.

## Embedded allocator hooks

Bare-metal builds must provide:

- `void *telemetryMalloc(size_t)`
- `void telemetryFree(void *)`
- `void telemetry_lock(void)`
- `void telemetry_unlock(void)`
- `void seds_error_msg(const char *, size_t)`
- `void telemetry_panic_hook(const char *, size_t)`

A simple stub is shown in `README.md` and can be adapted for your platform.

## Threading and reentrancy

The router uses internal locking, so the C API is safe to call from multiple threads if your platform supports it. In
bare-metal contexts, you may still want to synchronize access around interrupts.

Do not call router/logging APIs from ISR context on RTOS targets, because platform lock hooks may block.
