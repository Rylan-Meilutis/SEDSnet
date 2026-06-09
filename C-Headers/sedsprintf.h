#ifndef SEDSPRINTF_C_H
#define SEDSPRINTF_C_H
/* ============================================================================
    Static raw C/C++ ABI header for sedsprintf_rs.

    Runtime data types and endpoints are registered at runtime; this header only
    carries built-in IDs and ABI shapes. Optional convenience APIs live in
    c-wrapper/sedsprintf_c_wrapper.h and c-wrapper/sedsprintf_cpp_wrapper.hpp.
    Rust-side payload stack sizing is still controlled at build time with
    MAX_STACK_PAYLOAD / SEDSPRINTF_RS_MAX_STACK_PAYLOAD.
   ============================================================================ */
#include <stdint.h>
#include <stddef.h>
#include <string.h> /* for strlen in string macros */
#include <stdbool.h> /* for bool type */

#ifdef __cplusplus
extern "C" {

#endif

/* =================================================================
   Public built-in enums / constants. User schema entries are registered at runtime.
   ================================================================= */
typedef enum SedsDataType {
  /* Time source announce (priority, time_ms). */
  SEDS_DT_TIME_SYNC_ANNOUNCE = 4,
  /* Time sync request (seq, t1_ms). */
  SEDS_DT_TIME_SYNC_REQUEST = 5,
  /* Time sync response (seq, t1_ms, t2_ms, t3_ms). */
  SEDS_DT_TIME_SYNC_RESPONSE = 6,
  /* Endpoint discovery advertisement (dynamic list of endpoint IDs). */
  SEDS_DT_DISCOVERY_ANNOUNCE = 7,
  /* Time sync source discovery advertisement (dynamic list of sender IDs). */
  SEDS_DT_DISCOVERY_TIMESYNC_SOURCES = 8,
  /* Full board-topology discovery advertisement (boards, endpoints, and connections). */
  SEDS_DT_DISCOVERY_TOPOLOGY = 9,
  /* Runtime schema snapshot advertisement. */
  SEDS_DT_DISCOVERY_SCHEMA = 10,
  /* Discovery request for current topology snapshot. */
  SEDS_DT_DISCOVERY_TOPOLOGY_REQUEST = 11,
  /* Discovery request for current runtime schema snapshot. */
  SEDS_DT_DISCOVERY_SCHEMA_REQUEST = 12,
  /* Request the latest cached value for a managed variable data type. */
  SEDS_DT_MANAGED_VARIABLE_REQUEST = 13,
  /* Reserved managed variable value control type. Values replay as their original data type. */
  SEDS_DT_MANAGED_VARIABLE_VALUE = 14,
  /* Built-in TelemetryError */
  SEDS_DT_TELEMETRY_ERROR = 0,
} SedsDataType;

typedef enum SedsDataEndpoint {
  /* Time sync routing endpoint (always forwarded). */
  SEDS_EP_TIME_SYNC = 200,
  /* Discovery control endpoint for internal route advertisements. */
  SEDS_EP_DISCOVERY = 201,
  /* Built-in TelemetryError endpoint */
  SEDS_EP_TELEMETRY_ERROR = 202,
} SedsDataEndpoint;

typedef enum SedsResult {
  SEDS_OK = 0,
  SEDS_ERR = -1,
  SEDS_GENERIC_ERROR = -2,
  SEDS_INVALID_TYPE = -3,
  SEDS_SIZE_MISMATCH = -4,
  SEDS_SIZE_MISMATCH_ERROR = -5,
  SEDS_EMPTY_ENDPOINTS = -6,
  SEDS_TIMESTAMP_INVALID = -7,
  SEDS_MISSING_PAYLOAD = -8,
  SEDS_HANDLER_ERROR = -9,
  SEDS_BAD_ARG = -10,
  SEDS_SERIALIZE = -11,
  SEDS_DESERIALIZE = -12,
  SEDS_IO = -13,
  SEDS_INVALID_UTF8 = -14,
  SEDS_TYPE_MISMATCH = -15,
  SEDS_INVALID_LINK_ID = -16,
  SEDS_PACKET_TOO_LARGE = -17,
} SedsResult;

/* ======================================================================== */
typedef uint64_t (* SedsNowMsFn)(void * user);

typedef struct SedsRouter SedsRouter;

typedef struct SedsRelay SedsRelay;

typedef struct SedsName
{
    const char * ptr;
    size_t len;
} SedsName;

typedef struct SedsTypeRef
{
    SedsDataType id;
} SedsTypeRef;

typedef struct SedsEndpointRef
{
    SedsDataEndpoint id;
} SedsEndpointRef;

typedef struct SedsSideRef
{
    int32_t id;
} SedsSideRef;

#define SEDS_NAME_LITERAL(s_) ((SedsName){ (s_), sizeof(s_) - 1U })
#define SEDS_NAME_NULL ((SedsName){ NULL, 0U })
#define SEDS_TYPE_REF(id_) ((SedsTypeRef){ (SedsDataType)(id_) })
#define SEDS_ENDPOINT_REF(id_) ((SedsEndpointRef){ (SedsDataEndpoint)(id_) })
#define SEDS_SIDE_REF(id_) ((SedsSideRef){ (int32_t)(id_) })
#define SEDS_SIDE_INVALID ((SedsSideRef){ -1 })

static inline SedsName seds_name_cstr(const char * s)
{
    return (SedsName){ s, s ? strlen(s) : 0U };
}

static inline bool seds_side_is_valid(SedsSideRef side)
{
    return side.id >= 0;
}

typedef struct SedsPacketView
{
    uint32_t ty;
    size_t data_size;

    const char * sender;
    size_t sender_len;

    const uint32_t * endpoints;
    size_t num_endpoints;

    uint64_t timestamp;
    const uint8_t * payload;
    size_t payload_len;
} SedsPacketView;

typedef struct SedsEndpointInfo
{
    bool exists;
    uint32_t id;
    bool link_local_only;
    const char * name;
    size_t name_len;
    const char * description;
    size_t description_len;
} SedsEndpointInfo;

typedef struct SedsDataTypeInfo
{
    bool exists;
    uint32_t id;
    bool is_static;
    size_t element_count;
    uint8_t message_data_type;
    uint8_t message_class;
    uint8_t reliable;
    uint8_t priority;
    size_t fixed_size;
    const uint32_t * endpoints;
    size_t num_endpoints;
    const char * name;
    size_t name_len;
    const char * description;
    size_t description_len;
} SedsDataTypeInfo;

typedef struct SedsNetworkTime
{
    bool has_unix_time_ms;
    uint64_t unix_time_ms;
    bool has_year;
    int32_t year;
    bool has_month;
    uint8_t month;
    bool has_day;
    uint8_t day;
    bool has_hour;
    uint8_t hour;
    bool has_minute;
    uint8_t minute;
    bool has_second;
    uint8_t second;
    bool has_nanosecond;
    uint32_t nanosecond;
} SedsNetworkTime;

typedef enum SedsElemKind
{
    SEDS_EK_UNSIGNED = 0,
    SEDS_EK_SIGNED = 1,
    SEDS_EK_FLOAT = 2
} SedsElemKind;


typedef enum SedsRouterMode
{
    Seds_RM_Sink = 0,
    Seds_RM_Relay = 1,
} SedsRouterMode;

typedef enum SedsRouteSelectionMode
{
    Seds_RSM_Fanout = 0,
    Seds_RSM_Weighted = 1,
    Seds_RSM_Failover = 2,
} SedsRouteSelectionMode;


typedef SedsResult (* SedsTransmitFn)(const uint8_t * bytes, size_t len, void * user);

typedef SedsResult (* SedsEndpointHandlerFn)(const SedsPacketView * pkt, void * user);

typedef SedsResult (* SedsSerializedHandlerFn)(const uint8_t * bytes, size_t len, void * user);

typedef struct SedsLocalEndpointDesc
{
    uint32_t endpoint;
    SedsEndpointHandlerFn packet_handler; /* optional */
    SedsSerializedHandlerFn serialized_handler; /* optional */
    void * user;
} SedsLocalEndpointDesc;

/* =================================================================
   Public ABI wrappers
   ================================================================= */

/** @brief Legacy byte logger without timestamp or queue flag. */
SedsResult seds_router_log_bytes(SedsRouter * r, SedsDataType ty, const uint8_t * data, size_t len);

/** @brief Legacy f32 logger without timestamp or queue flag. */
SedsResult seds_router_log_f32(SedsRouter * r, SedsDataType ty, const float * vals, size_t n_vals);

/** @brief Legacy typed logger without timestamp or queue flag. */
SedsResult seds_router_log_typed(SedsRouter * r,
                                 SedsDataType ty,
                                 const void * data,
                                 size_t count,
                                 size_t elem_size,
                                 SedsElemKind elem_kind);

/** @brief Legacy typed logger that enqueues instead of sending immediately. */
SedsResult seds_router_log_queue_typed(SedsRouter * r,
                                       SedsDataType ty,
                                       const void * data,
                                       size_t count,
                                       size_t elem_size,
                                       SedsElemKind elem_kind);

/** @brief Byte logger with optional timestamp + queue flag. */
SedsResult seds_router_log_bytes_ex(SedsRouter * r,
                                    SedsDataType ty,
                                    const uint8_t * data,
                                    size_t len,
                                    const uint64_t * timestamp_ms_opt,
                                    int queue);

/** @brief f32 logger with optional timestamp + queue flag. */
SedsResult seds_router_log_f32_ex(SedsRouter * r,
                                  SedsDataType ty,
                                  const float * vals,
                                  size_t n_vals,
                                  const uint64_t * timestamp_ms_opt,
                                  int queue);

/* ==============================
   String / error formatting
   ============================== */

/** @brief Return required buffer length for formatting packet header text. */
int32_t seds_pkt_header_string_len(const SedsPacketView * pkt);

/** @brief Return required buffer length for formatting full packet text. */
int32_t seds_pkt_to_string_len(const SedsPacketView * pkt);

/** @brief Return required buffer length for formatting an error code string. */
int32_t seds_error_to_string_len(const int32_t error_code);

/** @brief Format only packet header fields into @p buf. */
SedsResult seds_pkt_header_string(const SedsPacketView * pkt, char * buf, size_t buf_len);

/** @brief Format full packet fields (header + payload) into @p buf. */
SedsResult seds_pkt_to_string(const SedsPacketView * pkt, char * buf, size_t buf_len);

/** @brief Convert a SedsResult / TelemetryError code to text. */
SedsResult seds_error_to_string(int32_t error_code, char * buf, size_t buf_len);

/* ==============================
   Router lifecycle
   ============================== */

/**
 * @brief Create a router instance.
 *
 * `now_ms_cb` is optional. On `std` builds, passing `NULL` makes the router use its own internal
 * monotonic clock. On `no_std` builds, provide a monotonic clock callback.
 *
 * @return Non-NULL handle on success; NULL on failure.
 */
SedsRouter * seds_router_new(
                             SedsRouterMode mode,
                             SedsNowMsFn now_ms_cb,
                             void * user,
                             const SedsLocalEndpointDesc * handlers,
                             size_t n_handlers
                             );

/** @brief Destroy a router created by seds_router_new(). */
void seds_router_free(SedsRouter * r);
SedsResult seds_router_set_sender_id(SedsRouter * r, const char * sender, size_t sender_len);

/**
 * @brief Read the router's current internally-synthesized network time in Unix milliseconds.
 *
 * Requires a build with the `timesync` feature and an available network time estimate.
 */
SedsResult seds_router_get_network_time_ms(SedsRouter * r, uint64_t * out_ms);

/**
 * @brief Read the router's current internally-synthesized network time components.
 *
 * Requires a build with the `timesync` feature. Presence flags indicate which
 * components are currently known.
 */
SedsResult seds_router_get_network_time(SedsRouter * r, SedsNetworkTime * out);

/**
 * @brief Configure the router's internal time-sync runtime.
 *
 * `role`: 0=Consumer, 1=Source, 2=Auto.
 * Requires a build with the `timesync` feature.
 */
SedsResult seds_router_configure_timesync(
    SedsRouter * r,
    bool enabled,
    uint32_t role,
    uint64_t priority,
    uint64_t source_timeout_ms,
    uint64_t announce_interval_ms,
    uint64_t request_interval_ms
);

/**
 * @brief Poll the router's internal time-sync runtime and queue any due announce/request traffic.
 *
 * This is the non-blocking hook intended for the application's main loop. Call it periodically,
 * then run the normal queue processing functions. If `out_did_queue` is non-NULL, it is set to
 * `true` when a time-sync packet was queued during this call.
 *
 * Requires a build with the `timesync` feature.
 */
SedsResult seds_router_poll_timesync(SedsRouter * r, bool * out_did_queue);

/**
 * @brief Queue a built-in discovery advertisement immediately.
 *
 * This advertises the router's locally reachable endpoints and, when time sync is
 * enabled, any local time source sender IDs.
 *
 * Requires a build with the `discovery` feature.
 */
SedsResult seds_router_announce_discovery(SedsRouter * r);

/**
 * @brief Poll the router's internal discovery runtime and queue any due discovery traffic.
 *
 * This is the non-blocking hook intended for the application's main loop. Call it periodically,
 * then run the normal queue processing functions. If `out_did_queue` is non-NULL, it is set to
 * `true` when a discovery packet was queued during this call.
 *
 * Requires a build with the `discovery` feature.
 */
SedsResult seds_router_poll_discovery(SedsRouter * r, bool * out_did_queue);

/**
 * @brief Enable latest-value caching for a user data type.
 *
 * Once enabled, the router remembers the latest packet for this data type when it is locally
 * transmitted or received from the network. Managed variables cannot be internal control types.
 */
SedsResult seds_router_enable_managed_variable(SedsRouter * r, SedsDataType ty);

/**
 * @brief Disable and clear latest-value caching for a user data type.
 */
void seds_router_disable_managed_variable(SedsRouter * r, SedsDataType ty);

/**
 * @brief Ask the network to replay the latest cached value for a managed variable data type.
 *
 * Responders send the original value packet, so normal endpoint handlers are invoked exactly as if
 * an update had just occurred. Requires a build with the `discovery` feature.
 */
SedsResult seds_router_request_managed_variable(SedsRouter * r, SedsDataType ty);

/**
 * @brief Seed a managed variable cache entry from an already serialized packet.
 */
SedsResult seds_router_seed_managed_variable_serialized(
    SedsRouter * r,
    const uint8_t * bytes,
    size_t len
);

/**
 * @brief Return the serialized size of the cached value for `ty`, or 0 if none is cached.
 */
int32_t seds_router_cached_managed_variable_serialized_len(SedsRouter * r, SedsDataType ty);

/**
 * @brief Copy the cached managed-variable packet as serialized bytes.
 *
 * Returns the copied byte count, 0 when no value is cached, or a negative SedsResult error.
 */
int32_t seds_router_cached_managed_variable_serialized(
    SedsRouter * r,
    SedsDataType ty,
    uint8_t * out,
    size_t out_len
);

/**
 * @brief Return the required buffer length for the router topology export JSON.
 *
 * The returned size includes the trailing NUL byte.
 * Requires a build with the `discovery` feature.
 */
int32_t seds_router_export_topology_len(SedsRouter * r);

/**
 * @brief Export the current router discovery topology as JSON.
 *
 * Use `seds_router_export_topology_len()` to size the destination buffer.
 * Requires a build with the `discovery` feature.
 */
SedsResult seds_router_export_topology(SedsRouter * r, char * buf, size_t buf_len);

/**
 * @brief Return the required buffer length for the router runtime stats JSON export.
 *
 * The returned size includes the trailing NUL byte.
 * Requires a build with the `discovery` feature.
 */
int32_t seds_router_export_runtime_stats_len(SedsRouter * r);

/**
 * @brief Export the current router runtime stats as JSON.
 *
 * This includes per-side traffic, retry/failure counters, adaptive link estimates,
 * route policy state, queue usage, and discovery runtime state.
 * Use `seds_router_export_runtime_stats_len()` to size the destination buffer.
 * Requires a build with the `discovery` feature.
 */
SedsResult seds_router_export_runtime_stats(SedsRouter * r, char * buf, size_t buf_len);

/**
 * @brief Run one router maintenance cycle.
 *
 * This polls time sync, polls discovery when enabled in the build, and then
 * processes RX/TX queues for up to @p timeout_ms milliseconds.
 */
SedsResult seds_router_periodic(SedsRouter * r, uint32_t timeout_ms);

/**
 * @brief Run one router maintenance cycle without polling time sync.
 *
 * This still polls discovery when enabled in the build, then processes RX/TX
 * queues for up to @p timeout_ms milliseconds.
 */
SedsResult seds_router_periodic_no_timesync(SedsRouter * r, uint32_t timeout_ms);

/**
 * @brief Set the router's local/master network time source with partial fields.
 *
 * Requires a build with the `timesync` feature. Presence flags indicate which
 * components are being updated. Complete date+time values are anchored at the
 * commit point so brief context switches during the call do not stale the clock.
 */
SedsResult seds_router_set_local_network_time(
    SedsRouter * r,
    bool has_year,
    int32_t year,
    bool has_month,
    uint8_t month,
    bool has_day,
    uint8_t day,
    bool has_hour,
    uint8_t hour,
    bool has_minute,
    uint8_t minute,
    bool has_second,
    uint8_t second,
    bool has_nanosecond,
    uint32_t nanosecond
);

SedsResult seds_router_set_local_network_date(
    SedsRouter * r,
    int32_t year,
    uint8_t month,
    uint8_t day
);

SedsResult seds_router_set_local_network_time_hm(
    SedsRouter * r,
    uint8_t hour,
    uint8_t minute
);

SedsResult seds_router_set_local_network_time_hms(
    SedsRouter * r,
    uint8_t hour,
    uint8_t minute,
    uint8_t second
);

SedsResult seds_router_set_local_network_time_hms_millis(
    SedsRouter * r,
    uint8_t hour,
    uint8_t minute,
    uint8_t second,
    uint16_t millisecond
);

SedsResult seds_router_set_local_network_time_hms_nanos(
    SedsRouter * r,
    uint8_t hour,
    uint8_t minute,
    uint8_t second,
    uint32_t nanosecond
);

SedsResult seds_router_set_local_network_datetime(
    SedsRouter * r,
    int32_t year,
    uint8_t month,
    uint8_t day,
    uint8_t hour,
    uint8_t minute,
    uint8_t second
);

SedsResult seds_router_set_local_network_datetime_millis(
    SedsRouter * r,
    int32_t year,
    uint8_t month,
    uint8_t day,
    uint8_t hour,
    uint8_t minute,
    uint8_t second,
    uint16_t millisecond
);

SedsResult seds_router_set_local_network_datetime_nanos(
    SedsRouter * r,
    int32_t year,
    uint8_t month,
    uint8_t day,
    uint8_t hour,
    uint8_t minute,
    uint8_t second,
    uint32_t nanosecond
);

/* ==============================
   Router side registration
   ============================== */

/**
 * @brief Add a serialized router side.
 *
 * @param r                 Router handle.
 * @param name              Optional UTF-8 side name used for topology/debug output.
 * @param name_len          Length of @p name in bytes.
 * @param tx                Side TX callback that receives serialized packet bytes.
 * @param tx_user           Opaque pointer passed back into @p tx.
 * @param reliable_enabled  Enable the router's hop-level reliable framing on this side.
 *                          When true, reliable schema traffic on this serialized side uses
 *                          router-managed sequence numbers, ACKs, packet requests, and retransmits.
 *                          When false, the router sends the application packet once on this side
 *                          without that hop-level reliable wrapper.
 *
 * @return Non-negative side id on success; negative SedsResult on failure.
 */
int32_t seds_router_add_side_serialized(
    SedsRouter * r,
    const char * name,
    size_t name_len,
    SedsTransmitFn tx,
    void * tx_user,
    bool reliable_enabled
);

/**
 * @brief Add a serialized router side with compact/bounded side transport enabled.
 *
 * `max_frame_bytes == 0` enables compact header-template transport without chunking.
 * Values greater than zero also split outgoing serialized frames so each TX callback
 * receives at most that many bytes.
 */
int32_t seds_router_add_side_serialized_small_packets(
    SedsRouter * r,
    const char * name,
    size_t name_len,
    SedsTransmitFn tx,
    void * tx_user,
    bool reliable_enabled,
    size_t max_frame_bytes
);

/**
 * @brief Add a packet-view router side.
 *
 * @param r                 Router handle.
 * @param name              Optional UTF-8 side name used for topology/debug output.
 * @param name_len          Length of @p name in bytes.
 * @param tx                Side TX callback that receives a decoded packet view.
 * @param tx_user           Opaque pointer passed back into @p tx.
 * @param reliable_enabled  Declares whether this side should be considered reliable-capable.
 *                          Packet-view callbacks receive decoded packets rather than serialized
 *                          hop-level reliable framing, so the router's per-hop reliable wrapper is
 *                          most meaningful on serialized sides.
 *
 * @return Non-negative side id on success; negative SedsResult on failure.
 */
int32_t seds_router_add_side_packet(
    SedsRouter * r,
    const char * name,
    size_t name_len,
    SedsEndpointHandlerFn tx,
    void * tx_user,
    bool reliable_enabled
);

/** @brief Remove a router side by its previously returned side id. Remaining side ids do not move. */
SedsResult seds_router_remove_side(SedsRouter * r, int32_t side_id);

/** @brief Enable or disable packet ingress from a router side. */
SedsResult seds_router_set_side_ingress_enabled(SedsRouter * r, int32_t side_id, bool enabled);

/** @brief Enable or disable packet egress toward a router side. */
SedsResult seds_router_set_side_egress_enabled(SedsRouter * r, int32_t side_id, bool enabled);

/**
 * @brief Override whether traffic from @p src_side_id may be routed to @p dst_side_id.
 *
 * @param r            Router handle.
 * @param src_side_id  Source/ingress side id. Pass -1 to target locally-originated router TX.
 * @param dst_side_id  Candidate destination/egress side id.
 * @param enabled      Whether this route is allowed.
 */
SedsResult seds_router_set_route(SedsRouter * r, int32_t src_side_id, int32_t dst_side_id, bool enabled);

/**
 * @brief Clear a route override so the router falls back to its default routing behavior.
 *
 * @param r            Router handle.
 * @param src_side_id  Source/ingress side id. Pass -1 to target locally-originated router TX.
 * @param dst_side_id  Candidate destination/egress side id.
 */
SedsResult seds_router_clear_route(SedsRouter * r, int32_t src_side_id, int32_t dst_side_id);
/** @brief Set a per-DataType route override for traffic from @p src_side_id toward @p dst_side_id. */
SedsResult seds_router_set_typed_route(SedsRouter * r, int32_t src_side_id, uint32_t ty, int32_t dst_side_id, bool enabled);
/** @brief Clear a per-DataType route override for traffic from @p src_side_id toward @p dst_side_id. */
SedsResult seds_router_clear_typed_route(SedsRouter * r, int32_t src_side_id, uint32_t ty, int32_t dst_side_id);

/** @brief Set the multi-path selection mode used for traffic from @p src_side_id (-1 => local TX). */
SedsResult seds_router_set_source_route_mode(SedsRouter * r, int32_t src_side_id, SedsRouteSelectionMode mode);
/** @brief Clear the source-specific multi-path selection override for @p src_side_id (-1 => local TX). */
SedsResult seds_router_clear_source_route_mode(SedsRouter * r, int32_t src_side_id);
/** @brief Set the weighted-routing weight from @p src_side_id to @p dst_side_id. Used by Seds_RSM_Weighted. */
SedsResult seds_router_set_route_weight(SedsRouter * r, int32_t src_side_id, int32_t dst_side_id, uint32_t weight);
/** @brief Clear a weighted-routing weight override. */
SedsResult seds_router_clear_route_weight(SedsRouter * r, int32_t src_side_id, int32_t dst_side_id);
/** @brief Set the failover priority from @p src_side_id to @p dst_side_id. Lower numbers win in Seds_RSM_Failover. */
SedsResult seds_router_set_route_priority(SedsRouter * r, int32_t src_side_id, int32_t dst_side_id, uint32_t priority);
/** @brief Clear a failover priority override. */
SedsResult seds_router_clear_route_priority(SedsRouter * r, int32_t src_side_id, int32_t dst_side_id);

/* ==============================
   NEW: schema helper
   ============================== */

/**
 * @brief Return the fixed schema payload size (in bytes) required for a type.
 * @return size (>=0) on success; negative SedsResult on error (e.g., invalid type).
 */
int32_t seds_dtype_expected_size(SedsDataType ty);
bool seds_endpoint_exists(uint32_t endpoint);
bool seds_dtype_exists(uint32_t ty);
SedsResult seds_endpoint_register(uint32_t endpoint, const char * name, size_t name_len, bool link_local_only);
SedsResult seds_endpoint_register_ex(uint32_t endpoint,
                                     const char * name,
                                     size_t name_len,
                                     const char * description,
                                     size_t description_len,
                                     bool link_local_only);
SedsResult seds_dtype_register(uint32_t ty,
                               const char * name,
                               size_t name_len,
                               bool is_static,
                               size_t element_count,
                               uint8_t message_data_type,
                               uint8_t message_class,
                               uint8_t reliable,
                               uint8_t priority,
                               const uint32_t * endpoints,
                               size_t num_endpoints);
SedsResult seds_dtype_register_ex(uint32_t ty,
                                  const char * name,
                                  size_t name_len,
                                  const char * description,
                                  size_t description_len,
                                  bool is_static,
                                  size_t element_count,
                                  uint8_t message_data_type,
                                  uint8_t message_class,
                                  uint8_t reliable,
                                  uint8_t priority,
                                  const uint32_t * endpoints,
                                  size_t num_endpoints);
SedsResult seds_schema_register_json_bytes(const uint8_t * json, size_t json_len);
SedsResult seds_schema_register_json_file(const char * path, size_t path_len);
SedsResult seds_endpoint_get_info(uint32_t endpoint, SedsEndpointInfo * out);
SedsResult seds_endpoint_get_info_by_name(const char * name, size_t name_len, SedsEndpointInfo * out);
SedsResult seds_dtype_get_info(uint32_t ty, uint32_t * endpoints_out, size_t endpoints_cap, SedsDataTypeInfo * out);
SedsResult seds_dtype_get_info_by_name(const char * name,
                                       size_t name_len,
                                       uint32_t * endpoints_out,
                                       size_t endpoints_cap,
                                       SedsDataTypeInfo * out);
SedsResult seds_endpoint_remove(uint32_t endpoint);
SedsResult seds_endpoint_remove_by_name(const char * name, size_t name_len);
SedsResult seds_dtype_remove(uint32_t ty);
SedsResult seds_dtype_remove_by_name(const char * name, size_t name_len);

/* ==============================
   NEW: unified logging entry points
   ============================== */

/**
 * @brief Unified typed logger with optional timestamp + queue flag.
 *
 * If @p timestamp_ms_opt is NULL, the router’s monotonic clock will be used.
 * If @p queue is non-zero, the packet is queued instead of sent immediately.
 *
 * For multi-byte element types, values are encoded in little-endian.
 * The total bytes (count * elem_size) MUST equal the schema size.
 */
SedsResult seds_router_log_typed_ex(SedsRouter * r,
                                    SedsDataType ty,
                                    const void * data,
                                    size_t count,
                                    size_t elem_size,
                                    SedsElemKind elem_kind,
                                    const uint64_t * timestamp_ms_opt, /* NULL => now */
                                    int queue /* 0 = immediate, non-zero = queue */);

/**
 * @brief String/byte logger that pads or truncates to the schema’s size.
 *
 * Copies at most @p len bytes from @p bytes into an internal buffer sized to the
 * schema’s fixed size for @p ty. If @p len < schema, remaining bytes are zeroed.
 * If @p len > schema, input is truncated.
 *
 * This avoids SEDS_SIZE_MISMATCH for fixed-size “message” types while preserving
 * the Router’s size invariants.
 */
SedsResult seds_router_log_string_ex(SedsRouter * r,
                                     SedsDataType ty,
                                     const char * bytes,
                                     size_t len,
                                     const uint64_t * timestamp_ms_opt, /* NULL => now */
                                     int queue /* 0 = immediate, non-zero = queue */);

/* ==============================
   Legacy convenience (still supported)
   ============================== */

/** @brief Receive serialized packet bytes immediately (non-queued, treated as locally-originated input). */
SedsResult seds_router_receive_serialized(SedsRouter * r, const uint8_t * bytes, size_t len);

/** @brief Receive a packet view immediately (non-queued, treated as locally-originated input). */
SedsResult seds_router_receive(SedsRouter * r, const SedsPacketView * view);

/** @brief Transmit a packet view immediately. */
SedsResult seds_router_transmit_message(SedsRouter * r, const SedsPacketView * view);

/** @brief Process TX queue until empty. */
SedsResult seds_router_process_tx_queue(SedsRouter * r);

/** @brief Enqueue a packet view for TX processing. */
SedsResult seds_router_transmit_message_queue(SedsRouter * r, const SedsPacketView * view);

/** @brief Enqueue serialized bytes for TX processing. */
SedsResult seds_router_transmit_serialized_message_queue(SedsRouter * r, const uint8_t * bytes, size_t len);

/** @brief Transmit serialized bytes immediately. */
SedsResult seds_router_transmit_serialized_message(SedsRouter * r, const uint8_t * bytes, size_t len);

/** @brief Process RX queue until empty. */
SedsResult seds_router_process_rx_queue(SedsRouter * r);

/** @brief Enqueue serialized bytes for RX processing. */
SedsResult seds_router_rx_serialized_packet_to_queue(SedsRouter * r, const uint8_t * bytes, size_t len);

/** @brief Enqueue a packet view for RX processing. */
SedsResult seds_router_rx_packet_to_queue(SedsRouter * r, const SedsPacketView * view);

/** @brief Process TX queue for up to @p timeout_ms (0 drains fully). */
SedsResult seds_router_process_tx_queue_with_timeout(SedsRouter * r, uint32_t timeout_ms);

/** @brief Process RX queue for up to @p timeout_ms (0 drains fully). */
SedsResult seds_router_process_rx_queue_with_timeout(SedsRouter * r, uint32_t timeout_ms);

/** @brief Process TX and RX queues for up to @p timeout_ms (0 drains fully). */
SedsResult seds_router_process_all_queues_with_timeout(SedsRouter * r, uint32_t timeout_ms);

/** @brief Process TX and RX queues until empty. */
SedsResult seds_router_process_all_queues(SedsRouter * r);

/** @brief Clear TX and RX queues without processing. */
SedsResult seds_router_clear_queues(SedsRouter * r);

/** @brief Clear RX queue without processing. */
SedsResult seds_router_clear_rx_queue(SedsRouter * r);

/** @brief Clear TX queue without processing. */
SedsResult seds_router_clear_tx_queue(SedsRouter * r);

/** @brief Immediate receive with explicit ingress side id. */
SedsResult seds_router_receive_serialized_from_side(
    SedsRouter* r, uint32_t side_id, const uint8_t* bytes, size_t len);

/** @brief Immediate packet receive with explicit ingress side id. */
SedsResult seds_router_receive_from_side(
    SedsRouter* r, uint32_t side_id, const SedsPacketView* view);

/** @brief Enqueue serialized receive with explicit ingress side id. */
SedsResult seds_router_rx_serialized_packet_to_queue_from_side(
    SedsRouter* r, uint32_t side_id, const uint8_t* bytes, size_t len);

/** @brief Enqueue packet receive with explicit ingress side id. */
SedsResult seds_router_rx_packet_to_queue_from_side(
    SedsRouter* r, uint32_t side_id, const SedsPacketView* view);


/* ==============================
   Payload extraction / serialization helpers
   ============================== */

/** @brief Borrow raw payload bytes and optionally return length in bytes. */
const void * seds_pkt_bytes_ptr(const SedsPacketView * pkt, size_t * out_len);

/** @brief Borrow payload as elements of @p elem_size and optionally return count. */
const void * seds_pkt_data_ptr(const SedsPacketView * pkt, size_t elem_size, size_t * out_count);

/** @brief Copy raw payload bytes to @p dst. */
int32_t seds_pkt_copy_bytes(const SedsPacketView * pkt, void * dst, size_t dst_len);

/** @brief Copy payload elements to @p dst using caller-supplied element size. */
int32_t seds_pkt_copy_data(const SedsPacketView * pkt, size_t elem_size, void * dst, size_t dst_elems);


/**
 * Typed payload getters using Packet::data_as_* helpers.
 *
 * Semantics (matching seds_pkt_copy_data / Rust side):
 *  - If out is NULL or out_elems == 0 or out_elems < needed:
 *       returns the required element count (>= 0), performs NO copy.
 *  - On success:
 *       returns the number of elements written (>= 0).
 *  - On error:
 *       returns a negative SedsResult error code.
 */

int32_t seds_pkt_get_f32 (const SedsPacketView * pkt, float    * out, size_t out_elems);
int32_t seds_pkt_get_f64 (const SedsPacketView * pkt, double   * out, size_t out_elems);

int32_t seds_pkt_get_u8  (const SedsPacketView * pkt, uint8_t  * out, size_t out_elems);
int32_t seds_pkt_get_u16 (const SedsPacketView * pkt, uint16_t * out, size_t out_elems);
int32_t seds_pkt_get_u32 (const SedsPacketView * pkt, uint32_t * out, size_t out_elems);
int32_t seds_pkt_get_u64 (const SedsPacketView * pkt, uint64_t * out, size_t out_elems);

int32_t seds_pkt_get_i8  (const SedsPacketView * pkt, int8_t   * out, size_t out_elems);
int32_t seds_pkt_get_i16 (const SedsPacketView * pkt, int16_t  * out, size_t out_elems);
int32_t seds_pkt_get_i32 (const SedsPacketView * pkt, int32_t  * out, size_t out_elems);
int32_t seds_pkt_get_i64 (const SedsPacketView * pkt, int64_t  * out, size_t out_elems);

int32_t seds_pkt_get_bool(const SedsPacketView * pkt, bool     * out, size_t out_elems);

/**
 * String getter for MessageDataType::String payloads.
 *
 * Semantics:
 *  - If buf is NULL or buf_len == 0:
 *       returns required length INCLUDING terminating NUL (>= 1), no copy.
 *  - If buf_len is too small:
 *       writes as much as fits (buf_len-1 chars), NUL-terminates,
 *       returns required length (>= 1).
 *  - On success:
 *       returns 0.
 *  - On error:
 *       returns negative SedsResult error code.
 */
int32_t seds_pkt_get_string(const SedsPacketView * pkt, char * buf, size_t buf_len);

/* @brief Get the length of a string payload (Including NUL terminator).
 * @return length (>=0) on success; SedsResult on error.
 */
int32_t seds_pkt_get_string_len(const SedsPacketView * pkt);


/** @brief Generic typed payload extraction helper. */
SedsResult seds_pkt_get_typed(const SedsPacketView * pkt,
                              void * out,
                              size_t count,
                              size_t elem_size,
                              SedsElemKind elem_kind);

/** @brief Return required serialized length for @p view. */
int32_t seds_pkt_serialize_len(const SedsPacketView * view);

/** @brief Serialize packet view into @p out. */
int32_t seds_pkt_serialize(const SedsPacketView * view, uint8_t * out, size_t out_len);

typedef struct SedsOwnedPacket SedsOwnedPacket;

/** @brief Deserialize bytes into an owned packet object. */
SedsOwnedPacket * seds_pkt_deserialize_owned(const uint8_t * bytes, size_t len);

/** @brief Convert owned packet into borrowed packet view fields. */
SedsResult seds_owned_pkt_view(const SedsOwnedPacket * pkt, SedsPacketView * out_view);

/** @brief Free owned packet object. */
void seds_owned_pkt_free(SedsOwnedPacket * pkt);

/** @brief Validate serialized packet bytes. */
SedsResult seds_pkt_validate_serialized(const uint8_t * bytes, size_t len);

typedef struct SedsOwnedHeader SedsOwnedHeader;

/** @brief Deserialize only packet header fields into an owned header object. */
SedsOwnedHeader * seds_pkt_deserialize_header_owned(const uint8_t * bytes, size_t len);

/** @brief Convert owned header into borrowed packet-view-compatible fields. */
SedsResult seds_owned_header_view(const SedsOwnedHeader * h, SedsPacketView * out_view);

/** @brief Free owned header object. */
void seds_owned_header_free(SedsOwnedHeader * h);

/* ==============================
   Relay lifecycle
   ============================== */

/**
 * @brief Create a new relay instance.
 *
 * @param now_ms_cb  Optional monotonic clock callback (may be NULL).
 * @param user       Opaque user pointer passed back into @p now_ms_cb.
 *
 * @return Non-NULL relay handle on success; NULL on failure.
 */
SedsRelay * seds_relay_new(SedsNowMsFn now_ms_cb, void * user);

/**
 * @brief Destroy a relay previously returned by seds_relay_new().
 */
void seds_relay_free(SedsRelay * r);
SedsResult seds_relay_set_sender_id(SedsRelay * r, const char * sender, size_t sender_len);

/**
 * @brief Queue a built-in discovery advertisement immediately for this relay.
 *
 * Requires a build with the `discovery` feature.
 */
SedsResult seds_relay_announce_discovery(SedsRelay * r);

/**
 * @brief Poll the relay's internal discovery runtime and queue any due discovery traffic.
 *
 * If `out_did_queue` is non-NULL, it is set to `true` when a discovery packet was
 * queued during this call.
 *
 * Requires a build with the `discovery` feature.
 */
SedsResult seds_relay_poll_discovery(SedsRelay * r, bool * out_did_queue);

/**
 * @brief Return the required buffer length for the relay topology export JSON.
 *
 * The returned size includes the trailing NUL byte.
 * Requires a build with the `discovery` feature.
 */
int32_t seds_relay_export_topology_len(SedsRelay * r);

/**
 * @brief Export the current relay discovery topology as JSON.
 *
 * Use `seds_relay_export_topology_len()` to size the destination buffer.
 * Requires a build with the `discovery` feature.
 */
SedsResult seds_relay_export_topology(SedsRelay * r, char * buf, size_t buf_len);

/**
 * @brief Return the required buffer length for the relay runtime stats JSON export.
 *
 * The returned size includes the trailing NUL byte.
 * Requires a build with the `discovery` feature.
 */
int32_t seds_relay_export_runtime_stats_len(SedsRelay * r);

/**
 * @brief Export the current relay runtime stats as JSON.
 *
 * This includes per-side traffic, retry/failure counters, adaptive link estimates,
 * route policy state, queue usage, and discovery runtime state.
 * Use `seds_relay_export_runtime_stats_len()` to size the destination buffer.
 * Requires a build with the `discovery` feature.
 */
SedsResult seds_relay_export_runtime_stats(SedsRelay * r, char * buf, size_t buf_len);

/**
 * @brief Run one relay maintenance cycle.
 *
 * This polls discovery when enabled in the build, then processes RX/TX queues
 * for up to @p timeout_ms milliseconds.
 */
SedsResult seds_relay_periodic(SedsRelay * r, uint32_t timeout_ms);

/**
 * @brief Add a new side/network to the relay.
 *
 * The side is identified by a small integer ID (0,1,2,...) returned from
 * this function. The same SedsTransmitFn type is used as for SedsRouter.
 *
 * @param r         Relay handle.
 * @param name      Optional UTF-8 name (may be NULL).
 * @param name_len  Length of @p name in bytes (0 if unused).
 * @param tx        TX callback for this side (must not be NULL).
 * @param tx_user   Opaque user pointer passed to @p tx.
 * @param reliable_enabled  Enable the relay's hop-level reliable framing on this serialized side.
 *                          When true, reliable schema traffic on this side uses relay-managed
 *                          sequence numbers, ACKs, packet requests, and retransmits. When false,
 *                          the relay sends the application packet once on this side without that
 *                          hop-level reliable wrapper.
 *
 * @return On success: non-negative side ID.
 *         On error:   negative SedsResult error code.
 */
int32_t seds_relay_add_side_serialized(SedsRelay * r,
                            const char * name,
                            size_t name_len,
                            SedsTransmitFn tx,
                            void * tx_user,
                            bool reliable_enabled);

/**
 * @brief Add a serialized relay side with bounded side transport enabled.
 *
 * `max_frame_bytes == 0` leaves relay frames unbounded. Values greater than zero split outgoing
 * serialized frames so each TX callback receives at most that many bytes.
 */
int32_t seds_relay_add_side_serialized_small_packets(SedsRelay * r,
                            const char * name,
                            size_t name_len,
                            SedsTransmitFn tx,
                            void * tx_user,
                            bool reliable_enabled,
                            size_t max_frame_bytes);

/**
 * @brief Add a new side/network to the relay whose TX callback receives packets.
 *
 * The callback uses the same SedsPacketView shape as router endpoint handlers.
 * This is useful when the “side” is an in-process consumer instead of a raw
 * network link.
 *
 * @param r         Relay handle.
 * @param name      Optional UTF-8 name (may be NULL).
 * @param name_len  Length of @p name in bytes (0 if unused).
 * @param tx        TX callback for this side (packet-based, must not be NULL).
 * @param tx_user   Opaque user pointer passed to @p tx.
 * @param reliable_enabled  Declares whether this side should be considered reliable-capable.
 *                          Packet-view callbacks receive decoded packets rather than serialized
 *                          hop-level reliable framing, so the relay's per-hop reliable wrapper is
 *                          most meaningful on serialized sides.
 *
 * @return On success: non-negative side ID.
 *         On error:   negative SedsResult error code.
 */
int32_t seds_relay_add_side_packet(SedsRelay *r,
                                   const char *name,
                                   size_t name_len,
                                   SedsEndpointHandlerFn tx,
                                   void *tx_user,
                                   bool reliable_enabled);

/** @brief Remove a relay side by its previously returned side id. Remaining side ids do not move. */
SedsResult seds_relay_remove_side(SedsRelay * r, int32_t side_id);
/** @brief Enable or disable packet ingress from a relay side. */
SedsResult seds_relay_set_side_ingress_enabled(SedsRelay * r, int32_t side_id, bool enabled);
/** @brief Enable or disable packet egress toward a relay side. */
SedsResult seds_relay_set_side_egress_enabled(SedsRelay * r, int32_t side_id, bool enabled);
/** @brief Allow or block routing from @p src_side_id toward @p dst_side_id (-1 => locally-originated relay TX). */
SedsResult seds_relay_set_route(SedsRelay * r, int32_t src_side_id, int32_t dst_side_id, bool enabled);
/** @brief Clear a route override so the relay falls back to its default routing behavior. */
SedsResult seds_relay_clear_route(SedsRelay * r, int32_t src_side_id, int32_t dst_side_id);
/** @brief Set a per-DataType route override for traffic from @p src_side_id toward @p dst_side_id. */
SedsResult seds_relay_set_typed_route(SedsRelay * r, int32_t src_side_id, uint32_t ty, int32_t dst_side_id, bool enabled);
/** @brief Clear a per-DataType route override for traffic from @p src_side_id toward @p dst_side_id. */
SedsResult seds_relay_clear_typed_route(SedsRelay * r, int32_t src_side_id, uint32_t ty, int32_t dst_side_id);
/** @brief Set the multi-path selection mode used for traffic from @p src_side_id (-1 => local relay TX). */
SedsResult seds_relay_set_source_route_mode(SedsRelay * r, int32_t src_side_id, SedsRouteSelectionMode mode);
/** @brief Clear the source-specific multi-path selection override for @p src_side_id (-1 => local relay TX). */
SedsResult seds_relay_clear_source_route_mode(SedsRelay * r, int32_t src_side_id);
/** @brief Set the weighted-routing weight from @p src_side_id to @p dst_side_id. Used by Seds_RSM_Weighted. */
SedsResult seds_relay_set_route_weight(SedsRelay * r, int32_t src_side_id, int32_t dst_side_id, uint32_t weight);
/** @brief Clear a weighted-routing weight override. */
SedsResult seds_relay_clear_route_weight(SedsRelay * r, int32_t src_side_id, int32_t dst_side_id);
/** @brief Set the failover priority from @p src_side_id to @p dst_side_id. Lower numbers win in Seds_RSM_Failover. */
SedsResult seds_relay_set_route_priority(SedsRelay * r, int32_t src_side_id, int32_t dst_side_id, uint32_t priority);
/** @brief Clear a failover priority override. */
SedsResult seds_relay_clear_route_priority(SedsRelay * r, int32_t src_side_id, int32_t dst_side_id);


/**
 * @brief Feed serialized bytes that arrived on a given side into the relay.
 *
 * This corresponds to “RX from network into relay”. The relay will fan-out
 * the packet to all other sides when you later call the process_* functions.
 *
 * @param r        Relay handle.
 * @param side_id  Side ID returned by seds_relay_add_side().
 * @param bytes    Serialized packet bytes.
 * @param len      Length of @p bytes.
 *
 * @return SEDS_OK on success or a negative SedsResult on error.
 */
SedsResult seds_relay_rx_serialized_from_side(SedsRelay * r,
                                              uint32_t side_id,
                                              const uint8_t * bytes,
                                              size_t len);


/**
 * @brief Feed a Packet (described by SedsPacketView) that arrived on
 *        a given side into the relay.
 *
 * This is the packet-based counterpart to seds_relay_rx_serialized_from_side().
 *
 * @param r        Relay handle.
 * @param side_id  Side ID returned by seds_relay_add_side*().
 * @param view     Packet view describing the incoming packet.
 *
 * @return SEDS_OK on success or a negative SedsResult on error.
 */
SedsResult seds_relay_rx_packet_from_side(SedsRelay *r,
                                          uint32_t side_id,
                                          const SedsPacketView *view);


/* --- Relay queue processing (matching router style) --- */

/**
 * @brief Process all pending RX in the relay RX queue (expand into TX).
 */
SedsResult seds_relay_process_rx_queue(SedsRelay * r);

/**
 * @brief Process all pending TX in the relay TX queue (invoke side TX callbacks).
 *
 * If called from inside a relay side TX callback, this becomes a no-op so a side callback cannot
 * recursively drive nested relay TX on the same stack.
 */
SedsResult seds_relay_process_tx_queue(SedsRelay * r);

/**
 * @brief Process both RX and TX queues until they are empty.
 */
SedsResult seds_relay_process_all_queues(SedsRelay * r);

/**
 * @brief Clear both RX and TX queues without processing.
 */
SedsResult seds_relay_clear_queues(SedsRelay * r);

/* --- Relay queue processing with time budget (ms) --- */

/**
 * @brief Process RX queue until timeout (ms) or completion.
 *
 * If @p timeout_ms is 0, drains the queue fully.
 */
SedsResult seds_relay_process_rx_queue_with_timeout(SedsRelay * r, uint32_t timeout_ms);

/**
 * @brief Process TX queue until timeout (ms) or completion.
 *
 * If @p timeout_ms is 0, drains the queue fully.
 * If called from inside a relay side TX callback, this becomes a no-op so a side callback cannot
 * recursively drive nested relay TX on the same stack.
 */
SedsResult seds_relay_process_tx_queue_with_timeout(SedsRelay * r, uint32_t timeout_ms);

/**
 * @brief Process RX and TX queues until timeout (ms) or completion.
 *
 * If @p timeout_ms is 0, drains both queues fully.
 * If called from inside a relay side TX callback, this becomes a no-op so a side callback cannot
 * recursively drive nested relay TX on the same stack.
 */
SedsResult seds_relay_process_all_queues_with_timeout(SedsRelay * r, uint32_t timeout_ms);

#if defined(SEDS_ENABLE_CRYPTO_SHIM)
typedef SedsResult (* SedsCryptoSealFn)(
    uint32_t key_id,
    const uint8_t * nonce,
    size_t nonce_len,
    const uint8_t * aad,
    size_t aad_len,
    const uint8_t * plaintext,
    size_t plaintext_len,
    uint8_t * ciphertext_out,
    size_t ciphertext_cap,
    size_t * ciphertext_len_out,
    uint8_t * tag_out,
    size_t tag_cap,
    size_t * tag_len_out,
    void * user);

typedef SedsResult (* SedsCryptoOpenFn)(
    uint32_t key_id,
    const uint8_t * nonce,
    size_t nonce_len,
    const uint8_t * aad,
    size_t aad_len,
    const uint8_t * ciphertext,
    size_t ciphertext_len,
    const uint8_t * tag,
    size_t tag_len,
    uint8_t * plaintext_out,
    size_t plaintext_cap,
    size_t * plaintext_len_out,
    void * user);

SedsResult seds_crypto_register_shim(SedsCryptoSealFn seal, SedsCryptoOpenFn open, void * user);
void seds_crypto_clear_shim(void);
SedsResult seds_crypto_seal(uint32_t key_id,
                            const uint8_t * nonce,
                            size_t nonce_len,
                            const uint8_t * aad,
                            size_t aad_len,
                            const uint8_t * plaintext,
                            size_t plaintext_len,
                            uint8_t * ciphertext_out,
                            size_t ciphertext_cap,
                            size_t * ciphertext_len_out,
                            uint8_t * tag_out,
                            size_t tag_cap,
                            size_t * tag_len_out);
SedsResult seds_crypto_open(uint32_t key_id,
                            const uint8_t * nonce,
                            size_t nonce_len,
                            const uint8_t * aad,
                            size_t aad_len,
                            const uint8_t * ciphertext,
                            size_t ciphertext_len,
                            const uint8_t * tag,
                            size_t tag_len,
                            uint8_t * plaintext_out,
                            size_t plaintext_cap,
                            size_t * plaintext_len_out);
#endif

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SEDSPRINTF_C_H */
