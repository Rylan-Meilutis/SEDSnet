#ifndef SEDSNET_C_WRAPPER_H
#define SEDSNET_C_WRAPPER_H

#include "sedsnet.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SedsWrapperRouterConfig
{
    SedsRouterMode mode;
    SedsNowMsFn now_ms;
    void * now_user;
    const SedsLocalEndpointDesc * handlers;
    size_t num_handlers;
    SedsName sender;
    uint8_t e2e_mode;
    uint32_t e2e_key_id;

    bool configure_timesync;
    uint32_t timesync_role;
    uint64_t timesync_priority;
    uint64_t timesync_source_timeout_ms;
    uint64_t timesync_announce_interval_ms;
    uint64_t timesync_request_interval_ms;

    bool announce_discovery;
} SedsWrapperRouterConfig;

typedef struct SedsWrapperRouter
{
    SedsRouter * router;
    uint8_t created;
    uint64_t start_time_ms;
    SedsSideRef primary_side;
    int32_t init_error;
} SedsWrapperRouter;

typedef struct SedsWrapperRelayConfig
{
    SedsNowMsFn now_ms;
    void * now_user;
    SedsName sender;
    bool announce_discovery;
} SedsWrapperRelayConfig;

typedef struct SedsWrapperRelay
{
    SedsRelay * relay;
    uint8_t created;
    SedsSideRef primary_side;
    int32_t init_error;
} SedsWrapperRelay;

SedsWrapperRouterConfig seds_wrapper_router_default_config(void);
SedsWrapperRelayConfig seds_wrapper_relay_default_config(void);

SedsResult seds_wrapper_router_init(SedsWrapperRouter * node,
                                    const SedsWrapperRouterConfig * cfg);
void seds_wrapper_router_free(SedsWrapperRouter * node);

SedsRouter * seds_wrapper_router_handle(SedsWrapperRouter * node);
int32_t seds_wrapper_router_init_error(const SedsWrapperRouter * node);
SedsRouter * seds_global_router_handle(void);
int32_t seds_global_router_init_error(void);
SedsResult seds_global_router_init(const SedsWrapperRouterConfig * cfg);
void seds_global_router_free(void);

SedsSideRef seds_wrapper_router_add_serialized_side(SedsWrapperRouter * node,
                                                    SedsName name,
                                                    SedsTransmitFn tx,
                                                    void * tx_user,
                                                    bool reliable_enabled);
SedsSideRef seds_wrapper_router_add_serialized_small_side(SedsWrapperRouter * node,
                                                          SedsName name,
                                                          SedsTransmitFn tx,
                                                          void * tx_user,
                                                          bool reliable_enabled,
                                                          size_t max_frame_bytes);
SedsSideRef seds_wrapper_router_add_packet_side(SedsWrapperRouter * node,
                                                SedsName name,
                                                SedsEndpointHandlerFn tx,
                                                void * tx_user,
                                                bool reliable_enabled);
SedsSideRef seds_global_router_add_serialized_side(SedsName name,
                                                   SedsTransmitFn tx,
                                                   void * tx_user,
                                                   bool reliable_enabled);
SedsSideRef seds_global_router_add_serialized_small_side(SedsName name,
                                                         SedsTransmitFn tx,
                                                         void * tx_user,
                                                         bool reliable_enabled,
                                                         size_t max_frame_bytes);
SedsSideRef seds_global_router_add_packet_side(SedsName name,
                                               SedsEndpointHandlerFn tx,
                                               void * tx_user,
                                               bool reliable_enabled);
SedsResult seds_global_router_remove_side(SedsSideRef side);
SedsResult seds_global_router_set_side_ingress_enabled(SedsSideRef side, bool enabled);
SedsResult seds_global_router_set_side_egress_enabled(SedsSideRef side, bool enabled);
SedsResult seds_global_router_set_route(SedsSideRef src_side, SedsSideRef dst_side, bool enabled);
SedsResult seds_global_router_clear_route(SedsSideRef src_side, SedsSideRef dst_side);
SedsResult seds_global_router_set_typed_route(SedsSideRef src_side, SedsTypeRef ty, SedsSideRef dst_side, bool enabled);
SedsResult seds_global_router_clear_typed_route(SedsSideRef src_side, SedsTypeRef ty, SedsSideRef dst_side);
SedsResult seds_global_router_set_source_route_mode(SedsSideRef src_side, SedsRouteSelectionMode mode);
SedsResult seds_global_router_clear_source_route_mode(SedsSideRef src_side);
SedsResult seds_global_router_set_route_weight(SedsSideRef src_side, SedsSideRef dst_side, uint32_t weight);
SedsResult seds_global_router_clear_route_weight(SedsSideRef src_side, SedsSideRef dst_side);
SedsResult seds_global_router_set_route_priority(SedsSideRef src_side, SedsSideRef dst_side, uint32_t priority);
SedsResult seds_global_router_clear_route_priority(SedsSideRef src_side, SedsSideRef dst_side);

SedsResult seds_wrapper_router_rx_serialized(SedsWrapperRouter * node,
                                             const uint8_t * bytes,
                                             size_t len);
SedsResult seds_wrapper_router_rx_serialized_from_side(SedsWrapperRouter * node,
                                                       SedsSideRef side,
                                                       const uint8_t * bytes,
                                                       size_t len);
SedsResult seds_global_router_rx_serialized(const uint8_t * bytes, size_t len);
SedsResult seds_global_router_rx_serialized_from_side(SedsSideRef side,
                                                      const uint8_t * bytes,
                                                      size_t len);

SedsResult seds_wrapper_router_process(SedsWrapperRouter * node, uint32_t timeout_ms);
SedsResult seds_wrapper_router_periodic(SedsWrapperRouter * node, uint32_t timeout_ms);
SedsResult seds_wrapper_router_poll_timesync(SedsWrapperRouter * node, bool * out_did_queue);
SedsResult seds_wrapper_router_announce_discovery(SedsWrapperRouter * node);
SedsResult seds_wrapper_router_announce_leave(SedsWrapperRouter * node);
SedsResult seds_wrapper_router_poll_discovery(SedsWrapperRouter * node, bool * out_did_queue);
SedsResult seds_wrapper_router_enable_managed_variable(SedsWrapperRouter * node, SedsTypeRef ty);
SedsResult seds_wrapper_router_enable_network_variable(SedsWrapperRouter * node,
                                                       SedsTypeRef ty,
                                                       bool can_read,
                                                       bool can_write);
SedsResult seds_wrapper_router_on_network_variable_update(SedsWrapperRouter * node,
                                                          SedsTypeRef ty,
                                                          SedsEndpointHandlerFn cb,
                                                          void * user);
void seds_wrapper_router_disable_managed_variable(SedsWrapperRouter * node, SedsTypeRef ty);
SedsResult seds_wrapper_router_request_managed_variable(SedsWrapperRouter * node, SedsTypeRef ty);
SedsResult seds_wrapper_router_set_network_variable_serialized(SedsWrapperRouter * node,
                                                               const uint8_t * bytes,
                                                               size_t len);
SedsResult seds_wrapper_router_seed_managed_variable_serialized(SedsWrapperRouter * node,
                                                                const uint8_t * bytes,
                                                                size_t len);
int32_t seds_wrapper_router_cached_managed_variable_serialized_len(SedsWrapperRouter * node,
                                                                   SedsTypeRef ty);
int32_t seds_wrapper_router_cached_managed_variable_serialized(SedsWrapperRouter * node,
                                                               SedsTypeRef ty,
                                                               uint8_t * out,
                                                               size_t out_len);
int32_t seds_wrapper_router_get_network_variable_serialized_len(SedsWrapperRouter * node,
                                                                SedsTypeRef ty,
                                                                uint32_t stale_after_ms);
int32_t seds_wrapper_router_get_network_variable_serialized(SedsWrapperRouter * node,
                                                            SedsTypeRef ty,
                                                            uint32_t stale_after_ms,
                                                            uint8_t * out,
                                                            size_t out_len);
SedsResult seds_global_router_process(uint32_t timeout_ms);
SedsResult seds_global_router_periodic(uint32_t timeout_ms);
SedsResult seds_global_router_periodic_no_timesync(uint32_t timeout_ms);
SedsResult seds_global_router_poll_timesync(bool * out_did_queue);
SedsResult seds_global_router_announce_discovery(void);
SedsResult seds_global_router_announce_leave(void);
SedsResult seds_global_router_poll_discovery(bool * out_did_queue);
SedsResult seds_global_router_enable_managed_variable(SedsTypeRef ty);
SedsResult seds_global_router_enable_network_variable(SedsTypeRef ty, bool can_read, bool can_write);
SedsResult seds_global_router_on_network_variable_update(SedsTypeRef ty,
                                                         SedsEndpointHandlerFn cb,
                                                         void * user);
void seds_global_router_disable_managed_variable(SedsTypeRef ty);
SedsResult seds_global_router_request_managed_variable(SedsTypeRef ty);
SedsResult seds_global_router_set_network_variable_serialized(const uint8_t * bytes, size_t len);
SedsResult seds_global_router_seed_managed_variable_serialized(const uint8_t * bytes, size_t len);
int32_t seds_global_router_cached_managed_variable_serialized_len(SedsTypeRef ty);
int32_t seds_global_router_cached_managed_variable_serialized(SedsTypeRef ty,
                                                              uint8_t * out,
                                                              size_t out_len);
int32_t seds_global_router_get_network_variable_serialized_len(SedsTypeRef ty,
                                                               uint32_t stale_after_ms);
int32_t seds_global_router_get_network_variable_serialized(SedsTypeRef ty,
                                                           uint32_t stale_after_ms,
                                                           uint8_t * out,
                                                           size_t out_len);
SedsResult seds_global_router_get_network_time_ms(uint64_t * out_ms);
SedsResult seds_global_router_get_network_time(SedsNetworkTime * out);
int32_t seds_global_router_export_topology_len(void);
SedsResult seds_global_router_export_topology(char * buf, size_t buf_len);
int32_t seds_global_router_export_client_stats_len(SedsName sender);
SedsResult seds_global_router_export_client_stats(SedsName sender, char * buf, size_t buf_len);
int32_t seds_global_router_export_runtime_stats_len(void);
SedsResult seds_global_router_export_runtime_stats(char * buf, size_t buf_len);
int32_t seds_global_router_export_memory_layout_len(void);
SedsResult seds_global_router_export_memory_layout(char * buf, size_t buf_len);

SedsResult seds_wrapper_router_log_typed(SedsWrapperRouter * node,
                                         SedsTypeRef ty,
                                         const void * data,
                                         size_t count,
                                         size_t elem_size,
                                         SedsElemKind elem_kind,
                                         const uint64_t * timestamp_ms_opt,
                                         int queue);
SedsResult seds_wrapper_router_log_string(SedsWrapperRouter * node,
                                          SedsTypeRef ty,
                                          const char * text,
                                          const uint64_t * timestamp_ms_opt,
                                          int queue);
SedsResult seds_global_router_log_typed(SedsTypeRef ty,
                                        const void * data,
                                        size_t count,
                                        size_t elem_size,
                                        SedsElemKind elem_kind,
                                        const uint64_t * timestamp_ms_opt,
                                        int queue);
SedsResult seds_global_router_log_string(SedsTypeRef ty,
                                         const char * text,
                                         const uint64_t * timestamp_ms_opt,
                                         int queue);

SedsResult seds_wrapper_relay_init(SedsWrapperRelay * node,
                                   const SedsWrapperRelayConfig * cfg);
void seds_wrapper_relay_free(SedsWrapperRelay * node);
SedsRelay * seds_wrapper_relay_handle(SedsWrapperRelay * node);
int32_t seds_wrapper_relay_init_error(const SedsWrapperRelay * node);
SedsRelay * seds_global_relay_handle(void);
int32_t seds_global_relay_init_error(void);
SedsResult seds_global_relay_init(const SedsWrapperRelayConfig * cfg);
void seds_global_relay_free(void);

SedsSideRef seds_wrapper_relay_add_serialized_side(SedsWrapperRelay * node,
                                                   SedsName name,
                                                   SedsTransmitFn tx,
                                                   void * tx_user,
                                                   bool reliable_enabled);
SedsSideRef seds_wrapper_relay_add_serialized_small_side(SedsWrapperRelay * node,
                                                         SedsName name,
                                                         SedsTransmitFn tx,
                                                         void * tx_user,
                                                         bool reliable_enabled,
                                                         size_t max_frame_bytes);
SedsSideRef seds_wrapper_relay_add_packet_side(SedsWrapperRelay * node,
                                               SedsName name,
                                               SedsEndpointHandlerFn tx,
                                               void * tx_user,
                                               bool reliable_enabled);
SedsSideRef seds_global_relay_add_serialized_side(SedsName name,
                                                  SedsTransmitFn tx,
                                                  void * tx_user,
                                                  bool reliable_enabled);
SedsSideRef seds_global_relay_add_serialized_small_side(SedsName name,
                                                        SedsTransmitFn tx,
                                                        void * tx_user,
                                                        bool reliable_enabled,
                                                        size_t max_frame_bytes);
SedsSideRef seds_global_relay_add_packet_side(SedsName name,
                                              SedsEndpointHandlerFn tx,
                                              void * tx_user,
                                              bool reliable_enabled);

SedsResult seds_wrapper_relay_rx_serialized_from_side(SedsWrapperRelay * node,
                                                      SedsSideRef side,
                                                      const uint8_t * bytes,
                                                      size_t len);
SedsResult seds_wrapper_relay_rx_packet_from_side(SedsWrapperRelay * node,
                                                  SedsSideRef side,
                                                  const SedsPacketView * view);
SedsResult seds_global_relay_rx_serialized_from_side(SedsSideRef side,
                                                     const uint8_t * bytes,
                                                     size_t len);
SedsResult seds_global_relay_rx_packet_from_side(SedsSideRef side,
                                                 const SedsPacketView * view);

SedsResult seds_wrapper_relay_process(SedsWrapperRelay * node, uint32_t timeout_ms);
SedsResult seds_wrapper_relay_periodic(SedsWrapperRelay * node, uint32_t timeout_ms);
SedsResult seds_wrapper_relay_announce_discovery(SedsWrapperRelay * node);
SedsResult seds_wrapper_relay_announce_leave(SedsWrapperRelay * node);
SedsResult seds_wrapper_relay_poll_discovery(SedsWrapperRelay * node, bool * out_did_queue);
SedsResult seds_global_relay_process(uint32_t timeout_ms);
SedsResult seds_global_relay_periodic(uint32_t timeout_ms);
SedsResult seds_global_relay_announce_discovery(void);
SedsResult seds_global_relay_announce_leave(void);
SedsResult seds_global_relay_poll_discovery(bool * out_did_queue);
int32_t seds_global_relay_export_topology_len(void);
SedsResult seds_global_relay_export_topology(char * buf, size_t buf_len);
int32_t seds_global_relay_export_client_stats_len(SedsName sender);
SedsResult seds_global_relay_export_client_stats(SedsName sender, char * buf, size_t buf_len);
int32_t seds_global_relay_export_runtime_stats_len(void);
SedsResult seds_global_relay_export_runtime_stats(char * buf, size_t buf_len);
int32_t seds_global_relay_export_memory_layout_len(void);
SedsResult seds_global_relay_export_memory_layout(char * buf, size_t buf_len);

SedsResult seds_global_relay_remove_side(SedsSideRef side);
SedsResult seds_global_relay_set_side_ingress_enabled(SedsSideRef side, bool enabled);
SedsResult seds_global_relay_set_side_egress_enabled(SedsSideRef side, bool enabled);
SedsResult seds_global_relay_set_route(SedsSideRef src_side, SedsSideRef dst_side, bool enabled);
SedsResult seds_global_relay_clear_route(SedsSideRef src_side, SedsSideRef dst_side);
SedsResult seds_global_relay_set_typed_route(SedsSideRef src_side, SedsTypeRef ty, SedsSideRef dst_side, bool enabled);
SedsResult seds_global_relay_clear_typed_route(SedsSideRef src_side, SedsTypeRef ty, SedsSideRef dst_side);
SedsResult seds_global_relay_set_source_route_mode(SedsSideRef src_side, SedsRouteSelectionMode mode);
SedsResult seds_global_relay_clear_source_route_mode(SedsSideRef src_side);
SedsResult seds_global_relay_set_route_weight(SedsSideRef src_side, SedsSideRef dst_side, uint32_t weight);
SedsResult seds_global_relay_clear_route_weight(SedsSideRef src_side, SedsSideRef dst_side);
SedsResult seds_global_relay_set_route_priority(SedsSideRef src_side, SedsSideRef dst_side, uint32_t priority);
SedsResult seds_global_relay_clear_route_priority(SedsSideRef src_side, SedsSideRef dst_side);

static inline SedsResult seds_type_ref_by_name(SedsName name, SedsTypeRef * out)
{
    SedsDataTypeInfo info;
    SedsResult result;
    if (!out) {
        return SEDS_BAD_ARG;
    }
    result = seds_dtype_get_info_by_name(name.ptr, name.len, NULL, 0U, &info);
    if (result != SEDS_OK || !info.exists) {
        return result != SEDS_OK ? result : SEDS_INVALID_TYPE;
    }
    out->id = (SedsDataType)info.id;
    return SEDS_OK;
}

static inline SedsResult seds_endpoint_ref_by_name(SedsName name, SedsEndpointRef * out)
{
    SedsEndpointInfo info;
    SedsResult result;
    if (!out) {
        return SEDS_BAD_ARG;
    }
    result = seds_endpoint_get_info_by_name(name.ptr, name.len, &info);
    if (result != SEDS_OK || !info.exists) {
        return result != SEDS_OK ? result : SEDS_BAD_ARG;
    }
    out->id = (SedsDataEndpoint)info.id;
    return SEDS_OK;
}

static inline bool seds_type_ref_exists(SedsTypeRef ty)
{
    return seds_dtype_exists((uint32_t)ty.id);
}

static inline bool seds_endpoint_ref_exists(SedsEndpointRef endpoint)
{
    return seds_endpoint_exists((uint32_t)endpoint.id);
}

static inline int32_t seds_type_ref_expected_size(SedsTypeRef ty)
{
    return seds_dtype_expected_size(ty.id);
}

#if !defined(__cplusplus) && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L

#define SEDS__KIND_SIZE(x, KIND_OUT, SIZE_OUT) do {                                    \
    _Static_assert(sizeof(*(x))==1 || sizeof(*(x))==2 ||                                \
                   sizeof(*(x))==4 || sizeof(*(x))==8,                                  \
                   "element size must be 1,2,4,8");                                     \
    (SIZE_OUT) = (size_t)sizeof(*(x));                                                  \
    (KIND_OUT) = _Generic(*(x),                                                         \
        unsigned char: SEDS_EK_UNSIGNED,                                                \
        uint16_t:      SEDS_EK_UNSIGNED,                                                \
        uint32_t:      SEDS_EK_UNSIGNED,                                                \
        uint64_t:      SEDS_EK_UNSIGNED,                                                \
        signed char:   SEDS_EK_SIGNED,                                                  \
        int16_t:       SEDS_EK_SIGNED,                                                  \
        int32_t:       SEDS_EK_SIGNED,                                                  \
        int64_t:       SEDS_EK_SIGNED,                                                  \
        float:         SEDS_EK_FLOAT,                                                   \
        double:        SEDS_EK_FLOAT,                                                   \
        default:       SEDS_EK_UNSIGNED                                                 \
    );                                                                                  \
} while(0)

#define seds_router_log(router, datatype, data, count)                                  \
    (__extension__({                                                                    \
        const void   *_s_data  = (const void*)(data);                                   \
        size_t        _s_count = (size_t)(count);                                       \
        size_t        _s_esize;                                                         \
        SedsElemKind  _s_kind;                                                          \
        SEDS__KIND_SIZE((data), _s_kind, _s_esize);                                     \
        seds_router_log_typed_ex((router), (datatype), _s_data, _s_count,               \
                                 _s_esize, _s_kind, NULL, 0);                           \
    }))

#define seds_router_log_queue(router, datatype, data, count)                            \
    (__extension__({                                                                    \
        const void   *_s_data  = (const void*)(data);                                   \
        size_t        _s_count = (size_t)(count);                                       \
        size_t        _s_esize;                                                         \
        SedsElemKind  _s_kind;                                                          \
        SEDS__KIND_SIZE((data), _s_kind, _s_esize);                                     \
        seds_router_log_typed_ex((router), (datatype), _s_data, _s_count,               \
                                 _s_esize, _s_kind, NULL, 1);                           \
    }))

#define seds_router_log_ts(router, datatype, ts_ms, data, count)                        \
    (__extension__({                                                                    \
        const void   *_s_data  = (const void*)(data);                                   \
        size_t        _s_count = (size_t)(count);                                       \
        size_t        _s_esize;                                                         \
        SedsElemKind  _s_kind;                                                          \
        const uint64_t _s_ts = (uint64_t)(ts_ms);                                       \
        SEDS__KIND_SIZE((data), _s_kind, _s_esize);                                     \
        seds_router_log_typed_ex((router), (datatype), _s_data, _s_count,               \
                                 _s_esize, _s_kind, &_s_ts, 0);                         \
    }))

#define seds_router_log_queue_ts(router, datatype, ts_ms, data, count)                  \
    (__extension__({                                                                    \
        const void   *_s_data  = (const void*)(data);                                   \
        size_t        _s_count = (size_t)(count);                                       \
        size_t        _s_esize;                                                         \
        SedsElemKind  _s_kind;                                                          \
        const uint64_t _s_ts = (uint64_t)(ts_ms);                                       \
        SEDS__KIND_SIZE((data), _s_kind, _s_esize);                                     \
        seds_router_log_typed_ex((router), (datatype), _s_data, _s_count,               \
                                 _s_esize, _s_kind, &_s_ts, 1);                         \
    }))

#define seds_router_log_cstr(router, datatype, cstr)                                    \
    (__extension__({                                                                    \
        const char *_s = (const char*)(cstr);                                           \
        seds_router_log_string_ex((router), (datatype), _s, (_s?strlen(_s):0), NULL, 0);\
    }))

#define seds_router_log_cstr_queue(router, datatype, cstr)                              \
    (__extension__({                                                                    \
        const char *_s = (const char*)(cstr);                                           \
        seds_router_log_string_ex((router), (datatype), _s, (_s?strlen(_s):0), NULL, 1);\
    }))

#define seds_router_log_cstr_ts(router, datatype, ts_ms, cstr)                          \
    (__extension__({                                                                    \
        const char *_s = (const char*)(cstr);                                           \
        const uint64_t _s_ts = (uint64_t)(ts_ms);                                       \
        seds_router_log_string_ex((router), (datatype), _s, (_s?strlen(_s):0), &_s_ts, 0);\
    }))

#define seds_router_log_cstr_queue_ts(router, datatype, ts_ms, cstr)                    \
    (__extension__({                                                                    \
        const char *_s = (const char*)(cstr);                                           \
        const uint64_t _s_ts = (uint64_t)(ts_ms);                                       \
        seds_router_log_string_ex((router), (datatype), _s, (_s?strlen(_s):0), &_s_ts, 1);\
    }))

#define seds_pkt_get(pkt, out, count)                                                   \
    (__extension__({                                                                    \
        void        *_s_out   = (void*)(out);                                           \
        size_t       _s_count = (size_t)(count);                                        \
        size_t       _s_esize;                                                          \
        SedsElemKind _s_kind;                                                           \
        SEDS__KIND_SIZE((out), _s_kind, _s_esize);                                      \
        seds_pkt_get_typed((pkt), _s_out, _s_count, _s_esize, _s_kind);                 \
    }))
#endif

#ifdef __cplusplus
}
#endif

#endif
