#include "sedsprintf_c_wrapper.h"

#include <string.h>

static SedsWrapperRouter g_router;
static SedsWrapperRelay g_relay;

static int32_t side_id(SedsSideRef side)
{
    return side.id;
}

SedsWrapperRouterConfig seds_wrapper_router_default_config(void)
{
    SedsWrapperRouterConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = Seds_RM_Relay;
#if defined(SEDS_ENABLE_CRYPTO_SHIM)
    cfg.e2e_mode = SEDS_ROUTER_E2E_PREFERRED;
#else
    cfg.e2e_mode = SEDS_ROUTER_E2E_DISABLED;
#endif
    cfg.e2e_key_id = 0U;
    cfg.timesync_source_timeout_ms = 5000ULL;
    cfg.timesync_announce_interval_ms = 2000ULL;
    cfg.timesync_request_interval_ms = 2000ULL;
    cfg.announce_discovery = true;
    return cfg;
}

SedsWrapperRelayConfig seds_wrapper_relay_default_config(void)
{
    SedsWrapperRelayConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.announce_discovery = true;
    return cfg;
}

SedsResult seds_wrapper_router_init(SedsWrapperRouter * node,
                                    const SedsWrapperRouterConfig * cfg)
{
    SedsResult result;

    if (!node || !cfg) {
        return SEDS_BAD_ARG;
    }

    memset(node, 0, sizeof(*node));
    node->primary_side = SEDS_SIDE_INVALID;
    node->init_error = SEDS_OK;
    node->router = seds_router_new_ex(cfg->mode,
                                      cfg->now_ms,
                                      cfg->now_user,
                                      cfg->handlers,
                                      cfg->num_handlers,
                                      cfg->e2e_mode,
                                      cfg->e2e_key_id);
    if (!node->router) {
        node->init_error = SEDS_ERR;
        return SEDS_ERR;
    }

    node->created = 1U;

    if (cfg->sender.ptr && cfg->sender.len != 0U) {
        result = seds_router_set_sender_id(node->router, cfg->sender.ptr, cfg->sender.len);
        if (result != SEDS_OK) {
            node->init_error = result;
            return result;
        }
    }

    if (cfg->configure_timesync) {
        result = seds_router_configure_timesync(node->router,
                                                true,
                                                cfg->timesync_role,
                                                cfg->timesync_priority,
                                                cfg->timesync_source_timeout_ms,
                                                cfg->timesync_announce_interval_ms,
                                                cfg->timesync_request_interval_ms);
        if (result != SEDS_OK) {
            node->init_error = result;
            return result;
        }
    }

    if (cfg->announce_discovery) {
        result = seds_router_announce_discovery(node->router);
        if (result != SEDS_OK) {
            node->init_error = result;
            return result;
        }
    }

    return SEDS_OK;
}

SedsResult seds_global_router_init(const SedsWrapperRouterConfig * cfg)
{
    return seds_wrapper_router_init(&g_router, cfg);
}

void seds_wrapper_router_free(SedsWrapperRouter * node)
{
    if (node && node->router) {
        seds_router_free(node->router);
        node->router = NULL;
        node->created = 0U;
        node->primary_side = SEDS_SIDE_INVALID;
    }
}

void seds_global_router_free(void)
{
    seds_wrapper_router_free(&g_router);
}

SedsRouter * seds_wrapper_router_handle(SedsWrapperRouter * node)
{
    return node ? node->router : NULL;
}

SedsRouter * seds_global_router_handle(void)
{
    return seds_wrapper_router_handle(&g_router);
}

int32_t seds_wrapper_router_init_error(const SedsWrapperRouter * node)
{
    return node ? node->init_error : SEDS_BAD_ARG;
}

int32_t seds_global_router_init_error(void)
{
    return seds_wrapper_router_init_error(&g_router);
}

SedsSideRef seds_wrapper_router_add_serialized_side(SedsWrapperRouter * node,
                                                    SedsName name,
                                                    SedsTransmitFn tx,
                                                    void * tx_user,
                                                    bool reliable_enabled)
{
    SedsSideRef side = SEDS_SIDE_INVALID;

    if (!node || !node->router) {
        return side;
    }

    side.id = seds_router_add_side_serialized(node->router,
                                              name.ptr,
                                              name.len,
                                              tx,
                                              tx_user,
                                              reliable_enabled);
    if (seds_side_is_valid(side) && !seds_side_is_valid(node->primary_side)) {
        node->primary_side = side;
    }
    return side;
}

SedsSideRef seds_global_router_add_serialized_side(SedsName name,
                                                   SedsTransmitFn tx,
                                                   void * tx_user,
                                                   bool reliable_enabled)
{
    return seds_wrapper_router_add_serialized_side(&g_router, name, tx, tx_user, reliable_enabled);
}

SedsSideRef seds_wrapper_router_add_serialized_small_side(SedsWrapperRouter * node,
                                                          SedsName name,
                                                          SedsTransmitFn tx,
                                                          void * tx_user,
                                                          bool reliable_enabled,
                                                          size_t max_frame_bytes)
{
    SedsSideRef side = SEDS_SIDE_INVALID;

    if (!node || !node->router) {
        return side;
    }

    side.id = seds_router_add_side_serialized_small_packets(node->router,
                                                            name.ptr,
                                                            name.len,
                                                            tx,
                                                            tx_user,
                                                            reliable_enabled,
                                                            max_frame_bytes);
    if (seds_side_is_valid(side) && !seds_side_is_valid(node->primary_side)) {
        node->primary_side = side;
    }
    return side;
}

SedsSideRef seds_global_router_add_serialized_small_side(SedsName name,
                                                         SedsTransmitFn tx,
                                                         void * tx_user,
                                                         bool reliable_enabled,
                                                         size_t max_frame_bytes)
{
    return seds_wrapper_router_add_serialized_small_side(&g_router,
                                                         name,
                                                         tx,
                                                         tx_user,
                                                         reliable_enabled,
                                                         max_frame_bytes);
}

SedsSideRef seds_wrapper_router_add_packet_side(SedsWrapperRouter * node,
                                                SedsName name,
                                                SedsEndpointHandlerFn tx,
                                                void * tx_user,
                                                bool reliable_enabled)
{
    SedsSideRef side = SEDS_SIDE_INVALID;

    if (!node || !node->router) {
        return side;
    }

    side.id = seds_router_add_side_packet(node->router,
                                          name.ptr,
                                          name.len,
                                          tx,
                                          tx_user,
                                          reliable_enabled);
    if (seds_side_is_valid(side) && !seds_side_is_valid(node->primary_side)) {
        node->primary_side = side;
    }
    return side;
}

SedsSideRef seds_global_router_add_packet_side(SedsName name,
                                               SedsEndpointHandlerFn tx,
                                               void * tx_user,
                                               bool reliable_enabled)
{
    return seds_wrapper_router_add_packet_side(&g_router, name, tx, tx_user, reliable_enabled);
}

SedsResult seds_wrapper_router_rx_serialized(SedsWrapperRouter * node,
                                             const uint8_t * bytes,
                                             size_t len)
{
    if (!node || !node->router) {
        return SEDS_BAD_ARG;
    }
    return seds_router_rx_serialized_packet_to_queue(node->router, bytes, len);
}

SedsResult seds_global_router_rx_serialized(const uint8_t * bytes, size_t len)
{
    return seds_wrapper_router_rx_serialized(&g_router, bytes, len);
}

SedsResult seds_wrapper_router_rx_serialized_from_side(SedsWrapperRouter * node,
                                                       SedsSideRef side,
                                                       const uint8_t * bytes,
                                                       size_t len)
{
    if (!node || !node->router || !seds_side_is_valid(side)) {
        return SEDS_BAD_ARG;
    }
    return seds_router_rx_serialized_packet_to_queue_from_side(node->router,
                                                               (uint32_t)side.id,
                                                               bytes,
                                                               len);
}

SedsResult seds_global_router_rx_serialized_from_side(SedsSideRef side,
                                                      const uint8_t * bytes,
                                                      size_t len)
{
    return seds_wrapper_router_rx_serialized_from_side(&g_router, side, bytes, len);
}

SedsResult seds_wrapper_router_process(SedsWrapperRouter * node, uint32_t timeout_ms)
{
    if (!node || !node->router) {
        return SEDS_BAD_ARG;
    }
    return seds_router_process_all_queues_with_timeout(node->router, timeout_ms);
}

SedsResult seds_global_router_process(uint32_t timeout_ms)
{
    return seds_wrapper_router_process(&g_router, timeout_ms);
}

SedsResult seds_wrapper_router_periodic(SedsWrapperRouter * node, uint32_t timeout_ms)
{
    if (!node || !node->router) {
        return SEDS_BAD_ARG;
    }
    return seds_router_periodic(node->router, timeout_ms);
}

SedsResult seds_global_router_periodic(uint32_t timeout_ms)
{
    return seds_wrapper_router_periodic(&g_router, timeout_ms);
}

SedsResult seds_global_router_periodic_no_timesync(uint32_t timeout_ms)
{
    if (!g_router.router) {
        return SEDS_BAD_ARG;
    }
    return seds_router_periodic_no_timesync(g_router.router, timeout_ms);
}

SedsResult seds_wrapper_router_poll_timesync(SedsWrapperRouter * node, bool * out_did_queue)
{
    if (!node || !node->router) {
        return SEDS_BAD_ARG;
    }
    return seds_router_poll_timesync(node->router, out_did_queue);
}

SedsResult seds_global_router_poll_timesync(bool * out_did_queue)
{
    return seds_wrapper_router_poll_timesync(&g_router, out_did_queue);
}

SedsResult seds_wrapper_router_announce_discovery(SedsWrapperRouter * node)
{
    if (!node || !node->router) {
        return SEDS_BAD_ARG;
    }
    return seds_router_announce_discovery(node->router);
}

SedsResult seds_global_router_announce_discovery(void)
{
    return seds_wrapper_router_announce_discovery(&g_router);
}

SedsResult seds_wrapper_router_poll_discovery(SedsWrapperRouter * node, bool * out_did_queue)
{
    if (!node || !node->router) {
        return SEDS_BAD_ARG;
    }
    return seds_router_poll_discovery(node->router, out_did_queue);
}

SedsResult seds_global_router_poll_discovery(bool * out_did_queue)
{
    return seds_wrapper_router_poll_discovery(&g_router, out_did_queue);
}

SedsResult seds_wrapper_router_enable_managed_variable(SedsWrapperRouter * node, SedsTypeRef ty)
{
    if (!node || !node->router) {
        return SEDS_BAD_ARG;
    }
    return seds_router_enable_managed_variable(node->router, ty.id);
}

SedsResult seds_global_router_enable_managed_variable(SedsTypeRef ty)
{
    return seds_wrapper_router_enable_managed_variable(&g_router, ty);
}

void seds_wrapper_router_disable_managed_variable(SedsWrapperRouter * node, SedsTypeRef ty)
{
    if (!node || !node->router) {
        return;
    }
    seds_router_disable_managed_variable(node->router, ty.id);
}

void seds_global_router_disable_managed_variable(SedsTypeRef ty)
{
    seds_wrapper_router_disable_managed_variable(&g_router, ty);
}

SedsResult seds_wrapper_router_request_managed_variable(SedsWrapperRouter * node, SedsTypeRef ty)
{
    if (!node || !node->router) {
        return SEDS_BAD_ARG;
    }
    return seds_router_request_managed_variable(node->router, ty.id);
}

SedsResult seds_global_router_request_managed_variable(SedsTypeRef ty)
{
    return seds_wrapper_router_request_managed_variable(&g_router, ty);
}

SedsResult seds_wrapper_router_seed_managed_variable_serialized(SedsWrapperRouter * node,
                                                                const uint8_t * bytes,
                                                                size_t len)
{
    if (!node || !node->router) {
        return SEDS_BAD_ARG;
    }
    return seds_router_seed_managed_variable_serialized(node->router, bytes, len);
}

SedsResult seds_global_router_seed_managed_variable_serialized(const uint8_t * bytes, size_t len)
{
    return seds_wrapper_router_seed_managed_variable_serialized(&g_router, bytes, len);
}

int32_t seds_wrapper_router_cached_managed_variable_serialized_len(SedsWrapperRouter * node,
                                                                   SedsTypeRef ty)
{
    if (!node || !node->router) {
        return SEDS_BAD_ARG;
    }
    return seds_router_cached_managed_variable_serialized_len(node->router, ty.id);
}

int32_t seds_global_router_cached_managed_variable_serialized_len(SedsTypeRef ty)
{
    return seds_wrapper_router_cached_managed_variable_serialized_len(&g_router, ty);
}

int32_t seds_wrapper_router_cached_managed_variable_serialized(SedsWrapperRouter * node,
                                                               SedsTypeRef ty,
                                                               uint8_t * out,
                                                               size_t out_len)
{
    if (!node || !node->router) {
        return SEDS_BAD_ARG;
    }
    return seds_router_cached_managed_variable_serialized(node->router, ty.id, out, out_len);
}

int32_t seds_global_router_cached_managed_variable_serialized(SedsTypeRef ty,
                                                              uint8_t * out,
                                                              size_t out_len)
{
    return seds_wrapper_router_cached_managed_variable_serialized(&g_router, ty, out, out_len);
}

SedsResult seds_wrapper_router_log_typed(SedsWrapperRouter * node,
                                         SedsTypeRef ty,
                                         const void * data,
                                         size_t count,
                                         size_t elem_size,
                                         SedsElemKind elem_kind,
                                         const uint64_t * timestamp_ms_opt,
                                         int queue)
{
    if (!node || !node->router) {
        return SEDS_BAD_ARG;
    }
    return seds_router_log_typed_ex(node->router,
                                    ty.id,
                                    data,
                                    count,
                                    elem_size,
                                    elem_kind,
                                    timestamp_ms_opt,
                                    queue);
}

SedsResult seds_global_router_log_typed(SedsTypeRef ty,
                                        const void * data,
                                        size_t count,
                                        size_t elem_size,
                                        SedsElemKind elem_kind,
                                        const uint64_t * timestamp_ms_opt,
                                        int queue)
{
    return seds_wrapper_router_log_typed(&g_router,
                                         ty,
                                         data,
                                         count,
                                         elem_size,
                                         elem_kind,
                                         timestamp_ms_opt,
                                         queue);
}

SedsResult seds_wrapper_router_log_string(SedsWrapperRouter * node,
                                          SedsTypeRef ty,
                                          const char * text,
                                          const uint64_t * timestamp_ms_opt,
                                          int queue)
{
    if (!node || !node->router) {
        return SEDS_BAD_ARG;
    }
    return seds_router_log_string_ex(node->router,
                                     ty.id,
                                     text,
                                     text ? strlen(text) : 0U,
                                     timestamp_ms_opt,
                                     queue);
}

SedsResult seds_global_router_log_string(SedsTypeRef ty,
                                         const char * text,
                                         const uint64_t * timestamp_ms_opt,
                                         int queue)
{
    return seds_wrapper_router_log_string(&g_router, ty, text, timestamp_ms_opt, queue);
}

SedsResult seds_global_router_remove_side(SedsSideRef side)
{
    return g_router.router ? seds_router_remove_side(g_router.router, side_id(side)) : SEDS_BAD_ARG;
}

SedsResult seds_global_router_set_side_ingress_enabled(SedsSideRef side, bool enabled)
{
    return g_router.router ? seds_router_set_side_ingress_enabled(g_router.router, side_id(side), enabled) : SEDS_BAD_ARG;
}

SedsResult seds_global_router_set_side_egress_enabled(SedsSideRef side, bool enabled)
{
    return g_router.router ? seds_router_set_side_egress_enabled(g_router.router, side_id(side), enabled) : SEDS_BAD_ARG;
}

SedsResult seds_global_router_set_route(SedsSideRef src_side, SedsSideRef dst_side, bool enabled)
{
    return g_router.router ? seds_router_set_route(g_router.router, side_id(src_side), side_id(dst_side), enabled) : SEDS_BAD_ARG;
}

SedsResult seds_global_router_clear_route(SedsSideRef src_side, SedsSideRef dst_side)
{
    return g_router.router ? seds_router_clear_route(g_router.router, side_id(src_side), side_id(dst_side)) : SEDS_BAD_ARG;
}

SedsResult seds_global_router_set_typed_route(SedsSideRef src_side, SedsTypeRef ty, SedsSideRef dst_side, bool enabled)
{
    return g_router.router ? seds_router_set_typed_route(g_router.router, side_id(src_side), ty.id, side_id(dst_side), enabled) : SEDS_BAD_ARG;
}

SedsResult seds_global_router_clear_typed_route(SedsSideRef src_side, SedsTypeRef ty, SedsSideRef dst_side)
{
    return g_router.router ? seds_router_clear_typed_route(g_router.router, side_id(src_side), ty.id, side_id(dst_side)) : SEDS_BAD_ARG;
}

SedsResult seds_global_router_set_source_route_mode(SedsSideRef src_side, SedsRouteSelectionMode mode)
{
    return g_router.router ? seds_router_set_source_route_mode(g_router.router, side_id(src_side), mode) : SEDS_BAD_ARG;
}

SedsResult seds_global_router_clear_source_route_mode(SedsSideRef src_side)
{
    return g_router.router ? seds_router_clear_source_route_mode(g_router.router, side_id(src_side)) : SEDS_BAD_ARG;
}

SedsResult seds_global_router_set_route_weight(SedsSideRef src_side, SedsSideRef dst_side, uint32_t weight)
{
    return g_router.router ? seds_router_set_route_weight(g_router.router, side_id(src_side), side_id(dst_side), weight) : SEDS_BAD_ARG;
}

SedsResult seds_global_router_clear_route_weight(SedsSideRef src_side, SedsSideRef dst_side)
{
    return g_router.router ? seds_router_clear_route_weight(g_router.router, side_id(src_side), side_id(dst_side)) : SEDS_BAD_ARG;
}

SedsResult seds_global_router_set_route_priority(SedsSideRef src_side, SedsSideRef dst_side, uint32_t priority)
{
    return g_router.router ? seds_router_set_route_priority(g_router.router, side_id(src_side), side_id(dst_side), priority) : SEDS_BAD_ARG;
}

SedsResult seds_global_router_clear_route_priority(SedsSideRef src_side, SedsSideRef dst_side)
{
    return g_router.router ? seds_router_clear_route_priority(g_router.router, side_id(src_side), side_id(dst_side)) : SEDS_BAD_ARG;
}

SedsResult seds_global_router_get_network_time_ms(uint64_t * out_ms)
{
    return g_router.router ? seds_router_get_network_time_ms(g_router.router, out_ms) : SEDS_BAD_ARG;
}

SedsResult seds_global_router_get_network_time(SedsNetworkTime * out)
{
    return g_router.router ? seds_router_get_network_time(g_router.router, out) : SEDS_BAD_ARG;
}

int32_t seds_global_router_export_topology_len(void)
{
    return g_router.router ? seds_router_export_topology_len(g_router.router) : SEDS_BAD_ARG;
}

SedsResult seds_global_router_export_topology(char * buf, size_t buf_len)
{
    return g_router.router ? seds_router_export_topology(g_router.router, buf, buf_len) : SEDS_BAD_ARG;
}

int32_t seds_global_router_export_runtime_stats_len(void)
{
    return g_router.router ? seds_router_export_runtime_stats_len(g_router.router) : SEDS_BAD_ARG;
}

SedsResult seds_global_router_export_runtime_stats(char * buf, size_t buf_len)
{
    return g_router.router ? seds_router_export_runtime_stats(g_router.router, buf, buf_len) : SEDS_BAD_ARG;
}

SedsResult seds_wrapper_relay_init(SedsWrapperRelay * node,
                                   const SedsWrapperRelayConfig * cfg)
{
    SedsResult result;

    if (!node || !cfg) {
        return SEDS_BAD_ARG;
    }

    memset(node, 0, sizeof(*node));
    node->primary_side = SEDS_SIDE_INVALID;
    node->init_error = SEDS_OK;
    node->relay = seds_relay_new(cfg->now_ms, cfg->now_user);
    if (!node->relay) {
        node->init_error = SEDS_ERR;
        return SEDS_ERR;
    }

    node->created = 1U;

    if (cfg->sender.ptr && cfg->sender.len != 0U) {
        result = seds_relay_set_sender_id(node->relay, cfg->sender.ptr, cfg->sender.len);
        if (result != SEDS_OK) {
            node->init_error = result;
            return result;
        }
    }

    if (cfg->announce_discovery) {
        result = seds_relay_announce_discovery(node->relay);
        if (result != SEDS_OK) {
            node->init_error = result;
            return result;
        }
    }

    return SEDS_OK;
}

SedsResult seds_global_relay_init(const SedsWrapperRelayConfig * cfg)
{
    return seds_wrapper_relay_init(&g_relay, cfg);
}

void seds_wrapper_relay_free(SedsWrapperRelay * node)
{
    if (node && node->relay) {
        seds_relay_free(node->relay);
        node->relay = NULL;
        node->created = 0U;
        node->primary_side = SEDS_SIDE_INVALID;
    }
}

void seds_global_relay_free(void)
{
    seds_wrapper_relay_free(&g_relay);
}

SedsRelay * seds_wrapper_relay_handle(SedsWrapperRelay * node)
{
    return node ? node->relay : NULL;
}

SedsRelay * seds_global_relay_handle(void)
{
    return seds_wrapper_relay_handle(&g_relay);
}

int32_t seds_wrapper_relay_init_error(const SedsWrapperRelay * node)
{
    return node ? node->init_error : SEDS_BAD_ARG;
}

int32_t seds_global_relay_init_error(void)
{
    return seds_wrapper_relay_init_error(&g_relay);
}

SedsSideRef seds_wrapper_relay_add_serialized_side(SedsWrapperRelay * node,
                                                   SedsName name,
                                                   SedsTransmitFn tx,
                                                   void * tx_user,
                                                   bool reliable_enabled)
{
    SedsSideRef side = SEDS_SIDE_INVALID;
    if (!node || !node->relay) {
        return side;
    }
    side.id = seds_relay_add_side_serialized(node->relay, name.ptr, name.len, tx, tx_user, reliable_enabled);
    if (seds_side_is_valid(side) && !seds_side_is_valid(node->primary_side)) {
        node->primary_side = side;
    }
    return side;
}

SedsSideRef seds_global_relay_add_serialized_side(SedsName name,
                                                  SedsTransmitFn tx,
                                                  void * tx_user,
                                                  bool reliable_enabled)
{
    return seds_wrapper_relay_add_serialized_side(&g_relay, name, tx, tx_user, reliable_enabled);
}

SedsSideRef seds_wrapper_relay_add_serialized_small_side(SedsWrapperRelay * node,
                                                         SedsName name,
                                                         SedsTransmitFn tx,
                                                         void * tx_user,
                                                         bool reliable_enabled,
                                                         size_t max_frame_bytes)
{
    SedsSideRef side = SEDS_SIDE_INVALID;
    if (!node || !node->relay) {
        return side;
    }
    side.id = seds_relay_add_side_serialized_small_packets(node->relay,
                                                           name.ptr,
                                                           name.len,
                                                           tx,
                                                           tx_user,
                                                           reliable_enabled,
                                                           max_frame_bytes);
    if (seds_side_is_valid(side) && !seds_side_is_valid(node->primary_side)) {
        node->primary_side = side;
    }
    return side;
}

SedsSideRef seds_global_relay_add_serialized_small_side(SedsName name,
                                                        SedsTransmitFn tx,
                                                        void * tx_user,
                                                        bool reliable_enabled,
                                                        size_t max_frame_bytes)
{
    return seds_wrapper_relay_add_serialized_small_side(&g_relay,
                                                        name,
                                                        tx,
                                                        tx_user,
                                                        reliable_enabled,
                                                        max_frame_bytes);
}

SedsSideRef seds_wrapper_relay_add_packet_side(SedsWrapperRelay * node,
                                               SedsName name,
                                               SedsEndpointHandlerFn tx,
                                               void * tx_user,
                                               bool reliable_enabled)
{
    SedsSideRef side = SEDS_SIDE_INVALID;
    if (!node || !node->relay) {
        return side;
    }
    side.id = seds_relay_add_side_packet(node->relay, name.ptr, name.len, tx, tx_user, reliable_enabled);
    if (seds_side_is_valid(side) && !seds_side_is_valid(node->primary_side)) {
        node->primary_side = side;
    }
    return side;
}

SedsSideRef seds_global_relay_add_packet_side(SedsName name,
                                              SedsEndpointHandlerFn tx,
                                              void * tx_user,
                                              bool reliable_enabled)
{
    return seds_wrapper_relay_add_packet_side(&g_relay, name, tx, tx_user, reliable_enabled);
}

SedsResult seds_wrapper_relay_rx_serialized_from_side(SedsWrapperRelay * node,
                                                      SedsSideRef side,
                                                      const uint8_t * bytes,
                                                      size_t len)
{
    if (!node || !node->relay || !seds_side_is_valid(side)) {
        return SEDS_BAD_ARG;
    }
    return seds_relay_rx_serialized_from_side(node->relay, (uint32_t)side.id, bytes, len);
}

SedsResult seds_global_relay_rx_serialized_from_side(SedsSideRef side,
                                                     const uint8_t * bytes,
                                                     size_t len)
{
    return seds_wrapper_relay_rx_serialized_from_side(&g_relay, side, bytes, len);
}

SedsResult seds_wrapper_relay_rx_packet_from_side(SedsWrapperRelay * node,
                                                  SedsSideRef side,
                                                  const SedsPacketView * view)
{
    if (!node || !node->relay || !seds_side_is_valid(side)) {
        return SEDS_BAD_ARG;
    }
    return seds_relay_rx_packet_from_side(node->relay, (uint32_t)side.id, view);
}

SedsResult seds_global_relay_rx_packet_from_side(SedsSideRef side,
                                                 const SedsPacketView * view)
{
    return seds_wrapper_relay_rx_packet_from_side(&g_relay, side, view);
}

SedsResult seds_wrapper_relay_process(SedsWrapperRelay * node, uint32_t timeout_ms)
{
    if (!node || !node->relay) {
        return SEDS_BAD_ARG;
    }
    return seds_relay_process_all_queues_with_timeout(node->relay, timeout_ms);
}

SedsResult seds_global_relay_process(uint32_t timeout_ms)
{
    return seds_wrapper_relay_process(&g_relay, timeout_ms);
}

SedsResult seds_wrapper_relay_periodic(SedsWrapperRelay * node, uint32_t timeout_ms)
{
    if (!node || !node->relay) {
        return SEDS_BAD_ARG;
    }
    return seds_relay_periodic(node->relay, timeout_ms);
}

SedsResult seds_global_relay_periodic(uint32_t timeout_ms)
{
    return seds_wrapper_relay_periodic(&g_relay, timeout_ms);
}

SedsResult seds_wrapper_relay_announce_discovery(SedsWrapperRelay * node)
{
    if (!node || !node->relay) {
        return SEDS_BAD_ARG;
    }
    return seds_relay_announce_discovery(node->relay);
}

SedsResult seds_global_relay_announce_discovery(void)
{
    return seds_wrapper_relay_announce_discovery(&g_relay);
}

SedsResult seds_wrapper_relay_poll_discovery(SedsWrapperRelay * node, bool * out_did_queue)
{
    if (!node || !node->relay) {
        return SEDS_BAD_ARG;
    }
    return seds_relay_poll_discovery(node->relay, out_did_queue);
}

SedsResult seds_global_relay_poll_discovery(bool * out_did_queue)
{
    return seds_wrapper_relay_poll_discovery(&g_relay, out_did_queue);
}

int32_t seds_global_relay_export_topology_len(void)
{
    return g_relay.relay ? seds_relay_export_topology_len(g_relay.relay) : SEDS_BAD_ARG;
}

SedsResult seds_global_relay_export_topology(char * buf, size_t buf_len)
{
    return g_relay.relay ? seds_relay_export_topology(g_relay.relay, buf, buf_len) : SEDS_BAD_ARG;
}

int32_t seds_global_relay_export_runtime_stats_len(void)
{
    return g_relay.relay ? seds_relay_export_runtime_stats_len(g_relay.relay) : SEDS_BAD_ARG;
}

SedsResult seds_global_relay_export_runtime_stats(char * buf, size_t buf_len)
{
    return g_relay.relay ? seds_relay_export_runtime_stats(g_relay.relay, buf, buf_len) : SEDS_BAD_ARG;
}

SedsResult seds_global_relay_remove_side(SedsSideRef side)
{
    return g_relay.relay ? seds_relay_remove_side(g_relay.relay, side_id(side)) : SEDS_BAD_ARG;
}

SedsResult seds_global_relay_set_side_ingress_enabled(SedsSideRef side, bool enabled)
{
    return g_relay.relay ? seds_relay_set_side_ingress_enabled(g_relay.relay, side_id(side), enabled) : SEDS_BAD_ARG;
}

SedsResult seds_global_relay_set_side_egress_enabled(SedsSideRef side, bool enabled)
{
    return g_relay.relay ? seds_relay_set_side_egress_enabled(g_relay.relay, side_id(side), enabled) : SEDS_BAD_ARG;
}

SedsResult seds_global_relay_set_route(SedsSideRef src_side, SedsSideRef dst_side, bool enabled)
{
    return g_relay.relay ? seds_relay_set_route(g_relay.relay, side_id(src_side), side_id(dst_side), enabled) : SEDS_BAD_ARG;
}

SedsResult seds_global_relay_clear_route(SedsSideRef src_side, SedsSideRef dst_side)
{
    return g_relay.relay ? seds_relay_clear_route(g_relay.relay, side_id(src_side), side_id(dst_side)) : SEDS_BAD_ARG;
}

SedsResult seds_global_relay_set_typed_route(SedsSideRef src_side, SedsTypeRef ty, SedsSideRef dst_side, bool enabled)
{
    return g_relay.relay ? seds_relay_set_typed_route(g_relay.relay, side_id(src_side), ty.id, side_id(dst_side), enabled) : SEDS_BAD_ARG;
}

SedsResult seds_global_relay_clear_typed_route(SedsSideRef src_side, SedsTypeRef ty, SedsSideRef dst_side)
{
    return g_relay.relay ? seds_relay_clear_typed_route(g_relay.relay, side_id(src_side), ty.id, side_id(dst_side)) : SEDS_BAD_ARG;
}

SedsResult seds_global_relay_set_source_route_mode(SedsSideRef src_side, SedsRouteSelectionMode mode)
{
    return g_relay.relay ? seds_relay_set_source_route_mode(g_relay.relay, side_id(src_side), mode) : SEDS_BAD_ARG;
}

SedsResult seds_global_relay_clear_source_route_mode(SedsSideRef src_side)
{
    return g_relay.relay ? seds_relay_clear_source_route_mode(g_relay.relay, side_id(src_side)) : SEDS_BAD_ARG;
}

SedsResult seds_global_relay_set_route_weight(SedsSideRef src_side, SedsSideRef dst_side, uint32_t weight)
{
    return g_relay.relay ? seds_relay_set_route_weight(g_relay.relay, side_id(src_side), side_id(dst_side), weight) : SEDS_BAD_ARG;
}

SedsResult seds_global_relay_clear_route_weight(SedsSideRef src_side, SedsSideRef dst_side)
{
    return g_relay.relay ? seds_relay_clear_route_weight(g_relay.relay, side_id(src_side), side_id(dst_side)) : SEDS_BAD_ARG;
}

SedsResult seds_global_relay_set_route_priority(SedsSideRef src_side, SedsSideRef dst_side, uint32_t priority)
{
    return g_relay.relay ? seds_relay_set_route_priority(g_relay.relay, side_id(src_side), side_id(dst_side), priority) : SEDS_BAD_ARG;
}

SedsResult seds_global_relay_clear_route_priority(SedsSideRef src_side, SedsSideRef dst_side)
{
    return g_relay.relay ? seds_relay_clear_route_priority(g_relay.relay, side_id(src_side), side_id(dst_side)) : SEDS_BAD_ARG;
}
