#ifndef SEDSNET_CPP_WRAPPER_HPP
#define SEDSNET_CPP_WRAPPER_HPP

#include "sedsnet.h"
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace seds {

inline SedsResult type_ref_by_name(SedsName name, SedsTypeRef & out)
{
    SedsDataTypeInfo info{};
    SedsResult result = seds_dtype_get_info_by_name(name.ptr, name.len, nullptr, 0U, &info);
    if (result != SEDS_OK || !info.exists) {
        return result != SEDS_OK ? result : SEDS_INVALID_TYPE;
    }
    out.id = static_cast<SedsDataType>(info.id);
    return SEDS_OK;
}

inline SedsResult endpoint_ref_by_name(SedsName name, SedsEndpointRef & out)
{
    SedsEndpointInfo info{};
    SedsResult result = seds_endpoint_get_info_by_name(name.ptr, name.len, &info);
    if (result != SEDS_OK || !info.exists) {
        return result != SEDS_OK ? result : SEDS_BAD_ARG;
    }
    out.id = static_cast<SedsDataEndpoint>(info.id);
    return SEDS_OK;
}

inline bool exists(SedsTypeRef ty)
{
    return seds_dtype_exists(static_cast<uint32_t>(ty.id));
}

inline bool exists(SedsEndpointRef endpoint)
{
    return seds_endpoint_exists(static_cast<uint32_t>(endpoint.id));
}

inline SedsResult set_e2e_encryption_policy(SedsTypeRef ty, uint8_t policy)
{
    return seds_dtype_set_e2e_encryption_policy(static_cast<uint32_t>(ty.id), policy);
}

inline SedsRouter * router_new(SedsRouterMode mode,
                               SedsNowMsFn now_ms,
                               void * user,
                               const SedsLocalEndpointDesc * handlers,
                               size_t n_handlers,
                               uint8_t e2e_mode,
                               uint32_t e2e_key_id)
{
    return seds_router_new_ex(mode, now_ms, user, handlers, n_handlers, e2e_mode, e2e_key_id);
}

inline int32_t expected_size(SedsTypeRef ty)
{
    return seds_dtype_expected_size(ty.id);
}

namespace detail {
template<typename T>
struct elem_traits;

template<> struct elem_traits<uint8_t>  { static constexpr SedsElemKind kind = SEDS_EK_UNSIGNED; static constexpr size_t size = 1; };
template<> struct elem_traits<uint16_t> { static constexpr SedsElemKind kind = SEDS_EK_UNSIGNED; static constexpr size_t size = 2; };
template<> struct elem_traits<uint32_t> { static constexpr SedsElemKind kind = SEDS_EK_UNSIGNED; static constexpr size_t size = 4; };
template<> struct elem_traits<uint64_t> { static constexpr SedsElemKind kind = SEDS_EK_UNSIGNED; static constexpr size_t size = 8; };
template<> struct elem_traits<int8_t>   { static constexpr SedsElemKind kind = SEDS_EK_SIGNED;   static constexpr size_t size = 1; };
template<> struct elem_traits<int16_t>  { static constexpr SedsElemKind kind = SEDS_EK_SIGNED;   static constexpr size_t size = 2; };
template<> struct elem_traits<int32_t>  { static constexpr SedsElemKind kind = SEDS_EK_SIGNED;   static constexpr size_t size = 4; };
template<> struct elem_traits<int64_t>  { static constexpr SedsElemKind kind = SEDS_EK_SIGNED;   static constexpr size_t size = 8; };
template<> struct elem_traits<float>    { static constexpr SedsElemKind kind = SEDS_EK_FLOAT;    static constexpr size_t size = 4; };
template<> struct elem_traits<double>   { static constexpr SedsElemKind kind = SEDS_EK_FLOAT;    static constexpr size_t size = 8; };
} // namespace detail

template<typename T>
inline SedsResult router_log(SedsRouter * r, SedsDataType ty, const T * data, size_t count)
{
    return seds_router_log_typed_ex(r, ty, data, count,
                                    detail::elem_traits<T>::size,
                                    detail::elem_traits<T>::kind,
                                    nullptr, 0);
}

template<typename T>
inline SedsResult router_log(SedsRouter * r, SedsTypeRef ty, const T * data, size_t count)
{
    return router_log(r, ty.id, data, count);
}

template<typename T>
inline SedsResult router_log_queue(SedsRouter * r, SedsDataType ty, const T * data, size_t count)
{
    return seds_router_log_typed_ex(r, ty, data, count,
                                    detail::elem_traits<T>::size,
                                    detail::elem_traits<T>::kind,
                                    nullptr, 1);
}

template<typename T>
inline SedsResult router_log_queue(SedsRouter * r, SedsTypeRef ty, const T * data, size_t count)
{
    return router_log_queue(r, ty.id, data, count);
}

template<typename T>
inline SedsResult router_log_ts(SedsRouter * r, SedsDataType ty, uint64_t ts_ms, const T * data, size_t count)
{
    return seds_router_log_typed_ex(r, ty, data, count,
                                    detail::elem_traits<T>::size,
                                    detail::elem_traits<T>::kind,
                                    &ts_ms, 0);
}

template<typename T>
inline SedsResult router_log_ts(SedsRouter * r, SedsTypeRef ty, uint64_t ts_ms, const T * data, size_t count)
{
    return router_log_ts(r, ty.id, ts_ms, data, count);
}

inline SedsResult router_log_cstr(SedsRouter * r, SedsDataType ty, const char * s)
{
    return seds_router_log_string_ex(r, ty, s, s ? std::strlen(s) : 0U, nullptr, 0);
}

inline SedsResult router_log_cstr(SedsRouter * r, SedsTypeRef ty, const char * s)
{
    return router_log_cstr(r, ty.id, s);
}

inline SedsResult enable_managed_variable(SedsRouter * r, SedsTypeRef ty)
{
    return seds_router_enable_managed_variable(r, ty.id);
}

inline SedsResult enable_network_variable(SedsRouter * r, SedsTypeRef ty, bool can_read, bool can_write)
{
    return seds_router_enable_network_variable(r, ty.id, can_read, can_write);
}

inline SedsResult on_network_variable_update(SedsRouter * r,
                                             SedsTypeRef ty,
                                             SedsEndpointHandlerFn cb,
                                             void * user)
{
    return seds_router_on_network_variable_update(r, ty.id, cb, user);
}

inline void disable_managed_variable(SedsRouter * r, SedsTypeRef ty)
{
    seds_router_disable_managed_variable(r, ty.id);
}

inline SedsResult request_managed_variable(SedsRouter * r, SedsTypeRef ty)
{
    return seds_router_request_managed_variable(r, ty.id);
}

inline SedsResult seed_managed_variable_packed(SedsRouter * r, const uint8_t * bytes, size_t len)
{
    return seds_router_seed_managed_variable_packed(r, bytes, len);
}

inline SedsResult set_network_variable_packed(SedsRouter * r, const uint8_t * bytes, size_t len)
{
    return seds_router_set_network_variable_packed(r, bytes, len);
}

inline int32_t cached_managed_variable_packed_len(SedsRouter * r, SedsTypeRef ty)
{
    return seds_router_cached_managed_variable_packed_len(r, ty.id);
}

inline int32_t cached_managed_variable_packed(SedsRouter * r, SedsTypeRef ty, uint8_t * out, size_t out_len)
{
    return seds_router_cached_managed_variable_packed(r, ty.id, out, out_len);
}

inline int32_t get_network_variable_packed_len(SedsRouter * r, SedsTypeRef ty, uint32_t stale_after_ms)
{
    return seds_router_get_network_variable_packed_len(r, ty.id, stale_after_ms);
}

inline int32_t get_network_variable_packed(SedsRouter * r,
                                               SedsTypeRef ty,
                                               uint32_t stale_after_ms,
                                               uint8_t * out,
                                               size_t out_len)
{
    return seds_router_get_network_variable_packed(r, ty.id, stale_after_ms, out, out_len);
}

inline int32_t router_memory_layout_len(SedsRouter * r)
{
    return seds_router_export_memory_layout_len(r);
}

inline SedsResult router_memory_layout(SedsRouter * r, char * out, size_t out_len)
{
    return seds_router_export_memory_layout(r, out, out_len);
}

inline int32_t relay_memory_layout_len(SedsRelay * r)
{
    return seds_relay_export_memory_layout_len(r);
}

inline SedsResult relay_memory_layout(SedsRelay * r, char * out, size_t out_len)
{
    return seds_relay_export_memory_layout(r, out, out_len);
}

inline int32_t router_client_stats_len(SedsRouter * r, SedsName sender)
{
    return seds_router_export_client_stats_len(r, sender.ptr, sender.len);
}

inline SedsResult router_client_stats(SedsRouter * r, SedsName sender, char * out, size_t out_len)
{
    return seds_router_export_client_stats(r, sender.ptr, sender.len, out, out_len);
}

inline int32_t relay_client_stats_len(SedsRelay * r, SedsName sender)
{
    return seds_relay_export_client_stats_len(r, sender.ptr, sender.len);
}

inline SedsResult relay_client_stats(SedsRelay * r, SedsName sender, char * out, size_t out_len)
{
    return seds_relay_export_client_stats(r, sender.ptr, sender.len, out, out_len);
}

inline SedsResult router_announce_leave(SedsRouter * r)
{
    return seds_router_announce_leave(r);
}

inline SedsResult relay_announce_leave(SedsRelay * r)
{
    return seds_relay_announce_leave(r);
}

template<typename T>
inline SedsResult pkt_get(const SedsPacketView * pkt, T * out, size_t count)
{
    return seds_pkt_get_typed(pkt, out, count,
                              detail::elem_traits<T>::size,
                              detail::elem_traits<T>::kind);
}

} // namespace seds

#endif
