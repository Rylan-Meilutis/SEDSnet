#include "sedsnet.h"
#include "sedsnet_c_wrapper.h"
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static bool view_eq(const char * ptr, size_t len, const char * expected)
{
    return ptr != NULL && len == strlen(expected) && memcmp(ptr, expected, len) == 0;
}

static SedsResult noop_tx(const uint8_t *bytes, size_t len, void *user)
{
    (void)bytes;
    (void)len;
    (void)user;
    return SEDS_OK;
}

typedef struct CaptureTx
{
    size_t frames;
    size_t max_len;
} CaptureTx;

static SedsResult capture_tx(const uint8_t *bytes, size_t len, void *user)
{
    CaptureTx * capture = (CaptureTx *) user;
    assert(bytes != NULL);
    assert(capture != NULL);
    capture->frames += 1U;
    if (len > capture->max_len) {
        capture->max_len = len;
    }
    return SEDS_OK;
}

#if defined(SEDS_ENABLE_CRYPTOGRAPHY)
static SedsResult test_crypto_seal(uint32_t key_id,
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
                                   void * user)
{
    (void) nonce;
    (void) nonce_len;
    (void) aad;
    (void) aad_len;
    (void) user;
    if (ciphertext_cap < plaintext_len || tag_cap < 4U) {
        return SEDS_SIZE_MISMATCH_ERROR;
    }
    for (size_t i = 0; i < plaintext_len; ++i) {
        ciphertext_out[i] = (uint8_t)(plaintext[i] ^ (uint8_t)key_id);
    }
    tag_out[0] = 'S';
    tag_out[1] = 'E';
    tag_out[2] = 'D';
    tag_out[3] = 'S';
    *ciphertext_len_out = plaintext_len;
    *tag_len_out = 4U;
    return SEDS_OK;
}

static SedsResult test_crypto_open(uint32_t key_id,
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
                                   void * user)
{
    (void) nonce;
    (void) nonce_len;
    (void) aad;
    (void) aad_len;
    (void) user;
    if (plaintext_cap < ciphertext_len || tag_len != 4U ||
        tag[0] != 'S' || tag[1] != 'E' || tag[2] != 'D' || tag[3] != 'S') {
        return SEDS_SIZE_MISMATCH_ERROR;
    }
    for (size_t i = 0; i < ciphertext_len; ++i) {
        plaintext_out[i] = (uint8_t)(ciphertext[i] ^ (uint8_t)key_id);
    }
    *plaintext_len_out = ciphertext_len;
    return SEDS_OK;
}
#endif

int main(void)
{
    const char ep_name[] = "C_RUNTIME_SCHEMA_EP_220";
    const char ep_desc[] = "C runtime schema endpoint";
    const char ty_name[] = "C_RUNTIME_SCHEMA_TYPE_221";
    const char ty_desc[] = "C runtime schema type";
    const char chunk_ep_name[] = "C_RUNTIME_CHUNK_EP_222";
    const char chunk_ty_name[] = "C_RUNTIME_CHUNK_TYPE_223";
    const uint32_t ep_id = 220;
    const uint32_t ty_id = 221;
    const uint32_t chunk_ep_id = 222;
    const uint32_t chunk_ty_id = 223;
    const SedsName ep_name_ref = seds_name_cstr(ep_name);
    const SedsName ty_name_ref = seds_name_cstr(ty_name);
    const SedsName chunk_ep_name_ref = seds_name_cstr(chunk_ep_name);
    const SedsName chunk_ty_name_ref = seds_name_cstr(chunk_ty_name);
    SedsEndpointRef ep_ref = SEDS_ENDPOINT_REF(ep_id);
    SedsTypeRef ty_ref = SEDS_TYPE_REF(ty_id);
    SedsEndpointRef chunk_ep_ref = SEDS_ENDPOINT_REF(chunk_ep_id);
    SedsTypeRef chunk_ty_ref = SEDS_TYPE_REF(chunk_ty_id);

    (void) seds_dtype_remove_by_name(ty_name_ref.ptr, ty_name_ref.len);
    (void) seds_endpoint_remove_by_name(ep_name_ref.ptr, ep_name_ref.len);
    (void) seds_dtype_remove_by_name(chunk_ty_name_ref.ptr, chunk_ty_name_ref.len);
    (void) seds_endpoint_remove_by_name(chunk_ep_name_ref.ptr, chunk_ep_name_ref.len);

    SedsEndpointInfo missing_ep;
    assert(seds_endpoint_get_info_by_name("C_RUNTIME_SCHEMA_MISSING_EP",
                                          strlen("C_RUNTIME_SCHEMA_MISSING_EP"),
                                          &missing_ep)
           == SEDS_OK);
    assert(!missing_ep.exists);

    assert(seds_endpoint_register_ex(ep_ref.id,
                                     ep_name_ref.ptr,
                                     ep_name_ref.len,
                                     ep_desc,
                                     strlen(ep_desc),
                                     true)
           == SEDS_OK);
    assert(seds_endpoint_ref_exists(ep_ref));

    SedsEndpointInfo ep_info;
    assert(seds_endpoint_ref_by_name(ep_name_ref, &ep_ref) == SEDS_OK);
    assert(seds_endpoint_get_info_by_name(ep_name_ref.ptr, ep_name_ref.len, &ep_info) == SEDS_OK);
    assert(ep_info.exists);
    assert(ep_info.id == ep_ref.id);
    assert(ep_info.link_local_only);
    assert(view_eq(ep_info.name, ep_info.name_len, ep_name));
    assert(view_eq(ep_info.description, ep_info.description_len, ep_desc));

    const uint32_t endpoints[] = {ep_ref.id};
    assert(seds_dtype_register_ex(ty_ref.id,
                                  ty_name_ref.ptr,
                                  ty_name_ref.len,
                                  ty_desc,
                                  strlen(ty_desc),
                                  true,
                                  2,
                                  3, /* UInt16 */
                                  2, /* Warning */
                                  1, /* Ordered */
                                  66,
                                  endpoints,
                                  1)
           == SEDS_OK);
    assert(seds_type_ref_by_name(ty_name_ref, &ty_ref) == SEDS_OK);
    assert(seds_type_ref_exists(ty_ref));
    assert(seds_type_ref_expected_size(ty_ref) == 4);

    uint32_t endpoints_out[4] = {0};
    SedsDataTypeInfo ty_info;
    assert(seds_dtype_get_info_by_name(ty_name_ref.ptr,
                                       ty_name_ref.len,
                                       endpoints_out,
                                       4,
                                       &ty_info)
           == SEDS_OK);
    assert(ty_info.exists);
    assert(ty_info.id == ty_ref.id);
    assert(ty_info.is_static);
    assert(ty_info.element_count == 2);
    assert(ty_info.message_data_type == 3);
    assert(ty_info.message_class == 2);
    assert(ty_info.reliable == 1);
    assert(ty_info.priority == 66);
    assert(ty_info.fixed_size == 4);
    assert(ty_info.num_endpoints == 1);
    assert(endpoints_out[0] == ep_ref.id);
    assert(view_eq(ty_info.name, ty_info.name_len, ty_name));
    assert(view_eq(ty_info.description, ty_info.description_len, ty_desc));

    assert(seds_dtype_register(ty_ref.id,
                               ty_name_ref.ptr,
                               ty_name_ref.len,
                               true,
                               3,
                               3,
                               2,
                               1,
                               66,
                               endpoints,
                               1)
           == SEDS_BAD_ARG);

    const char json[] =
        "{"
        "\"endpoints\":[{"
        "\"rust\":\"CRuntimeJsonEp\","
        "\"name\":\"C_RUNTIME_JSON_EP\","
        "\"description\":\"C JSON endpoint\""
        "}],"
        "\"types\":[{"
        "\"rust\":\"CRuntimeJsonType\","
        "\"name\":\"C_RUNTIME_JSON_TYPE\","
        "\"description\":\"C JSON type\","
        "\"priority\":23,"
        "\"reliable_mode\":\"Unordered\","
        "\"class\":\"Data\","
        "\"element\":{\"kind\":\"Static\",\"data_type\":\"Float32\",\"count\":1},"
        "\"endpoints\":[\"CRuntimeJsonEp\"]"
        "}]"
        "}";
    (void) seds_dtype_remove_by_name("C_RUNTIME_JSON_TYPE", strlen("C_RUNTIME_JSON_TYPE"));
    (void) seds_endpoint_remove_by_name("C_RUNTIME_JSON_EP", strlen("C_RUNTIME_JSON_EP"));
    assert(seds_schema_register_json_bytes((const uint8_t *) json, strlen(json)) == SEDS_OK);

    SedsEndpointInfo json_ep;
    assert(seds_endpoint_get_info_by_name("C_RUNTIME_JSON_EP",
                                          strlen("C_RUNTIME_JSON_EP"),
                                          &json_ep)
           == SEDS_OK);
    assert(json_ep.exists);
    assert(view_eq(json_ep.description, json_ep.description_len, "C JSON endpoint"));

    uint32_t json_eps[2] = {0};
    SedsDataTypeInfo json_ty;
    assert(seds_dtype_get_info_by_name("C_RUNTIME_JSON_TYPE",
                                       strlen("C_RUNTIME_JSON_TYPE"),
                                       json_eps,
                                       2,
                                       &json_ty)
           == SEDS_OK);
    assert(json_ty.exists);
    assert(json_ty.message_data_type == 1);
    assert(json_ty.reliable == 2);
    assert(json_ty.priority == 23);
    assert(json_ty.num_endpoints == 1);
    assert(json_eps[0] == json_ep.id);

    assert(seds_dtype_remove_by_name("C_RUNTIME_JSON_TYPE", strlen("C_RUNTIME_JSON_TYPE")) == SEDS_OK);
    assert(seds_endpoint_remove_by_name("C_RUNTIME_JSON_EP", strlen("C_RUNTIME_JSON_EP")) == SEDS_OK);
    assert(seds_dtype_remove(ty_ref.id) == SEDS_OK);
    assert(seds_endpoint_remove(ep_ref.id) == SEDS_OK);
    assert(!seds_type_ref_exists(ty_ref));
    assert(!seds_endpoint_ref_exists(ep_ref));

    assert(seds_endpoint_register(chunk_ep_ref.id,
                                  chunk_ep_name_ref.ptr,
                                  chunk_ep_name_ref.len,
                                  false)
           == SEDS_OK);
    assert(seds_endpoint_ref_by_name(chunk_ep_name_ref, &chunk_ep_ref) == SEDS_OK);
    const uint32_t chunk_endpoints[] = {chunk_ep_ref.id};
    assert(seds_dtype_register(chunk_ty_ref.id,
                               chunk_ty_name_ref.ptr,
                               chunk_ty_name_ref.len,
                               true,
                               160,
                               2, /* UInt8 */
                               1, /* Data */
                               0, /* BestEffort */
                               20,
                               chunk_endpoints,
                               1)
           == SEDS_OK);
    assert(seds_type_ref_by_name(chunk_ty_name_ref, &chunk_ty_ref) == SEDS_OK);
    assert(seds_type_ref_expected_size(chunk_ty_ref) == 160);

    SedsWrapperRouter wrapper;
    CaptureTx capture = {0U, 0U};
    SedsWrapperRouterConfig cfg = seds_wrapper_router_default_config();
    cfg.sender = SEDS_NAME_LITERAL("C_RUNTIME_WRAPPER");
    cfg.announce_discovery = false;
    assert(seds_wrapper_router_init(&wrapper, &cfg) == SEDS_OK);
    SedsSideRef side = seds_wrapper_router_add_serialized_small_side(
        &wrapper,
        SEDS_NAME_LITERAL("SIDE_A"),
        capture_tx,
        &capture,
        false,
        64);
    assert(seds_side_is_valid(side));
    uint8_t chunk_payload[160];
    for (size_t i = 0; i < sizeof(chunk_payload); ++i) {
        chunk_payload[i] = (uint8_t) i;
    }
    assert(seds_wrapper_router_log_typed(&wrapper,
                                         chunk_ty_ref,
                                         chunk_payload,
                                         sizeof(chunk_payload),
                                         sizeof(chunk_payload[0]),
                                         SEDS_EK_UNSIGNED,
                                         NULL,
                                         0)
           == SEDS_OK);
    assert(capture.frames > 1U);
    assert(capture.max_len <= 64U);
    assert(seds_wrapper_router_process(&wrapper, 0) == SEDS_OK);
    seds_wrapper_router_free(&wrapper);

    CaptureTx global_router_capture = {0U, 0U};
    SedsWrapperRouterConfig global_router_cfg = seds_wrapper_router_default_config();
    global_router_cfg.sender = SEDS_NAME_LITERAL("C_RUNTIME_GLOBAL_ROUTER");
    global_router_cfg.announce_discovery = false;
    assert(seds_global_router_init(&global_router_cfg) == SEDS_OK);
    SedsSideRef global_router_side = seds_global_router_add_serialized_small_side(
        SEDS_NAME_LITERAL("GLOBAL_ROUTER_SIDE"),
        capture_tx,
        &global_router_capture,
        false,
        64);
    assert(seds_side_is_valid(global_router_side));
    assert(seds_global_router_set_route_weight(SEDS_SIDE_INVALID, global_router_side, 2) == SEDS_OK);
    assert(seds_global_router_log_typed(chunk_ty_ref,
                                        chunk_payload,
                                        sizeof(chunk_payload),
                                        sizeof(chunk_payload[0]),
                                        SEDS_EK_UNSIGNED,
                                        NULL,
                                        0)
           == SEDS_OK);
    assert(global_router_capture.frames > 1U);
    assert(global_router_capture.max_len <= 64U);
    assert(seds_global_router_process(0) == SEDS_OK);
    assert(seds_global_router_export_runtime_stats_len() > 0);
    seds_global_router_free();

    CaptureTx global_relay_capture = {0U, 0U};
    SedsWrapperRelayConfig relay_cfg = seds_wrapper_relay_default_config();
    relay_cfg.sender = SEDS_NAME_LITERAL("C_RUNTIME_GLOBAL_RELAY");
    relay_cfg.announce_discovery = false;
    assert(seds_global_relay_init(&relay_cfg) == SEDS_OK);
    SedsSideRef relay_in = seds_global_relay_add_serialized_side(
        SEDS_NAME_LITERAL("RELAY_IN"),
        noop_tx,
        NULL,
        false);
    SedsSideRef relay_out = seds_global_relay_add_serialized_small_side(
        SEDS_NAME_LITERAL("RELAY_OUT"),
        capture_tx,
        &global_relay_capture,
        false,
        64);
    assert(seds_side_is_valid(relay_in));
    assert(seds_side_is_valid(relay_out));
    assert(seds_global_relay_set_typed_route(relay_in, chunk_ty_ref, relay_out, true) == SEDS_OK);
    SedsPacketView relay_view;
    memset(&relay_view, 0, sizeof(relay_view));
    relay_view.ty = chunk_ty_ref.id;
    relay_view.data_size = sizeof(chunk_payload);
    relay_view.sender = "C_RUNTIME_RELAY_SRC";
    relay_view.sender_len = strlen(relay_view.sender);
    relay_view.endpoints = chunk_endpoints;
    relay_view.num_endpoints = 1;
    relay_view.timestamp = 1234U;
    relay_view.payload = chunk_payload;
    relay_view.payload_len = sizeof(chunk_payload);
    assert(seds_global_relay_rx_packet_from_side(relay_in, &relay_view) == SEDS_OK);
    assert(seds_global_relay_process(0) == SEDS_OK);
    assert(global_relay_capture.frames > 1U);
    assert(global_relay_capture.max_len <= 64U);
    assert(seds_global_relay_export_runtime_stats_len() > 0);
    seds_global_relay_free();

    assert(seds_dtype_remove(chunk_ty_ref.id) == SEDS_OK);
    assert(seds_endpoint_remove(chunk_ep_ref.id) == SEDS_OK);

#if defined(SEDS_ENABLE_CRYPTOGRAPHY)
    assert(seds_crypto_register_provider(test_crypto_seal, test_crypto_open, NULL) == SEDS_OK);
    const uint8_t crypto_nonce[12] = {0};
    const uint8_t crypto_aad[3] = {1U, 2U, 3U};
    const uint8_t plaintext[5] = {10U, 11U, 12U, 13U, 14U};
    uint8_t ciphertext[8] = {0};
    uint8_t tag[16] = {0};
    size_t ciphertext_len = 0U;
    size_t tag_len = 0U;
    assert(seds_crypto_seal(7U,
                            crypto_nonce,
                            sizeof(crypto_nonce),
                            crypto_aad,
                            sizeof(crypto_aad),
                            plaintext,
                            sizeof(plaintext),
                            ciphertext,
                            sizeof(ciphertext),
                            &ciphertext_len,
                            tag,
                            sizeof(tag),
                            &tag_len)
           == SEDS_OK);
    assert(ciphertext_len == sizeof(plaintext));
    assert(tag_len == 4U);
    uint8_t opened[8] = {0};
    size_t opened_len = 0U;
    assert(seds_crypto_open(7U,
                            crypto_nonce,
                            sizeof(crypto_nonce),
                            crypto_aad,
                            sizeof(crypto_aad),
                            ciphertext,
                            ciphertext_len,
                            tag,
                            tag_len,
                            opened,
                            sizeof(opened),
                            &opened_len)
           == SEDS_OK);
    assert(opened_len == sizeof(plaintext));
    assert(memcmp(opened, plaintext, sizeof(plaintext)) == 0);
    seds_crypto_clear_provider();
#endif

    SedsRelay *relay = seds_relay_new(NULL, NULL);
    assert(relay != NULL);
    assert(seds_relay_add_side_serialized_small_packets(
               relay,
               "SIDE_A",
               strlen("SIDE_A"),
               noop_tx,
               NULL,
               false,
               64)
           >= 0);
    int32_t runtime_len = seds_relay_export_runtime_stats_len(relay);
    assert(runtime_len > 0);
    char *runtime_json = (char *)malloc((size_t)runtime_len);
    assert(runtime_json != NULL);
    assert(seds_relay_export_runtime_stats(relay, runtime_json, (size_t)runtime_len) == SEDS_OK);
    assert(strstr(runtime_json, "\"sides\":[") != NULL);
    assert(strstr(runtime_json, "\"route_modes\":[") != NULL);
    assert(strstr(runtime_json, "\"queues\":{") != NULL);
    assert(strstr(runtime_json, "\"reliable\":{") != NULL);
    free(runtime_json);
    seds_relay_free(relay);

    printf("runtime schema C ABI ok\n");
    return 0;
}
