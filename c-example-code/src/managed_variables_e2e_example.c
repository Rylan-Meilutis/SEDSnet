#include "sedsprintf_c_wrapper.h"

static SedsResult radio_tx(const uint8_t * bytes, size_t len, void * user)
{
    (void)bytes;
    (void)len;
    (void)user;
    return SEDS_OK;
}

#if defined(SEDS_ENABLE_CRYPTO_SHIM)
static SedsResult seal_cb(uint32_t key_id,
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
    (void)key_id;
    (void)nonce;
    (void)nonce_len;
    (void)aad;
    (void)aad_len;
    (void)plaintext;
    (void)plaintext_len;
    (void)ciphertext_out;
    (void)ciphertext_cap;
    (void)ciphertext_len_out;
    (void)tag_out;
    (void)tag_cap;
    (void)tag_len_out;
    (void)user;
    return SEDS_ERR; /* Replace with board AEAD seal. */
}

static SedsResult open_cb(uint32_t key_id,
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
    (void)key_id;
    (void)nonce;
    (void)nonce_len;
    (void)aad;
    (void)aad_len;
    (void)ciphertext;
    (void)ciphertext_len;
    (void)tag;
    (void)tag_len;
    (void)plaintext_out;
    (void)plaintext_cap;
    (void)plaintext_len_out;
    (void)user;
    return SEDS_ERR; /* Replace with board AEAD open. */
}
#endif

void managed_variables_e2e_example(void)
{
    SedsTypeRef flight_state = SEDS_TYPE_REF(3100);
    SedsSideRef radio_side;
    uint8_t state = 3U;
    uint32_t endpoints[] = { 101U };

#if defined(SEDS_ENABLE_CRYPTO_SHIM)
    (void)seds_crypto_register_shim(seal_cb, open_cb, NULL);
#endif

    (void)seds_endpoint_register(101U, "RADIO", 5U, false);
    (void)seds_dtype_register(3100U,
                              "FLIGHT_STATE",
                              12U,
                              true,
                              1U,
                              0U,
                              0U,
                              0U,
                              90U,
                              endpoints,
                              1U);
    (void)seds_dtype_set_e2e_encryption_policy((uint32_t)flight_state.id, SEDS_E2E_REQUIRE_ON);

    SedsWrapperRouterConfig cfg = seds_wrapper_router_default_config();
    cfg.sender = SEDS_NAME_LITERAL("FLIGHT_COMPUTER");
    cfg.e2e_mode = SEDS_ROUTER_E2E_REQUIRED_ONLY;
    cfg.e2e_key_id = 7U;
    (void)seds_global_router_init(&cfg);

    radio_side = seds_global_router_add_serialized_small_side(
        SEDS_NAME_LITERAL("RADIO"),
        radio_tx,
        NULL,
        false,
        64U);
    (void)radio_side;

    (void)seds_global_router_enable_managed_variable(flight_state);
    (void)seds_global_router_log_typed(
        flight_state, &state, 1U, sizeof(state), SEDS_EK_UNSIGNED, NULL, 0);
    (void)seds_global_router_request_managed_variable(flight_state);
    (void)seds_global_router_process(0U);
}
