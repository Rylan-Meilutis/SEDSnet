#include "sedsprintf_cpp_wrapper.hpp"

static SedsResult radio_tx(const uint8_t * bytes, size_t len, void * user)
{
    (void)bytes;
    (void)len;
    (void)user;
    return SEDS_OK;
}

void managed_variables_e2e_cpp_example()
{
    uint32_t endpoints[] = { 101U };
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

    SedsTypeRef flight_state{};
    (void)seds::type_ref_by_name(SEDS_NAME_LITERAL("FLIGHT_STATE"), flight_state);
    (void)seds::set_e2e_encryption_policy(flight_state, SEDS_E2E_REQUIRE_ON);

    SedsRouter * router = seds::router_new(Seds_RM_Relay,
                                           nullptr,
                                           nullptr,
                                           nullptr,
                                           0U,
                                           SEDS_ROUTER_E2E_REQUIRED_ONLY,
                                           7U);
    (void)seds_router_set_sender_id(router, "FLIGHT_COMPUTER", 15U);
    (void)seds_router_enable_managed_variable(router, flight_state.id);
    (void)seds_router_add_side_serialized_small_packets(
        router, "RADIO", 5U, radio_tx, nullptr, false, 64U);

    const uint8_t state = 3U;
    (void)seds::router_log(router, flight_state, &state, 1U);
    (void)seds::request_managed_variable(router, flight_state);
    (void)seds_router_process_all_queues(router);

    seds_router_free(router);
}
