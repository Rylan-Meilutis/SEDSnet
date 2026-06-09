#include "sedsprintf_c_wrapper.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

static uint64_t host_now_ms(void * user)
{
    (void) user;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t) tv.tv_sec * 1000ULL + (uint64_t) (tv.tv_usec / 1000ULL);
}

static SedsResult tx_send(const uint8_t * bytes, size_t len, void * user)
{
    (void) bytes;
    (void) len;
    (void) user;
    return SEDS_OK;
}

static SedsResult on_packet(const SedsPacketView * pkt, void * user)
{
    (void) user;
    char buf[seds_pkt_to_string_len(pkt)];
    if (seds_pkt_to_string(pkt, buf, sizeof(buf)) == SEDS_OK)
    {
        printf("%s\n", buf);
    }
    return SEDS_OK;
}

int main(void)
{
    SedsEndpointRef radio_endpoint;
    SedsEndpointRef sd_card_endpoint;
    SedsTypeRef gps_data;
    SedsTypeRef imu_data;
    SedsTypeRef battery_status;
    SedsTypeRef message_data;
    SedsTypeRef heartbeat;

    if (seds_endpoint_ref_by_name(SEDS_NAME_LITERAL("RADIO"), &radio_endpoint) != SEDS_OK ||
        seds_endpoint_ref_by_name(SEDS_NAME_LITERAL("SD_CARD"), &sd_card_endpoint) != SEDS_OK ||
        seds_type_ref_by_name(SEDS_NAME_LITERAL("GPS_DATA"), &gps_data) != SEDS_OK ||
        seds_type_ref_by_name(SEDS_NAME_LITERAL("IMU_DATA"), &imu_data) != SEDS_OK ||
        seds_type_ref_by_name(SEDS_NAME_LITERAL("BATTERY_STATUS"), &battery_status) != SEDS_OK ||
        seds_type_ref_by_name(SEDS_NAME_LITERAL("MESSAGE_DATA"), &message_data) != SEDS_OK ||
        seds_type_ref_by_name(SEDS_NAME_LITERAL("HEARTBEAT"), &heartbeat) != SEDS_OK)
    {
        fprintf(stderr, "runtime schema is missing an example endpoint or data type\n");
        return 1;
    }

    const SedsLocalEndpointDesc locals[] = {
        {.endpoint = radio_endpoint.id, .packet_handler = on_packet, .user = NULL},
        {.endpoint = sd_card_endpoint.id, .packet_handler = on_packet, .user = NULL},
    };

    SedsRouter * r = seds_router_new(Seds_RM_Sink, host_now_ms, NULL, locals, 2);
    if (!r)
    {
        fprintf(stderr, "router init failed\n");
        return 1;
    }
    seds_router_add_side_serialized(r, "TX", 2, tx_send, NULL, true);
    seds_router_configure_timesync(r, true, 1U, 10U, 5000U, 1000U, 1000U);
    seds_router_set_local_network_datetime_millis(r, 2025, 1, 1, 12, 0, 0, 0);

    const float gps[3] = {37.7749f, -122.4194f, 30.0f};
    const float imu[6] = {0.1f, 0.2f, 0.3f, 1.1f, 1.2f, 1.3f};
    const float batt[2] = {12.5f, 1.8f};
    seds_router_log(r, gps_data.id, gps, sizeof(gps));
    seds_router_log(r, imu_data.id, imu, sizeof(imu));
    seds_router_log(r, battery_status.id, batt, sizeof(batt));
    seds_router_log_cstr(r, message_data.id, "hello from C timesync example");
    seds_router_log_cstr(r, heartbeat.id, "");

    seds_router_periodic(r, 0);

    uint64_t network_ms = 0;
    if (seds_router_get_network_time_ms(r, &network_ms) == SEDS_OK)
    {
        printf("network_time_ms=%llu\n", (unsigned long long) network_ms);
    }

    seds_router_free(r);
    return 0;
}
