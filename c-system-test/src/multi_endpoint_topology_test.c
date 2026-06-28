#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "sedsnet.h"

enum {
    TEST_EP_SD_CARD = 100,
    TEST_EP_RADIO = 101
};

typedef struct
{
    unsigned packet_handler_hits;
    unsigned tx_packets;
} CaptureState;

static uint64_t host_now_ms(void *user)
{
    (void)user;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)(tv.tv_usec / 1000ULL);
}

static SedsResult noop_packet_handler(const SedsPacketView *pkt, void *user)
{
    (void)pkt;
    CaptureState *state = (CaptureState *)user;
    if (state != NULL)
    {
        state->packet_handler_hits++;
    }
    return SEDS_OK;
}

static SedsResult capture_tx(const uint8_t *bytes, size_t len, void *user)
{
    CaptureState *state = (CaptureState *)user;
    SedsOwnedPacket *owned = NULL;
    SedsPacketView view;

    assert(state != NULL);
    assert(bytes != NULL);
    assert(len > 0U);

    state->tx_packets++;

    owned = seds_pkt_unpack_owned(bytes, len);
    assert(owned != NULL);

    assert(seds_owned_pkt_view(owned, &view) == SEDS_OK);

    seds_owned_pkt_free(owned);
    return SEDS_OK;
}

int main(void)
{
    CaptureState state = {0};
    bool did_queue = false;
    const SedsLocalEndpointDesc locals[] = {
        {
            .endpoint = TEST_EP_RADIO,
            .packet_handler = noop_packet_handler,
            .packed_handler = NULL,
            .user = &state,
        },
        {
            .endpoint = TEST_EP_SD_CARD,
            .packet_handler = noop_packet_handler,
            .packed_handler = NULL,
            .user = &state,
        },
    };

    SedsRouter *r = seds_router_new(
        Seds_RM_Relay,
        host_now_ms,
        NULL,
        locals,
        sizeof(locals) / sizeof(locals[0]));
    assert(r != NULL);

    assert(seds_router_add_side_packed(r, "CAN", 3, capture_tx, &state, false) >= 0);
    assert(seds_router_configure_timesync(r, true, 0U, 0ULL, 5000ULL, 2000ULL, 2000ULL) ==
           SEDS_OK);

    assert(seds_router_announce_discovery(r) == SEDS_OK);
    assert(seds_router_process_tx_queue_with_timeout(r, 5U) == SEDS_OK);

    usleep(300000);

    assert(seds_router_poll_discovery(r, &did_queue) == SEDS_OK);
    assert(did_queue);
    assert(seds_router_process_tx_queue_with_timeout(r, 5U) == SEDS_OK);

    assert(state.tx_packets >= 2U);
    int32_t topology_len = seds_router_export_topology_len(r);
    assert(topology_len > 0);
    char *topology_json = (char *)malloc((size_t)topology_len);
    assert(topology_json != NULL);
    assert(seds_router_export_topology(r, topology_json, (size_t)topology_len) == SEDS_OK);
    assert(strstr(topology_json, "\"advertised_endpoint_ids\":[100,101]") != NULL);
    free(topology_json);

    printf("multi-endpoint topology ok: tx=%u\n", state.tx_packets);

    seds_router_free(r);
    return 0;
}
