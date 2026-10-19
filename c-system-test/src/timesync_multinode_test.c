#include "test_assertions.h"
#include <stdio.h>
#include <unistd.h>

#include "telemetry_sim.h"

static void pump_nodes(SimNode **nodes, size_t count, unsigned rounds)
{
    for (unsigned i = 0; i < rounds; ++i)
    {
        for (size_t n = 0; n < count; ++n)
        {
            if (nodes[n] && nodes[n]->r)
            {
                (void)seds_router_process_tx_queue_with_timeout(nodes[n]->r, 5);
                (void)seds_router_process_rx_queue_with_timeout(nodes[n]->r, 5);
            }
        }
        usleep(1000);
    }
}

static void scenario_grandmaster_and_consumers(void)
{
    SimBus bus;
    bus_init(&bus);

    SimNode gm, c1, c2;
    assert(node_init(&gm, &bus, "GM", 0, 0, 1) == SEDS_OK);
    assert(node_init(&c1, &bus, "C1", 0, 0, 0) == SEDS_OK);
    assert(node_init(&c2, &bus, "C2", 0, 0, 0) == SEDS_OK);

    SimNode *nodes[] = {&gm, &c1, &c2};
    pump_nodes(nodes, 3, 300);

    uint64_t c1_network_ms = 0;
    uint64_t c2_network_ms = 0;
    assert(seds_router_get_network_time_ms(c1.r, &c1_network_ms) == SEDS_OK);
    assert(seds_router_get_network_time_ms(c2.r, &c2_network_ms) == SEDS_OK);
    assert(c1_network_ms > 0);
    assert(c2_network_ms > 0);

    node_free(&c2);
    node_free(&c1);
    node_free(&gm);
    bus_free(&bus);
}

static void scenario_failover_primary_to_backup(void)
{
    SimBus bus;
    bus_init(&bus);

    SimNode primary, backup, consumer;
    assert(node_init(&primary, &bus, "GM_PRIMARY", 0, 0, 1) == SEDS_OK);
    assert(node_init(&backup, &bus, "GM_BACKUP", 0, 0, 0) == SEDS_OK);
    assert(node_init(&consumer, &bus, "CONSUMER", 0, 0, 0) == SEDS_OK);

    SimNode *nodes[] = {&primary, &backup, &consumer};
    pump_nodes(nodes, 3, 200);

    uint64_t before_failover = 0;
    assert(seds_router_get_network_time_ms(consumer.r, &before_failover) == SEDS_OK);
    assert(before_failover > 0);

    node_free(&primary);
    backup.is_time_source = 1;
    assert(seds_router_configure_timesync(backup.r, true, 1u, 2u, 5000u, 100u, 100u) == SEDS_OK);

    pump_nodes(nodes, 3, 300);

    uint64_t after_failover = 0;
    assert(seds_router_get_network_time_ms(consumer.r, &after_failover) == SEDS_OK);
    assert(after_failover >= before_failover);

    node_free(&consumer);
    node_free(&backup);
    bus_free(&bus);
}

int main(void)
{
    scenario_grandmaster_and_consumers();
    scenario_failover_primary_to_backup();
    printf("timesync multinode scenarios passed\n");
    return 0;
}
