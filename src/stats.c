#include <stdint.h>
#include <string.h>

#include <rte_ethdev.h>

#include "stats.h"
#include "port.h"
#include "log.h"

/*
 * TODO: P4-01 — full atomic counters implementation.
 *
 * Phase 1 stubs: minimal implementation so the project compiles.
 */

static volatile uint64_t s_rx_pkts;
static volatile uint64_t s_tx_pkts;
static volatile uint64_t s_dropped_pkts;
static volatile uint64_t s_rx_bytes;
static volatile uint64_t s_tx_bytes;

void
stats_init(void)
{
    s_rx_pkts = s_tx_pkts = s_dropped_pkts = s_rx_bytes = s_tx_bytes = 0;
}

void
stats_inc_rx(uint64_t bytes)
{
    __atomic_fetch_add(&s_rx_pkts,  1,     __ATOMIC_RELAXED);
    __atomic_fetch_add(&s_rx_bytes, bytes, __ATOMIC_RELAXED);
}

void
stats_inc_tx(uint64_t bytes)
{
    __atomic_fetch_add(&s_tx_pkts,  1,     __ATOMIC_RELAXED);
    __atomic_fetch_add(&s_tx_bytes, bytes, __ATOMIC_RELAXED);
}

void
stats_inc_dropped(void)
{
    __atomic_fetch_add(&s_dropped_pkts, 1, __ATOMIC_RELAXED);
}

void
stats_get_snapshot(struct fw_stats_snapshot *out)
{
    if (!out)
        return;
    out->total_rx_pkts     = __atomic_load_n(&s_rx_pkts,     __ATOMIC_RELAXED);
    out->total_tx_pkts     = __atomic_load_n(&s_tx_pkts,     __ATOMIC_RELAXED);
    out->total_dropped_pkts= __atomic_load_n(&s_dropped_pkts,__ATOMIC_RELAXED);
    out->total_rx_bytes    = __atomic_load_n(&s_rx_bytes,    __ATOMIC_RELAXED);
    out->total_tx_bytes    = __atomic_load_n(&s_tx_bytes,    __ATOMIC_RELAXED);

    uint16_t n_ports = rte_eth_dev_count_avail();
    for (uint16_t i = 0; i < n_ports && i < FW_MAX_PORTS; i++)
        port_stats_get(i, &out->port_stats[i]);
}

void
stats_periodic_dump(void)
{
    struct fw_stats_snapshot snap;
    stats_get_snapshot(&snap);
    RTE_LOG_FW_INFO("stats: rx=%lu tx=%lu dropped=%lu\n",
                    snap.total_rx_pkts,
                    snap.total_tx_pkts,
                    snap.total_dropped_pkts);
}
