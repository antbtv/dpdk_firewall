#ifndef FW_STATS_H
#define FW_STATS_H

#include <stdint.h>
#include <rte_ethdev.h>

#define FW_MAX_PORTS 2

/** Атомарный снимок всех счётчиков + аппаратная статистика на порт. */
struct fw_stats_snapshot {
    uint64_t total_rx_pkts;
    uint64_t total_tx_pkts;
    uint64_t total_dropped_pkts;
    uint64_t total_rx_bytes;
    uint64_t total_tx_bytes;
    struct rte_eth_stats port_stats[FW_MAX_PORTS];
};

void stats_init(void);
void stats_inc_rx(uint64_t bytes);
void stats_inc_tx(uint64_t bytes);
void stats_inc_dropped(void);
void stats_get_snapshot(struct fw_stats_snapshot *out);
void stats_periodic_dump(void);

#endif /* FW_STATS_H */
