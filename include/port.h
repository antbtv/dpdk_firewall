#ifndef FW_PORT_H
#define FW_PORT_H

#include <stdint.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>

/* Ring / pool sizing */
#define RX_RING_SIZE  1024
#define TX_RING_SIZE  1024
#define NUM_MBUFS     8192   /* per port */
#define MBUF_CACHE    256

/**
 * Shared packet-buffer pool.
 * Created once in port_init_all(), used by all ports and lcores.
 */
extern struct rte_mempool *g_mbuf_pool;

/**
 * port_init_all() — open and configure all DPDK ports found by EAL.
 *
 * Creates g_mbuf_pool, configures each port with one RX and one TX queue,
 * then starts all ports.
 *
 * @param n_ports  Expected number of ports (must match rte_eth_dev_count_avail()).
 * @return 0 on success, negative errno on failure.
 */
int port_init_all(uint16_t n_ports);

/**
 * port_stop_all() — stop and close all DPDK ports.
 */
void port_stop_all(void);

/**
 * port_stats_get() — retrieve hardware statistics for a single port.
 *
 * @param port_id  DPDK port index.
 * @param stats    Output buffer filled by rte_eth_stats_get().
 * @return 0 on success, negative errno on failure.
 */
int port_stats_get(uint16_t port_id, struct rte_eth_stats *stats);

#endif /* FW_PORT_H */
