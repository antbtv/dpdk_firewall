#ifndef FW_PORT_H
#define FW_PORT_H

#include <stdint.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>

/* Размеры колец и пула */
#define RX_RING_SIZE  4096
#define TX_RING_SIZE  4096
#define NUM_MBUFS     16384  /* на порт */
#define MBUF_CACHE    256

/**
 * Общий пул буферов пакетов.
 * Создаётся один раз в port_init_all(), используется всеми портами и lcore.
 */
extern struct rte_mempool *g_mbuf_pool;

/**
 * port_init_all() — открыть и настроить все DPDK-порты, обнаруженные EAL.
 *
 * Создаёт g_mbuf_pool, настраивает каждый порт с одной очередью RX и TX,
 * затем запускает все порты.
 *
 * @param n_ports  Ожидаемое количество портов (должно совпадать с rte_eth_dev_count_avail()).
 * @return 0 при успехе, отрицательный errno при ошибке.
 */
int port_init_all(uint16_t n_ports);

/**
 * port_stop_all() — остановить и закрыть все DPDK-порты.
 */
void port_stop_all(void);

/**
 * port_stats_get() — получить аппаратную статистику для одного порта.
 *
 * @param port_id  Индекс DPDK-порта.
 * @param stats    Выходной буфер, заполняемый rte_eth_stats_get().
 * @return 0 при успехе, отрицательный errno при ошибке.
 */
int port_stats_get(uint16_t port_id, struct rte_eth_stats *stats);

#endif /* FW_PORT_H */
