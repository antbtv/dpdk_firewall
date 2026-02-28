#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include "port.h"
#include "log.h"

struct rte_mempool *g_mbuf_pool = NULL;

/* Default port configuration: no multi-queue, no offloads required */
static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .mq_mode = RTE_ETH_MQ_RX_NONE,
    },
    .txmode = {
        .mq_mode = RTE_ETH_MQ_TX_NONE,
    },
};

/* ─── Internal helpers ──────────────────────────────────────────────────── */

static int
port_configure(uint16_t port_id)
{
    struct rte_eth_conf     port_conf = port_conf_default;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_rxconf   rxconf;
    struct rte_eth_txconf   txconf;
    int ret;

    ret = rte_eth_dev_info_get(port_id, &dev_info);
    if (ret != 0) {
        RTE_LOG_FW_ERR("Cannot get device info for port %u: %s\n",
                       port_id, rte_strerror(-ret));
        return ret;
    }

    /* Enable scatter if the driver requires it */
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

    ret = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
    if (ret != 0) {
        RTE_LOG_FW_ERR("Cannot configure port %u: %s\n",
                       port_id, rte_strerror(-ret));
        return ret;
    }

    /* Adjust ring sizes to what the device supports */
    uint16_t nb_rx = RX_RING_SIZE;
    uint16_t nb_tx = TX_RING_SIZE;
    ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rx, &nb_tx);
    if (ret != 0) {
        RTE_LOG_FW_ERR("Cannot adjust descriptors for port %u: %s\n",
                       port_id, rte_strerror(-ret));
        return ret;
    }

    /* Set up RX queue 0 */
    rxconf = dev_info.default_rxconf;
    rxconf.offloads = port_conf.rxmode.offloads;
    ret = rte_eth_rx_queue_setup(port_id, 0, nb_rx,
                                 rte_eth_dev_socket_id(port_id),
                                 &rxconf, g_mbuf_pool);
    if (ret != 0) {
        RTE_LOG_FW_ERR("Cannot setup RX queue for port %u: %s\n",
                       port_id, rte_strerror(-ret));
        return ret;
    }

    /* Set up TX queue 0 */
    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    ret = rte_eth_tx_queue_setup(port_id, 0, nb_tx,
                                 rte_eth_dev_socket_id(port_id),
                                 &txconf);
    if (ret != 0) {
        RTE_LOG_FW_ERR("Cannot setup TX queue for port %u: %s\n",
                       port_id, rte_strerror(-ret));
        return ret;
    }

    return 0;
}

/* ─── Public API ────────────────────────────────────────────────────────── */

int
port_init_all(uint16_t n_ports)
{
    uint16_t avail = rte_eth_dev_count_avail();
    if (avail != n_ports) {
        RTE_LOG_FW_ERR("Expected %u ports, found %u\n", n_ports, avail);
        return -1;
    }

    /* Create a single shared mbuf pool large enough for all ports */
    unsigned int total_mbufs = NUM_MBUFS * n_ports;
    g_mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool",
                                          total_mbufs,
                                          MBUF_CACHE,
                                          0,
                                          RTE_MBUF_DEFAULT_BUF_SIZE,
                                          rte_socket_id());
    if (g_mbuf_pool == NULL) {
        RTE_LOG_FW_ERR("Cannot create mbuf pool: %s\n",
                       rte_strerror(rte_errno));
        return -rte_errno;
    }

    uint16_t port_id;
    RTE_ETH_FOREACH_DEV(port_id) {
        int ret = port_configure(port_id);
        if (ret != 0)
            return ret;

        ret = rte_eth_dev_start(port_id);
        if (ret != 0) {
            RTE_LOG_FW_ERR("Cannot start port %u: %s\n",
                           port_id, rte_strerror(-ret));
            return ret;
        }

        /* Enable promiscuous mode so bridge sees all frames */
        ret = rte_eth_promiscuous_enable(port_id);
        if (ret != 0) {
            RTE_LOG_FW_WARN("Cannot enable promiscuous on port %u: %s\n",
                            port_id, rte_strerror(-ret));
            /* non-fatal — continue */
        }

        /* Wait up to 9 s for link to come UP (required for I210 DMA init) */
        struct rte_eth_link link;
        for (int i = 0; i < 9; i++) {
            rte_eth_link_get_nowait(port_id, &link);
            if (link.link_status == RTE_ETH_LINK_UP)
                break;
            RTE_LOG_FW_INFO("Port %u waiting for link... (%d/9)\n", port_id, i + 1);
            sleep(1);
        }
        rte_eth_link_get_nowait(port_id, &link);

        RTE_LOG_FW_INFO("Port %u started (socket %d) — link %s %u Mbps %s\n",
                        port_id, rte_eth_dev_socket_id(port_id),
                        link.link_status == RTE_ETH_LINK_UP ? "UP" : "DOWN",
                        link.link_speed,
                        link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX ? "FD" : "HD");
    }

    return 0;
}

void
port_stop_all(void)
{
    uint16_t port_id;
    RTE_ETH_FOREACH_DEV(port_id) {
        RTE_LOG_FW_INFO("Stopping port %u\n", port_id);
        rte_eth_dev_stop(port_id);
        rte_eth_dev_close(port_id);
    }
}

int
port_stats_get(uint16_t port_id, struct rte_eth_stats *stats)
{
    if (stats == NULL)
        return -1;
    return rte_eth_stats_get(port_id, stats);
}
