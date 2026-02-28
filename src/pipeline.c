#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>

#include "pipeline.h"
#include "firewall.h"
#include "log.h"

/*
 * Phase 1: minimal RX→TX forwarding loop (7 stages, stubs for stages 2-6).
 *
 * Stages planned (PRD §8):
 *  1. RX BURST         — implemented
 *  2. CLASSIFIER       — TODO: P2-02
 *  3. BLACKLIST CHECK  — TODO: P3-03
 *  4. RULE ENGINE      — TODO: P2-03
 *  5. RATE LIMIT       — TODO: P3-02
 *  6. DDOS UPDATE      — TODO: P3-03
 *  7. TX BURST         — implemented
 */

int
pipeline_lcore_main(void *arg)
{
    const struct pipeline_args *pa = (const struct pipeline_args *)arg;
    const uint16_t port_in  = pa->port_in;
    const uint16_t port_out = pa->port_out;

    RTE_LOG_FW_INFO("lcore %u: pipeline started, port %u → port %u\n",
                    rte_lcore_id(), port_in, port_out);

    /* Stack-allocated packet arrays — never heap-allocated (PRD §8 key principles) */
    struct rte_mbuf *rx_pkts[MAX_BURST];

    while (!g_force_quit) {

        /* ── Stage 1: RX BURST ─────────────────────────────────────────── */
        uint16_t n = rte_eth_rx_burst(port_in, 0, rx_pkts, MAX_BURST);
        if (n == 0)
            continue;

        /* DEBUG P1-09 */
        fprintf(stderr, "DBG lcore%u port%u->%u rx=%u\n",
                rte_lcore_id(), port_in, port_out, n);

        /*
         * Stages 2-6 are stubs for Phase 1.
         * All packets are forwarded as-is (bridge mode, no filtering).
         *
         * TODO P2-02: CLASSIFIER — parse Ethernet/IPv4/L4 into pkt_meta[]
         * TODO P3-03: BLACKLIST CHECK — drop packets from blacklisted IPs
         * TODO P2-03: RULE ENGINE — rte_acl_classify → ACCEPT/DROP/RATE_LIMIT
         * TODO P3-02: RATE LIMIT — rte_meter_srtcm for RATE_LIMIT rules
         * TODO P3-03: DDOS UPDATE — sliding window, auto-blacklist on flood
         */

        /* ── Stage 7: TX BURST ─────────────────────────────────────────── */
        uint16_t sent = rte_eth_tx_burst(port_out, 0, rx_pkts, n);

        /* Free any packets that the TX queue could not accept */
        if (unlikely(sent < n)) {
            for (uint16_t i = sent; i < n; i++)
                rte_pktmbuf_free(rx_pkts[i]);
        }
    }

    RTE_LOG_FW_INFO("lcore %u: pipeline stopped\n", rte_lcore_id());
    return 0;
}
