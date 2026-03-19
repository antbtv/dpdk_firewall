#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_icmp.h>
#include <rte_cycles.h>
#include <rte_meter.h>

#include "pipeline.h"
#include "firewall.h"
#include "port.h"
#include "rule_engine.h"
#include "ddos.h"
#include "stats.h"
#include "log.h"

/*
 * Packet pipeline (7 stages per burst of MAX_BURST=32 packets):
 *  1. RX BURST         — implemented
 *  2. CLASSIFIER       — implemented (P2-02)
 *  3. BLACKLIST CHECK  — implemented (P3-03)
 *  4. RULE ENGINE      — implemented (P2-03)
 *  5. RATE LIMIT       — implemented (P3-02)
 *  6. DDOS UPDATE      — implemented (P3-03)
 *  7. TX BURST         — implemented
 */

/* ─── Stage 2: CLASSIFIER ───────────────────────────────────────────────── */

/*
 * Parse one mbuf and fill pkt_meta.
 * IPs are converted to host byte order (HBo) — rte_acl MASK applies prefix from
 * the MSB of the integer, so HBo is required for correct CIDR matching on LE ARM.
 * Ports are converted to host byte order (HBo) — required for correct rte_acl RANGE cmp.
 * Non-IPv4 frames set is_ipv4=0; all other fields are zeroed.
 */
static void
classify_pkt(struct rte_mbuf *mbuf, struct pkt_meta *meta)
{
    memset(meta, 0, sizeof(*meta));

    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    if (rte_be_to_cpu_16(eth->ether_type) != RTE_ETHER_TYPE_IPV4) {
        /* Non-IPv4: forward as-is in bridge mode (meta->is_ipv4 stays 0) */
        return;
    }

    struct rte_ipv4_hdr *iph = (struct rte_ipv4_hdr *)(eth + 1);
    meta->src_ip  = rte_be_to_cpu_32(iph->src_addr);  /* HBo: rte_acl MASK needs HBo */
    meta->dst_ip  = rte_be_to_cpu_32(iph->dst_addr);  /* HBo */
    meta->proto   = iph->next_proto_id;
    meta->is_ipv4 = 1;

    uint8_t *l4 = (uint8_t *)iph + (iph->version_ihl & 0x0f) * 4;

    switch (meta->proto) {
    case IPPROTO_TCP: {
        struct rte_tcp_hdr *tcph = (struct rte_tcp_hdr *)l4;
        meta->src_port  = rte_be_to_cpu_16(tcph->src_port); /* HBO */
        meta->dst_port  = rte_be_to_cpu_16(tcph->dst_port); /* HBO */
        meta->tcp_flags = tcph->tcp_flags;
        break;
    }
    case IPPROTO_UDP: {
        struct rte_udp_hdr *udph = (struct rte_udp_hdr *)l4;
        meta->src_port = rte_be_to_cpu_16(udph->src_port); /* HBO */
        meta->dst_port = rte_be_to_cpu_16(udph->dst_port); /* HBO */
        break;
    }
    case IPPROTO_ICMP: {
        struct rte_icmp_hdr *icmph = (struct rte_icmp_hdr *)l4;
        meta->icmp_type = icmph->icmp_type;
        meta->icmp_code = icmph->icmp_code;
        /* src_port/dst_port remain 0; ICMP rules use range 0-65535 */
        break;
    }
    default:
        break;
    }
}

/* ─── Forwarding loop ───────────────────────────────────────────────────── */

int
pipeline_lcore_main(void *arg)
{
    const struct pipeline_args *pa = (const struct pipeline_args *)arg;
    const uint16_t port_in  = pa->port_in;
    const uint16_t port_out = pa->port_out;

    RTE_LOG_FW_INFO("lcore %u: pipeline started, port %u → port %u\n",
                    rte_lcore_id(), port_in, port_out);

    /* Stack-allocated arrays — never heap-allocated (zero-copy, PRD §8) */
    struct rte_mbuf *rx_pkts[MAX_BURST];
    struct rte_mbuf *tx_pkts[MAX_BURST];
    struct pkt_meta  meta[MAX_BURST];

    /* Precompute TSC frequency for TSC→ns conversion (stage 6).
     * Integer math: avoids floating-point in the hot path.
     * Formula: now_ns = (cycles / tsc_hz) * 1e9 + (cycles % tsc_hz) * 1e9 / tsc_hz
     * Safe on RPi5 (tsc_hz ≈ 54 MHz): rem < 54e6, rem * 1e9 < 5.4e16 < 2^64. */
    const uint64_t tsc_hz = rte_get_tsc_hz();

    while (!g_force_quit) {

        /* ── Stage 1: RX BURST ─────────────────────────────────────────── */
        uint16_t n = rte_eth_rx_burst(port_in, 0, rx_pkts, MAX_BURST);
        if (n == 0)
            continue;

        /* ── Stage 2: CLASSIFIER + RX stats ───────────────────────────── */
        for (uint16_t i = 0; i < n; i++) {
            /* Prefetch 2 packets ahead: Cortex-A76 4-wide decode needs extra
             * lead time to hide memory latency compared to prefetch-1. */
            if (i + 2 < n)
                rte_prefetch0(rte_pktmbuf_mtod(rx_pkts[i + 2], void *));
            classify_pkt(rx_pkts[i], &meta[i]);
            stats_inc_rx(rx_pkts[i]->pkt_len);
        }

        /* Snapshot time once per burst — shared by stages 3, 5, 6 */
        uint64_t now_cycles = rte_get_tsc_cycles();
        uint64_t now_ns     = (now_cycles / tsc_hz) * UINT64_C(1000000000)
                            + (now_cycles % tsc_hz) * UINT64_C(1000000000) / tsc_hz;

        /* ── Stages 3-6 → Stage 7 ──────────────────────────────────────── */
        uint16_t n_tx = 0;

        for (uint16_t i = 0; i < n; i++) {

            if (!meta[i].is_ipv4) {
                /* Non-IPv4: forward as-is (bridge mode) */
                tx_pkts[n_tx++] = rx_pkts[i];
                continue;
            }

            /* ── Stage 3: BLACKLIST CHECK ──────────────────────────────── */
            if (blacklist_check(meta[i].src_ip, now_cycles)) {
                rte_pktmbuf_free(rx_pkts[i]);
                stats_inc_dropped();
                continue;
            }

            /* ── Stage 4: RULE ENGINE ──────────────────────────────────── */
            uint32_t rule_id;
            fw_action_t action = rule_match(&meta[i], &rule_id,
                                            rx_pkts[i]->pkt_len);

            if (action == ACTION_DROP) {
                rte_pktmbuf_free(rx_pkts[i]);
                stats_inc_dropped();
                continue;
            }

            /* ── Stage 5: RATE LIMIT ────────────────────────────────────── */
            if (action == ACTION_RATE_LIMIT &&
                meter_check(rule_id, rx_pkts[i]->pkt_len, now_cycles)
                    == RTE_COLOR_RED) {
                rte_pktmbuf_free(rx_pkts[i]);
                stats_inc_dropped();
                continue;
            }

            /* ── Stage 6: DDOS UPDATE ───────────────────────────────────── */
            ddos_update(meta[i].src_ip, &meta[i], now_ns);

            tx_pkts[n_tx++] = rx_pkts[i];
        }

        /* ── Stage 7: TX BURST ─────────────────────────────────────────── */
        if (n_tx == 0)
            continue;

        /* force_copy=1 in net_af_xdp PMD: UMEM frames are copied to regular
         * mbufs inside the PMD before being handed to us.  No userspace copy
         * needed here — all mbufs in tx_pkts[] are regular pool buffers. */
        uint16_t sent = rte_eth_tx_burst(port_out, 0, tx_pkts, n_tx);

        /* Account for transmitted packets */
        for (uint16_t i = 0; i < sent; i++)
            stats_inc_tx(tx_pkts[i]->pkt_len);

        /* Free packets the TX queue could not accept */
        if (unlikely(sent < n_tx)) {
            for (uint16_t i = sent; i < n_tx; i++) {
                stats_inc_dropped();
                rte_pktmbuf_free(tx_pkts[i]);
            }
        }
    }

    RTE_LOG_FW_INFO("lcore %u: pipeline stopped\n", rte_lcore_id());
    return 0;
}
