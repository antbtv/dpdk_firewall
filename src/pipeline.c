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
 * Конвейер пакетов (7 этапов на burst из MAX_BURST=32 пакетов):
 *  1. RX BURST         — реализовано
 *  2. CLASSIFIER       — реализовано 
 *  3. BLACKLIST CHECK  — реализовано
 *  4. RULE ENGINE      — реализовано
 *  5. RATE LIMIT       — реализовано
 *  6. DDOS UPDATE      — реализовано
 *  7. TX BURST         — реализовано
 */

/* ─── Этап 2: CLASSIFIER ────────────────────────────────────────────────── */

/*
 * Разобрать один mbuf и заполнить pkt_meta.
 * IP-адреса конвертируются в порядок байт хоста (HBo) — rte_acl MASK применяет префикс
 * от старшего бита целого числа, поэтому HBo необходим для корректного CIDR-сравнения на LE ARM.
 * Порты конвертируются в порядок байт хоста (HBo) — требуется для корректного сравнения RANGE в rte_acl.
 * Не-IPv4 кадры устанавливают is_ipv4=0; все остальные поля обнуляются.
 */
static void
classify_pkt(struct rte_mbuf *mbuf, struct pkt_meta *meta)
{
    memset(meta, 0, sizeof(*meta));

    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    if (rte_be_to_cpu_16(eth->ether_type) != RTE_ETHER_TYPE_IPV4) {
        /* Не IPv4: передаётся как есть в режиме бриджа (meta->is_ipv4 остаётся 0) */
        return;
    }

    struct rte_ipv4_hdr *iph = (struct rte_ipv4_hdr *)(eth + 1);
    meta->src_ip  = rte_be_to_cpu_32(iph->src_addr);  /* HBo: rte_acl MASK требует HBo */
    meta->dst_ip  = rte_be_to_cpu_32(iph->dst_addr);  /* HBo */
    meta->proto   = iph->next_proto_id;
    meta->is_ipv4 = 1;

    uint8_t *l4 = (uint8_t *)iph + (iph->version_ihl & 0x0f) * 4;

    switch (meta->proto) {
    case IPPROTO_TCP: {
        struct rte_tcp_hdr *tcph = (struct rte_tcp_hdr *)l4;
        meta->src_port  = rte_be_to_cpu_16(tcph->src_port); /* HBo */
        meta->dst_port  = rte_be_to_cpu_16(tcph->dst_port); /* HBo */
        meta->tcp_flags = tcph->tcp_flags;
        break;
    }
    case IPPROTO_UDP: {
        struct rte_udp_hdr *udph = (struct rte_udp_hdr *)l4;
        meta->src_port = rte_be_to_cpu_16(udph->src_port); /* HBo */
        meta->dst_port = rte_be_to_cpu_16(udph->dst_port); /* HBo */
        break;
    }
    case IPPROTO_ICMP: {
        struct rte_icmp_hdr *icmph = (struct rte_icmp_hdr *)l4;
        meta->icmp_type = icmph->icmp_type;
        meta->icmp_code = icmph->icmp_code;
        /* src_port/dst_port остаются 0; правила ICMP используют диапазон 0-65535 */
        break;
    }
    default:
        break;
    }
}

/* ─── Цикл пересылки ────────────────────────────────────────────────────── */

int
pipeline_lcore_main(void *arg)
{
    const struct pipeline_args *pa = (const struct pipeline_args *)arg;
    const uint16_t port_in  = pa->port_in;
    const uint16_t port_out = pa->port_out;

    RTE_LOG_FW_INFO("lcore %u: pipeline started, port %u → port %u\n",
                    rte_lcore_id(), port_in, port_out);

    /* Массивы на стеке — никогда не выделяются в куче (zero-copy, PRD §8) */
    struct rte_mbuf *rx_pkts[MAX_BURST];
    struct rte_mbuf *tx_pkts[MAX_BURST];
    struct pkt_meta  meta[MAX_BURST];

    /* Предвычислить частоту TSC для преобразования TSC→нс (этап 6).
     * Целочисленная арифметика: избегает операций с плавающей точкой на горячем пути.
     * Формула: now_ns = (cycles / tsc_hz) * 1e9 + (cycles % tsc_hz) * 1e9 / tsc_hz
     * Безопасно на RPi5 (tsc_hz ≈ 54 МГц): rem < 54e6, rem * 1e9 < 5.4e16 < 2^64. */
    const uint64_t tsc_hz = rte_get_tsc_hz();

    while (!g_force_quit) {

        /* ── Этап 1: RX BURST ──────────────────────────────────────────── */
        uint16_t n = rte_eth_rx_burst(port_in, 0, rx_pkts, MAX_BURST);
        if (n == 0)
            continue;

        /* ── Этап 2: CLASSIFIER + статистика RX ────────────────────────── */
        for (uint16_t i = 0; i < n; i++) {
            /* Предвыборка на 2 пакета вперёд: 4-ширинный декодер Cortex-A76 требует
             * большего опережения для скрытия задержки памяти по сравнению с prefetch-1. */
            if (i + 2 < n)
                rte_prefetch0(rte_pktmbuf_mtod(rx_pkts[i + 2], void *));
            classify_pkt(rx_pkts[i], &meta[i]);
            stats_inc_rx(rx_pkts[i]->pkt_len);
        }

        /* Снять время один раз на burst — используется этапами 3, 5, 6 */
        uint64_t now_cycles = rte_get_tsc_cycles();
        uint64_t now_ns     = (now_cycles / tsc_hz) * UINT64_C(1000000000)
                            + (now_cycles % tsc_hz) * UINT64_C(1000000000) / tsc_hz;

        /* ── Этапы 3-6 → Этап 7 ────────────────────────────────────────── */
        uint16_t n_tx = 0;

        for (uint16_t i = 0; i < n; i++) {

            if (!meta[i].is_ipv4) {
                /* Не IPv4: передаётся как есть (режим бриджа) */
                tx_pkts[n_tx++] = rx_pkts[i];
                continue;
            }

            /* ── Этап 3: BLACKLIST CHECK ────────────────────────────────── */
            if (blacklist_check(meta[i].src_ip, now_cycles)) {
                rte_pktmbuf_free(rx_pkts[i]);
                stats_inc_dropped();
                continue;
            }

            /* ── Этап 4: RULE ENGINE ────────────────────────────────────── */
            uint32_t rule_id;
            fw_action_t action = rule_match(&meta[i], &rule_id,
                                            rx_pkts[i]->pkt_len);

            if (action == ACTION_DROP) {
                rte_pktmbuf_free(rx_pkts[i]);
                stats_inc_dropped();
                continue;
            }

            /* ── Этап 5: RATE LIMIT ─────────────────────────────────────── */
            if (action == ACTION_RATE_LIMIT &&
                meter_check(rule_id, rx_pkts[i]->pkt_len, now_cycles)
                    == RTE_COLOR_RED) {
                rte_pktmbuf_free(rx_pkts[i]);
                stats_inc_dropped();
                continue;
            }

            /* ── Этап 6: DDOS UPDATE ────────────────────────────────────── */
            ddos_update(meta[i].src_ip, &meta[i], now_ns);

            tx_pkts[n_tx++] = rx_pkts[i];
        }

        /* ── Этап 7: TX BURST ──────────────────────────────────────────── */
        if (n_tx == 0)
            continue;

        /* force_copy=1 в net_af_xdp PMD: UMEM-фреймы копируются в обычные
         * mbufs внутри PMD до передачи нам. Копирование в пользовательском пространстве
         * не нужно — все mbufs в tx_pkts[] являются обычными буферами пула. */
        uint16_t sent = rte_eth_tx_burst(port_out, 0, tx_pkts, n_tx);

        /* Учесть переданные пакеты */
        for (uint16_t i = 0; i < sent; i++)
            stats_inc_tx(tx_pkts[i]->pkt_len);

        /* Освободить пакеты, которые очередь TX не смогла принять */
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
