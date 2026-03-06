#ifndef FW_DDOS_H
#define FW_DDOS_H

#include <stdint.h>
#include <rte_meter.h>

#include "firewall.h"
#include "config.h"

/** Per-source-IP traffic counters (position-indexed via rte_hash). */
struct ddos_entry {
    uint64_t syn_count;
    uint64_t udp_count;
    uint64_t icmp_count;
    uint64_t window_start_ns;
};

/* ─── DDoS / Blacklist API ───────────────────────────────────────────────── */

/**
 * ddos_init() — create hash tables, precompute timing constants.
 * Must be called after rte_eal_init() and before any other ddos_* function.
 */
void ddos_init(const struct ddos_config *cfg);

/**
 * ddos_update() — update sliding-window counters for src_ip.
 * If a threshold is exceeded, src_ip is auto-added to the blacklist.
 * @param now_ns  Current time in nanoseconds (convert from TSC with rte_get_tsc_hz()).
 */
void ddos_update(uint32_t src_ip, struct pkt_meta *m, uint64_t now_ns);

/**
 * blacklist_check() — O(1) blacklist lookup.
 * @param now_cycles  rte_get_tsc_cycles() value.
 * @return 1 if src_ip is currently blocked, 0 otherwise.
 */
int  blacklist_check(uint32_t src_ip, uint64_t now_cycles);

/** blacklist_add() — block src_ip until expire_cycles (TSC value). */
void blacklist_add(uint32_t src_ip, uint64_t expire_cycles);

/** blacklist_del() — manually unblock src_ip. */
void blacklist_del(uint32_t src_ip);

/**
 * blacklist_list() — enumerate all currently blocked IPs.
 * @param ips_out      Caller-allocated array for blocked IPs.
 * @param expires_out  Caller-allocated array for TSC expire times.
 * @param n_out        Output: number of entries written.
 */
void blacklist_list(uint32_t *ips_out, uint64_t *expires_out, uint32_t *n_out);

/* ─── Rate limiting API (P3-02) ──────────────────────────────────────────── */

/**
 * meter_init_all() — initialize srTCM meters for all ACTION_RATE_LIMIT rules.
 * Must be called after rule_engine_init() and again after every config reload.
 */
void meter_init_all(void);

/**
 * meter_check() — run the srTCM color check for a packet.
 * @param rule_id    Rule ID returned by rule_match() (must be a RATE_LIMIT rule).
 * @param pkt_len    Packet length in bytes.
 * @param now_cycles rte_get_tsc_cycles() value.
 * @return RTE_COLOR_GREEN/YELLOW → forward; RTE_COLOR_RED → drop.
 */
enum rte_color meter_check(uint32_t rule_id, uint32_t pkt_len, uint64_t now_cycles);

#endif /* FW_DDOS_H */
