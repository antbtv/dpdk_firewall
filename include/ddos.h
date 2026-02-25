#ifndef FW_DDOS_H
#define FW_DDOS_H

#include <stdint.h>
#include "firewall.h"
#include "config.h"

/** Per-source-IP traffic counters (stored in rte_hash). */
struct ddos_entry {
    uint64_t syn_count;
    uint64_t udp_count;
    uint64_t icmp_count;
    uint64_t window_start_ns;
};

void ddos_init(const struct ddos_config *cfg);

/**
 * ddos_update() — update sliding-window counters for src_ip.
 * If a threshold is exceeded, src_ip is added to the blacklist.
 * @param now_ns  Current time in nanoseconds (from TSC).
 */
void ddos_update(uint32_t src_ip, struct pkt_meta *m, uint64_t now_ns);

/**
 * blacklist_check() — O(1) blacklist lookup.
 * @param now_cycles  rte_get_tsc_cycles() value.
 * @return 1 if src_ip is currently blocked, 0 otherwise.
 */
int  blacklist_check(uint32_t src_ip, uint64_t now_cycles);

/** blacklist_add() — block src_ip until expire_cycles. */
void blacklist_add(uint32_t src_ip, uint64_t expire_cycles);

/** blacklist_del() — manually unblock src_ip. */
void blacklist_del(uint32_t src_ip);

/**
 * blacklist_list() — enumerate blocked IPs.
 * @param n_out  In: max entries; Out: actual entries written.
 */
void blacklist_list(uint32_t *ips_out, uint64_t *expires_out, uint32_t *n_out);

#endif /* FW_DDOS_H */
