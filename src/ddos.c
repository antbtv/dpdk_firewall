#include "ddos.h"
#include "log.h"

/*
 * TODO: P3-01 — full implementation using rte_hash + sliding window.
 * TODO: P3-02 — integrate rte_meter_srtcm for RATE_LIMIT.
 *
 * Phase 1 stubs: no-ops so the project compiles.
 */

void
ddos_init(const struct ddos_config *cfg)
{
    (void)cfg;
    RTE_LOG_FW_INFO("ddos: stub (P3-01 not yet implemented)\n");
}

void
ddos_update(uint32_t src_ip, struct pkt_meta *m, uint64_t now_ns)
{
    (void)src_ip;
    (void)m;
    (void)now_ns;
}

int
blacklist_check(uint32_t src_ip, uint64_t now_cycles)
{
    (void)src_ip;
    (void)now_cycles;
    return 0;  /* nothing is blocked */
}

void
blacklist_add(uint32_t src_ip, uint64_t expire_cycles)
{
    (void)src_ip;
    (void)expire_cycles;
}

void
blacklist_del(uint32_t src_ip)
{
    (void)src_ip;
}

void
blacklist_list(uint32_t *ips_out, uint64_t *expires_out, uint32_t *n_out)
{
    (void)ips_out;
    (void)expires_out;
    if (n_out)
        *n_out = 0;
}
