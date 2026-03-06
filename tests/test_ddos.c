#include <stdio.h>
#include <stdlib.h>

#include "firewall.h"
#include "rule_engine.h"

/* ─── Stub globals (normally defined in main.c) ─────────────────────────── */

volatile fw_action_t g_default_policy = ACTION_DROP;
volatile int         g_force_quit     = 0;

/*
 * meter_init_all() in ddos.c calls rule_list().
 * test_ddos does not link rule_engine.c — provide a stub that returns
 * an empty rule set so meter_init_all() is a no-op in these tests.
 */
int
rule_list(struct fw_rule *rules_out, uint32_t *n_out)
{
    (void)rules_out;
    if (n_out) *n_out = 0;
    return 0;
}

/*
 * TODO: P3-04 — full unit tests for DDoS detector.
 *
 * Tests planned:
 *  1. SYN flood: 101 SYN packets in window → blacklist_check() == 1
 *  2. Window reset: 50 SYN, pause > window_ns, 50 more → not blacklisted
 *  3. Expired TTL: blacklist_add(ip, past_cycle) → blacklist_check() == 0
 *  4. blacklist_del() → blacklist_check() == 0
 *  5. UDP flood: analogous to SYN test
 */

int
main(void)
{
    printf("test_ddos: stub — will be implemented in P3-04\n");
    return EXIT_SUCCESS;
}
