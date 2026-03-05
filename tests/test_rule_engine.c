#include <stdio.h>
#include <stdlib.h>

#include "firewall.h"

/* Stub globals — defined in main.c which test binaries do not link */
volatile fw_action_t g_default_policy = ACTION_DROP;
volatile int         g_force_quit     = 0;

/* Stub g_fw_config — defined in config.c which test binaries do not link */
#include "config.h"
struct fw_config g_fw_config = {0};

/*
 * TODO: P2-04 — full unit tests for the rule engine.
 *
 * Tests planned:
 *  1. DROP rule for TCP dst_port=80 → ACTION_DROP
 *  2. Same packet, dst_port=443 → ACTION_ACCEPT (default policy)
 *  3. Priority: two rules for same traffic, lower number wins
 *  4. CIDR mask: src_ip=192.168.1.100 matches 192.168.1.0/24
 *  5. Reload: rule_engine_rebuild() applies new rules
 *
 * Stub: do nothing, return 0 so 'meson test' passes during Phase 1.
 */

int
main(void)
{
    printf("test_rule_engine: stub — will be implemented in P2-04\n");
    return EXIT_SUCCESS;
}
