#include <stdio.h>
#include <stdlib.h>

#include "firewall.h"

/*
 * Stub globals normally defined in main.c.
 * Required because config.c references g_default_policy,
 * but test binaries do not link main.c.
 */
volatile fw_action_t g_default_policy = ACTION_DROP;
volatile int         g_force_quit     = 0;

/*
 * TODO: P4-06 — full unit tests for the config parser.
 *
 * Tests planned:
 *  1. Load valid config/rules.json → n_rules == 4
 *  2. JSON missing 'mode' → config_load() returns non-zero
 *  3. Rule with unknown action → returns error
 *  4. src_ip "192.168.1.0/24" → src_ip=0xC0A80100 (net order), mask=0x00FFFFFF
 *  5. dst_port "1024-65535" → dst_port_min=1024, dst_port_max=65535
 *  6. Hot-reload: modify rule count in temp file, config_reload() updates n_rules
 */

int
main(void)
{
    printf("test_config: stub — will be implemented in P4-06\n");
    return EXIT_SUCCESS;
}
