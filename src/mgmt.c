#include <unistd.h>

#include "mgmt.h"
#include "firewall.h"
#include "config.h"
#include "stats.h"
#include "log.h"

/*
 * TODO: P4-02 — full UNIX socket + epoll implementation.
 * TODO: P4-03 — implement all 9 management commands.
 *
 * Phase 1 stub: simple loop that handles SIGHUP and periodic stats dump.
 * This is sufficient for Milestone 1 (basic forwarding verification).
 */

#define STATS_DUMP_INTERVAL_US  5000000ULL  /* 5 seconds */
#define SLEEP_INTERVAL_US        100000ULL  /* 100 ms */

void
mgmt_server_run(void)
{
    RTE_LOG_FW_INFO("mgmt: control plane started (stub, P4-02 pending)\n");

    uint64_t elapsed_us = 0;

    while (!g_force_quit) {
        usleep(SLEEP_INTERVAL_US);
        elapsed_us += SLEEP_INTERVAL_US;

        /* Hot-reload on SIGHUP */
        if (g_sighup_flag) {
            g_sighup_flag = 0;
            config_reload();
        }

        /* Periodic stats dump every 5 seconds */
        if (elapsed_us >= STATS_DUMP_INTERVAL_US) {
            stats_periodic_dump();
            elapsed_us = 0;
        }
    }

    RTE_LOG_FW_INFO("mgmt: control plane exiting\n");
}
