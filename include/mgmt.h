#ifndef FW_MGMT_H
#define FW_MGMT_H

#include <signal.h>

/**
 * g_sighup_flag — set by SIGHUP handler in main.c; polled by mgmt_server_run().
 * Defined in main.c, declared here so mgmt.c can access it.
 */
extern volatile sig_atomic_t g_sighup_flag;

/**
 * mgmt_server_run() — blocking control-plane loop on lcore 0.
 * Handles the management UNIX socket, periodic stats dump,
 * and config hot-reload on SIGHUP.
 * Returns when g_force_quit is set.
 */
void mgmt_server_run(void);

#endif /* FW_MGMT_H */
