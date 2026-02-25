#include <stdio.h>
#include <stdlib.h>

/*
 * TODO: P4-05 — full CLI implementation.
 *
 * fw_ctl connects to /var/run/dpdk_firewall/mgmt.sock,
 * sends a JSON command, prints the response, and exits.
 *
 * Stub: prints usage and exits with an error so the build system
 * can verify the binary compiles successfully.
 */

int
main(int argc, char *argv[])
{
    (void)argc;
    fprintf(stderr,
            "fw_ctl: management CLI (not yet implemented — P4-05)\n"
            "Usage: %s <rule|stats|blacklist|config|set-policy> ...\n",
            argv[0]);
    return EXIT_FAILURE;
}
