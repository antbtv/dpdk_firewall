#include <stdio.h>
#include <stdlib.h>

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
