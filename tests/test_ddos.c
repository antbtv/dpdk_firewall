#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <netinet/in.h>

#include <rte_eal.h>
#include <rte_cycles.h>

#include "firewall.h"
#include "rule_engine.h"
#include "ddos.h"
#include "log.h"

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

/* ─── DDoS config used by all tests ─────────────────────────────────────── */

/*
 * Low thresholds make tests fast (no need to send millions of packets).
 * window_ns is large (1 s) to prevent accidental expiry during a test.
 */
static const struct ddos_config test_cfg = {
    .enabled           = 1,
    .window_ns         = 1000000000ULL,          /* 1 second */
    .syn_threshold     = 100,
    .udp_threshold     = 1000,
    .icmp_threshold    = 500,
    .block_duration_ns = 300ULL * 1000000000ULL, /* 300 s */
};

/* ─── Helpers ────────────────────────────────────────────────────────────── */

static struct pkt_meta
make_syn(uint32_t src_ip)
{
    struct pkt_meta m;
    memset(&m, 0, sizeof(m));
    m.src_ip    = src_ip;
    m.proto     = IPPROTO_TCP;
    m.tcp_flags = TCP_FLAG_SYN;
    m.is_ipv4   = 1;
    return m;
}

static struct pkt_meta
make_udp(uint32_t src_ip)
{
    struct pkt_meta m;
    memset(&m, 0, sizeof(m));
    m.src_ip  = src_ip;
    m.proto   = IPPROTO_UDP;
    m.is_ipv4 = 1;
    return m;
}

/* ─── Test 1 ─────────────────────────────────────────────────────────────── */
/*
 * SYN flood: exactly syn_threshold SYN packets must NOT trigger blacklist;
 * the (threshold+1)-th packet must auto-blacklist the source IP.
 *
 * ddos_update() blacklists when ++syn_count > syn_threshold, so:
 *   - after 100 SYNs: syn_count=100, 100>100 is FALSE → not blacklisted
 *   - after 101st SYN: syn_count=101, 101>100 is TRUE → blacklisted
 */
static void
test_syn_flood(void)
{
    uint32_t ip = 0x01020304u;   /* 1.2.3.4, unique per test */
    struct pkt_meta m = make_syn(ip);

    for (uint64_t i = 0; i < test_cfg.syn_threshold; i++)
        ddos_update(ip, &m, 0);
    assert(blacklist_check(ip, rte_get_tsc_cycles()) == 0);

    ddos_update(ip, &m, 0);     /* (threshold+1)-th SYN */
    assert(blacklist_check(ip, rte_get_tsc_cycles()) == 1);

    printf("  test 1 PASS: %llu SYNs → blacklisted\n",
           (unsigned long long)test_cfg.syn_threshold + 1);
}

/* ─── Test 2 ─────────────────────────────────────────────────────────────── */
/*
 * Window reset: send syn_threshold/2 SYNs in window A (now_ns=0),
 * then syn_threshold/2 SYNs in window B (now_ns = window_ns+1).
 * The counter must reset at the window boundary, so the IP is never blacklisted.
 */
static void
test_window_reset(void)
{
    uint32_t ip = 0x02020304u;   /* 2.2.3.4 */
    struct pkt_meta m = make_syn(ip);
    uint64_t half = test_cfg.syn_threshold / 2;

    /* Phase A — window [0, window_ns) */
    for (uint64_t i = 0; i < half; i++)
        ddos_update(ip, &m, 0);
    assert(blacklist_check(ip, rte_get_tsc_cycles()) == 0);

    /* Phase B — new window starts; counters reset to 0 */
    uint64_t t_new = test_cfg.window_ns + 1;
    for (uint64_t i = 0; i < half; i++)
        ddos_update(ip, &m, t_new);

    /* Only half the threshold accumulated in the new window → not blocked */
    assert(blacklist_check(ip, rte_get_tsc_cycles()) == 0);

    printf("  test 2 PASS: window reset at %llu ns, counters cleared\n",
           (unsigned long long)test_cfg.window_ns);
}

/* ─── Test 3 ─────────────────────────────────────────────────────────────── */
/*
 * Expired TTL: blacklist_add() with expire_cycles already in the past.
 * blacklist_check() must perform lazy deletion and return 0.
 */
static void
test_expired_ttl(void)
{
    uint32_t ip = 0x03020304u;   /* 3.2.3.4 */

    /*
     * expire_cycles = rte_get_tsc_cycles() - 1 is guaranteed to be in the
     * past at the time of the subsequent blacklist_check() call.
     */
    uint64_t past = rte_get_tsc_cycles() - 1;
    blacklist_add(ip, past);

    assert(blacklist_check(ip, rte_get_tsc_cycles()) == 0);

    printf("  test 3 PASS: expired TTL → lazy removal, not blocked\n");
}

/* ─── Test 4 ─────────────────────────────────────────────────────────────── */
/*
 * blacklist_del() — manually remove an active blacklist entry.
 */
static void
test_blacklist_del(void)
{
    uint32_t ip = 0x04020304u;   /* 4.2.3.4 */

    blacklist_add(ip, UINT64_MAX);   /* far-future expiry */
    assert(blacklist_check(ip, rte_get_tsc_cycles()) == 1);

    blacklist_del(ip);
    assert(blacklist_check(ip, rte_get_tsc_cycles()) == 0);

    printf("  test 4 PASS: blacklist_del() removes active entry\n");
}

/* ─── Test 5 ─────────────────────────────────────────────────────────────── */
/*
 * UDP flood: analogous to test 1 but for the UDP counter.
 * (threshold+1) UDP packets must trigger auto-blacklist.
 */
static void
test_udp_flood(void)
{
    uint32_t ip = 0x05020304u;   /* 5.2.3.4 */
    struct pkt_meta m = make_udp(ip);

    for (uint64_t i = 0; i <= test_cfg.udp_threshold; i++)
        ddos_update(ip, &m, 0);
    assert(blacklist_check(ip, rte_get_tsc_cycles()) == 1);

    printf("  test 5 PASS: %llu UDP packets → blacklisted\n",
           (unsigned long long)test_cfg.udp_threshold + 1);
}

/* ─── Entry point ────────────────────────────────────────────────────────── */

int
main(void)
{
    static char arg0[] = "test_ddos";
    static char arg1[] = "--no-pci";
    static char arg2[] = "-m";
    static char arg3[] = "64";
    char *eal_argv[] = { arg0, arg1, arg2, arg3 };

    if (rte_eal_init(4, eal_argv) < 0) {
        fprintf(stderr, "rte_eal_init failed\n");
        return EXIT_FAILURE;
    }

    fw_log_init();

    /*
     * ddos_init() creates the rte_hash tables and precomputes timing constants.
     * Called once; test functions use different IPs to avoid state interference.
     */
    ddos_init(&test_cfg);

    printf("test_ddos: running 5 tests\n");

    test_syn_flood();
    test_window_reset();
    test_expired_ttl();
    test_blacklist_del();
    test_udp_flood();

    printf("test_ddos: all 5 tests PASSED\n");

    rte_eal_cleanup();
    return EXIT_SUCCESS;
}
