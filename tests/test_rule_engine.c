#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <rte_eal.h>

#include "firewall.h"
#include "config.h"
#include "rule_engine.h"
#include "log.h"

/* ─── Stub globals (normally defined in main.c) ─────────────────────────── */

volatile fw_action_t g_default_policy = ACTION_DROP;
volatile int         g_force_quit     = 0;

/* ─── Stub g_fw_config (normally defined in config.c) ──────────────────── */

struct fw_config g_fw_config;

/* ─── Helpers ────────────────────────────────────────────────────────────── */

/*
 * Convert "a.b.c.d" to a uint32_t in host byte order.
 * All IP fields in fw_rule and pkt_meta use HBo (rte_acl MASK requires HBo on LE ARM).
 */
static uint32_t
ip4(const char *s)
{
    struct in_addr a;
    inet_pton(AF_INET, s, &a);
    return ntohl(a.s_addr);
}

/* Build a TCP pkt_meta; all IPs and ports in host byte order */
static struct pkt_meta
make_tcp(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port)
{
    struct pkt_meta m;
    memset(&m, 0, sizeof(m));
    m.src_ip   = src_ip;
    m.dst_ip   = dst_ip;
    m.proto    = IPPROTO_TCP;
    m.src_port = src_port;
    m.dst_port = dst_port;
    m.is_ipv4  = 1;
    return m;
}

/*
 * Build a minimal fw_rule with only the fields needed for a port-based test.
 * rule_add() will overwrite .id with a freshly allocated monotonic ID.
 */
static struct fw_rule
make_rule(uint32_t prio, uint8_t proto,
          uint16_t dport_min, uint16_t dport_max,
          fw_action_t action)
{
    struct fw_rule r;
    memset(&r, 0, sizeof(r));
    r.priority     = prio;
    r.proto        = proto;
    r.src_port_min = 0;
    r.src_port_max = 65535;
    r.dst_port_min = dport_min;
    r.dst_port_max = dport_max;
    r.action       = action;
    return r;
}

/*
 * Delete every rule currently loaded in the engine.
 * Used to reset state between tests without reinitialising EAL or the engine.
 */
static void
clear_rules(void)
{
    struct fw_rule listed[MAX_RULES];
    uint32_t n = 0;
    if (rule_list(listed, &n) == 0) {
        for (uint32_t i = 0; i < n; i++)
            rule_del(listed[i].id);
    }
}

/* ─── Test 1 ─────────────────────────────────────────────────────────────── */
/*
 * A DROP rule for TCP dst_port=80 must block matching traffic.
 * The returned rule_id must equal the ID assigned by rule_add().
 */
static void
test_drop_rule(void)
{
    clear_rules();
    g_default_policy = ACTION_ACCEPT;

    struct fw_rule r = make_rule(100, IPPROTO_TCP, 80, 80, ACTION_DROP);
    int id = rule_add(&r);
    assert(id > 0);

    uint32_t rid;
    struct pkt_meta m = make_tcp(ip4("1.2.3.4"), ip4("5.6.7.8"), 12345, 80);
    assert(rule_match(&m, &rid) == ACTION_DROP);
    assert(rid == (uint32_t)id);

    printf("  test 1 PASS: TCP dst_port=80 → DROP, rule_id matched\n");
}

/* ─── Test 2 ─────────────────────────────────────────────────────────────── */
/*
 * A packet that matches no rule must return the default policy.
 * Same rule set as test 1 (TCP:80 → DROP); dst_port=443 must get ACTION_ACCEPT.
 */
static void
test_default_policy(void)
{
    clear_rules();
    g_default_policy = ACTION_ACCEPT;

    struct fw_rule r = make_rule(100, IPPROTO_TCP, 80, 80, ACTION_DROP);
    rule_add(&r);

    uint32_t rid;
    struct pkt_meta m = make_tcp(ip4("1.2.3.4"), ip4("5.6.7.8"), 12345, 443);
    assert(rule_match(&m, &rid) == ACTION_ACCEPT);
    assert(rid == 0);   /* 0 = no rule matched */

    printf("  test 2 PASS: TCP dst_port=443 → ACCEPT (default policy, rid=0)\n");
}

/* ─── Test 3 ─────────────────────────────────────────────────────────────── */
/*
 * Lower priority number beats higher number (lower = more important).
 *   Rule A: priority=200, TCP dst_port=80 → DROP
 *   Rule B: priority=100, TCP dst_port=80 → ACCEPT
 * Both match; rule B must win and the returned rule_id must be B's id.
 */
static void
test_priority(void)
{
    clear_rules();
    g_default_policy = ACTION_DROP;

    struct fw_rule ra = make_rule(200, IPPROTO_TCP, 80, 80, ACTION_DROP);
    struct fw_rule rb = make_rule(100, IPPROTO_TCP, 80, 80, ACTION_ACCEPT);
    rule_add(&ra);
    int id_b = rule_add(&rb);
    assert(id_b > 0);

    uint32_t rid;
    struct pkt_meta m = make_tcp(ip4("1.2.3.4"), ip4("5.6.7.8"), 12345, 80);
    assert(rule_match(&m, &rid) == ACTION_ACCEPT);
    assert(rid == (uint32_t)id_b);

    printf("  test 3 PASS: priority 100 (ACCEPT) beats 200 (DROP)\n");
}

/* ─── Test 4 ─────────────────────────────────────────────────────────────── */
/*
 * CIDR subnet matching.
 *   Rule: src_ip=192.168.1.0/24 → DROP, default=ACCEPT.
 *   192.168.1.100 is inside the subnet  → ACTION_DROP.
 *   10.0.0.1      is outside the subnet → ACTION_ACCEPT (default policy).
 */
static void
test_cidr_mask(void)
{
    clear_rules();
    g_default_policy = ACTION_ACCEPT;

    struct fw_rule r;
    memset(&r, 0, sizeof(r));
    r.priority     = 100;
    r.src_ip       = ip4("192.168.1.0");
    r.src_mask     = 0xFFFFFF00u;   /* /24 in host byte order */
    r.src_port_min = 0;
    r.src_port_max = 65535;
    r.dst_port_min = 0;
    r.dst_port_max = 65535;
    r.action       = ACTION_DROP;
    int id = rule_add(&r);
    assert(id > 0);

    uint32_t rid;

    /* 192.168.1.100 is inside 192.168.1.0/24 → DROP */
    struct pkt_meta m1 = make_tcp(ip4("192.168.1.100"), ip4("10.0.0.1"), 0, 0);
    assert(rule_match(&m1, &rid) == ACTION_DROP);
    assert(rid == (uint32_t)id);

    /* 10.0.0.1 is outside → ACCEPT (default policy) */
    struct pkt_meta m2 = make_tcp(ip4("10.0.0.1"), ip4("192.168.1.100"), 0, 0);
    assert(rule_match(&m2, &rid) == ACTION_ACCEPT);
    assert(rid == 0);

    printf("  test 4 PASS: CIDR /24 matches 192.168.1.100, skips 10.0.0.1\n");
}

/* ─── Test 5 ─────────────────────────────────────────────────────────────── */
/*
 * rule_add() triggers an implicit rule_engine_rebuild().
 *   Phase A — no rules, default ACCEPT → packet must be ACCEPTed.
 *   Phase B — add DROP rule for TCP:9999 → same packet must now be DROPped.
 */
static void
test_rebuild(void)
{
    clear_rules();
    g_default_policy = ACTION_ACCEPT;

    uint32_t rid;
    struct pkt_meta m = make_tcp(ip4("1.2.3.4"), ip4("5.6.7.8"), 12345, 9999);

    /* Phase A: no rules */
    assert(rule_match(&m, &rid) == ACTION_ACCEPT);
    assert(rid == 0);

    /* Phase B: add DROP rule; rule_add() calls rule_engine_rebuild() internally */
    struct fw_rule r = make_rule(100, IPPROTO_TCP, 9999, 9999, ACTION_DROP);
    int id = rule_add(&r);
    assert(id > 0);

    assert(rule_match(&m, &rid) == ACTION_DROP);
    assert(rid == (uint32_t)id);

    printf("  test 5 PASS: rule_add() rebuilt engine, TCP:9999 now DROPped\n");
}

/* ─── Entry point ────────────────────────────────────────────────────────── */

int
main(void)
{
    /*
     * Minimal EAL init: no PCI scan, 64 MB of memory.
     * rule_engine uses rte_acl (requires EAL + hugepages) and rte_rwlock.
     */
    static char arg0[] = "test_rule_engine";
    static char arg1[] = "--no-pci";
    static char arg2[] = "--log-level=0";
    static char arg3[] = "-m";
    static char arg4[] = "64";
    char *eal_argv[] = { arg0, arg1, arg2, arg3, arg4 };
    int   eal_argc   = 5;

    if (rte_eal_init(eal_argc, eal_argv) < 0) {
        fprintf(stderr, "rte_eal_init failed\n");
        return EXIT_FAILURE;
    }

    fw_log_init();

    /*
     * rule_engine_init() is designed to be called once at startup.
     * Calling it multiple times would leak ACL contexts (the static
     * g_acl_ctx is set to NULL without freeing) and would cause
     * rte_acl_create() to return a stale context on name collision.
     *
     * Solution: init once with an empty rule set, then manipulate
     * rules between tests via rule_add() / rule_del() which each
     * call rule_engine_rebuild() internally.
     */
    memset(&g_fw_config, 0, sizeof(g_fw_config));
    g_default_policy = ACTION_DROP;
    if (rule_engine_init() != 0) {
        fprintf(stderr, "rule_engine_init failed\n");
        rte_eal_cleanup();
        return EXIT_FAILURE;
    }

    printf("test_rule_engine: running 5 tests\n");

    test_drop_rule();
    test_default_policy();
    test_priority();
    test_cidr_mask();
    test_rebuild();

    printf("test_rule_engine: all 5 tests PASSED\n");

    rte_eal_cleanup();
    return EXIT_SUCCESS;
}
