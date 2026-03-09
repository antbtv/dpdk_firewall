/*
 * tests/test_config.c — Unit tests for the config parser (P4-06)
 *
 * Links: config.c, rule_engine.c, log.c  (via tests/meson.build)
 * Does NOT link main.c → must define stub globals g_default_policy / g_force_quit.
 * g_fw_config is defined in the linked config.c — no stub needed here.
 *
 * Tests:
 *  1. Load a valid 4-rule config → n_rules == 4
 *  2. JSON missing required 'mode' → config_load() returns non-zero
 *  3. Rule with unknown action → config_load() returns non-zero
 *  4. src_ip "192.168.1.0/24" → src_ip = 0xC0A80100 (HBo), mask = 0xFFFFFF00 (HBo)
 *  5. dst_port "1024-65535" → dst_port_min=1024, dst_port_max=65535
 *  6. Hot-reload: overwrite temp file, config_reload() updates n_rules
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <rte_eal.h>

#include "firewall.h"
#include "config.h"
#include "rule_engine.h"
#include "log.h"

/* ─── Stub globals (normally defined in main.c) ─────────────────────────── */

volatile fw_action_t g_default_policy = ACTION_DROP;
volatile int         g_force_quit     = 0;

/* ─── Temp file helper ───────────────────────────────────────────────────── */

static void
write_file(const char *path, const char *content)
{
    FILE *f = fopen(path, "w");
    assert(f != NULL);
    fputs(content, f);
    fclose(f);
}

/* ─── Test JSON fixtures ─────────────────────────────────────────────────── */

/* Valid config with exactly 4 rules */
static const char JSON_VALID_4[] =
"{"
"  \"version\": 1,"
"  \"mode\": \"bridge\","
"  \"ports\": { \"wan\": \"eth0\" },"
"  \"default_policy\": \"drop\","
"  \"rules\": ["
"    { \"id\": 1, \"priority\": 100, \"proto\": \"tcp\","
"      \"dst_port\": \"22\", \"action\": \"accept\" },"
"    { \"id\": 2, \"priority\": 200, \"proto\": \"icmp\","
"      \"action\": \"rate_limit\","
"      \"rate\": { \"cir_kbps\": 1000, \"cbs_bytes\": 65536 } },"
"    { \"id\": 3, \"priority\": 300,"
"      \"src_ip\": \"10.0.0.0/8\", \"action\": \"drop\" },"
"    { \"id\": 4, \"priority\": 1,"
"      \"src_ip\": \"10.99.0.0/24\", \"action\": \"accept\" }"
"  ]"
"}";

/* Missing required 'mode' field */
static const char JSON_NO_MODE[] =
"{"
"  \"version\": 1,"
"  \"ports\": { \"wan\": \"eth0\" },"
"  \"default_policy\": \"drop\","
"  \"rules\": []"
"}";

/* Rule with unknown action */
static const char JSON_BAD_ACTION[] =
"{"
"  \"version\": 1,"
"  \"mode\": \"bridge\","
"  \"ports\": { \"wan\": \"eth0\" },"
"  \"default_policy\": \"drop\","
"  \"rules\": ["
"    { \"id\": 1, \"priority\": 100, \"action\": \"explode\" }"
"  ]"
"}";

/* Single rule with src_ip CIDR and dst_port range */
static const char JSON_CIDR_PORTS[] =
"{"
"  \"version\": 1,"
"  \"mode\": \"bridge\","
"  \"ports\": { \"wan\": \"eth0\" },"
"  \"default_policy\": \"drop\","
"  \"rules\": ["
"    { \"id\": 1, \"priority\": 100, \"proto\": \"tcp\","
"      \"src_ip\": \"192.168.1.0/24\","
"      \"dst_port\": \"1024-65535\","
"      \"action\": \"drop\" }"
"  ]"
"}";

/* Config with 2 rules (used in hot-reload test — initial state) */
static const char JSON_2_RULES[] =
"{"
"  \"version\": 1,"
"  \"mode\": \"bridge\","
"  \"ports\": { \"wan\": \"eth0\" },"
"  \"default_policy\": \"drop\","
"  \"rules\": ["
"    { \"id\": 1, \"priority\": 100, \"action\": \"accept\" },"
"    { \"id\": 2, \"priority\": 200, \"action\": \"drop\" }"
"  ]"
"}";

/* Config with 1 rule (used in hot-reload test — reloaded state) */
static const char JSON_1_RULE[] =
"{"
"  \"version\": 1,"
"  \"mode\": \"bridge\","
"  \"ports\": { \"wan\": \"eth0\" },"
"  \"default_policy\": \"accept\","
"  \"rules\": ["
"    { \"id\": 1, \"priority\": 50, \"action\": \"drop\" }"
"  ]"
"}";

/* ─── Tests ───────────────────────────────────────────────────────────────── */

/*
 * Test 1: valid 4-rule config parses without error.
 */
static void
test_valid_config(void)
{
    write_file("/tmp/fw_tc_valid.json", JSON_VALID_4);

    int rc = config_load("/tmp/fw_tc_valid.json");
    assert(rc == 0);
    assert(g_fw_config.n_rules == 4);
    assert(g_fw_config.default_policy == ACTION_DROP);

    printf("  test 1 PASS: valid config, n_rules=%u\n", g_fw_config.n_rules);
}

/*
 * Test 2: JSON missing required 'mode' field → config_load returns non-zero.
 */
static void
test_missing_mode(void)
{
    write_file("/tmp/fw_tc_no_mode.json", JSON_NO_MODE);

    int rc = config_load("/tmp/fw_tc_no_mode.json");
    assert(rc != 0);

    printf("  test 2 PASS: missing 'mode' → error code %d\n", rc);
}

/*
 * Test 3: rule with unknown action string → config_load returns non-zero.
 */
static void
test_bad_action(void)
{
    write_file("/tmp/fw_tc_bad_action.json", JSON_BAD_ACTION);

    int rc = config_load("/tmp/fw_tc_bad_action.json");
    assert(rc != 0);

    printf("  test 3 PASS: unknown action → error code %d\n", rc);
}

/*
 * Test 4: src_ip "192.168.1.0/24" → host byte order values.
 *
 * Host byte order (HBo) on LE ARM:
 *   192.168.1.0 → 0xC0A80100  (C0=192, A8=168, 01=1, 00=0)
 *   /24 mask    → 0xFFFFFF00  (top 24 bits set)
 *
 * parse_cidr() in config.c stores HBo (ntohl(addr.s_addr)), and
 * rte_acl MASK type requires HBo for correct CIDR matching on LE ARM
 * (applies prefix from MSB of the integer value).
 */
static void
test_cidr_parse(void)
{
    write_file("/tmp/fw_tc_cidr.json", JSON_CIDR_PORTS);

    int rc = config_load("/tmp/fw_tc_cidr.json");
    assert(rc == 0);
    assert(g_fw_config.n_rules == 1);

    const struct fw_rule *r = &g_fw_config.rules[0];
    assert(r->src_ip   == 0xC0A80100u);   /* 192.168.1.0 in host byte order */
    assert(r->src_mask == 0xFFFFFF00u);   /* /24 mask in host byte order    */

    printf("  test 4 PASS: src_ip=0x%08X mask=0x%08X\n",
           r->src_ip, r->src_mask);
}

/*
 * Test 5: dst_port "1024-65535" → dst_port_min=1024, dst_port_max=65535.
 */
static void
test_port_range(void)
{
    /* Reuse the file already written by test 4 */
    write_file("/tmp/fw_tc_cidr.json", JSON_CIDR_PORTS);

    int rc = config_load("/tmp/fw_tc_cidr.json");
    assert(rc == 0);
    assert(g_fw_config.n_rules == 1);

    const struct fw_rule *r = &g_fw_config.rules[0];
    assert(r->dst_port_min == 1024);
    assert(r->dst_port_max == 65535);

    printf("  test 5 PASS: dst_port_min=%u dst_port_max=%u\n",
           r->dst_port_min, r->dst_port_max);
}

/*
 * Test 6: hot-reload — overwrite config file, config_reload() updates n_rules.
 *
 * Flow:
 *   1. config_load() with 2-rule JSON → n_rules=2
 *   2. Overwrite same file with 1-rule JSON
 *   3. config_reload() → reads from stored config_path, n_rules=1
 */
static void
test_hot_reload(void)
{
    const char *path = "/tmp/fw_tc_reload.json";

    /* Initial load: 2 rules */
    write_file(path, JSON_2_RULES);
    int rc = config_load(path);
    assert(rc == 0);
    assert(g_fw_config.n_rules == 2);

    /* Overwrite with 1 rule */
    write_file(path, JSON_1_RULE);

    /* config_reload() re-reads from g_fw_config.config_path */
    rc = config_reload();
    assert(rc == 0);
    assert(g_fw_config.n_rules == 1);
    assert(g_fw_config.default_policy == ACTION_ACCEPT);

    printf("  test 6 PASS: hot-reload n_rules=%u default_policy=accept\n",
           g_fw_config.n_rules);
}

/* ─── Entry point ────────────────────────────────────────────────────────── */

int
main(void)
{
    /*
     * Minimal EAL init: no PCI scan, 64 MB of memory.
     * Required because config_reload() calls rule_engine_reload_from_config()
     * → rule_engine_rebuild() → rte_acl_create() (needs EAL + hugepages).
     */
    static char arg0[] = "test_config";
    static char arg1[] = "--no-pci";
    static char arg2[] = "-m";
    static char arg3[] = "64";
    char *eal_argv[] = { arg0, arg1, arg2, arg3 };
    int   eal_argc   = 4;

    if (rte_eal_init(eal_argc, eal_argv) < 0) {
        fprintf(stderr, "test_config: rte_eal_init failed\n");
        return EXIT_FAILURE;
    }

    fw_log_init();

    /*
     * Initialise the rule engine with an empty rule set.
     * Tests 1-5 only call config_load() (no rule_engine calls).
     * Test 6 calls config_reload() which internally calls
     * rule_engine_reload_from_config(); the engine must be initialised first.
     */
    memset(&g_fw_config, 0, sizeof(g_fw_config));
    if (rule_engine_init() != 0) {
        fprintf(stderr, "test_config: rule_engine_init failed\n");
        rte_eal_cleanup();
        return EXIT_FAILURE;
    }

    printf("test_config: running 6 tests\n");

    test_valid_config();
    test_missing_mode();
    test_bad_action();
    test_cidr_parse();
    test_port_range();
    test_hot_reload();

    printf("test_config: all 6 tests PASSED\n");

    rte_eal_cleanup();
    return EXIT_SUCCESS;
}
