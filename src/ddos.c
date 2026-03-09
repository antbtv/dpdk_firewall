#include <string.h>
#include <inttypes.h>
#include <netinet/in.h>

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_cycles.h>
#include <rte_meter.h>
#include <rte_lcore.h>
#include <rte_malloc.h>

#include "ddos.h"
#include "config.h"
#include "rule_engine.h"
#include "log.h"

/* ─── Constants ──────────────────────────────────────────────────────────── */

/*
 * Requested hash capacity.  DPDK cuckoo hash allocates:
 *   num_buckets = rte_align32pow2(entries) / RTE_HASH_BUCKET_ENTRIES(8)
 * For entries=65536 (power of 2), positions are in [0, 65535].
 */
#define HASH_ENTRIES 65536

/* ─── DDoS / blacklist state ─────────────────────────────────────────────── */

static struct rte_hash  *g_blacklist_hash;
static struct rte_hash  *g_ddos_hash;

/*
 * Position-indexed arrays.  rte_hash_add_key / rte_hash_lookup return a
 * stable int32_t position used as the array index.
 */
static uint64_t          g_blacklist_expires[HASH_ENTRIES]; /* TSC expire time */
static struct ddos_entry g_ddos_entries[HASH_ENTRIES];

static struct ddos_config g_ddos_cfg;
static uint64_t           g_block_duration_cycles; /* precomputed at init */

/* ─── Meter state (P3-02) ────────────────────────────────────────────────── */

/*
 * Indexed by fw_rule.id (1-based).  Index 0 is unused.
 * IDs are assigned monotonically; at most MAX_RULES rules ever exist,
 * so IDs stay in [1, MAX_RULES].
 */
static struct rte_meter_srtcm_profile g_meter_profiles[MAX_RULES + 1];
static struct rte_meter_srtcm         g_meters[MAX_RULES + 1];
static int                            g_meter_valid[MAX_RULES + 1];

/* ─── Private helper ─────────────────────────────────────────────────────── */

static struct rte_hash *
create_hash(const char *name, uint32_t entries)
{
    struct rte_hash_parameters p = {
        .name       = name,
        .entries    = entries,
        .key_len    = sizeof(uint32_t),
        .socket_id  = (int)rte_socket_id(),
        /*
         * RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY: safe for single-writer +
         * multiple-concurrent-reader access.  Minor inter-lcore write races
         * in ddos_update() are tolerated for DDoS detection accuracy.
         */
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,
    };
    struct rte_hash *h = rte_hash_create(&p);
    if (h == NULL)
        RTE_LOG_FW_ERR("ddos: rte_hash_create(%s) failed\n", name);
    return h;
}

/* ─── P3-01: init ────────────────────────────────────────────────────────── */

void
ddos_init(const struct ddos_config *cfg)
{
    g_ddos_cfg = *cfg;

    g_blacklist_hash = create_hash("fw_blacklist", HASH_ENTRIES);
    g_ddos_hash      = create_hash("fw_ddos",      HASH_ENTRIES);

    if (!g_blacklist_hash || !g_ddos_hash) {
        RTE_LOG_FW_ERR("ddos_init: hash table creation failed\n");
        return;
    }

    memset(g_blacklist_expires, 0, sizeof(g_blacklist_expires));
    memset(g_ddos_entries,      0, sizeof(g_ddos_entries));

    /*
     * Precompute block_duration in TSC cycles using double to avoid
     * uint64_t overflow (block_ns * hz can exceed 2^64 for large values).
     */
    g_block_duration_cycles = (uint64_t)(
        (double)cfg->block_duration_ns / 1e9 * (double)rte_get_tsc_hz());

    RTE_LOG_FW_INFO("ddos: initialized (enabled=%d, window=%" PRIu64 "ns, "
                    "syn=%" PRIu64 " udp=%" PRIu64 " icmp=%" PRIu64
                    ", block=%" PRIu64 "s)\n",
                    cfg->enabled, cfg->window_ns,
                    cfg->syn_threshold, cfg->udp_threshold,
                    cfg->icmp_threshold,
                    cfg->block_duration_ns / (uint64_t)1000000000);
}

/* ─── P3-01: DDoS sliding-window update ─────────────────────────────────── */

void
ddos_update(uint32_t src_ip, struct pkt_meta *m, uint64_t now_ns)
{
    if (!g_ddos_cfg.enabled || !g_ddos_hash)
        return;

    /*
     * rte_hash_add_key() returns the existing position for known keys,
     * or creates a new entry and returns its position.
     */
    int32_t pos = rte_hash_add_key(g_ddos_hash, &src_ip);
    if (pos < 0 || pos >= HASH_ENTRIES)
        return;   /* hash full or unexpected position */

    struct ddos_entry *e = &g_ddos_entries[pos];

    /* Reset window when it expires */
    if (now_ns - e->window_start_ns >= g_ddos_cfg.window_ns) {
        e->syn_count       = 0;
        e->udp_count       = 0;
        e->icmp_count      = 0;
        e->window_start_ns = now_ns;
    }

    /* Increment protocol-specific counter and check threshold */
    int exceeded = 0;
    if (m->proto == IPPROTO_TCP && (m->tcp_flags & TCP_FLAG_SYN)) {
        if (++e->syn_count > g_ddos_cfg.syn_threshold)
            exceeded = 1;
    } else if (m->proto == IPPROTO_UDP) {
        if (++e->udp_count > g_ddos_cfg.udp_threshold)
            exceeded = 1;
    } else if (m->proto == IPPROTO_ICMP) {
        if (++e->icmp_count > g_ddos_cfg.icmp_threshold)
            exceeded = 1;
    }

    if (exceeded) {
        blacklist_add(src_ip, rte_get_tsc_cycles() + g_block_duration_cycles);
        /* Reset to avoid re-triggering on every subsequent packet */
        e->syn_count  = 0;
        e->udp_count  = 0;
        e->icmp_count = 0;
        /*
         * src_ip is in host byte order on LE ARM: LSB = first IP octet.
         * Extract bytes manually to print correct dotted-decimal.
         */
        RTE_LOG_FW_INFO("ddos: auto-blacklisted %u.%u.%u.%u\n",
                        (src_ip >> 24) & 0xff, (src_ip >> 16) & 0xff,
                        (src_ip >> 8) & 0xff, src_ip & 0xff);
    }
}

/* ─── P3-01: blacklist ───────────────────────────────────────────────────── */

int
blacklist_check(uint32_t src_ip, uint64_t now_cycles)
{
    if (!g_blacklist_hash)
        return 0;

    int32_t pos = rte_hash_lookup(g_blacklist_hash, &src_ip);
    if (pos < 0)
        return 0;   /* not in blacklist */

    if (now_cycles >= g_blacklist_expires[pos]) {
        /* TTL expired: lazily remove */
        rte_hash_del_key(g_blacklist_hash, &src_ip);
        return 0;
    }
    return 1;
}

void
blacklist_add(uint32_t src_ip, uint64_t expire_cycles)
{
    if (!g_blacklist_hash)
        return;

    int32_t pos = rte_hash_add_key(g_blacklist_hash, &src_ip);
    if (pos < 0 || pos >= HASH_ENTRIES) {
        RTE_LOG_FW_WARN("blacklist_add: hash full (pos=%d)\n", pos);
        return;
    }
    g_blacklist_expires[pos] = expire_cycles;
}

void
blacklist_del(uint32_t src_ip)
{
    if (!g_blacklist_hash)
        return;
    rte_hash_del_key(g_blacklist_hash, &src_ip);
}

void
blacklist_list(uint32_t *ips_out, uint64_t *expires_out, uint32_t *n_out)
{
    if (!n_out)
        return;

    if (!g_blacklist_hash || !ips_out || !expires_out) {
        *n_out = 0;
        return;
    }

    uint32_t    count = 0;
    uint64_t    now   = rte_get_tsc_cycles();
    uint32_t    iter  = 0;
    const void *key;
    void       *val;   /* rte_hash_iterate requires non-NULL data ptr */

    while (rte_hash_iterate(g_blacklist_hash, &key, &val, &iter) >= 0) {
        uint32_t ip = *(const uint32_t *)key;

        int32_t pos = rte_hash_lookup(g_blacklist_hash, &ip);
        if (pos < 0)
            continue;

        /* Lazily expire during enumeration */
        if (now >= g_blacklist_expires[pos]) {
            rte_hash_del_key(g_blacklist_hash, &ip);
            continue;
        }

        ips_out[count]     = ip;
        expires_out[count] = g_blacklist_expires[pos];
        count++;
    }

    *n_out = count;
}

/* ─── P3-02: rate limiting ───────────────────────────────────────────────── */

void
meter_init_all(void)
{
    struct fw_rule rules[MAX_RULES];
    uint32_t n = 0;

    memset(g_meter_valid, 0, sizeof(g_meter_valid));

    if (rule_list(rules, &n) != 0)
        return;

    for (uint32_t i = 0; i < n; i++) {
        if (rules[i].action != ACTION_RATE_LIMIT)
            continue;

        uint32_t id = rules[i].id;
        if (id == 0 || id > MAX_RULES) {
            RTE_LOG_FW_WARN("meter_init_all: rule id %u out of range\n", id);
            continue;
        }
        if (rules[i].rate_cir == 0) {
            RTE_LOG_FW_WARN("meter_init_all: rule %u has cir=0, skipping\n", id);
            continue;
        }

        struct rte_meter_srtcm_params params = {
            .cir = rules[i].rate_cir,
            .cbs = rules[i].rate_cbs,
            .ebs = rules[i].rate_cbs,   /* EBS = CBS for simplicity */
        };

        int rc = rte_meter_srtcm_profile_config(&g_meter_profiles[id], &params);
        if (rc != 0) {
            RTE_LOG_FW_ERR("meter: profile_config rule %u failed: %d\n", id, rc);
            continue;
        }

        rc = rte_meter_srtcm_config(&g_meters[id], &g_meter_profiles[id]);
        if (rc != 0) {
            RTE_LOG_FW_ERR("meter: srtcm_config rule %u failed: %d\n", id, rc);
            continue;
        }

        g_meter_valid[id] = 1;
        RTE_LOG_FW_INFO("meter: rule %u ready (cir=%" PRIu64 " B/s, "
                        "cbs=%" PRIu64 " B)\n",
                        id, params.cir, params.cbs);
    }
}

enum rte_color
meter_check(uint32_t rule_id, uint32_t pkt_len, uint64_t now_cycles)
{
    if (rule_id == 0 || rule_id > MAX_RULES || !g_meter_valid[rule_id])
        return RTE_COLOR_GREEN;   /* no meter → accept */

    return rte_meter_srtcm_color_blind_check(
        &g_meters[rule_id],
        &g_meter_profiles[rule_id],
        now_cycles,
        pkt_len);
}
