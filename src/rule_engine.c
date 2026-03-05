#include <string.h>
#include <arpa/inet.h>
#include <errno.h>

#include <rte_acl.h>
#include <rte_malloc.h>
#include <rte_rwlock.h>
#include <rte_lcore.h>

#include "rule_engine.h"
#include "config.h"
#include "firewall.h"
#include "log.h"

/* ─── ACL field definitions ─────────────────────────────────────────────── */

#define FW_NUM_ACL_FIELDS     5
#define FW_NUM_ACL_CATEGORIES 1

enum acl_field_idx {
    ACL_FIELD_SRC_IP   = 0,
    ACL_FIELD_DST_IP   = 1,
    ACL_FIELD_SRC_PORT = 2,
    ACL_FIELD_DST_PORT = 3,
    ACL_FIELD_PROTO    = 4,
};

/*
 * Fields are laid out at fixed offsets within struct pkt_meta:
 *
 *   src_ip   : offset  0, 4 bytes  (MASK)    — network byte order
 *   dst_ip   : offset  4, 4 bytes  (MASK)    — network byte order
 *   src_port : offset  8, 2 bytes  (RANGE)   — host byte order (for correct range cmp)
 *   dst_port : offset 10, 2 bytes  (RANGE)   — host byte order
 *   proto    : offset 12, 1 byte   (BITMASK)
 *
 * input_index groups must be 4-byte aligned and contiguous:
 *   group 0 → src_ip   (bytes  0-3)
 *   group 1 → dst_ip   (bytes  4-7)
 *   group 2 → src_port + dst_port (bytes 8-11)
 *   group 3 → proto    (byte  12; bytes 13-15 are padding)
 */
static const struct rte_acl_field_def fw_acl_defs[FW_NUM_ACL_FIELDS] = {
    [ACL_FIELD_SRC_IP] = {
        .type        = RTE_ACL_FIELD_TYPE_MASK,
        .size        = sizeof(uint32_t),
        .field_index = ACL_FIELD_SRC_IP,
        .input_index = 0,
        .offset      = offsetof(struct pkt_meta, src_ip),
    },
    [ACL_FIELD_DST_IP] = {
        .type        = RTE_ACL_FIELD_TYPE_MASK,
        .size        = sizeof(uint32_t),
        .field_index = ACL_FIELD_DST_IP,
        .input_index = 1,
        .offset      = offsetof(struct pkt_meta, dst_ip),
    },
    [ACL_FIELD_SRC_PORT] = {
        .type        = RTE_ACL_FIELD_TYPE_RANGE,
        .size        = sizeof(uint16_t),
        .field_index = ACL_FIELD_SRC_PORT,
        .input_index = 2,
        .offset      = offsetof(struct pkt_meta, src_port),
    },
    [ACL_FIELD_DST_PORT] = {
        .type        = RTE_ACL_FIELD_TYPE_RANGE,
        .size        = sizeof(uint16_t),
        .field_index = ACL_FIELD_DST_PORT,
        .input_index = 2,
        .offset      = offsetof(struct pkt_meta, dst_port),
    },
    [ACL_FIELD_PROTO] = {
        .type        = RTE_ACL_FIELD_TYPE_BITMASK,
        .size        = sizeof(uint8_t),
        .field_index = ACL_FIELD_PROTO,
        .input_index = 3,
        .offset      = offsetof(struct pkt_meta, proto),
    },
};

/* ACL rule struct with our 5 fields */
RTE_ACL_RULE_DEF(fw_acl_rule, FW_NUM_ACL_FIELDS);

/* ─── Global state ──────────────────────────────────────────────────────── */

static struct fw_rule      g_rules[MAX_RULES];
static uint32_t            g_n_rules;
static uint32_t            g_next_id;        /* monotonically increasing rule ID */
static struct rte_acl_ctx *g_acl_ctx;
static rte_rwlock_t        g_acl_rwlock;
static uint32_t            g_rebuild_count;  /* unique suffix for ACL context name */

/* ─── Internal helpers ──────────────────────────────────────────────────── */

/*
 * Convert a subnet mask stored in network byte order to a prefix length.
 *
 * fw_rule stores masks as NBO uint32_t:
 *   /24 → inet_pton gives bytes [FF FF FF 00] → uint32_t NBO = 0x00FFFFFF on LE
 *   ntohl(0x00FFFFFF) = 0xFFFFFF00 → 8 trailing zeros → prefix = 32 - 8 = 24
 */
static uint8_t
mask_to_prefix(uint32_t mask_nbo)
{
    if (mask_nbo == 0)
        return 0;
    uint32_t h = ntohl(mask_nbo);
    return (uint8_t)(32 - __builtin_ctz(h));
}

/*
 * Populate an rte_acl_rule from a fw_rule.
 * idx: 0-based position in g_rules[]; userdata = idx+1 so 0 means "no match".
 */
static void
fw_rule_to_acl(const struct fw_rule *r, uint32_t idx, struct fw_acl_rule *ar)
{
    memset(ar, 0, sizeof(*ar));

    /*
     * Priority: fw_rule uses "lower number = higher priority".
     * rte_acl uses "higher value wins". Map by inversion.
     */
    ar->data.priority      = RTE_ACL_MAX_PRIORITY - r->priority;
    ar->data.userdata      = idx + 1;   /* 1-based; 0 reserved for "no match" */
    ar->data.category_mask = 0x1;       /* single category */

    /* src_ip — NBO, MASK */
    ar->field[ACL_FIELD_SRC_IP].value.u32     = r->src_ip;
    ar->field[ACL_FIELD_SRC_IP].mask_range.u8 = mask_to_prefix(r->src_mask);

    /* dst_ip — NBO, MASK */
    ar->field[ACL_FIELD_DST_IP].value.u32     = r->dst_ip;
    ar->field[ACL_FIELD_DST_IP].mask_range.u8 = mask_to_prefix(r->dst_mask);

    /* src_port — HBO, RANGE [min, max] */
    ar->field[ACL_FIELD_SRC_PORT].value.u16      = r->src_port_min;
    ar->field[ACL_FIELD_SRC_PORT].mask_range.u16 = r->src_port_max;

    /* dst_port — HBO, RANGE [min, max] */
    ar->field[ACL_FIELD_DST_PORT].value.u16      = r->dst_port_min;
    ar->field[ACL_FIELD_DST_PORT].mask_range.u16 = r->dst_port_max;

    /* proto — BITMASK; proto=0 means any (mask=0 matches all values) */
    if (r->proto == 0) {
        ar->field[ACL_FIELD_PROTO].value.u8      = 0;
        ar->field[ACL_FIELD_PROTO].mask_range.u8 = 0;
    } else {
        ar->field[ACL_FIELD_PROTO].value.u8      = r->proto;
        ar->field[ACL_FIELD_PROTO].mask_range.u8 = 0xFF;
    }
}

/*
 * Create and compile a new rte_acl_ctx from g_rules[0..g_n_rules-1].
 * Returns NULL if g_n_rules == 0 (caller treats this as "apply default policy").
 */
static struct rte_acl_ctx *
build_acl_ctx(void)
{
    if (g_n_rules == 0)
        return NULL;

    char name[RTE_ACL_NAMESIZE];
    snprintf(name, sizeof(name), "fw_acl_%u", g_rebuild_count++);

    struct rte_acl_param prm = {
        .name         = name,
        .socket_id    = rte_socket_id(),
        .rule_size    = RTE_ACL_RULE_SZ(FW_NUM_ACL_FIELDS),
        .max_rule_num = MAX_RULES + 1,
    };

    struct rte_acl_ctx *ctx = rte_acl_create(&prm);
    if (ctx == NULL) {
        RTE_LOG_FW_ERR("rte_acl_create failed\n");
        return NULL;
    }

    /* Allocate temporary ACL rule array */
    struct fw_acl_rule *acl_rules = rte_malloc(NULL,
        sizeof(struct fw_acl_rule) * g_n_rules, 0);
    if (acl_rules == NULL) {
        RTE_LOG_FW_ERR("rte_malloc for ACL rules failed\n");
        rte_acl_free(ctx);
        return NULL;
    }

    for (uint32_t i = 0; i < g_n_rules; i++)
        fw_rule_to_acl(&g_rules[i], i, &acl_rules[i]);

    int rc = rte_acl_add_rules(ctx,
        (const struct rte_acl_rule *)acl_rules, g_n_rules);
    rte_free(acl_rules);

    if (rc != 0) {
        RTE_LOG_FW_ERR("rte_acl_add_rules failed: %d\n", rc);
        rte_acl_free(ctx);
        return NULL;
    }

    struct rte_acl_config cfg = {
        .num_categories = FW_NUM_ACL_CATEGORIES,
        .num_fields     = FW_NUM_ACL_FIELDS,
    };
    memcpy(cfg.defs, fw_acl_defs, sizeof(fw_acl_defs));

    rc = rte_acl_build(ctx, &cfg);
    if (rc != 0) {
        RTE_LOG_FW_ERR("rte_acl_build failed: %d\n", rc);
        rte_acl_free(ctx);
        return NULL;
    }

    return ctx;
}

/* ─── Public API ────────────────────────────────────────────────────────── */

int
rule_engine_init(void)
{
    rte_rwlock_init(&g_acl_rwlock);
    g_acl_ctx       = NULL;
    g_rebuild_count = 0;
    g_next_id       = 0;

    /* Copy rules from global config */
    g_n_rules = g_fw_config.n_rules;
    if (g_n_rules > MAX_RULES)
        g_n_rules = MAX_RULES;

    memcpy(g_rules, g_fw_config.rules, g_n_rules * sizeof(struct fw_rule));

    /* Track max assigned ID so rule_add can issue unique IDs */
    for (uint32_t i = 0; i < g_n_rules; i++) {
        if (g_rules[i].id > g_next_id)
            g_next_id = g_rules[i].id;
    }

    RTE_LOG_FW_INFO("rule_engine: init with %u rules\n", g_n_rules);
    return rule_engine_rebuild();
}

int
rule_engine_rebuild(void)
{
    struct rte_acl_ctx *new_ctx = build_acl_ctx();

    if (new_ctx == NULL && g_n_rules > 0) {
        RTE_LOG_FW_ERR("rule_engine_rebuild: build_acl_ctx failed\n");
        return -1;
    }

    /* Atomically swap the context pointer under write-lock.
     * Forwarding lcores hold the read-lock only during rte_acl_classify
     * (nanoseconds), so write-lock contention is minimal. */
    rte_rwlock_write_lock(&g_acl_rwlock);
    struct rte_acl_ctx *old_ctx = g_acl_ctx;
    g_acl_ctx = new_ctx;
    rte_rwlock_write_unlock(&g_acl_rwlock);

    if (old_ctx != NULL)
        rte_acl_free(old_ctx);

    RTE_LOG_FW_INFO("rule_engine: rebuilt ACL with %u rules\n", g_n_rules);
    return 0;
}

fw_action_t
rule_match(struct pkt_meta *m, uint32_t *rule_id_out)
{
    rte_rwlock_read_lock(&g_acl_rwlock);
    struct rte_acl_ctx *ctx = g_acl_ctx;

    if (ctx == NULL) {
        /* No rules loaded: apply default policy */
        rte_rwlock_read_unlock(&g_acl_rwlock);
        if (rule_id_out)
            *rule_id_out = 0;
        return g_default_policy;
    }

    uint32_t result = 0;
    const uint8_t *data = (const uint8_t *)m;
    rte_acl_classify(ctx, &data, &result, 1, FW_NUM_ACL_CATEGORIES);

    rte_rwlock_read_unlock(&g_acl_rwlock);

    if (result == 0) {
        /* No rule matched: apply default policy */
        if (rule_id_out)
            *rule_id_out = 0;
        return g_default_policy;
    }

    /* result is a 1-based index into g_rules[] */
    uint32_t idx = result - 1;
    if (idx >= g_n_rules) {
        if (rule_id_out)
            *rule_id_out = 0;
        return g_default_policy;
    }

    struct fw_rule *matched = &g_rules[idx];
    __atomic_fetch_add(&matched->pkt_count, 1, __ATOMIC_RELAXED);

    if (rule_id_out)
        *rule_id_out = matched->id;
    return matched->action;
}

int
rule_add(struct fw_rule *r)
{
    if (g_n_rules >= MAX_RULES) {
        RTE_LOG_FW_ERR("rule_add: max rules (%d) reached\n", MAX_RULES);
        return -ENOSPC;
    }

    r->id         = ++g_next_id;
    r->pkt_count  = 0;
    r->byte_count = 0;

    memcpy(&g_rules[g_n_rules++], r, sizeof(*r));

    int rc = rule_engine_rebuild();
    return (rc == 0) ? (int)r->id : rc;
}

int
rule_del(uint32_t id)
{
    for (uint32_t i = 0; i < g_n_rules; i++) {
        if (g_rules[i].id == id) {
            memmove(&g_rules[i], &g_rules[i + 1],
                (g_n_rules - i - 1) * sizeof(struct fw_rule));
            g_n_rules--;
            return rule_engine_rebuild();
        }
    }
    return -ENOENT;
}

int
rule_list(struct fw_rule *out, uint32_t *n_out)
{
    if (out == NULL || n_out == NULL)
        return -EINVAL;

    *n_out = g_n_rules;
    memcpy(out, g_rules, g_n_rules * sizeof(struct fw_rule));
    return 0;
}
