#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <jansson.h>
#include <rte_log.h>

#include "config.h"
#include "firewall.h"
#include "log.h"

/*
 * Forward declaration: sync rule_engine's internal copy from g_fw_config,
 * then rebuild the ACL context.  Defined in rule_engine.c.
 * Using a forward declaration (not a header include) to avoid circular deps.
 */
extern int rule_engine_reload_from_config(void);

/* ─── Global configuration instance ────────────────────────────────────── */

struct fw_config g_fw_config;

/* ─── Parsing helpers ───────────────────────────────────────────────────── */

/**
 * Parse "192.168.0.0/24" → ip (network byte order), mask (network byte order).
 * Wildcard (prefix 0 or absent): mask = 0.
 */
static int
parse_cidr(const char *s, uint32_t *ip_out, uint32_t *mask_out)
{
    char buf[32];
    int  prefix = 32;

    snprintf(buf, sizeof(buf), "%s", s);
    char *slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        prefix = atoi(slash + 1);
        if (prefix < 0 || prefix > 32)
            return -1;
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, buf, &addr) != 1)
        return -1;

    *ip_out = ntohl(addr.s_addr);   /* host byte order — rte_acl MASK requires HBo */

    if (prefix == 0)
        *mask_out = 0;
    else
        *mask_out = ~((1u << (32 - prefix)) - 1);  /* HBo mask: 0xFFFFFF00 for /24 */

    return 0;
}

/**
 * Parse "80" → min=max=80, "1024-65535" → min=1024, max=65535.
 * Returns -1 if min > max.
 */
static int
parse_port_range(const char *s, uint16_t *min_out, uint16_t *max_out)
{
    char buf[16];
    snprintf(buf, sizeof(buf), "%s", s);

    char *dash = strchr(buf, '-');
    if (dash) {
        *dash    = '\0';
        *min_out = (uint16_t)atoi(buf);
        *max_out = (uint16_t)atoi(dash + 1);
    } else {
        *min_out = *max_out = (uint16_t)atoi(buf);
    }
    if (*min_out > *max_out) {
        RTE_LOG_FW_ERR("Invalid port range: min %u > max %u\n",
                       *min_out, *max_out);
        return -1;
    }
    return 0;
}

/** "tcp"→6, "udp"→17, "icmp"→1, anything else → 0 (any) */
static uint8_t
parse_proto(const char *s)
{
    if (strcasecmp(s, "tcp")  == 0) return IPPROTO_TCP;
    if (strcasecmp(s, "udp")  == 0) return IPPROTO_UDP;
    if (strcasecmp(s, "icmp") == 0) return IPPROTO_ICMP;
    return 0;
}

/**
 * "SYN,ACK" → TCP_FLAG_SYN | TCP_FLAG_ACK stored in *flags_out.
 * Returns 0 on success, -1 if an unknown token is encountered.
 */
static int
parse_tcp_flags(const char *s, uint8_t *flags_out)
{
    uint8_t flags = 0;
    char    buf[64];
    snprintf(buf, sizeof(buf), "%s", s);

    char *tok = strtok(buf, ", ");
    while (tok) {
        if      (strcasecmp(tok, "FIN") == 0) flags |= TCP_FLAG_FIN;
        else if (strcasecmp(tok, "SYN") == 0) flags |= TCP_FLAG_SYN;
        else if (strcasecmp(tok, "RST") == 0) flags |= TCP_FLAG_RST;
        else if (strcasecmp(tok, "PSH") == 0) flags |= TCP_FLAG_PSH;
        else if (strcasecmp(tok, "ACK") == 0) flags |= TCP_FLAG_ACK;
        else if (strcasecmp(tok, "URG") == 0) flags |= TCP_FLAG_URG;
        else return -1;  /* unknown flag token → reject */
        tok = strtok(NULL, ", ");
    }
    *flags_out = flags;
    return 0;
}

/** "accept"→0, "drop"→1, "rate_limit"→2; returns -1 on unknown */
static int
parse_action(const char *s, fw_action_t *out)
{
    if (strcasecmp(s, "accept")     == 0) { *out = ACTION_ACCEPT;     return 0; }
    if (strcasecmp(s, "drop")       == 0) { *out = ACTION_DROP;       return 0; }
    if (strcasecmp(s, "rate_limit") == 0) { *out = ACTION_RATE_LIMIT; return 0; }
    return -1;
}

/** "debug"→8, "info"→7, "warning"/"warn"→5, "error"/"err"→4; default info */
static int
parse_log_level(const char *s)
{
    if (strcasecmp(s, "debug")   == 0) return RTE_LOG_DEBUG;
    if (strcasecmp(s, "info")    == 0) return RTE_LOG_INFO;
    if (strcasecmp(s, "notice")  == 0) return RTE_LOG_NOTICE;
    if (strcasecmp(s, "warning") == 0 ||
        strcasecmp(s, "warn")    == 0) return RTE_LOG_WARNING;
    if (strcasecmp(s, "error")   == 0 ||
        strcasecmp(s, "err")     == 0) return RTE_LOG_ERR;
    return RTE_LOG_INFO;
}

/**
 * Parse a single rule object from JSON.
 * Returns 0 on success, -1 on error.
 */
static int
parse_rule(json_t *obj, struct fw_rule *r)
{
    memset(r, 0, sizeof(*r));

    /* Required: action */
    json_t *jact = json_object_get(obj, "action");
    if (!jact || !json_is_string(jact)) {
        RTE_LOG_FW_ERR("Rule missing 'action' field\n");
        return -1;
    }
    if (parse_action(json_string_value(jact), &r->action) != 0) {
        RTE_LOG_FW_ERR("Unknown action: %s\n", json_string_value(jact));
        return -1;
    }

    /* Optional: id, priority */
    json_t *j = json_object_get(obj, "id");
    if (j && json_is_integer(j)) r->id = (uint32_t)json_integer_value(j);

    j = json_object_get(obj, "priority");
    r->priority = (j && json_is_integer(j)) ? (uint32_t)json_integer_value(j) : 100;

    /* Optional: comment */
    j = json_object_get(obj, "comment");
    if (j && json_is_string(j))
        snprintf(r->comment, sizeof(r->comment), "%s", json_string_value(j));

    /* Optional: proto */
    j = json_object_get(obj, "proto");
    if (j && json_is_string(j))
        r->proto = parse_proto(json_string_value(j));

    /* Optional: src_ip / dst_ip (CIDR) */
    j = json_object_get(obj, "src_ip");
    if (j && json_is_string(j)) {
        if (parse_cidr(json_string_value(j), &r->src_ip, &r->src_mask) != 0) {
            RTE_LOG_FW_ERR("Bad src_ip: %s\n", json_string_value(j));
            return -1;
        }
    }

    j = json_object_get(obj, "dst_ip");
    if (j && json_is_string(j)) {
        if (parse_cidr(json_string_value(j), &r->dst_ip, &r->dst_mask) != 0) {
            RTE_LOG_FW_ERR("Bad dst_ip: %s\n", json_string_value(j));
            return -1;
        }
    }

    /* Optional: src_port / dst_port (number or range string) */
    j = json_object_get(obj, "src_port");
    if (j && json_is_string(j)) {
        if (parse_port_range(json_string_value(j),
                             &r->src_port_min, &r->src_port_max) != 0) {
            RTE_LOG_FW_ERR("Bad src_port range: %s\n", json_string_value(j));
            return -1;
        }
    } else {
        r->src_port_min = 0;
        r->src_port_max = 65535;
    }

    j = json_object_get(obj, "dst_port");
    if (j && json_is_string(j)) {
        if (parse_port_range(json_string_value(j),
                             &r->dst_port_min, &r->dst_port_max) != 0) {
            RTE_LOG_FW_ERR("Bad dst_port range: %s\n", json_string_value(j));
            return -1;
        }
    } else {
        r->dst_port_min = 0;
        r->dst_port_max = 65535;
    }

    /* Optional: tcp_flags (mask = all matched bits, val = expected bits) */
    j = json_object_get(obj, "tcp_flags");
    if (j && json_is_string(j)) {
        uint8_t flags;
        if (parse_tcp_flags(json_string_value(j), &flags) != 0) {
            RTE_LOG_FW_ERR("Unknown tcp_flags value: %s\n",
                           json_string_value(j));
            return -1;
        }
        r->tcp_flags_val  = flags;
        r->tcp_flags_mask = flags;  /* exact match on specified flags */
    }

    /* Optional: icmp_type / icmp_code (255 = any) */
    j = json_object_get(obj, "icmp_type");
    r->icmp_type = (j && json_is_integer(j)) ? (uint8_t)json_integer_value(j) : 255;

    j = json_object_get(obj, "icmp_code");
    r->icmp_code = (j && json_is_integer(j)) ? (uint8_t)json_integer_value(j) : 255;

    /* Optional: rate (for ACTION_RATE_LIMIT) */
    j = json_object_get(obj, "rate");
    if (j && json_is_object(j)) {
        json_t *cir = json_object_get(j, "cir_kbps");
        json_t *cbs = json_object_get(j, "cbs_bytes");
        if (cir && json_is_integer(cir))
            r->rate_cir = (uint64_t)json_integer_value(cir) * 1000 / 8;
        if (cbs && json_is_integer(cbs))
            r->rate_cbs = (uint64_t)json_integer_value(cbs);
    }

    /* Validate: RATE_LIMIT rule must have rate_cir > 0 (avoid divide-by-zero in meter) */
    if (r->action == ACTION_RATE_LIMIT && r->rate_cir == 0) {
        RTE_LOG_FW_ERR("RATE_LIMIT rule requires rate.cir_kbps > 0\n");
        return -1;
    }

    /* Validate: id=0 is reserved for "no match" in rte_acl userdata */
    if (r->id == 0) {
        static uint32_t s_auto_id = 0;
        r->id = ++s_auto_id;
    }

    return 0;
}

/* ─── Internal load ─────────────────────────────────────────────────────── */

static int
do_load(const char *path, struct fw_config *cfg)
{
    /* All declarations hoisted to avoid -Wjump-misses-init with goto. */
    json_error_t  jerr;
    json_t       *root;
    json_t       *jmode, *jports, *jwan, *jlan, *jpol;
    json_t       *jddos, *jlog, *jrules, *j, *jrule;
    size_t        idx;
    uint64_t      window_ms, block_s;
    int           rc = -1;

    root = json_load_file(path, 0, &jerr);
    if (!root) {
        RTE_LOG_FW_ERR("Cannot parse %s: %s (line %d)\n",
                       path, jerr.text, jerr.line);
        return -1;
    }

    /* Validate required field: mode */
    jmode = json_object_get(root, "mode");
    if (!jmode || !json_is_string(jmode)) {
        RTE_LOG_FW_ERR("Config missing required field 'mode'\n");
        goto out;
    }
    if (strcasecmp(json_string_value(jmode), "bridge") != 0) {
        RTE_LOG_FW_ERR("Unsupported mode '%s' (only 'bridge' is supported)\n",
                       json_string_value(jmode));
        goto out;
    }

    /* Validate required field: ports.wan */
    jports = json_object_get(root, "ports");
    if (!jports || !json_is_object(jports)) {
        RTE_LOG_FW_ERR("Config missing required 'ports' section\n");
        goto out;
    }
    jwan = json_object_get(jports, "wan");
    if (!jwan || !json_is_string(jwan)) {
        RTE_LOG_FW_ERR("Config missing required field 'ports.wan'\n");
        goto out;
    }
    snprintf(cfg->wan_pci_addr, sizeof(cfg->wan_pci_addr),
             "%s", json_string_value(jwan));

    /* Optional: ports.lan — "builtin" resolved to known PCI address */
    jlan = json_object_get(jports, "lan");
    if (jlan && json_is_string(jlan)) {
        if (strcasecmp(json_string_value(jlan), "builtin") == 0)
            snprintf(cfg->lan_pci_addr, sizeof(cfg->lan_pci_addr), "0002:01:00.0");
        else
            snprintf(cfg->lan_pci_addr, sizeof(cfg->lan_pci_addr),
                     "%s", json_string_value(jlan));
    }

    /* default_policy */
    jpol = json_object_get(root, "default_policy");
    if (jpol && json_is_string(jpol)) {
        if (parse_action(json_string_value(jpol), &cfg->default_policy) != 0) {
            RTE_LOG_FW_ERR("Unknown default_policy: %s\n",
                           json_string_value(jpol));
            goto out;
        }
    } else {
        cfg->default_policy = ACTION_DROP;  /* safe default */
    }

    /* DDoS configuration */
    jddos = json_object_get(root, "ddos");
    if (jddos && json_is_object(jddos)) {
        j = json_object_get(jddos, "enabled");
        cfg->ddos_cfg.enabled = (j && json_is_boolean(j)) ? json_boolean_value(j) : 0;

        j = json_object_get(jddos, "window_ms");
        window_ms = (j && json_is_integer(j)) ?
                    (uint64_t)json_integer_value(j) : 100;
        cfg->ddos_cfg.window_ns = window_ms * 1000000ULL;

        j = json_object_get(jddos, "syn_pps_threshold");
        cfg->ddos_cfg.syn_threshold = (j && json_is_integer(j)) ?
                                      (uint64_t)json_integer_value(j) : 10000;

        j = json_object_get(jddos, "udp_pps_threshold");
        cfg->ddos_cfg.udp_threshold = (j && json_is_integer(j)) ?
                                      (uint64_t)json_integer_value(j) : 50000;

        j = json_object_get(jddos, "icmp_pps_threshold");
        cfg->ddos_cfg.icmp_threshold = (j && json_is_integer(j)) ?
                                       (uint64_t)json_integer_value(j) : 5000;

        j = json_object_get(jddos, "block_duration_s");
        block_s = (j && json_is_integer(j)) ?
                  (uint64_t)json_integer_value(j) : 300;
        cfg->ddos_cfg.block_duration_ns = block_s * 1000000000ULL;
    }

    /* Logging configuration */
    jlog = json_object_get(root, "logging");
    if (jlog && json_is_object(jlog)) {
        j = json_object_get(jlog, "level");
        cfg->log_level = (j && json_is_string(j)) ?
                         parse_log_level(json_string_value(j)) : RTE_LOG_INFO;

        j = json_object_get(jlog, "file");
        if (j && json_is_string(j))
            snprintf(cfg->log_file, sizeof(cfg->log_file),
                     "%s", json_string_value(j));
    } else {
        cfg->log_level = RTE_LOG_INFO;
    }

    /* Rules array */
    jrules = json_object_get(root, "rules");
    cfg->n_rules = 0;
    if (jrules && json_is_array(jrules)) {
        json_array_foreach(jrules, idx, jrule) {
            if (cfg->n_rules >= MAX_RULES) {
                RTE_LOG_FW_WARN("Reached MAX_RULES=%u, ignoring remaining rules\n",
                                MAX_RULES);
                break;
            }
            if (parse_rule(jrule, &cfg->rules[cfg->n_rules]) != 0) {
                RTE_LOG_FW_ERR("Error parsing rule at index %zu\n", idx);
                goto out;
            }
            cfg->n_rules++;
        }
    }

    snprintf(cfg->config_path, sizeof(cfg->config_path), "%s", path);
    rc = 0;

out:
    json_decref(root);
    return rc;
}

/* ─── Public API ────────────────────────────────────────────────────────── */

int
config_load(const char *path)
{
    RTE_LOG_FW_INFO("Loading config from %s\n", path);
    int rc = do_load(path, &g_fw_config);
    if (rc == 0) {
        /* Sync global default policy */
        g_default_policy = g_fw_config.default_policy;
        RTE_LOG_FW_INFO("Loaded %u rule(s), default_policy=%s\n",
                        g_fw_config.n_rules,
                        g_fw_config.default_policy == ACTION_DROP ? "drop" : "accept");
    }
    return rc;
}

int
config_reload(void)
{
    RTE_LOG_FW_INFO("Hot-reloading config from %s\n", g_fw_config.config_path);

    /*
     * static to avoid a ~197 KB stack allocation (1024 rules × ~192 B each).
     * config_reload() is only called from lcore 0, so no concurrent access.
     */
    static struct fw_config new_cfg;
    if (do_load(g_fw_config.config_path, &new_cfg) != 0) {
        RTE_LOG_FW_ERR("Config reload failed — keeping current configuration\n");
        return -1;
    }

    /* Swap atomically (single write on lcore 0, no concurrent readers for config struct) */
    g_fw_config = new_cfg;
    g_default_policy = g_fw_config.default_policy;

    /* Sync rule_engine's internal g_rules[] from the new config and rebuild ACL */
    int rc = rule_engine_reload_from_config();
    if (rc != 0)
        RTE_LOG_FW_WARN("rule_engine_rebuild() returned %d after reload\n", rc);

    RTE_LOG_FW_INFO("Config reloaded: %u rule(s)\n", g_fw_config.n_rules);
    return 0;
}

const struct fw_config *
config_get(void)
{
    return &g_fw_config;
}
