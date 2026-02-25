#ifndef FW_CONFIG_H
#define FW_CONFIG_H

#include <stdint.h>
#include "firewall.h"

/* ─── DDoS protection sub-configuration ────────────────────────────────── */

struct ddos_config {
    int      enabled;
    uint64_t window_ns;           /* detection window (ns) */
    uint64_t syn_threshold;       /* SYN packets per window */
    uint64_t udp_threshold;
    uint64_t icmp_threshold;
    uint64_t block_duration_ns;   /* how long to keep IP in blacklist */
};

/* ─── Full firewall configuration ───────────────────────────────────────── */

struct fw_config {
    char             config_path[256];  /* absolute path, kept for hot-reload */
    char             wan_pci_addr[32];  /* e.g. "0001:01:00.0" */
    char             lan_pci_addr[32];  /* e.g. "0002:01:00.0"; "builtin" resolved on load */
    fw_action_t      default_policy;
    uint32_t         n_rules;
    struct fw_rule   rules[MAX_RULES];
    struct ddos_config ddos_cfg;
    int              log_level;         /* RTE_LOG_* value */
    char             log_file[256];
};

/* Global configuration instance — defined in config.c */
extern struct fw_config g_fw_config;

/* ─── API ───────────────────────────────────────────────────────────────── */

/**
 * config_load() — parse rules.json, validate, fill g_fw_config.
 * Must be called before any other config_* function.
 * @return 0 on success, -1 on error.
 */
int config_load(const char *path);

/**
 * config_reload() — re-read the same file and rebuild the rule engine.
 * Safe to call from lcore 0 only.
 * @return 0 on success, -1 on error.
 */
int config_reload(void);

/**
 * config_get() — read-only access to the current configuration.
 */
const struct fw_config *config_get(void);

#endif /* FW_CONFIG_H */
