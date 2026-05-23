#ifndef FW_CONFIG_H
#define FW_CONFIG_H

#include <stdint.h>
#include "firewall.h"

/* ─── Подконфигурация защиты от DDoS ───────────────────────────────────── */

struct ddos_config {
    int      enabled;
    uint64_t window_ns;           /* окно обнаружения (нс) */
    uint64_t syn_threshold;       /* SYN-пакетов за окно */
    uint64_t udp_threshold;
    uint64_t icmp_threshold;
    uint64_t block_duration_ns;   /* как долго держать IP в чёрном списке */
};

/* ─── Полная конфигурация межсетевого экрана ─────────────────────────────── */

struct fw_config {
    char             config_path[256];  /* абсолютный путь, сохраняется для горячей перезагрузки */
    char             wan_pci_addr[32];  /* напр. "0001:01:00.0" */
    char             lan_pci_addr[32];  /* напр. "0002:01:00.0"; "builtin" разрешается при загрузке */
    fw_action_t      default_policy;
    uint32_t         n_rules;
    struct fw_rule   rules[MAX_RULES];
    struct ddos_config ddos_cfg;
    int              log_level;         /* значение RTE_LOG_* */
    char             log_file[256];
};

/* Глобальный экземпляр конфигурации — определён в config.c */
extern struct fw_config g_fw_config;

/* ─── API ───────────────────────────────────────────────────────────────── */

/**
 * config_load() — разобрать rules.json, проверить и заполнить g_fw_config.
 * Должна быть вызвана до любой другой функции config_*.
 * @return 0 при успехе, -1 при ошибке.
 */
int config_load(const char *path);

/**
 * config_reload() — повторно прочитать тот же файл и пересобрать движок правил.
 * Безопасно вызывать только из lcore 0.
 * @return 0 при успехе, -1 при ошибке.
 */
int config_reload(void);

/**
 * config_get() — доступ только для чтения к текущей конфигурации.
 */
const struct fw_config *config_get(void);

#endif /* FW_CONFIG_H */
