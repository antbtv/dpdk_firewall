#ifndef FW_LOG_H
#define FW_LOG_H

#include <rte_log.h>

/* Registered log type handle — defined in src/log.c */
extern uint32_t fw_logtype;

/* ─── Logging macros ────────────────────────────────────────────────────── */

#define RTE_LOG_FW_ERR(fmt, ...) \
    rte_log(RTE_LOG_ERR,   fw_logtype, "FW ERR  " fmt, ##__VA_ARGS__)

#define RTE_LOG_FW_WARN(fmt, ...) \
    rte_log(RTE_LOG_WARNING, fw_logtype, "FW WARN " fmt, ##__VA_ARGS__)

#define RTE_LOG_FW_INFO(fmt, ...) \
    rte_log(RTE_LOG_INFO,  fw_logtype, "FW INFO " fmt, ##__VA_ARGS__)

/* Debug macro includes file and line for easier tracing */
#define RTE_LOG_FW_DEBUG(fmt, ...) \
    rte_log(RTE_LOG_DEBUG, fw_logtype, \
            "FW DBG  [%s:%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__)

/* ─── Log type initialisation ───────────────────────────────────────────── */

/**
 * Register the firewall log type with DPDK.
 * Must be called once before any RTE_LOG_FW_* macro is used.
 * Returns 0 on success, negative on error.
 */
int fw_log_init(void);

#endif /* FW_LOG_H */
