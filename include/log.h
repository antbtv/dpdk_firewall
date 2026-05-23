#ifndef FW_LOG_H
#define FW_LOG_H

#include <rte_log.h>

/* Дескриптор зарегистрированного типа лога — определён в src/log.c */
extern uint32_t fw_logtype;

/* ─── Макросы логирования ────────────────────────────────────────────────── */

#define RTE_LOG_FW_ERR(fmt, ...) \
    rte_log(RTE_LOG_ERR,   fw_logtype, "FW ERR  " fmt, ##__VA_ARGS__)

#define RTE_LOG_FW_WARN(fmt, ...) \
    rte_log(RTE_LOG_WARNING, fw_logtype, "FW WARN " fmt, ##__VA_ARGS__)

#define RTE_LOG_FW_INFO(fmt, ...) \
    rte_log(RTE_LOG_INFO,  fw_logtype, "FW INFO " fmt, ##__VA_ARGS__)

/* Отладочный макрос включает имя файла и номер строки для упрощения трассировки */
#define RTE_LOG_FW_DEBUG(fmt, ...) \
    rte_log(RTE_LOG_DEBUG, fw_logtype, \
            "FW DBG  [%s:%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__)

/* ─── Инициализация типа лога ───────────────────────────────────────────── */

/**
 * Зарегистрировать тип лога межсетевого экрана в DPDK.
 * Должна вызываться один раз до использования любого макроса RTE_LOG_FW_*.
 * Возвращает 0 при успехе, отрицательное значение при ошибке.
 */
int fw_log_init(void);

#endif /* FW_LOG_H */
