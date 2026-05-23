#ifndef FW_RULE_ENGINE_H
#define FW_RULE_ENGINE_H

#include <stdint.h>
#include "firewall.h"

/**
 * rule_engine_init() — построить начальный ACL-контекст из g_fw_config.rules.
 * Вызывается один раз после config_load().
 */
int rule_engine_init(void);

/**
 * rule_engine_rebuild() — пересобрать ACL-контекст под блокировкой записи.
 * Использует текущий g_rules[] (копию движка правил в памяти).
 * Вызывается после динамических изменений правил (rule_add / rule_del / rule_flush).
 */
int rule_engine_rebuild(void);

/**
 * rule_engine_reload_from_config() — синхронизировать g_rules из g_fw_config, затем пересобрать.
 * Вызывается после config_reload(), чтобы движок правил принял новый JSON-конфиг.
 * НЕ вызывается после динамических изменений правил (те идут напрямую через rule_add/del/flush).
 */
int rule_engine_reload_from_config(void);

/**
 * rule_match() — классифицировать один пакет.
 * @param m            Метаданные пакета, заполненные на этапе CLASSIFIER.
 * @param rule_id_out  Устанавливается в ID совпавшего правила (0 если применяется политика по умолчанию).
 * @param pkt_len      Длина пакета в байтах (используется для обновления счётчика byte_count).
 * @return             Действие (ACCEPT / DROP / RATE_LIMIT).
 */
fw_action_t rule_match(struct pkt_meta *m, uint32_t *rule_id_out, uint32_t pkt_len);

/** Динамическое управление правилами (вызывается из обработчиков mgmt). */
int rule_add(struct fw_rule *r);
int rule_del(uint32_t id);
int rule_flush(void);
int rule_list(struct fw_rule *out, uint32_t *n_out);

#endif /* FW_RULE_ENGINE_H */
