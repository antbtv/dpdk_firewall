#ifndef FW_RULE_ENGINE_H
#define FW_RULE_ENGINE_H

#include <stdint.h>
#include "firewall.h"

/**
 * rule_engine_init() — build the initial ACL context from g_fw_config.rules.
 * Called once after config_load().
 */
int rule_engine_init(void);

/**
 * rule_engine_rebuild() — rebuild the ACL context under write-lock.
 * Uses the current g_rules[] (rule_engine's in-memory copy).
 * Called after dynamic rule changes (rule_add / rule_del / rule_flush).
 */
int rule_engine_rebuild(void);

/**
 * rule_engine_reload_from_config() — sync g_rules from g_fw_config, then rebuild.
 * Called after config_reload() so the rule engine picks up the new JSON config.
 * NOT called after dynamic rule changes (those go directly via rule_add/del/flush).
 */
int rule_engine_reload_from_config(void);

/**
 * rule_match() — classify a single packet.
 * @param m            Packet metadata filled by CLASSIFIER stage.
 * @param rule_id_out  Set to the matching rule ID (0 if default policy).
 * @param pkt_len      Packet length in bytes (used to update byte_count counter).
 * @return             Action to take (ACCEPT / DROP / RATE_LIMIT).
 */
fw_action_t rule_match(struct pkt_meta *m, uint32_t *rule_id_out, uint32_t pkt_len);

/** Dynamic rule management (called from mgmt handlers). */
int rule_add(struct fw_rule *r);
int rule_del(uint32_t id);
int rule_flush(void);
int rule_list(struct fw_rule *out, uint32_t *n_out);

#endif /* FW_RULE_ENGINE_H */
