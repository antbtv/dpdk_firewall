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
 * Called from lcore 0 on config reload or rule add/del.
 */
int rule_engine_rebuild(void);

/**
 * rule_match() — classify a single packet.
 * @param m            Packet metadata filled by CLASSIFIER stage.
 * @param rule_id_out  Set to the matching rule ID (0 if default policy).
 * @return             Action to take (ACCEPT / DROP / RATE_LIMIT).
 */
fw_action_t rule_match(struct pkt_meta *m, uint32_t *rule_id_out);

/** Dynamic rule management (called from mgmt handlers). */
int rule_add(struct fw_rule *r);
int rule_del(uint32_t id);
int rule_list(struct fw_rule *out, uint32_t *n_out);

#endif /* FW_RULE_ENGINE_H */
