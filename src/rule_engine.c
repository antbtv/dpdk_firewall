#include "rule_engine.h"
#include "config.h"
#include "firewall.h"
#include "log.h"

/*
 * TODO: P2-01 — full implementation using rte_acl_ctx.
 *
 * Phase 1 stubs: allow everything to compile and link.
 * All packets will be ACCEPTED until rule engine is implemented.
 */

int
rule_engine_init(void)
{
    RTE_LOG_FW_INFO("rule_engine: stub (P2-01 not yet implemented)\n");
    return 0;
}

int
rule_engine_rebuild(void)
{
    return 0;
}

fw_action_t
rule_match(struct pkt_meta *m, uint32_t *rule_id_out)
{
    (void)m;
    if (rule_id_out)
        *rule_id_out = 0;
    /*
     * Stub: return ACTION_ACCEPT so test binaries link without main.c.
     * Full implementation (P2-01) will apply g_default_policy via ACL.
     */
    return ACTION_ACCEPT;
}

int
rule_add(struct fw_rule *r)
{
    (void)r;
    return -1;
}

int
rule_del(uint32_t id)
{
    (void)id;
    return -1;
}

int
rule_list(struct fw_rule *out, uint32_t *n_out)
{
    (void)out;
    if (n_out)
        *n_out = 0;
    return 0;
}
