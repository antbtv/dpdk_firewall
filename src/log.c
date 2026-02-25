#include "log.h"

/* Global log type handle used by all RTE_LOG_FW_* macros */
uint32_t fw_logtype;

int
fw_log_init(void)
{
    int ret = rte_log_register("pmd.net.fw");
    if (ret < 0)
        return ret;

    fw_logtype = (uint32_t)ret;
    rte_log_set_level(fw_logtype, RTE_LOG_INFO);
    return 0;
}
