#ifndef FW_MGMT_H
#define FW_MGMT_H

#include <signal.h>

/**
 * g_sighup_flag — устанавливается обработчиком SIGHUP в main.c; опрашивается mgmt_server_run().
 * Определён в main.c, объявлен здесь для доступа из mgmt.c.
 */
extern volatile sig_atomic_t g_sighup_flag;

/**
 * mgmt_server_run() — блокирующий цикл плоскости управления на lcore 0.
 * Обрабатывает управляющий UNIX-сокет, периодический дамп статистики
 * и горячую перезагрузку конфига по сигналу SIGHUP.
 * Возвращает управление когда устанавливается g_force_quit.
 */
void mgmt_server_run(void);

#endif /* FW_MGMT_H */
