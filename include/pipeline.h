#ifndef FW_PIPELINE_H
#define FW_PIPELINE_H

#include <stdint.h>

/** Максимальное количество пакетов, обрабатываемых за один burst. */
#define MAX_BURST 8

/** Аргументы, передаваемые pipeline_lcore_main() через rte_eal_remote_launch(). */
struct pipeline_args {
    uint16_t port_in;   /* порт RX: 0 = WAN (lcore 1), 1 = LAN (lcore 2) */
    uint16_t port_out;  /* порт TX: 1 = LAN (lcore 1), 0 = WAN (lcore 2) */
};

/**
 * pipeline_lcore_main() — цикл пересылки пакетов на каждом lcore.
 *
 * Фаза 1: минимальная пересылка RX→TX (без фильтрации).
 * Фаза 2: добавляет CLASSIFIER + RULE ENGINE.
 * Фаза 3: добавляет BLACKLIST CHECK, RATE LIMIT, DDOS UPDATE.
 *
 * @param arg  Указатель на struct pipeline_args.
 * @return     Всегда 0 (код завершения lcore).
 */
int pipeline_lcore_main(void *arg);

#endif /* FW_PIPELINE_H */
