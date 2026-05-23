#ifndef FW_DDOS_H
#define FW_DDOS_H

#include <stdint.h>
#include <rte_meter.h>

#include "firewall.h"
#include "config.h"

/** Счётчики трафика на исходный IP-адрес (индексированы позицией через rte_hash). */
struct ddos_entry {
    uint64_t syn_count;
    uint64_t udp_count;
    uint64_t icmp_count;
    uint64_t window_start_ns;
};

/* ─── API DDoS / чёрного списка ─────────────────────────────────────────── */

/**
 * ddos_init() — создать хэш-таблицы, вычислить константы времени.
 * Должна вызываться после rte_eal_init() и до любой другой функции ddos_*.
 */
void ddos_init(const struct ddos_config *cfg);

/**
 * ddos_update() — обновить счётчики скользящего окна для src_ip.
 * Если порог превышен, src_ip автоматически добавляется в чёрный список.
 * @param now_ns  Текущее время в наносекундах (перевод из TSC через rte_get_tsc_hz()).
 */
void ddos_update(uint32_t src_ip, struct pkt_meta *m, uint64_t now_ns);

/**
 * blacklist_check() — поиск в чёрном списке за O(1).
 * @param now_cycles  Значение rte_get_tsc_cycles().
 * @return 1 если src_ip в данный момент заблокирован, 0 иначе.
 */
int  blacklist_check(uint32_t src_ip, uint64_t now_cycles);

/** blacklist_add() — заблокировать src_ip до expire_cycles (значение TSC). */
void blacklist_add(uint32_t src_ip, uint64_t expire_cycles);

/** blacklist_del() — снять блокировку с src_ip вручную. */
void blacklist_del(uint32_t src_ip);

/**
 * blacklist_list() — перечислить все заблокированные IP-адреса.
 * @param ips_out      Массив, выделенный вызывающим, для заблокированных IP.
 * @param expires_out  Массив, выделенный вызывающим, для времён истечения TSC.
 * @param n_out        Выходной параметр: количество записанных элементов.
 */
void blacklist_list(uint32_t *ips_out, uint64_t *expires_out, uint32_t *n_out);

/* ─── API ограничения скорости (P3-02) ──────────────────────────────────── */

/**
 * meter_init_all() — инициализировать счётчики srTCM для всех правил ACTION_RATE_LIMIT.
 * Должна вызываться после rule_engine_init() и после каждой перезагрузки конфига.
 */
void meter_init_all(void);

/**
 * meter_check() — выполнить цветовую проверку srTCM для пакета.
 * @param rule_id    ID правила, возвращённый rule_match() (должно быть правило RATE_LIMIT).
 * @param pkt_len    Длина пакета в байтах.
 * @param now_cycles Значение rte_get_tsc_cycles().
 * @return RTE_COLOR_GREEN/YELLOW → пропустить; RTE_COLOR_RED → отбросить.
 */
enum rte_color meter_check(uint32_t rule_id, uint32_t pkt_len, uint64_t now_cycles);

#endif /* FW_DDOS_H */
