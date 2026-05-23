#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <netinet/in.h>

#include <rte_eal.h>
#include <rte_cycles.h>

#include "firewall.h"
#include "rule_engine.h"
#include "ddos.h"
#include "log.h"

/* ─── Заглушки глобальных переменных (обычно определяются в main.c) ─────── */

volatile fw_action_t g_default_policy = ACTION_DROP;
volatile int         g_force_quit     = 0;

/*
 * meter_init_all() в ddos.c вызывает rule_list().
 * test_ddos не компонуется с rule_engine.c — предоставить заглушку, возвращающую
 * пустой набор правил, чтобы meter_init_all() был no-op в этих тестах.
 */
int
rule_list(struct fw_rule *rules_out, uint32_t *n_out)
{
    (void)rules_out;
    if (n_out) *n_out = 0;
    return 0;
}

/* ─── Конфигурация DDoS, используемая во всех тестах ────────────────────── */

/*
 * Низкие пороги делают тесты быстрыми (не нужно отправлять миллионы пакетов).
 * window_ns большой (1 с), чтобы предотвратить случайное истечение окна во время теста.
 */
static const struct ddos_config test_cfg = {
    .enabled           = 1,
    .window_ns         = 1000000000ULL,          /* 1 секунда */
    .syn_threshold     = 100,
    .udp_threshold     = 1000,
    .icmp_threshold    = 500,
    .block_duration_ns = 300ULL * 1000000000ULL, /* 300 с */
};

/* ─── Вспомогательные функции ────────────────────────────────────────────── */

static struct pkt_meta
make_syn(uint32_t src_ip)
{
    struct pkt_meta m;
    memset(&m, 0, sizeof(m));
    m.src_ip    = src_ip;
    m.proto     = IPPROTO_TCP;
    m.tcp_flags = TCP_FLAG_SYN;
    m.is_ipv4   = 1;
    return m;
}

static struct pkt_meta
make_udp(uint32_t src_ip)
{
    struct pkt_meta m;
    memset(&m, 0, sizeof(m));
    m.src_ip  = src_ip;
    m.proto   = IPPROTO_UDP;
    m.is_ipv4 = 1;
    return m;
}

/* ─── Тест 1 ─────────────────────────────────────────────────────────────── */
/*
 * SYN-флуд: ровно syn_threshold SYN-пакетов НЕ должны вызывать занесение в чёрный список;
 * (threshold+1)-й пакет должен автоматически заблокировать исходный IP.
 *
 * ddos_update() блокирует при ++syn_count > syn_threshold, то есть:
 *   - после 100 SYN: syn_count=100, 100>100 — ЛОЖЬ → не заблокирован
 *   - после 101-го SYN: syn_count=101, 101>100 — ИСТИНА → заблокирован
 */
static void
test_syn_flood(void)
{
    uint32_t ip = 0x01020304u;   /* 1.2.3.4, уникальный для каждого теста */
    struct pkt_meta m = make_syn(ip);

    for (uint64_t i = 0; i < test_cfg.syn_threshold; i++)
        ddos_update(ip, &m, 0);
    assert(blacklist_check(ip, rte_get_tsc_cycles()) == 0);

    ddos_update(ip, &m, 0);     /* (threshold+1)-й SYN */
    assert(blacklist_check(ip, rte_get_tsc_cycles()) == 1);

    printf("  test 1 PASS: %llu SYNs → blacklisted\n",
           (unsigned long long)test_cfg.syn_threshold + 1);
}

/* ─── Тест 2 ─────────────────────────────────────────────────────────────── */
/*
 * Сброс окна: отправить syn_threshold/2 SYN-пакетов в окне A (now_ns=0),
 * затем syn_threshold/2 SYN-пакетов в окне B (now_ns = window_ns+1).
 * Счётчик должен сбрасываться на границе окна, поэтому IP никогда не блокируется.
 */
static void
test_window_reset(void)
{
    uint32_t ip = 0x02020304u;   /* 2.2.3.4 */
    struct pkt_meta m = make_syn(ip);
    uint64_t half = test_cfg.syn_threshold / 2;

    /* Фаза A — окно [0, window_ns) */
    for (uint64_t i = 0; i < half; i++)
        ddos_update(ip, &m, 0);
    assert(blacklist_check(ip, rte_get_tsc_cycles()) == 0);

    /* Фаза B — начинается новое окно; счётчики сбрасываются в 0 */
    uint64_t t_new = test_cfg.window_ns + 1;
    for (uint64_t i = 0; i < half; i++)
        ddos_update(ip, &m, t_new);

    /* В новом окне накоплена только половина порога → не заблокирован */
    assert(blacklist_check(ip, rte_get_tsc_cycles()) == 0);

    printf("  test 2 PASS: window reset at %llu ns, counters cleared\n",
           (unsigned long long)test_cfg.window_ns);
}

/* ─── Тест 3 ─────────────────────────────────────────────────────────────── */
/*
 * Истёкший TTL: blacklist_add() с expire_cycles уже в прошлом.
 * blacklist_check() должен выполнить ленивое удаление и вернуть 0.
 */
static void
test_expired_ttl(void)
{
    uint32_t ip = 0x03020304u;   /* 3.2.3.4 */

    /*
     * expire_cycles = rte_get_tsc_cycles() - 1 гарантированно находится в прошлом
     * на момент последующего вызова blacklist_check().
     */
    uint64_t past = rte_get_tsc_cycles() - 1;
    blacklist_add(ip, past);

    assert(blacklist_check(ip, rte_get_tsc_cycles()) == 0);

    printf("  test 3 PASS: expired TTL → lazy removal, not blocked\n");
}

/* ─── Тест 4 ─────────────────────────────────────────────────────────────── */
/*
 * blacklist_del() — вручную удалить активную запись из чёрного списка.
 */
static void
test_blacklist_del(void)
{
    uint32_t ip = 0x04020304u;   /* 4.2.3.4 */

    blacklist_add(ip, UINT64_MAX);   /* истечение в далёком будущем */
    assert(blacklist_check(ip, rte_get_tsc_cycles()) == 1);

    blacklist_del(ip);
    assert(blacklist_check(ip, rte_get_tsc_cycles()) == 0);

    printf("  test 4 PASS: blacklist_del() removes active entry\n");
}

/* ─── Тест 5 ─────────────────────────────────────────────────────────────── */
/*
 * UDP-флуд: аналогично тесту 1, но для счётчика UDP.
 * (threshold+1) UDP-пакетов должны вызвать автоматическое занесение в чёрный список.
 */
static void
test_udp_flood(void)
{
    uint32_t ip = 0x05020304u;   /* 5.2.3.4 */
    struct pkt_meta m = make_udp(ip);

    for (uint64_t i = 0; i <= test_cfg.udp_threshold; i++)
        ddos_update(ip, &m, 0);
    assert(blacklist_check(ip, rte_get_tsc_cycles()) == 1);

    printf("  test 5 PASS: %llu UDP packets → blacklisted\n",
           (unsigned long long)test_cfg.udp_threshold + 1);
}

/* ─── Точка входа ────────────────────────────────────────────────────────── */

int
main(void)
{
    static char arg0[] = "test_ddos";
    static char arg1[] = "--no-pci";
    static char arg2[] = "-m";
    static char arg3[] = "64";
    char *eal_argv[] = { arg0, arg1, arg2, arg3 };

    if (rte_eal_init(4, eal_argv) < 0) {
        fprintf(stderr, "rte_eal_init failed\n");
        return EXIT_FAILURE;
    }

    fw_log_init();

    /*
     * ddos_init() создаёт таблицы rte_hash и предвычисляет временны́е константы.
     * Вызывается один раз; тестовые функции используют разные IP для исключения
     * влияния состояния одного теста на другой.
     */
    ddos_init(&test_cfg);

    printf("test_ddos: running 5 tests\n");

    test_syn_flood();
    test_window_reset();
    test_expired_ttl();
    test_blacklist_del();
    test_udp_flood();

    printf("test_ddos: all 5 tests PASSED\n");

    rte_eal_cleanup();
    return EXIT_SUCCESS;
}
