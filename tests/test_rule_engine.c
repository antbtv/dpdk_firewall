#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <rte_eal.h>

#include "firewall.h"
#include "config.h"
#include "rule_engine.h"
#include "log.h"

/* ─── Заглушки глобальных переменных (обычно определяются в main.c) ─────── */

volatile fw_action_t g_default_policy = ACTION_DROP;
volatile int         g_force_quit     = 0;

/* ─── Заглушка g_fw_config (обычно определяется в config.c) ────────────── */

struct fw_config g_fw_config;

/* ─── Вспомогательные функции ────────────────────────────────────────────── */

/*
 * Преобразовать "a.b.c.d" в uint32_t в порядке байт хоста.
 * Все IP-поля в fw_rule и pkt_meta используют HBo (rte_acl MASK требует HBo на LE ARM).
 */
static uint32_t
ip4(const char *s)
{
    struct in_addr a;
    inet_pton(AF_INET, s, &a);
    return ntohl(a.s_addr);
}

/* Создать TCP pkt_meta; все IP и порты в порядке байт хоста */
static struct pkt_meta
make_tcp(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port)
{
    struct pkt_meta m;
    memset(&m, 0, sizeof(m));
    m.src_ip   = src_ip;
    m.dst_ip   = dst_ip;
    m.proto    = IPPROTO_TCP;
    m.src_port = src_port;
    m.dst_port = dst_port;
    m.is_ipv4  = 1;
    return m;
}

/*
 * Создать минимальный fw_rule только с полями, необходимыми для теста по портам.
 * rule_add() перезапишет .id свежевыделенным монотонным ID.
 */
static struct fw_rule
make_rule(uint32_t prio, uint8_t proto,
          uint16_t dport_min, uint16_t dport_max,
          fw_action_t action)
{
    struct fw_rule r;
    memset(&r, 0, sizeof(r));
    r.priority     = prio;
    r.proto        = proto;
    r.src_port_min = 0;
    r.src_port_max = 65535;
    r.dst_port_min = dport_min;
    r.dst_port_max = dport_max;
    r.action       = action;
    return r;
}

/*
 * Удалить все правила, загруженные в движок.
 * Используется для сброса состояния между тестами без повторной инициализации EAL или движка.
 */
static void
clear_rules(void)
{
    struct fw_rule listed[MAX_RULES];
    uint32_t n = 0;
    if (rule_list(listed, &n) == 0) {
        for (uint32_t i = 0; i < n; i++)
            rule_del(listed[i].id);
    }
}

/* ─── Тест 1 ─────────────────────────────────────────────────────────────── */
/*
 * Правило DROP для TCP dst_port=80 должно блокировать совпадающий трафик.
 * Возвращённый rule_id должен совпадать с ID, назначенным rule_add().
 */
static void
test_drop_rule(void)
{
    clear_rules();
    g_default_policy = ACTION_ACCEPT;

    struct fw_rule r = make_rule(100, IPPROTO_TCP, 80, 80, ACTION_DROP);
    int id = rule_add(&r);
    assert(id > 0);

    uint32_t rid;
    struct pkt_meta m = make_tcp(ip4("1.2.3.4"), ip4("5.6.7.8"), 12345, 80);
    assert(rule_match(&m, &rid, 200) == ACTION_DROP);
    assert(rid == (uint32_t)id);

    /* Проверить, что byte_count увеличен на переданный pkt_len */
    struct fw_rule listed[MAX_RULES];
    uint32_t n = 0;
    rule_list(listed, &n);
    assert(n == 1);
    assert(listed[0].pkt_count  == 1);
    assert(listed[0].byte_count == 200);

    printf("  test 1 PASS: TCP dst_port=80 → DROP, rule_id matched, byte_count=200\n");
}

/* ─── Тест 2 ─────────────────────────────────────────────────────────────── */
/*
 * Пакет, не совпавший ни с одним правилом, должен возвращать политику по умолчанию.
 * Тот же набор правил, что в тесте 1 (TCP:80 → DROP); dst_port=443 должен получить ACTION_ACCEPT.
 */
static void
test_default_policy(void)
{
    clear_rules();
    g_default_policy = ACTION_ACCEPT;

    struct fw_rule r = make_rule(100, IPPROTO_TCP, 80, 80, ACTION_DROP);
    rule_add(&r);

    uint32_t rid;
    struct pkt_meta m = make_tcp(ip4("1.2.3.4"), ip4("5.6.7.8"), 12345, 443);
    assert(rule_match(&m, &rid, 100) == ACTION_ACCEPT);
    assert(rid == 0);   /* 0 = ни одно правило не совпало */

    printf("  test 2 PASS: TCP dst_port=443 → ACCEPT (default policy, rid=0)\n");
}

/* ─── Тест 3 ─────────────────────────────────────────────────────────────── */
/*
 * Меньший номер приоритета важнее большего (меньше = важнее).
 *   Правило A: priority=200, TCP dst_port=80 → DROP
 *   Правило B: priority=100, TCP dst_port=80 → ACCEPT
 * Оба совпадают; правило B должно победить, и возвращённый rule_id должен быть id B.
 */
static void
test_priority(void)
{
    clear_rules();
    g_default_policy = ACTION_DROP;

    struct fw_rule ra = make_rule(200, IPPROTO_TCP, 80, 80, ACTION_DROP);
    struct fw_rule rb = make_rule(100, IPPROTO_TCP, 80, 80, ACTION_ACCEPT);
    rule_add(&ra);
    int id_b = rule_add(&rb);
    assert(id_b > 0);

    uint32_t rid;
    struct pkt_meta m = make_tcp(ip4("1.2.3.4"), ip4("5.6.7.8"), 12345, 80);
    assert(rule_match(&m, &rid, 100) == ACTION_ACCEPT);
    assert(rid == (uint32_t)id_b);

    printf("  test 3 PASS: priority 100 (ACCEPT) beats 200 (DROP)\n");
}

/* ─── Тест 4 ─────────────────────────────────────────────────────────────── */
/*
 * Сопоставление подсетей CIDR.
 *   Правило: src_ip=192.168.1.0/24 → DROP, default=ACCEPT.
 *   192.168.1.100 — внутри подсети → ACTION_DROP.
 *   10.0.0.1      — вне подсети    → ACTION_ACCEPT (политика по умолчанию).
 */
static void
test_cidr_mask(void)
{
    clear_rules();
    g_default_policy = ACTION_ACCEPT;

    struct fw_rule r;
    memset(&r, 0, sizeof(r));
    r.priority     = 100;
    r.src_ip       = ip4("192.168.1.0");
    r.src_mask     = 0xFFFFFF00u;   /* /24 в порядке байт хоста */
    r.src_port_min = 0;
    r.src_port_max = 65535;
    r.dst_port_min = 0;
    r.dst_port_max = 65535;
    r.action       = ACTION_DROP;
    int id = rule_add(&r);
    assert(id > 0);

    uint32_t rid;

    /* 192.168.1.100 — внутри 192.168.1.0/24 → DROP */
    struct pkt_meta m1 = make_tcp(ip4("192.168.1.100"), ip4("10.0.0.1"), 0, 0);
    assert(rule_match(&m1, &rid, 100) == ACTION_DROP);
    assert(rid == (uint32_t)id);

    /* 10.0.0.1 — вне подсети → ACCEPT (политика по умолчанию) */
    struct pkt_meta m2 = make_tcp(ip4("10.0.0.1"), ip4("192.168.1.100"), 0, 0);
    assert(rule_match(&m2, &rid, 100) == ACTION_ACCEPT);
    assert(rid == 0);

    printf("  test 4 PASS: CIDR /24 matches 192.168.1.100, skips 10.0.0.1\n");
}

/* ─── Тест 5 ─────────────────────────────────────────────────────────────── */
/*
 * rule_add() вызывает неявный rule_engine_rebuild().
 *   Фаза A — нет правил, default ACCEPT → пакет должен быть ACCEPTed.
 *   Фаза B — добавить правило DROP для TCP:9999 → тот же пакет теперь должен быть DROPped.
 */
static void
test_rebuild(void)
{
    clear_rules();
    g_default_policy = ACTION_ACCEPT;

    uint32_t rid;
    struct pkt_meta m = make_tcp(ip4("1.2.3.4"), ip4("5.6.7.8"), 12345, 9999);

    /* Фаза A: нет правил */
    assert(rule_match(&m, &rid, 100) == ACTION_ACCEPT);
    assert(rid == 0);

    /* Фаза B: добавить правило DROP; rule_add() вызывает rule_engine_rebuild() внутри */
    struct fw_rule r = make_rule(100, IPPROTO_TCP, 9999, 9999, ACTION_DROP);
    int id = rule_add(&r);
    assert(id > 0);

    assert(rule_match(&m, &rid, 100) == ACTION_DROP);
    assert(rid == (uint32_t)id);

    printf("  test 5 PASS: rule_add() rebuilt engine, TCP:9999 now DROPped\n");
}

/* ─── Тест 6 ─────────────────────────────────────────────────────────────── */
/*
 * Сопоставление флагов TCP: правило с tcp_flags="SYN" должно совпадать только с SYN-пакетами.
 *   Правило: proto=TCP, tcp_flags=SYN → DROP.
 *   SYN-пакет → ACTION_DROP.
 *   ACK-пакет → ACTION_ACCEPT (политика по умолчанию, флаги не совпадают).
 */
static void
test_tcp_flags(void)
{
    clear_rules();
    g_default_policy = ACTION_ACCEPT;

    struct fw_rule r;
    memset(&r, 0, sizeof(r));
    r.priority      = 100;
    r.proto         = IPPROTO_TCP;
    r.src_port_min  = 0;
    r.src_port_max  = 65535;
    r.dst_port_min  = 0;
    r.dst_port_max  = 65535;
    r.tcp_flags_val  = TCP_FLAG_SYN;
    r.tcp_flags_mask = TCP_FLAG_SYN;
    r.action        = ACTION_DROP;
    int id = rule_add(&r);
    assert(id > 0);

    uint32_t rid;

    /* SYN-пакет → должен совпасть с правилом → DROP */
    struct pkt_meta msyn;
    memset(&msyn, 0, sizeof(msyn));
    msyn.src_ip   = ip4("1.2.3.4");
    msyn.dst_ip   = ip4("5.6.7.8");
    msyn.proto    = IPPROTO_TCP;
    msyn.tcp_flags = TCP_FLAG_SYN;
    msyn.is_ipv4  = 1;
    assert(rule_match(&msyn, &rid, 60) == ACTION_DROP);
    assert(rid == (uint32_t)id);

    /* ACK-пакет → флаги не совпадают → ACCEPT (по умолчанию) */
    struct pkt_meta mack;
    memset(&mack, 0, sizeof(mack));
    mack.src_ip   = ip4("1.2.3.4");
    mack.dst_ip   = ip4("5.6.7.8");
    mack.proto    = IPPROTO_TCP;
    mack.tcp_flags = TCP_FLAG_ACK;
    mack.is_ipv4  = 1;
    assert(rule_match(&mack, &rid, 60) == ACTION_ACCEPT);
    assert(rid == 0);

    printf("  test 6 PASS: tcp_flags=SYN matches SYN, skips ACK\n");
}

/* ─── Тест 7 ─────────────────────────────────────────────────────────────── */
/*
 * Сопоставление типа/кода ICMP.
 *   Правило: proto=ICMP, icmp_type=8 (echo request) → DROP, default=ACCEPT.
 *   type=8 → ACTION_DROP.
 *   type=0 → ACTION_ACCEPT (echo reply, не совпадает).
 */
static void
test_icmp_matching(void)
{
    clear_rules();
    g_default_policy = ACTION_ACCEPT;

    struct fw_rule r;
    memset(&r, 0, sizeof(r));
    r.priority     = 100;
    r.proto        = IPPROTO_ICMP;
    r.src_port_min = 0;
    r.src_port_max = 65535;
    r.dst_port_min = 0;
    r.dst_port_max = 65535;
    r.icmp_type    = 8;   /* echo request (эхо-запрос) */
    r.icmp_code    = 255; /* любой код */
    r.action       = ACTION_DROP;
    int id = rule_add(&r);
    assert(id > 0);

    uint32_t rid;

    /* ICMP echo request (type=8) → DROP (эхо-запрос) */
    struct pkt_meta mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.src_ip   = ip4("1.2.3.4");
    mreq.dst_ip   = ip4("5.6.7.8");
    mreq.proto    = IPPROTO_ICMP;
    mreq.icmp_type = 8;
    mreq.icmp_code = 0;
    mreq.is_ipv4  = 1;
    assert(rule_match(&mreq, &rid, 64) == ACTION_DROP);
    assert(rid == (uint32_t)id);

    /* ICMP echo reply (type=0) → ACCEPT (по умолчанию, эхо-ответ) */
    struct pkt_meta mrep;
    memset(&mrep, 0, sizeof(mrep));
    mrep.src_ip   = ip4("5.6.7.8");
    mrep.dst_ip   = ip4("1.2.3.4");
    mrep.proto    = IPPROTO_ICMP;
    mrep.icmp_type = 0;
    mrep.icmp_code = 0;
    mrep.is_ipv4  = 1;
    assert(rule_match(&mrep, &rid, 64) == ACTION_ACCEPT);
    assert(rid == 0);

    printf("  test 7 PASS: icmp_type=8 matches echo request, skips echo reply\n");
}

/* ─── Точка входа ────────────────────────────────────────────────────────── */

int
main(void)
{
    /*
     * Минимальная инициализация EAL: без сканирования PCI, 64 МБ памяти.
     * rule_engine использует rte_acl (требует EAL + hugepages) и rte_rwlock.
     */
    static char arg0[] = "test_rule_engine";
    static char arg1[] = "--no-pci";
    static char arg2[] = "-m";
    static char arg3[] = "64";
    char *eal_argv[] = { arg0, arg1, arg2, arg3 };
    int   eal_argc   = 4;

    if (rte_eal_init(eal_argc, eal_argv) < 0) {
        fprintf(stderr, "rte_eal_init failed\n");
        return EXIT_FAILURE;
    }

    fw_log_init();

    /*
     * rule_engine_init() предназначен для однократного вызова при запуске.
     * Многократный вызов приведёт к утечке ACL-контекстов (статический g_acl_ctx
     * обнуляется без освобождения) и заставит rte_acl_create() вернуть устаревший
     * контекст при коллизии имён.
     *
     * Решение: инициализировать один раз с пустым набором правил, затем управлять
     * правилами между тестами через rule_add() / rule_del(), каждый из которых
     * вызывает rule_engine_rebuild() внутри.
     */
    memset(&g_fw_config, 0, sizeof(g_fw_config));
    g_default_policy = ACTION_DROP;
    if (rule_engine_init() != 0) {
        fprintf(stderr, "rule_engine_init failed\n");
        rte_eal_cleanup();
        return EXIT_FAILURE;
    }

    printf("test_rule_engine: running 7 tests\n");

    test_drop_rule();
    test_default_policy();
    test_priority();
    test_cidr_mask();
    test_rebuild();
    test_tcp_flags();
    test_icmp_matching();

    printf("test_rule_engine: all 7 tests PASSED\n");

    rte_eal_cleanup();
    return EXIT_SUCCESS;
}
