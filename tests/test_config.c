/*
 * tests/test_config.c — Юнит-тесты парсера конфигурации (P4-06)
 *
 * Компонуется с: config.c, rule_engine.c, log.c  (через tests/meson.build)
 * НЕ компонуется с main.c → необходимо определить заглушки g_default_policy / g_force_quit.
 * g_fw_config определён в подключаемом config.c — заглушка здесь не нужна.
 *
 * Тесты:
 *  1. Загрузка корректного конфига с 4 правилами → n_rules == 4
 *  2. JSON без обязательного поля 'mode' → config_load() возвращает ненулевой код
 *  3. Правило с неизвестным действием → config_load() возвращает ненулевой код
 *  4. src_ip "192.168.1.0/24" → src_ip = 0xC0A80100 (HBo), mask = 0xFFFFFF00 (HBo)
 *  5. dst_port "1024-65535" → dst_port_min=1024, dst_port_max=65535
 *  6. Горячая перезагрузка: перезаписать временный файл, config_reload() обновляет n_rules
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <rte_eal.h>

#include "firewall.h"
#include "config.h"
#include "rule_engine.h"
#include "log.h"

/* ─── Заглушки глобальных переменных (обычно определяются в main.c) ─────── */

volatile fw_action_t g_default_policy = ACTION_DROP;
volatile int         g_force_quit     = 0;

/* ─── Вспомогательная функция для временных файлов ─────────────────────── */

static void
write_file(const char *path, const char *content)
{
    FILE *f = fopen(path, "w");
    assert(f != NULL);
    fputs(content, f);
    fclose(f);
}

/* ─── Тестовые JSON-фикстуры ─────────────────────────────────────────────── */

/* Корректный конфиг ровно с 4 правилами */
static const char JSON_VALID_4[] =
"{"
"  \"version\": 1,"
"  \"mode\": \"bridge\","
"  \"ports\": { \"wan\": \"eth0\" },"
"  \"default_policy\": \"drop\","
"  \"rules\": ["
"    { \"id\": 1, \"priority\": 100, \"proto\": \"tcp\","
"      \"dst_port\": \"22\", \"action\": \"accept\" },"
"    { \"id\": 2, \"priority\": 200, \"proto\": \"icmp\","
"      \"action\": \"rate_limit\","
"      \"rate\": { \"cir_kbps\": 1000, \"cbs_bytes\": 65536 } },"
"    { \"id\": 3, \"priority\": 300,"
"      \"src_ip\": \"10.0.0.0/8\", \"action\": \"drop\" },"
"    { \"id\": 4, \"priority\": 1,"
"      \"src_ip\": \"10.99.0.0/24\", \"action\": \"accept\" }"
"  ]"
"}";

/* Отсутствует обязательное поле 'mode' */
static const char JSON_NO_MODE[] =
"{"
"  \"version\": 1,"
"  \"ports\": { \"wan\": \"eth0\" },"
"  \"default_policy\": \"drop\","
"  \"rules\": []"
"}";

/* Правило с неизвестным действием */
static const char JSON_BAD_ACTION[] =
"{"
"  \"version\": 1,"
"  \"mode\": \"bridge\","
"  \"ports\": { \"wan\": \"eth0\" },"
"  \"default_policy\": \"drop\","
"  \"rules\": ["
"    { \"id\": 1, \"priority\": 100, \"action\": \"explode\" }"
"  ]"
"}";

/* Одно правило с CIDR в src_ip и диапазоном dst_port */
static const char JSON_CIDR_PORTS[] =
"{"
"  \"version\": 1,"
"  \"mode\": \"bridge\","
"  \"ports\": { \"wan\": \"eth0\" },"
"  \"default_policy\": \"drop\","
"  \"rules\": ["
"    { \"id\": 1, \"priority\": 100, \"proto\": \"tcp\","
"      \"src_ip\": \"192.168.1.0/24\","
"      \"dst_port\": \"1024-65535\","
"      \"action\": \"drop\" }"
"  ]"
"}";

/* Конфиг с 2 правилами (используется в тесте горячей перезагрузки — начальное состояние) */
static const char JSON_2_RULES[] =
"{"
"  \"version\": 1,"
"  \"mode\": \"bridge\","
"  \"ports\": { \"wan\": \"eth0\" },"
"  \"default_policy\": \"drop\","
"  \"rules\": ["
"    { \"id\": 1, \"priority\": 100, \"action\": \"accept\" },"
"    { \"id\": 2, \"priority\": 200, \"action\": \"drop\" }"
"  ]"
"}";

/* Конфиг с 1 правилом (используется в тесте горячей перезагрузки — состояние после перезагрузки) */
static const char JSON_1_RULE[] =
"{"
"  \"version\": 1,"
"  \"mode\": \"bridge\","
"  \"ports\": { \"wan\": \"eth0\" },"
"  \"default_policy\": \"accept\","
"  \"rules\": ["
"    { \"id\": 1, \"priority\": 50, \"action\": \"drop\" }"
"  ]"
"}";

/* ─── Тесты ───────────────────────────────────────────────────────────────── */

/*
 * Тест 1: корректный конфиг с 4 правилами разбирается без ошибок.
 */
static void
test_valid_config(void)
{
    write_file("/tmp/fw_tc_valid.json", JSON_VALID_4);

    int rc = config_load("/tmp/fw_tc_valid.json");
    assert(rc == 0);
    assert(g_fw_config.n_rules == 4);
    assert(g_fw_config.default_policy == ACTION_DROP);

    printf("  test 1 PASS: valid config, n_rules=%u\n", g_fw_config.n_rules);
}

/*
 * Тест 2: JSON без обязательного поля 'mode' → config_load возвращает ненулевой код.
 */
static void
test_missing_mode(void)
{
    write_file("/tmp/fw_tc_no_mode.json", JSON_NO_MODE);

    int rc = config_load("/tmp/fw_tc_no_mode.json");
    assert(rc != 0);

    printf("  test 2 PASS: missing 'mode' → error code %d\n", rc);
}

/*
 * Тест 3: правило с неизвестной строкой действия → config_load возвращает ненулевой код.
 */
static void
test_bad_action(void)
{
    write_file("/tmp/fw_tc_bad_action.json", JSON_BAD_ACTION);

    int rc = config_load("/tmp/fw_tc_bad_action.json");
    assert(rc != 0);

    printf("  test 3 PASS: unknown action → error code %d\n", rc);
}

/*
 * Тест 4: src_ip "192.168.1.0/24" → значения в порядке байт хоста (HBo).
 *
 * Порядок байт хоста (HBo) на LE ARM:
 *   192.168.1.0 → 0xC0A80100  (C0=192, A8=168, 01=1, 00=0)
 *   маска /24   → 0xFFFFFF00  (старшие 24 бита установлены)
 *
 * parse_cidr() в config.c хранит HBo (ntohl(addr.s_addr)), а
 * rte_acl тип MASK требует HBo для корректного CIDR-сопоставления на LE ARM
 * (применяет префикс от MSB целочисленного значения).
 */
static void
test_cidr_parse(void)
{
    write_file("/tmp/fw_tc_cidr.json", JSON_CIDR_PORTS);

    int rc = config_load("/tmp/fw_tc_cidr.json");
    assert(rc == 0);
    assert(g_fw_config.n_rules == 1);

    const struct fw_rule *r = &g_fw_config.rules[0];
    assert(r->src_ip   == 0xC0A80100u);   /* 192.168.1.0 в порядке байт хоста */
    assert(r->src_mask == 0xFFFFFF00u);   /* маска /24 в порядке байт хоста   */

    printf("  test 4 PASS: src_ip=0x%08X mask=0x%08X\n",
           r->src_ip, r->src_mask);
}

/*
 * Тест 5: dst_port "1024-65535" → dst_port_min=1024, dst_port_max=65535.
 */
static void
test_port_range(void)
{
    /* Повторно использовать файл, записанный в тесте 4 */
    write_file("/tmp/fw_tc_cidr.json", JSON_CIDR_PORTS);

    int rc = config_load("/tmp/fw_tc_cidr.json");
    assert(rc == 0);
    assert(g_fw_config.n_rules == 1);

    const struct fw_rule *r = &g_fw_config.rules[0];
    assert(r->dst_port_min == 1024);
    assert(r->dst_port_max == 65535);

    printf("  test 5 PASS: dst_port_min=%u dst_port_max=%u\n",
           r->dst_port_min, r->dst_port_max);
}

/*
 * Тест 6: горячая перезагрузка — перезаписать файл конфига, config_reload() обновляет n_rules.
 *
 * Сценарий:
 *   1. config_load() с JSON из 2 правил → n_rules=2
 *   2. Перезаписать тот же файл JSON из 1 правила
 *   3. config_reload() → читает из сохранённого config_path, n_rules=1
 */
static void
test_hot_reload(void)
{
    const char *path = "/tmp/fw_tc_reload.json";

    /* Начальная загрузка: 2 правила */
    write_file(path, JSON_2_RULES);
    int rc = config_load(path);
    assert(rc == 0);
    assert(g_fw_config.n_rules == 2);

    /* Перезаписать с 1 правилом */
    write_file(path, JSON_1_RULE);

    /* config_reload() перечитывает из g_fw_config.config_path */
    rc = config_reload();
    assert(rc == 0);
    assert(g_fw_config.n_rules == 1);
    assert(g_fw_config.default_policy == ACTION_ACCEPT);

    printf("  test 6 PASS: hot-reload n_rules=%u default_policy=accept\n",
           g_fw_config.n_rules);
}

/* ─── Точка входа ────────────────────────────────────────────────────────── */

int
main(void)
{
    /*
     * Минимальная инициализация EAL: без сканирования PCI, 64 МБ памяти.
     * Необходима, так как config_reload() вызывает rule_engine_reload_from_config()
     * → rule_engine_rebuild() → rte_acl_create() (требует EAL + hugepages).
     */
    static char arg0[] = "test_config";
    static char arg1[] = "--no-pci";
    static char arg2[] = "-m";
    static char arg3[] = "64";
    char *eal_argv[] = { arg0, arg1, arg2, arg3 };
    int   eal_argc   = 4;

    if (rte_eal_init(eal_argc, eal_argv) < 0) {
        fprintf(stderr, "test_config: rte_eal_init failed\n");
        return EXIT_FAILURE;
    }

    fw_log_init();

    /*
     * Инициализировать движок правил с пустым набором правил.
     * Тесты 1-5 вызывают только config_load() (без вызовов rule_engine).
     * Тест 6 вызывает config_reload(), который внутри вызывает
     * rule_engine_reload_from_config(); движок должен быть инициализирован заранее.
     */
    memset(&g_fw_config, 0, sizeof(g_fw_config));
    if (rule_engine_init() != 0) {
        fprintf(stderr, "test_config: rule_engine_init failed\n");
        rte_eal_cleanup();
        return EXIT_FAILURE;
    }

    printf("test_config: running 6 tests\n");

    test_valid_config();
    test_missing_mode();
    test_bad_action();
    test_cidr_parse();
    test_port_range();
    test_hot_reload();

    printf("test_config: all 6 tests PASSED\n");

    rte_eal_cleanup();
    return EXIT_SUCCESS;
}
