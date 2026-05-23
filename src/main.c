#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include <jansson.h>

#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_log.h>

#include "firewall.h"
#include "config.h"
#include "port.h"
#include "pipeline.h"
#include "rule_engine.h"
#include "ddos.h"
#include "stats.h"
#include "mgmt.h"
#include "log.h"

/* ─── Глобальное состояние ──────────────────────────────────────────────── */

volatile fw_action_t   g_default_policy = ACTION_DROP;
volatile int           g_force_quit     = 0;
volatile sig_atomic_t  g_sighup_flag    = 0;

/* Аргументы конвейера на lcore (статическое время жизни — передаются удалённым lcore) */
static struct pipeline_args s_pipe_args[RTE_MAX_LCORE];

/* ─── Обработчики сигналов ──────────────────────────────────────────────── */

static void
handle_sigint(int sig)
{
    (void)sig;
    g_force_quit = 1;
}

static void
handle_sighup(int sig)
{
    (void)sig;
    g_sighup_flag = 1;
}

/* ─── Разбор аргументов ─────────────────────────────────────────────────── */

static void
print_usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s --config <path> [--log-level debug|info|warning|error] [--hairpin]\n",
            prog);
}

/** Преобразовать строку уровня лога в константу RTE_LOG_*. При неизвестном значении возвращает RTE_LOG_INFO. */
static int
str_to_log_level(const char *s)
{
    if (strcasecmp(s, "debug")   == 0) return RTE_LOG_DEBUG;
    if (strcasecmp(s, "info")    == 0) return RTE_LOG_INFO;
    if (strcasecmp(s, "notice")  == 0) return RTE_LOG_NOTICE;
    if (strcasecmp(s, "warning") == 0 ||
        strcasecmp(s, "warn")    == 0) return RTE_LOG_WARNING;
    if (strcasecmp(s, "error")   == 0 ||
        strcasecmp(s, "err")     == 0) return RTE_LOG_ERR;
    return RTE_LOG_INFO;
}

/**
 * Предварительно просмотреть argv для поиска --config и --log-level БЕЗ их потребления.
 * @param cli_log_level_out  -1 если --log-level не был указан.
 * @return 0 при успехе, -1 если --config отсутствует.
 */
static int
prescan_args(int argc, char *argv[],
             const char **config_path_out,
             int *cli_log_level_out)
{
    *config_path_out  = NULL;
    *cli_log_level_out = -1;   /* -1 означает "не указан, использовать значение из конфига" */

    for (int i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "--config") == 0)
            *config_path_out = argv[i + 1];
        else if (strcmp(argv[i], "--log-level") == 0)
            *cli_log_level_out = str_to_log_level(argv[i + 1]);
    }

    if (*config_path_out == NULL) {
        fprintf(stderr, "Error: --config <path> is required\n");
        print_usage(argv[0]);
        return -1;
    }
    return 0;
}

/** Возвращает 1 если s похоже на адрес PCIe (DDDD:BB:SS.F). */
static int
is_pci_addr(const char *s)
{
    int colons = 0, dots = 0;
    if (!s) return 0;
    for (const char *p = s; *p; p++) {
        if      (*p == ':')  colons++;
        else if (*p == '.')  dots++;
        else if (!((*p >= '0' && *p <= '9') ||
                   (*p >= 'a' && *p <= 'f') ||
                   (*p >= 'A' && *p <= 'F')))
            return 0;
    }
    return (colons == 2 && dots == 1);
}

/**
 * Минимальный разбор JSON для извлечения конфигурации портов из файла.
 * Вызывается ДО rte_eal_init, чтобы собрать список --allow/--vdev.
 *
 * Каждое из полей "wan"/"lan" в секции "ports" конфига может быть:
 *   - адресом PCI ("0001:01:00.0") → записывается в *_pci_out
 *   - именем интерфейса ("enP1p1s0", "eth0") → записывается в *_iface_out
 *   - ключевым словом "builtin" (только для lan) → трактуется как iface "eth0"
 *
 * Ровно один из *_pci_out / *_iface_out будет непустым для каждого порта.
 */
static int
extract_pci_addrs(const char *path,
                  char *wan_pci_out,   size_t wan_pci_sz,
                  char *wan_iface_out, size_t wan_iface_sz,
                  char *lan_pci_out,   size_t lan_pci_sz,
                  char *lan_iface_out, size_t lan_iface_sz)
{
    wan_pci_out[0] = wan_iface_out[0] = '\0';
    lan_pci_out[0] = lan_iface_out[0] = '\0';

    json_error_t jerr;
    json_t *root = json_load_file(path, 0, &jerr);
    if (!root) {
        fprintf(stderr, "Cannot parse config '%s': %s (line %d)\n",
                path, jerr.text, jerr.line);
        return -1;
    }

    json_t *ports = json_object_get(root, "ports");
    if (ports && json_is_object(ports)) {
        const char *wan = json_string_value(json_object_get(ports, "wan"));
        const char *lan = json_string_value(json_object_get(ports, "lan"));

        if (wan) {
            if (is_pci_addr(wan))
                snprintf(wan_pci_out, wan_pci_sz, "%s", wan);
            else
                snprintf(wan_iface_out, wan_iface_sz, "%s", wan);
        }

        if (lan) {
            if (strcasecmp(lan, "builtin") == 0)
                snprintf(lan_iface_out, lan_iface_sz, "eth0");
            else if (is_pci_addr(lan))
                snprintf(lan_pci_out, lan_pci_sz, "%s", lan);
            else
                snprintf(lan_iface_out, lan_iface_sz, "%s", lan);
        }
    }

    json_decref(root);

    if (wan_pci_out[0] == '\0' && wan_iface_out[0] == '\0') {
        fprintf(stderr, "Config '%s' missing 'ports.wan'\n", path);
        return -1;
    }
    return 0;
}

/* ─── Точка входа ───────────────────────────────────────────────────────── */

int
main(int argc, char *argv[])
{
    /* ── Шаг 1: Предварительный просмотр аргументов приложения ─────────── */
    const char *config_path   = NULL;
    int         cli_log_level = -1;

    if (prescan_args(argc, argv, &config_path, &cli_log_level) != 0)
        return EXIT_FAILURE;

    int hairpin_mode = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--hairpin") == 0) {
            hairpin_mode = 1;
            break;
        }
    }

    /* ── Шаг 2: Извлечение конфигурации портов (EAL ещё не инициализирован) */
    char wan_pci[32], wan_iface[32];
    char lan_pci[32], lan_iface[32];
    if (extract_pci_addrs(config_path,
                          wan_pci,   sizeof(wan_pci),
                          wan_iface, sizeof(wan_iface),
                          lan_pci,   sizeof(lan_pci),
                          lan_iface, sizeof(lan_iface)) != 0)
        return EXIT_FAILURE;

    /* ── Шаг 3: Формирование синтетического argv для EAL ────────────────── */
    /*
     * rte_eal_init() требует записываемых строк, завершённых нулём.
     * Используется фиксированный двумерный массив на стеке; каждый слот — EAL_ARG_LEN байт.
     *
     * Порядок портов (в порядке зондирования):
     *   PCI-порты обнаруживаются раньше vdev-портов в порядке зондирования DPDK.
     *   vdev-порты зондируются в порядке аргументов --vdev.
     *   Поэтому: первая запись WAN → порт 0, вторая запись LAN → порт 1.
     *
     * Максимум аргументов: 9 (prog + --proc-type primary + 2×(--allow|--vdev X))
     */
#define EAL_MAX_ARGS 16
#define EAL_ARG_LEN  64
    char  eal_storage[EAL_MAX_ARGS][EAL_ARG_LEN];
    char *eal_argv[EAL_MAX_ARGS];
    int   eal_argc  = 0;
    int   vdev_idx  = 0;   /* суффикс индекса для имён PMD vdev */
    char  vdev_arg[EAL_ARG_LEN];

#define EAL_PUSH(str) \
    do { \
        snprintf(eal_storage[eal_argc], EAL_ARG_LEN, "%s", (str)); \
        eal_argv[eal_argc] = eal_storage[eal_argc]; \
        eal_argc++; \
    } while (0)

    EAL_PUSH(argv[0]);
    EAL_PUSH("--proc-type");
    EAL_PUSH("primary");

    /* Порт WAN */
    if (wan_pci[0]) {
        EAL_PUSH("--allow"); EAL_PUSH(wan_pci);
    } else if (wan_iface[0]) {
        /* BCM2712 PCIe не имеет IOMMU → DMA через uio_pci_generic не работает
         * (смещение адреса 64 ГБ). Оставить NIC под драйвером ядра igb и
         * обращаться через AF_PACKET-сокеты — перепривязка драйвера не нужна. */
        snprintf(vdev_arg, sizeof(vdev_arg),
                 "net_af_xdp0,iface=%s,force_copy=1", wan_iface);
        EAL_PUSH("--vdev"); EAL_PUSH(vdev_arg);
    }

    /* Порт LAN */
    if (lan_pci[0]) {
        EAL_PUSH("--allow"); EAL_PUSH(lan_pci);
    } else if (lan_iface[0]) {
        snprintf(vdev_arg, sizeof(vdev_arg),
                 "eth_af_packet%d,iface=%s", vdev_idx++, lan_iface);
        EAL_PUSH("--vdev"); EAL_PUSH(vdev_arg);
    }

#undef EAL_PUSH

    /* ── Шаг 4: Инициализация DPDK EAL ─────────────────────────────────── */
    int ret = rte_eal_init(eal_argc, eal_argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "rte_eal_init failed: %s\n",
                 rte_strerror(rte_errno));

    /* ── Шаг 5: Инициализация подсистемы логирования ───────────────────── */
    if (fw_log_init() != 0)
        rte_exit(EXIT_FAILURE, "fw_log_init failed\n");

    /* ── Шаг 6: Загрузка полной конфигурации ────────────────────────────── */
    if (config_load(config_path) != 0)
        rte_exit(EXIT_FAILURE, "Failed to load config: %s\n", config_path);

    /*
     * Приоритет уровня лога: CLI --log-level > значение "logging.level" из конфига.
     * Значение -1 из CLI означает "не указан" → использовать значение из конфига.
     */
    int effective_level = (cli_log_level >= 0) ? cli_log_level
                                               : g_fw_config.log_level;
    rte_log_set_level(fw_logtype, (uint32_t)effective_level);

    /* ── Шаг 7: Проверка раскладки lcore ───────────────────────────────── */
    if (!rte_lcore_is_enabled(1) ||
        (!hairpin_mode && !rte_lcore_is_enabled(2)))
        rte_exit(EXIT_FAILURE,
                 "Need at least 3 lcores (0=control, 1=WAN->LAN, 2=LAN->WAN)\n");

    /* ── Шаг 8: Инициализация модулей ───────────────────────────────────── */
    stats_init();

    if (port_init_all(hairpin_mode ? 1 : 2) != 0)
        rte_exit(EXIT_FAILURE, "port_init_all failed\n");

    if (rule_engine_init() != 0)
        rte_exit(EXIT_FAILURE, "rule_engine_init failed\n");

    ddos_init(&g_fw_config.ddos_cfg);
    meter_init_all();

    /* ── Шаг 9: Установка обработчиков сигналов ─────────────────────────── */
    struct sigaction sa_quit = { .sa_handler = handle_sigint,  .sa_flags = 0 };
    struct sigaction sa_hup  = { .sa_handler = handle_sighup,  .sa_flags = 0 };
    sigemptyset(&sa_quit.sa_mask);
    sigemptyset(&sa_hup.sa_mask);
    sigaction(SIGINT,  &sa_quit, NULL);
    sigaction(SIGTERM, &sa_quit, NULL);
    sigaction(SIGHUP,  &sa_hup,  NULL);

    /* ── Шаг 10: Запуск lcores пересылки ────────────────────────────────── */
    if (hairpin_mode) {
        /* Режим hairpin: порт 0 → порт 0 (однопортовая петля для тестирования) */
        s_pipe_args[1].port_in  = 0;
        s_pipe_args[1].port_out = 0;
        ret = rte_eal_remote_launch(pipeline_lcore_main, &s_pipe_args[1], 1);
        if (ret != 0)
            rte_exit(EXIT_FAILURE, "Failed to launch lcore 1: %s\n",
                     rte_strerror(-ret));
        RTE_LOG_FW_INFO("Hairpin mode: port 0 → port 0\n");
    } else {
        /* lcore 1: WAN (порт 0) → LAN (порт 1) */
        s_pipe_args[1].port_in  = 0;
        s_pipe_args[1].port_out = 1;
        ret = rte_eal_remote_launch(pipeline_lcore_main, &s_pipe_args[1], 1);
        if (ret != 0)
            rte_exit(EXIT_FAILURE, "Failed to launch lcore 1: %s\n",
                     rte_strerror(-ret));

        /* lcore 2: LAN (порт 1) → WAN (порт 0) */
        s_pipe_args[2].port_in  = 1;
        s_pipe_args[2].port_out = 0;
        ret = rte_eal_remote_launch(pipeline_lcore_main, &s_pipe_args[2], 2);
        if (ret != 0)
            rte_exit(EXIT_FAILURE, "Failed to launch lcore 2: %s\n",
                     rte_strerror(-ret));
    }

    RTE_LOG_FW_INFO("dpdk_firewall started — lcore 0 running control plane\n");

    /* ── Шаг 11: Цикл плоскости управления на lcore 0 (блокирующий) ────── */
    mgmt_server_run();

    /* ── Шаг 12: Очистка ────────────────────────────────────────────────── */
    RTE_LOG_FW_INFO("Shutting down...\n");

    rte_eal_wait_lcore(1);
    if (!hairpin_mode)
        rte_eal_wait_lcore(2);

    port_stop_all();
    rte_eal_cleanup();

    RTE_LOG_FW_INFO("Goodbye.\n");
    return EXIT_SUCCESS;
}
