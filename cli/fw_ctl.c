/*
 * cli/fw_ctl.c — Интерфейс командной строки управления для dpdk_firewall (P4-05)
 *
 * Автономный бинарный файл: без зависимости от DPDK, только POSIX + libjansson.
 * Подключается к /var/run/dpdk_firewall/mgmt.sock, отправляет одну JSON-команду,
 * выводит ответ, завершается с кодом 0 при успехе / 1 при ошибке.
 *
 * Использование:
 *   fw_ctl rule add [--proto tcp|udp|icmp|any] [--src-ip CIDR] [--dst-ip CIDR]
 *                   [--src-port PORT|RANGE] [--dst-port PORT|RANGE]
 *                   [--priority N] --action accept|drop|rate_limit
 *                   [--rate-cir-kbps N] [--rate-cbs-bytes N] [--comment TEXT]
 *   fw_ctl rule del --id N
 *   fw_ctl rule list
 *   fw_ctl rule flush
 *   fw_ctl stats
 *   fw_ctl blacklist add --ip X.X.X.X [--duration N]
 *   fw_ctl blacklist del --ip X.X.X.X
 *   fw_ctl blacklist list
 *   fw_ctl config reload
 *   fw_ctl set-policy accept|drop
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <stdint.h>
#include <jansson.h>

#define SOCK_PATH   "/var/run/dpdk_firewall/mgmt.sock"
#define RESP_BUFSZ  (256 * 1024)

/* ─── Вспомогательные функции для разбора аргументов ────────────────────── */

/* Вернуть значение после флага, или NULL если флаг не найден. */
static const char *
get_arg(int argc, char **argv, const char *flag)
{
    for (int i = 0; i < argc - 1; i++) {
        if (strcmp(argv[i], flag) == 0)
            return argv[i + 1];
    }
    return NULL;
}

/* ─── Взаимодействие через сокет ────────────────────────────────────────── */

/*
 * Отправить {"cmd": cmd, "args": args} на mgmt-сокет и вернуть разобранный
 * JSON-ответ. args может быть NULL (поле args не отправляется).
 * Вызывающий должен вызвать json_decref() для возвращённого объекта.
 * Возвращает NULL при ошибке.
 */
static json_t *
send_command(const char *cmd, json_t *args)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "fw_ctl: socket: %s\n", strerror(errno));
        return NULL;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", SOCK_PATH);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr,
                "fw_ctl: cannot connect to %s: %s\n"
                "        (is dpdk_firewall running?)\n",
                SOCK_PATH, strerror(errno));
        close(fd);
        if (args) json_decref(args);
        return NULL;
    }

    /* Сформировать JSON-запрос */
    json_t *req = json_object();
    json_object_set_new(req, "cmd", json_string(cmd));
    if (args)
        json_object_set_new(req, "args", args);  /* владение args передаётся */

    char *req_str = json_dumps(req, JSON_COMPACT);
    json_decref(req);
    if (!req_str) {
        close(fd);
        return NULL;
    }

    /* Отправить запрос + разделитель-перенос строки */
    if (send(fd, req_str, strlen(req_str), 0) < 0 ||
        send(fd, "\n", 1, 0) < 0) {
        fprintf(stderr, "fw_ctl: send failed: %s\n", strerror(errno));
        free(req_str);
        close(fd);
        return NULL;
    }
    free(req_str);

    /* Прочитать ответ (заканчивается символом новой строки) */
    char *buf = malloc(RESP_BUFSZ);
    if (!buf) {
        close(fd);
        return NULL;
    }

    ssize_t total = 0;
    ssize_t n;
    while (total < RESP_BUFSZ - 1) {
        n = recv(fd, buf + total, (size_t)(RESP_BUFSZ - 1 - total), 0);
        if (n <= 0)
            break;
        total += n;
        if (buf[total - 1] == '\n')
            break;
    }
    close(fd);

    buf[total] = '\0';
    if (total > 0 && buf[total - 1] == '\n')
        buf[--total] = '\0';

    json_error_t jerr;
    json_t *resp = json_loads(buf, 0, &jerr);
    free(buf);

    if (!resp)
        fprintf(stderr, "fw_ctl: invalid server response: %s\n", jerr.text);

    return resp;
}

/*
 * Проверить поле "status" в ответе.
 * Вывести сообщение об ошибке, если status != "ok".
 * Вернуть 0 при "ok", 1 иначе.
 */
static int
check_status(json_t *resp)
{
    if (!resp)
        return 1;

    const char *status = json_string_value(json_object_get(resp, "status"));
    if (status && strcmp(status, "ok") == 0)
        return 0;

    const char *msg = json_string_value(json_object_get(resp, "msg"));
    fprintf(stderr, "fw_ctl: error: %s\n", msg ? msg : "(no message)");
    return 1;
}

/* ─── Вспомогательные функции отображения ───────────────────────────────── */

static const char *
proto_name(int proto)
{
    switch (proto) {
    case  1: return "icmp";
    case  6: return "tcp";
    case 17: return "udp";
    case  0: return "any";
    default: {
        static char buf[8];
        snprintf(buf, sizeof(buf), "%d", proto);
        return buf;
    }
    }
}

/* Форматировать диапазон портов: "0-65535" → "any", "80-80" → "80", иначе "min-max" */
static const char *
fmt_port(uint16_t mn, uint16_t mx)
{
    static char buf[16];
    if (mn == 0 && mx == 65535)
        return "any";
    if (mn == mx) {
        snprintf(buf, sizeof(buf), "%u", mn);
    } else {
        snprintf(buf, sizeof(buf), "%u-%u", mn, mx);
    }
    return buf;
}

/* Вывести список правил в виде таблицы */
static void
print_rule_table(json_t *rules_arr)
{
    if (!json_is_array(rules_arr) || json_array_size(rules_arr) == 0) {
        printf("(no rules)\n");
        return;
    }

    printf("%-5s %-5s %-6s %-20s %-20s %-13s %-11s %s\n",
           "ID", "PRI", "PROTO", "SRC-IP", "DST-IP", "DST-PORT", "ACTION", "PKTS");
    printf("%-5s %-5s %-6s %-20s %-20s %-13s %-11s %s\n",
           "---", "---", "-----", "------", "------", "--------", "------", "----");

    size_t idx;
    json_t *r;
    json_array_foreach(rules_arr, idx, r) {
        int      id      = (int)json_integer_value(json_object_get(r, "id"));
        int      pri     = (int)json_integer_value(json_object_get(r, "priority"));
        int      proto   = (int)json_integer_value(json_object_get(r, "proto"));
        uint16_t dport_mn= (uint16_t)json_integer_value(json_object_get(r, "dst_port_min"));
        uint16_t dport_mx= (uint16_t)json_integer_value(json_object_get(r, "dst_port_max"));
        long long pkts   = json_integer_value(json_object_get(r, "pkt_count"));

        const char *src_ip = json_string_value(json_object_get(r, "src_ip"));
        const char *dst_ip = json_string_value(json_object_get(r, "dst_ip"));
        const char *action = json_string_value(json_object_get(r, "action"));

        printf("%-5d %-5d %-6s %-20s %-20s %-13s %-11s %lld\n",
               id, pri,
               proto_name(proto),
               src_ip   ? src_ip   : "-",
               dst_ip   ? dst_ip   : "-",
               fmt_port(dport_mn, dport_mx),
               action   ? action   : "-",
               pkts);
    }
}

/* Вывести глобальную статистику */
static void
print_stats(json_t *data)
{
    if (!data) return;

    long long rx_pkts  = json_integer_value(json_object_get(data, "rx_pkts"));
    long long tx_pkts  = json_integer_value(json_object_get(data, "tx_pkts"));
    long long dropped  = json_integer_value(json_object_get(data, "dropped_pkts"));
    long long rx_bytes = json_integer_value(json_object_get(data, "rx_bytes"));
    long long tx_bytes = json_integer_value(json_object_get(data, "tx_bytes"));

    printf("Global counters:\n");
    printf("  rx_pkts:  %lld\n", rx_pkts);
    printf("  tx_pkts:  %lld\n", tx_pkts);
    printf("  dropped:  %lld\n", dropped);
    printf("  rx_bytes: %lld\n", rx_bytes);
    printf("  tx_bytes: %lld\n", tx_bytes);

    json_t *ports = json_object_get(data, "ports");
    if (json_is_array(ports)) {
        printf("\nPort statistics:\n");
        size_t i;
        json_t *p;
        json_array_foreach(ports, i, p) {
            int port = (int)json_integer_value(json_object_get(p, "port"));
            long long ipkt = json_integer_value(json_object_get(p, "ipackets"));
            long long opkt = json_integer_value(json_object_get(p, "opackets"));
            long long ibyt = json_integer_value(json_object_get(p, "ibytes"));
            long long obyt = json_integer_value(json_object_get(p, "obytes"));
            long long miss = json_integer_value(json_object_get(p, "imissed"));
            long long ierr = json_integer_value(json_object_get(p, "ierrors"));
            long long oerr = json_integer_value(json_object_get(p, "oerrors"));
            printf("  Port %d: rx=%lld pkt/%lld B  tx=%lld pkt/%lld B"
                   "  missed=%lld  ierr=%lld  oerr=%lld\n",
                   port, ipkt, ibyt, opkt, obyt, miss, ierr, oerr);
        }
    }
}

/* Вывести чёрный список */
static void
print_blacklist(json_t *data)
{
    json_t *bl = json_object_get(data, "blacklist");
    if (!json_is_array(bl) || json_array_size(bl) == 0) {
        printf("(blacklist is empty)\n");
        return;
    }

    printf("%-20s %s\n", "IP", "TTL(s)");
    printf("%-20s %s\n", "------------------", "------");

    size_t i;
    json_t *e;
    json_array_foreach(bl, i, e) {
        const char *ip = json_string_value(json_object_get(e, "ip"));
        long long ttl  = json_integer_value(json_object_get(e, "ttl_s"));
        printf("%-20s %lld\n", ip ? ip : "?", ttl);
    }
}

/* ─── Обработчики подкоманд ─────────────────────────────────────────────── */

/* добавление правила */
static int
do_rule_add(int argc, char **argv)
{
    const char *action = get_arg(argc, argv, "--action");
    if (!action) {
        fprintf(stderr, "fw_ctl: rule add: --action is required\n");
        return 1;
    }

    json_t *args = json_object();
    json_object_set_new(args, "action", json_string(action));

    const char *v;
    if ((v = get_arg(argc, argv, "--proto")))
        json_object_set_new(args, "proto", json_string(v));
    if ((v = get_arg(argc, argv, "--src-ip")))
        json_object_set_new(args, "src_ip", json_string(v));
    if ((v = get_arg(argc, argv, "--dst-ip")))
        json_object_set_new(args, "dst_ip", json_string(v));
    if ((v = get_arg(argc, argv, "--src-port")))
        json_object_set_new(args, "src_port", json_string(v));
    if ((v = get_arg(argc, argv, "--dst-port")))
        json_object_set_new(args, "dst_port", json_string(v));
    if ((v = get_arg(argc, argv, "--priority")))
        json_object_set_new(args, "priority", json_integer(atoi(v)));
    if ((v = get_arg(argc, argv, "--rate-cir-kbps")))
        json_object_set_new(args, "rate_cir_kbps", json_integer(atoll(v)));
    if ((v = get_arg(argc, argv, "--rate-cbs-bytes")))
        json_object_set_new(args, "rate_cbs_bytes", json_integer(atoll(v)));
    if ((v = get_arg(argc, argv, "--comment")))
        json_object_set_new(args, "comment", json_string(v));

    json_t *resp = send_command("rule_add", args);
    if (check_status(resp)) {
        json_decref(resp);
        return 1;
    }

    json_t *data = json_object_get(resp, "data");
    long long id = data ? json_integer_value(json_object_get(data, "id")) : -1;
    printf("Rule added with id=%lld\n", id);
    json_decref(resp);
    return 0;
}

/* удаление правила */
static int
do_rule_del(int argc, char **argv)
{
    const char *id_str = get_arg(argc, argv, "--id");
    if (!id_str) {
        fprintf(stderr, "fw_ctl: rule del: --id is required\n");
        return 1;
    }

    json_t *args = json_object();
    json_object_set_new(args, "id", json_integer(atoi(id_str)));

    json_t *resp = send_command("rule_del", args);
    if (check_status(resp)) { json_decref(resp); return 1; }

    printf("Rule %s deleted\n", id_str);
    json_decref(resp);
    return 0;
}

/* список правил */
static int
do_rule_list(void)
{
    json_t *resp = send_command("rule_list", NULL);
    if (check_status(resp)) { json_decref(resp); return 1; }

    json_t *data  = json_object_get(resp, "data");
    json_t *rules = data ? json_object_get(data, "rules") : NULL;
    long long cnt = data ? json_integer_value(json_object_get(data, "count")) : 0;

    printf("%lld rule(s):\n", cnt);
    print_rule_table(rules);
    json_decref(resp);
    return 0;
}

/* сброс всех правил */
static int
do_rule_flush(void)
{
    json_t *resp = send_command("rule_flush", NULL);
    if (check_status(resp)) { json_decref(resp); return 1; }
    printf("All rules flushed\n");
    json_decref(resp);
    return 0;
}

/* статистика */
static int
do_stats(void)
{
    json_t *resp = send_command("stats_get", NULL);
    if (check_status(resp)) { json_decref(resp); return 1; }
    print_stats(json_object_get(resp, "data"));
    json_decref(resp);
    return 0;
}

/* добавление в чёрный список */
static int
do_blacklist_add(int argc, char **argv)
{
    const char *ip = get_arg(argc, argv, "--ip");
    if (!ip) {
        fprintf(stderr, "fw_ctl: blacklist add: --ip is required\n");
        return 1;
    }

    json_t *args = json_object();
    json_object_set_new(args, "ip", json_string(ip));

    const char *dur = get_arg(argc, argv, "--duration");
    if (dur)
        json_object_set_new(args, "duration_s", json_integer(atoll(dur)));

    json_t *resp = send_command("blacklist_add", args);
    if (check_status(resp)) { json_decref(resp); return 1; }
    printf("IP %s added to blacklist\n", ip);
    json_decref(resp);
    return 0;
}

/* удаление из чёрного списка */
static int
do_blacklist_del(int argc, char **argv)
{
    const char *ip = get_arg(argc, argv, "--ip");
    if (!ip) {
        fprintf(stderr, "fw_ctl: blacklist del: --ip is required\n");
        return 1;
    }

    json_t *args = json_object();
    json_object_set_new(args, "ip", json_string(ip));

    json_t *resp = send_command("blacklist_del", args);
    if (check_status(resp)) { json_decref(resp); return 1; }
    printf("IP %s removed from blacklist\n", ip);
    json_decref(resp);
    return 0;
}

/* вывод чёрного списка */
static int
do_blacklist_list(void)
{
    json_t *resp = send_command("blacklist_list", NULL);
    if (check_status(resp)) { json_decref(resp); return 1; }
    print_blacklist(json_object_get(resp, "data"));
    json_decref(resp);
    return 0;
}

/* перезагрузка конфигурации */
static int
do_config_reload(void)
{
    json_t *resp = send_command("config_reload", NULL);
    if (check_status(resp)) { json_decref(resp); return 1; }
    printf("Configuration reloaded\n");
    json_decref(resp);
    return 0;
}

/* установка политики по умолчанию */
static int
do_set_policy(int argc, char **argv)
{
    /* Политика — первый аргумент без флага после "set-policy" */
    const char *policy = NULL;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != '-') { policy = argv[i]; break; }
    }

    if (!policy) {
        fprintf(stderr, "fw_ctl: set-policy: specify accept or drop\n");
        return 1;
    }

    json_t *args = json_object();
    json_object_set_new(args, "action", json_string(policy));

    json_t *resp = send_command("set_default_policy", args);
    if (check_status(resp)) { json_decref(resp); return 1; }
    printf("Default policy set to %s\n", policy);
    json_decref(resp);
    return 0;
}

/* ─── Диспетчеризация подкоманд ─────────────────────────────────────────── */

static void
usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s <subcommand> [options]\n"
        "\n"
        "Rule management:\n"
        "  rule add --action accept|drop|rate_limit [--proto tcp|udp|icmp|any]\n"
        "           [--src-ip CIDR] [--dst-ip CIDR]\n"
        "           [--src-port PORT|RANGE] [--dst-port PORT|RANGE]\n"
        "           [--priority N] [--rate-cir-kbps N] [--rate-cbs-bytes N]\n"
        "           [--comment TEXT]\n"
        "  rule del --id N\n"
        "  rule list\n"
        "  rule flush\n"
        "\n"
        "Statistics:\n"
        "  stats\n"
        "\n"
        "Blacklist:\n"
        "  blacklist add --ip X.X.X.X [--duration SECONDS]\n"
        "  blacklist del --ip X.X.X.X\n"
        "  blacklist list\n"
        "\n"
        "Configuration:\n"
        "  config reload\n"
        "  set-policy accept|drop\n",
        prog);
}

static int
do_rule(int argc, char **argv)
{
    /* argv[0]="rule", argv[1]=подкоманда */
    if (argc < 2) {
        fprintf(stderr, "fw_ctl: rule: expected add|del|list|flush\n");
        return 1;
    }
    const char *sub = argv[1];
    if (strcmp(sub, "add")   == 0) return do_rule_add(argc - 1, argv + 1);
    if (strcmp(sub, "del")   == 0) return do_rule_del(argc - 1, argv + 1);
    if (strcmp(sub, "list")  == 0) return do_rule_list();
    if (strcmp(sub, "flush") == 0) return do_rule_flush();
    fprintf(stderr, "fw_ctl: rule: unknown subcommand '%s'\n", sub);
    return 1;
}

static int
do_blacklist(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "fw_ctl: blacklist: expected add|del|list\n");
        return 1;
    }
    const char *sub = argv[1];
    if (strcmp(sub, "add")  == 0) return do_blacklist_add(argc - 1, argv + 1);
    if (strcmp(sub, "del")  == 0) return do_blacklist_del(argc - 1, argv + 1);
    if (strcmp(sub, "list") == 0) return do_blacklist_list();
    fprintf(stderr, "fw_ctl: blacklist: unknown subcommand '%s'\n", sub);
    return 1;
}

static int
do_config(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "fw_ctl: config: expected reload\n");
        return 1;
    }
    if (strcmp(argv[1], "reload") == 0) return do_config_reload();
    fprintf(stderr, "fw_ctl: config: unknown subcommand '%s'\n", argv[1]);
    return 1;
}

/* ─── Точка входа ────────────────────────────────────────────────────────── */

int
main(int argc, char *argv[])
{
    if (argc < 2) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    /* Передать оставшиеся аргументы (argv+1, argc-1), где argv[0] — подкоманда */
    const char *cmd   = argv[1];
    int         sargc = argc - 1;
    char      **sargv = argv + 1;

    if (strcmp(cmd, "rule")       == 0) return do_rule(sargc, sargv);
    if (strcmp(cmd, "stats")      == 0) return do_stats();
    if (strcmp(cmd, "blacklist")  == 0) return do_blacklist(sargc, sargv);
    if (strcmp(cmd, "config")     == 0) return do_config(sargc, sargv);
    if (strcmp(cmd, "set-policy") == 0) return do_set_policy(sargc, sargv);

    fprintf(stderr, "fw_ctl: unknown command '%s'\n", cmd);
    usage(argv[0]);
    return EXIT_FAILURE;
}
