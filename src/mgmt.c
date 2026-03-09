/*
 * src/mgmt.c — Control-plane management server (P4-02, P4-03)
 *
 * UNIX domain socket at /var/run/dpdk_firewall/mgmt.sock.
 * Protocol: newline-delimited JSON, one command per connection.
 *   Request:  {"cmd": "<name>", "args": {...}}\n
 *   Response: {"status": "ok"|"error", "data": {...}, "msg": "<text>"}\n
 *
 * Runs on lcore 0 in an epoll loop (100 ms timeout) so it can also:
 *   - Check g_sighup_flag and perform hot-reload
 *   - Call stats_periodic_dump() every 5 seconds
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <jansson.h>

#include <rte_cycles.h>

#include "mgmt.h"
#include "firewall.h"
#include "config.h"
#include "stats.h"
#include "rule_engine.h"
#include "ddos.h"
#include "log.h"

/* ─── Constants ──────────────────────────────────────────────────────────── */

#define SOCK_DIR    "/var/run/dpdk_firewall"
#define SOCK_PATH   "/var/run/dpdk_firewall/mgmt.sock"
#define BACKLOG     8
#define REQ_BUF_SZ  4096

/* ─── IP helpers ─────────────────────────────────────────────────────────── */

/*
 * All IPs in rule_engine / ddos are in host byte order (HBo).
 * inet_ntop/inet_pton work with network byte order (NBO).
 * Conversion: HBo → htonl() → NBO for printing; NBO → ntohl() → HBo for storing.
 */

static void
ip_hbo_to_str(uint32_t ip_hbo, char *buf, size_t sz)
{
    struct in_addr a;
    a.s_addr = htonl(ip_hbo);
    inet_ntop(AF_INET, &a, buf, (socklen_t)sz);
}

static int
ip_str_to_hbo(const char *s, uint32_t *out)
{
    struct in_addr a;
    if (inet_pton(AF_INET, s, &a) != 1)
        return -1;
    *out = ntohl(a.s_addr);
    return 0;
}

/*
 * Parse "1.2.3.4/24" or "1.2.3.4" (implies /32).
 * Stores result in host byte order.
 */
static int
parse_cidr_str(const char *s, uint32_t *ip_out, uint32_t *mask_out)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%s", s);

    int prefix = 32;
    char *slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        prefix = atoi(slash + 1);
        if (prefix < 0 || prefix > 32)
            return -1;
    }

    struct in_addr a;
    if (inet_pton(AF_INET, buf, &a) != 1)
        return -1;

    *ip_out   = ntohl(a.s_addr);   /* HBo */
    *mask_out = (prefix == 0) ? 0u : (~0u << (32 - prefix));
    return 0;
}

/* Parse "80" or "1024-65535" → min, max */
static int
parse_port_range(const char *s, uint16_t *min_out, uint16_t *max_out)
{
    char *dash = strchr(s, '-');
    if (dash) {
        char lo[8] = {0};
        int n = (int)(dash - s);
        if (n <= 0 || n >= (int)sizeof(lo))
            return -1;
        memcpy(lo, s, (size_t)n);
        *min_out = (uint16_t)atoi(lo);
        *max_out = (uint16_t)atoi(dash + 1);
    } else {
        uint16_t p = (uint16_t)atoi(s);
        *min_out = *max_out = p;
    }
    return 0;
}

/* ─── JSON response builders ─────────────────────────────────────────────── */

static json_t *
make_ok(json_t *data)
{
    json_t *r = json_object();
    json_object_set_new(r, "status", json_string("ok"));
    if (data)
        json_object_set_new(r, "data", data);
    return r;
}

static json_t *
make_error(const char *msg)
{
    json_t *r = json_object();
    json_object_set_new(r, "status", json_string("error"));
    json_object_set_new(r, "msg",    json_string(msg ? msg : "unknown error"));
    return r;
}

/* ─── Rule ↔ JSON conversion ─────────────────────────────────────────────── */

static const char *
action_to_str(fw_action_t a)
{
    switch (a) {
    case ACTION_ACCEPT:     return "accept";
    case ACTION_DROP:       return "drop";
    case ACTION_RATE_LIMIT: return "rate_limit";
    default:                return "unknown";
    }
}

static json_t *
rule_to_json(const struct fw_rule *r)
{
    char ip_buf[INET_ADDRSTRLEN];
    char src_cidr[32], dst_cidr[32];

    ip_hbo_to_str(r->src_ip, ip_buf, sizeof(ip_buf));
    uint8_t sp = r->src_mask ? (uint8_t)(32 - __builtin_ctz(r->src_mask)) : 0;
    snprintf(src_cidr, sizeof(src_cidr), "%s/%u", ip_buf, sp);

    ip_hbo_to_str(r->dst_ip, ip_buf, sizeof(ip_buf));
    uint8_t dp = r->dst_mask ? (uint8_t)(32 - __builtin_ctz(r->dst_mask)) : 0;
    snprintf(dst_cidr, sizeof(dst_cidr), "%s/%u", ip_buf, dp);

    json_t *j = json_object();
    json_object_set_new(j, "id",           json_integer(r->id));
    json_object_set_new(j, "priority",     json_integer(r->priority));
    json_object_set_new(j, "src_ip",       json_string(src_cidr));
    json_object_set_new(j, "dst_ip",       json_string(dst_cidr));
    json_object_set_new(j, "src_port_min", json_integer(r->src_port_min));
    json_object_set_new(j, "src_port_max", json_integer(r->src_port_max));
    json_object_set_new(j, "dst_port_min", json_integer(r->dst_port_min));
    json_object_set_new(j, "dst_port_max", json_integer(r->dst_port_max));
    json_object_set_new(j, "proto",        json_integer(r->proto));
    json_object_set_new(j, "action",       json_string(action_to_str(r->action)));
    json_object_set_new(j, "rate_cir",     json_integer((json_int_t)r->rate_cir));
    json_object_set_new(j, "rate_cbs",     json_integer((json_int_t)r->rate_cbs));
    json_object_set_new(j, "pkt_count",    json_integer((json_int_t)r->pkt_count));
    json_object_set_new(j, "byte_count",   json_integer((json_int_t)r->byte_count));
    json_object_set_new(j, "comment",      json_string(r->comment));
    return j;
}

/*
 * Parse a fw_rule from JSON args (rule_add command).
 * All fields are optional except "action".
 */
static int
json_to_fw_rule(json_t *args, struct fw_rule *r)
{
    memset(r, 0, sizeof(*r));
    /* Defaults: wildcard ports, any ICMP type/code */
    r->src_port_max = 65535;
    r->dst_port_max = 65535;
    r->icmp_type    = 255;
    r->icmp_code    = 255;
    r->priority     = 100;

    json_t *j;

    /* proto */
    j = json_object_get(args, "proto");
    if (j && json_is_string(j)) {
        const char *p = json_string_value(j);
        if      (strcasecmp(p, "tcp")  == 0) r->proto = IPPROTO_TCP;
        else if (strcasecmp(p, "udp")  == 0) r->proto = IPPROTO_UDP;
        else if (strcasecmp(p, "icmp") == 0) r->proto = IPPROTO_ICMP;
        else if (strcasecmp(p, "any")  != 0) return -1;  /* "any" → 0 */
    }

    /* src_ip (CIDR string) */
    j = json_object_get(args, "src_ip");
    if (j && json_is_string(j)) {
        if (parse_cidr_str(json_string_value(j), &r->src_ip, &r->src_mask) != 0)
            return -1;
    }

    /* dst_ip (CIDR string) */
    j = json_object_get(args, "dst_ip");
    if (j && json_is_string(j)) {
        if (parse_cidr_str(json_string_value(j), &r->dst_ip, &r->dst_mask) != 0)
            return -1;
    }

    /* src_port (string: "80" or "1024-65535") */
    j = json_object_get(args, "src_port");
    if (j && json_is_string(j)) {
        if (parse_port_range(json_string_value(j),
                             &r->src_port_min, &r->src_port_max) != 0)
            return -1;
    }

    /* dst_port */
    j = json_object_get(args, "dst_port");
    if (j && json_is_string(j)) {
        if (parse_port_range(json_string_value(j),
                             &r->dst_port_min, &r->dst_port_max) != 0)
            return -1;
    }

    /* priority */
    j = json_object_get(args, "priority");
    if (j && json_is_integer(j))
        r->priority = (uint32_t)json_integer_value(j);

    /* action (required) */
    j = json_object_get(args, "action");
    if (!j || !json_is_string(j))
        return -1;
    const char *act = json_string_value(j);
    if      (strcasecmp(act, "accept")     == 0) r->action = ACTION_ACCEPT;
    else if (strcasecmp(act, "drop")       == 0) r->action = ACTION_DROP;
    else if (strcasecmp(act, "rate_limit") == 0) r->action = ACTION_RATE_LIMIT;
    else return -1;

    /* rate_cir_kbps → bytes/sec */
    j = json_object_get(args, "rate_cir_kbps");
    if (j && json_is_integer(j))
        r->rate_cir = (uint64_t)json_integer_value(j) * 1000 / 8;

    /* rate_cbs_bytes */
    j = json_object_get(args, "rate_cbs_bytes");
    if (j && json_is_integer(j))
        r->rate_cbs = (uint64_t)json_integer_value(j);

    /* comment */
    j = json_object_get(args, "comment");
    if (j && json_is_string(j))
        snprintf(r->comment, sizeof(r->comment), "%s", json_string_value(j));

    return 0;
}

/* ─── Command handlers ───────────────────────────────────────────────────── */

/* 1. rule_add */
static json_t *
cmd_rule_add(json_t *args)
{
    if (!args)
        return make_error("args required");

    struct fw_rule r;
    if (json_to_fw_rule(args, &r) != 0)
        return make_error("invalid rule parameters");

    int rc = rule_add(&r);
    if (rc < 0) {
        char msg[64];
        snprintf(msg, sizeof(msg), "rule_add failed: %d", rc);
        return make_error(msg);
    }

    /* rc is the assigned rule ID on success */
    json_t *data = json_object();
    json_object_set_new(data, "id", json_integer(rc));
    return make_ok(data);
}

/* 2. rule_del */
static json_t *
cmd_rule_del(json_t *args)
{
    if (!args)
        return make_error("args required");

    json_t *j = json_object_get(args, "id");
    if (!j || !json_is_integer(j))
        return make_error("id (integer) required");

    uint32_t id = (uint32_t)json_integer_value(j);
    int rc = rule_del(id);
    if (rc != 0) {
        char msg[64];
        snprintf(msg, sizeof(msg), "rule_del failed (id=%u): %d", id, rc);
        return make_error(msg);
    }
    return make_ok(NULL);
}

/* 3. rule_list */
static json_t *
cmd_rule_list(json_t *args)
{
    (void)args;

    struct fw_rule rules[MAX_RULES];
    uint32_t n = 0;
    if (rule_list(rules, &n) != 0)
        return make_error("rule_list failed");

    json_t *arr = json_array();
    for (uint32_t i = 0; i < n; i++)
        json_array_append_new(arr, rule_to_json(&rules[i]));

    json_t *data = json_object();
    json_object_set_new(data, "rules", arr);
    json_object_set_new(data, "count", json_integer(n));
    return make_ok(data);
}

/* 4. rule_flush */
static json_t *
cmd_rule_flush(json_t *args)
{
    (void)args;
    int rc = rule_flush();
    if (rc != 0)
        return make_error("rule_flush failed");
    return make_ok(NULL);
}

/* 5. stats_get */
static json_t *
cmd_stats_get(json_t *args)
{
    (void)args;

    struct fw_stats_snapshot snap;
    stats_get_snapshot(&snap);

    json_t *data = json_object();
    json_object_set_new(data, "rx_pkts",      json_integer((json_int_t)snap.total_rx_pkts));
    json_object_set_new(data, "tx_pkts",      json_integer((json_int_t)snap.total_tx_pkts));
    json_object_set_new(data, "dropped_pkts", json_integer((json_int_t)snap.total_dropped_pkts));
    json_object_set_new(data, "rx_bytes",     json_integer((json_int_t)snap.total_rx_bytes));
    json_object_set_new(data, "tx_bytes",     json_integer((json_int_t)snap.total_tx_bytes));

    json_t *ports = json_array();
    for (int i = 0; i < FW_MAX_PORTS; i++) {
        json_t *p = json_object();
        json_object_set_new(p, "port",     json_integer(i));
        json_object_set_new(p, "ipackets", json_integer((json_int_t)snap.port_stats[i].ipackets));
        json_object_set_new(p, "opackets", json_integer((json_int_t)snap.port_stats[i].opackets));
        json_object_set_new(p, "ibytes",   json_integer((json_int_t)snap.port_stats[i].ibytes));
        json_object_set_new(p, "obytes",   json_integer((json_int_t)snap.port_stats[i].obytes));
        json_object_set_new(p, "imissed",  json_integer((json_int_t)snap.port_stats[i].imissed));
        json_object_set_new(p, "ierrors",  json_integer((json_int_t)snap.port_stats[i].ierrors));
        json_object_set_new(p, "oerrors",  json_integer((json_int_t)snap.port_stats[i].oerrors));
        json_array_append_new(ports, p);
    }
    json_object_set_new(data, "ports", ports);
    return make_ok(data);
}

/* 6. blacklist_add */
static json_t *
cmd_blacklist_add(json_t *args)
{
    if (!args)
        return make_error("args required");

    json_t *j = json_object_get(args, "ip");
    if (!j || !json_is_string(j))
        return make_error("ip (string) required");

    uint32_t ip_hbo;
    if (ip_str_to_hbo(json_string_value(j), &ip_hbo) != 0)
        return make_error("invalid ip address");

    uint64_t duration_s = 300;   /* default 5 minutes */
    j = json_object_get(args, "duration_s");
    if (j && json_is_integer(j))
        duration_s = (uint64_t)json_integer_value(j);

    uint64_t expire_cycles = rte_get_tsc_cycles() + duration_s * rte_get_tsc_hz();
    blacklist_add(ip_hbo, expire_cycles);
    return make_ok(NULL);
}

/* 7. blacklist_del */
static json_t *
cmd_blacklist_del(json_t *args)
{
    if (!args)
        return make_error("args required");

    json_t *j = json_object_get(args, "ip");
    if (!j || !json_is_string(j))
        return make_error("ip (string) required");

    uint32_t ip_hbo;
    if (ip_str_to_hbo(json_string_value(j), &ip_hbo) != 0)
        return make_error("invalid ip address");

    blacklist_del(ip_hbo);
    return make_ok(NULL);
}

/* 8. blacklist_list */
static json_t *
cmd_blacklist_list(json_t *args)
{
    (void)args;

#define BL_MAX 65536
    uint32_t *ips     = malloc(BL_MAX * sizeof(uint32_t));
    uint64_t *expires = malloc(BL_MAX * sizeof(uint64_t));
    if (!ips || !expires) {
        free(ips);
        free(expires);
        return make_error("out of memory");
    }

    uint32_t n = 0;
    blacklist_list(ips, expires, &n);

    uint64_t now_cycles = rte_get_tsc_cycles();
    uint64_t hz         = rte_get_tsc_hz();

    json_t *arr = json_array();
    char ip_buf[INET_ADDRSTRLEN];
    for (uint32_t i = 0; i < n; i++) {
        ip_hbo_to_str(ips[i], ip_buf, sizeof(ip_buf));
        uint64_t ttl_s = (expires[i] > now_cycles)
                         ? (expires[i] - now_cycles) / hz : 0;
        json_t *e = json_object();
        json_object_set_new(e, "ip",    json_string(ip_buf));
        json_object_set_new(e, "ttl_s", json_integer((json_int_t)ttl_s));
        json_array_append_new(arr, e);
    }

    free(ips);
    free(expires);
#undef BL_MAX

    json_t *data = json_object();
    json_object_set_new(data, "blacklist", arr);
    json_object_set_new(data, "count",     json_integer(n));
    return make_ok(data);
}

/* 9. config_reload */
static json_t *
cmd_config_reload(json_t *args)
{
    (void)args;
    int rc = config_reload();
    if (rc != 0)
        return make_error("config_reload failed");
    /* Re-initialize meters for any new RATE_LIMIT rules */
    meter_init_all();
    return make_ok(NULL);
}

/* 10. set_default_policy */
static json_t *
cmd_set_default_policy(json_t *args)
{
    if (!args)
        return make_error("args required");

    json_t *j = json_object_get(args, "action");
    if (!j || !json_is_string(j))
        return make_error("action (\"accept\" or \"drop\") required");

    const char *act = json_string_value(j);
    fw_action_t new_policy;
    if      (strcasecmp(act, "accept") == 0) new_policy = ACTION_ACCEPT;
    else if (strcasecmp(act, "drop")   == 0) new_policy = ACTION_DROP;
    else return make_error("action must be \"accept\" or \"drop\"");

    /* g_default_policy is volatile — simple assignment is safe on lcore 0 */
    g_default_policy = new_policy;
    RTE_LOG_FW_INFO("mgmt: default policy set to %s\n", act);
    return make_ok(NULL);
}

/* ─── Command dispatch table ─────────────────────────────────────────────── */

typedef json_t *(*cmd_fn_t)(json_t *args);

static const struct {
    const char *name;
    cmd_fn_t    fn;
} cmd_table[] = {
    { "rule_add",           cmd_rule_add           },
    { "rule_del",           cmd_rule_del           },
    { "rule_list",          cmd_rule_list          },
    { "rule_flush",         cmd_rule_flush         },
    { "stats_get",          cmd_stats_get          },
    { "blacklist_add",      cmd_blacklist_add      },
    { "blacklist_del",      cmd_blacklist_del      },
    { "blacklist_list",     cmd_blacklist_list     },
    { "config_reload",      cmd_config_reload      },
    { "set_default_policy", cmd_set_default_policy },
};

static json_t *
dispatch(const char *cmd, json_t *args)
{
    for (size_t i = 0; i < sizeof(cmd_table) / sizeof(cmd_table[0]); i++) {
        if (strcmp(cmd, cmd_table[i].name) == 0)
            return cmd_table[i].fn(args);
    }
    char msg[80];
    snprintf(msg, sizeof(msg), "unknown command: %.64s", cmd);
    return make_error(msg);
}

/* ─── Per-connection handler ─────────────────────────────────────────────── */

static void
handle_client(int fd)
{
    /* 500 ms receive timeout */
    struct timeval tv = { .tv_sec = 0, .tv_usec = 500000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char buf[REQ_BUF_SZ];
    ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) {
        close(fd);
        return;
    }
    buf[n] = '\0';

    /* Strip trailing newline/whitespace */
    char *nl = strchr(buf, '\n');
    if (nl)
        *nl = '\0';

    json_error_t jerr;
    json_t *req = json_loads(buf, 0, &jerr);
    json_t *resp;

    if (!req) {
        resp = make_error("invalid JSON");
    } else {
        json_t *jcmd = json_object_get(req, "cmd");
        if (!jcmd || !json_is_string(jcmd)) {
            resp = make_error("missing or invalid 'cmd' field");
        } else {
            const char *cmd = json_string_value(jcmd);
            json_t      *args = json_object_get(req, "args");
            resp = dispatch(cmd, args);
        }
        json_decref(req);
    }

    /* Serialize and send response followed by newline */
    char *resp_str = json_dumps(resp, JSON_COMPACT);
    json_decref(resp);

    if (resp_str) {
        send(fd, resp_str, strlen(resp_str), MSG_NOSIGNAL);
        send(fd, "\n", 1, MSG_NOSIGNAL);
        free(resp_str);
    }

    close(fd);
}

/* ─── Server socket setup ────────────────────────────────────────────────── */

static int
create_server_socket(void)
{
    mkdir(SOCK_DIR, 0750);
    unlink(SOCK_PATH);    /* remove stale socket from previous run */

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        RTE_LOG_FW_ERR("mgmt: socket() failed: %s\n", strerror(errno));
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", SOCK_PATH);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        RTE_LOG_FW_ERR("mgmt: bind(%s) failed: %s\n", SOCK_PATH, strerror(errno));
        close(fd);
        return -1;
    }

    chmod(SOCK_PATH, 0660);

    if (listen(fd, BACKLOG) < 0) {
        RTE_LOG_FW_ERR("mgmt: listen() failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

/* ─── Fallback loop (no socket) ──────────────────────────────────────────── */

static void
fallback_loop(void)
{
    RTE_LOG_FW_WARN("mgmt: running in fallback mode (no socket)\n");
    uint64_t elapsed_us = 0;
    while (!g_force_quit) {
        usleep(100000);
        elapsed_us += 100000;
        if (g_sighup_flag) {
            g_sighup_flag = 0;
            config_reload();
            meter_init_all();
        }
        if (elapsed_us >= 5000000ULL) {
            stats_periodic_dump();
            elapsed_us = 0;
        }
    }
}

/* ─── Main control-plane loop ────────────────────────────────────────────── */

void
mgmt_server_run(void)
{
    RTE_LOG_FW_INFO("mgmt: starting control plane (socket: %s)\n", SOCK_PATH);

    int server_fd = create_server_socket();
    if (server_fd < 0) {
        fallback_loop();
        return;
    }

    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) {
        RTE_LOG_FW_ERR("mgmt: epoll_create1 failed: %s\n", strerror(errno));
        close(server_fd);
        fallback_loop();
        return;
    }

    struct epoll_event ev = {
        .events  = EPOLLIN,
        .data.fd = server_fd,
    };
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev);

    const uint64_t hz            = rte_get_tsc_hz();
    const uint64_t dump_interval = 5 * hz;
    uint64_t       last_dump     = rte_get_tsc_cycles();

    RTE_LOG_FW_INFO("mgmt: listening on %s\n", SOCK_PATH);

    while (!g_force_quit) {

        /* Hot-reload on SIGHUP */
        if (g_sighup_flag) {
            g_sighup_flag = 0;
            RTE_LOG_FW_INFO("mgmt: SIGHUP received — reloading config\n");
            config_reload();
            meter_init_all();
        }

        /* Periodic stats dump every 5 seconds */
        uint64_t now = rte_get_tsc_cycles();
        if (now - last_dump >= dump_interval) {
            stats_periodic_dump();
            last_dump = now;
        }

        /* Wait for new connection (100 ms timeout to stay responsive) */
        struct epoll_event events[1];
        int n = epoll_wait(epoll_fd, events, 1, 100);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            RTE_LOG_FW_ERR("mgmt: epoll_wait error: %s\n", strerror(errno));
            break;
        }
        if (n == 0)
            continue;

        int client_fd = accept4(server_fd, NULL, NULL, SOCK_CLOEXEC);
        if (client_fd < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                RTE_LOG_FW_WARN("mgmt: accept4 failed: %s\n", strerror(errno));
            continue;
        }

        handle_client(client_fd);
    }

    close(epoll_fd);
    close(server_fd);
    unlink(SOCK_PATH);

    RTE_LOG_FW_INFO("mgmt: control plane exiting\n");
}
