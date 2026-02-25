#ifndef FIREWALL_H
#define FIREWALL_H

#include <stdint.h>
#include <stdalign.h>

/* ─── Action types ─────────────────────────────────────────────────────── */

typedef enum {
    ACTION_ACCEPT     = 0,
    ACTION_DROP       = 1,
    ACTION_RATE_LIMIT = 2,
} fw_action_t;

/* ─── Packet metadata (filled by CLASSIFIER stage) ─────────────────────── */

struct pkt_meta {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;       /* IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP */
    uint8_t  tcp_flags;   /* TCP flags: SYN, ACK, RST, FIN, PSH, URG */
    uint8_t  icmp_type;
    uint8_t  icmp_code;
    uint8_t  is_ipv4;     /* 1 = IPv4; 0 = non-IPv4 (forward as-is) */
};

/* TCP flag bitmasks (matching values in rte_tcp.h) */
#define TCP_FLAG_FIN  0x01
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_PSH  0x08
#define TCP_FLAG_ACK  0x10
#define TCP_FLAG_URG  0x20

/* ─── Firewall rule ─────────────────────────────────────────────────────── */

#ifndef MAX_RULES
#define MAX_RULES 1024
#endif

struct fw_rule {
    uint32_t    id;
    uint32_t    priority;       /* lower number = higher priority (rte_acl) */
    uint32_t    src_ip;
    uint32_t    src_mask;       /* 0 = wildcard (match any) */
    uint32_t    dst_ip;
    uint32_t    dst_mask;
    uint16_t    src_port_min;
    uint16_t    src_port_max;   /* == src_port_min for exact match */
    uint16_t    dst_port_min;
    uint16_t    dst_port_max;
    uint8_t     proto;          /* 0 = any */
    uint8_t     tcp_flags_mask;
    uint8_t     tcp_flags_val;
    uint8_t     icmp_type;      /* 255 = any */
    uint8_t     icmp_code;      /* 255 = any */
    fw_action_t action;
    uint64_t    rate_cir;       /* bytes/sec, RATE_LIMIT only */
    uint64_t    rate_cbs;       /* burst bytes, RATE_LIMIT only */

    /* Per-rule statistics — cache-line aligned to avoid false sharing */
    alignas(64) uint64_t pkt_count;
    uint64_t    byte_count;

    char        comment[64];
};

/* ─── Global state (defined in main.c / config.c) ──────────────────────── */

/* Default policy applied when no rule matches */
extern volatile fw_action_t g_default_policy;

/* Set to 1 by SIGINT/SIGTERM handler; forwarding lcores poll this */
extern volatile int g_force_quit;

#endif /* FIREWALL_H */
