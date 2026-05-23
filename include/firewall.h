#ifndef FIREWALL_H
#define FIREWALL_H

#include <stdint.h>
#include <stdalign.h>

/* ─── Типы действий ────────────────────────────────────────────────────── */

typedef enum {
    ACTION_ACCEPT     = 0,
    ACTION_DROP       = 1,
    ACTION_RATE_LIMIT = 2,
} fw_action_t;

/* ─── Метаданные пакета (заполняется на этапе CLASSIFIER) ──────────────── */

struct pkt_meta {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;       /* IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP */
    uint8_t  tcp_flags;   /* TCP-флаги: SYN, ACK, RST, FIN, PSH, URG */
    uint8_t  icmp_type;
    uint8_t  icmp_code;
    uint8_t  is_ipv4;     /* 1 = IPv4; 0 = не IPv4 (передаётся как есть) */
};

/* Битовые маски TCP-флагов (значения совпадают с rte_tcp.h) */
#define TCP_FLAG_FIN  0x01
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_PSH  0x08
#define TCP_FLAG_ACK  0x10
#define TCP_FLAG_URG  0x20

/* ─── Правило межсетевого экрана ────────────────────────────────────────── */

#ifndef MAX_RULES
#define MAX_RULES 1024
#endif

struct fw_rule {
    uint32_t    id;
    uint32_t    priority;       /* меньшее число = более высокий приоритет (rte_acl) */
    uint32_t    src_ip;
    uint32_t    src_mask;       /* 0 = wildcard (совпадает с любым) */
    uint32_t    dst_ip;
    uint32_t    dst_mask;
    uint16_t    src_port_min;
    uint16_t    src_port_max;   /* == src_port_min при точном совпадении */
    uint16_t    dst_port_min;
    uint16_t    dst_port_max;
    uint8_t     proto;          /* 0 = любой */
    uint8_t     tcp_flags_mask;
    uint8_t     tcp_flags_val;
    uint8_t     icmp_type;      /* 255 = любой */
    uint8_t     icmp_code;      /* 255 = любой */
    fw_action_t action;
    uint64_t    rate_cir;       /* байт/с, только для RATE_LIMIT */
    uint64_t    rate_cbs;       /* пиковый размер в байтах, только для RATE_LIMIT */

    /* Статистика на правило — выровнена по линии кэша для избежания ложного разделения */
    alignas(64) uint64_t pkt_count;
    uint64_t    byte_count;

    char        comment[64];
};

/* ─── Глобальное состояние (определено в main.c / config.c) ────────────── */

/* Политика по умолчанию, применяемая когда ни одно правило не совпало */
extern volatile fw_action_t g_default_policy;

/* Устанавливается в 1 обработчиком SIGINT/SIGTERM; lcores пересылки опрашивают это поле */
extern volatile int g_force_quit;

#endif /* FIREWALL_H */
