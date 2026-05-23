#include <string.h>
#include <arpa/inet.h>
#include <errno.h>

#include <rte_acl.h>
#include <rte_malloc.h>
#include <rte_rwlock.h>
#include <rte_lcore.h>

#include "rule_engine.h"
#include "config.h"
#include "firewall.h"
#include "log.h"

/* ─── Определения полей ACL ─────────────────────────────────────────────── */

#define FW_NUM_ACL_FIELDS     5
#define FW_NUM_ACL_CATEGORIES 1

enum acl_field_idx {
    ACL_FIELD_SRC_IP   = 0,
    ACL_FIELD_DST_IP   = 1,
    ACL_FIELD_SRC_PORT = 2,
    ACL_FIELD_DST_PORT = 3,
    ACL_FIELD_PROTO    = 4,
};

/*
 * Поля расположены по фиксированным смещениям внутри struct pkt_meta:
 *
 *   src_ip   : смещение  0, 4 байта  (MASK)    — порядок байт хоста (rte_acl MASK требует HBo)
 *   dst_ip   : смещение  4, 4 байта  (MASK)    — порядок байт хоста
 *   src_port : смещение  8, 2 байта  (RANGE)   — порядок байт хоста (для корректного сравнения диапазона)
 *   dst_port : смещение 10, 2 байта  (RANGE)   — порядок байт хоста
 *   proto    : смещение 12, 1 байт   (BITMASK)
 *
 * Группы input_index должны быть выровнены по 4 байтам и идти непрерывно:
 *   группа 0 → src_ip   (байты  0-3)
 *   группа 1 → dst_ip   (байты  4-7)
 *   группа 2 → src_port + dst_port (байты 8-11)
 *   группа 3 → proto    (байт  12; байты 13-15 — выравнивание)
 */
static const struct rte_acl_field_def fw_acl_defs[FW_NUM_ACL_FIELDS] = {
    [ACL_FIELD_SRC_IP] = {
        .type        = RTE_ACL_FIELD_TYPE_MASK,
        .size        = sizeof(uint32_t),
        .field_index = ACL_FIELD_SRC_IP,
        .input_index = 0,
        .offset      = offsetof(struct pkt_meta, src_ip),
    },
    [ACL_FIELD_DST_IP] = {
        .type        = RTE_ACL_FIELD_TYPE_MASK,
        .size        = sizeof(uint32_t),
        .field_index = ACL_FIELD_DST_IP,
        .input_index = 1,
        .offset      = offsetof(struct pkt_meta, dst_ip),
    },
    [ACL_FIELD_SRC_PORT] = {
        .type        = RTE_ACL_FIELD_TYPE_RANGE,
        .size        = sizeof(uint16_t),
        .field_index = ACL_FIELD_SRC_PORT,
        .input_index = 2,
        .offset      = offsetof(struct pkt_meta, src_port),
    },
    [ACL_FIELD_DST_PORT] = {
        .type        = RTE_ACL_FIELD_TYPE_RANGE,
        .size        = sizeof(uint16_t),
        .field_index = ACL_FIELD_DST_PORT,
        .input_index = 2,
        .offset      = offsetof(struct pkt_meta, dst_port),
    },
    [ACL_FIELD_PROTO] = {
        .type        = RTE_ACL_FIELD_TYPE_BITMASK,
        .size        = sizeof(uint8_t),
        .field_index = ACL_FIELD_PROTO,
        .input_index = 3,
        .offset      = offsetof(struct pkt_meta, proto),
    },
};

/* Структура ACL-правила с 5 полями */
RTE_ACL_RULE_DEF(fw_acl_rule, FW_NUM_ACL_FIELDS);

/* ─── Глобальное состояние ──────────────────────────────────────────────── */

static struct fw_rule      g_rules[MAX_RULES];
static uint32_t            g_n_rules;
static uint32_t            g_next_id;        /* монотонно возрастающий ID правила */
static struct rte_acl_ctx *g_acl_ctx;
static rte_rwlock_t        g_acl_rwlock;
static uint32_t            g_rebuild_count;  /* уникальный суффикс для имени ACL-контекста */

/* ─── Внутренние вспомогательные функции ────────────────────────────────── */

/*
 * Преобразовать маску подсети в порядке байт хоста в длину префикса.
 *
 * fw_rule хранит маски как HBo uint32_t (после исправления NBO→HBo в parse_cidr):
 *   /24 → mask = 0xFFFFFF00 (HBo) → 8 нулевых бит в конце → prefix = 32 - 8 = 24
 */
static uint8_t
mask_to_prefix(uint32_t mask_hbo)
{
    if (mask_hbo == 0)
        return 0;
    return (uint8_t)(32 - __builtin_ctz(mask_hbo));
}

/*
 * Заполнить rte_acl_rule из fw_rule.
 * idx: позиция в g_rules[] с нуля; userdata = idx+1, поэтому 0 означает "нет совпадения".
 */
static void
fw_rule_to_acl(const struct fw_rule *r, uint32_t idx, struct fw_acl_rule *ar)
{
    memset(ar, 0, sizeof(*ar));

    /*
     * Приоритет: fw_rule использует "меньшее число = более высокий приоритет".
     * rte_acl использует "большее значение побеждает". Сопоставление инверсией.
     */
    ar->data.priority      = RTE_ACL_MAX_PRIORITY - r->priority;
    ar->data.userdata      = idx + 1;   /* с единицы; 0 зарезервирован для "нет совпадения" */
    ar->data.category_mask = 0x1;       /* одна категория */

    /* src_ip — HBo, MASK (rte_acl MASK применяет префикс от MSB целого числа → нужен HBo) */
    ar->field[ACL_FIELD_SRC_IP].value.u32     = r->src_ip;
    ar->field[ACL_FIELD_SRC_IP].mask_range.u8 = mask_to_prefix(r->src_mask);

    /* dst_ip — HBo, MASK (порядок байт хоста) */
    ar->field[ACL_FIELD_DST_IP].value.u32     = r->dst_ip;
    ar->field[ACL_FIELD_DST_IP].mask_range.u8 = mask_to_prefix(r->dst_mask);

    /* src_port — HBo, RANGE [min, max] */
    ar->field[ACL_FIELD_SRC_PORT].value.u16      = r->src_port_min;
    ar->field[ACL_FIELD_SRC_PORT].mask_range.u16 = r->src_port_max;

    /* dst_port — HBo, RANGE [min, max] */
    ar->field[ACL_FIELD_DST_PORT].value.u16      = r->dst_port_min;
    ar->field[ACL_FIELD_DST_PORT].mask_range.u16 = r->dst_port_max;

    /* proto — BITMASK; proto=0 означает любой (mask=0 совпадает со всеми значениями) */
    if (r->proto == 0) {
        ar->field[ACL_FIELD_PROTO].value.u8      = 0;
        ar->field[ACL_FIELD_PROTO].mask_range.u8 = 0;
    } else {
        ar->field[ACL_FIELD_PROTO].value.u8      = r->proto;
        ar->field[ACL_FIELD_PROTO].mask_range.u8 = 0xFF;
    }
}

/*
 * Создать и скомпилировать новый rte_acl_ctx из g_rules[0..g_n_rules-1].
 * Возвращает NULL если g_n_rules == 0 (вызывающий трактует это как "применить политику по умолчанию").
 */
static struct rte_acl_ctx *
build_acl_ctx(void)
{
    if (g_n_rules == 0)
        return NULL;

    char name[RTE_ACL_NAMESIZE];
    snprintf(name, sizeof(name), "fw_acl_%u", g_rebuild_count++);

    struct rte_acl_param prm = {
        .name         = name,
        .socket_id    = rte_socket_id(),
        .rule_size    = RTE_ACL_RULE_SZ(FW_NUM_ACL_FIELDS),
        .max_rule_num = MAX_RULES + 1,
    };

    struct rte_acl_ctx *ctx = rte_acl_create(&prm);
    if (ctx == NULL) {
        RTE_LOG_FW_ERR("rte_acl_create failed\n");
        return NULL;
    }

    /* Выделить временный массив ACL-правил */
    struct fw_acl_rule *acl_rules = rte_malloc(NULL,
        sizeof(struct fw_acl_rule) * g_n_rules, 0);
    if (acl_rules == NULL) {
        RTE_LOG_FW_ERR("rte_malloc for ACL rules failed\n");
        rte_acl_free(ctx);
        return NULL;
    }

    for (uint32_t i = 0; i < g_n_rules; i++)
        fw_rule_to_acl(&g_rules[i], i, &acl_rules[i]);

    int rc = rte_acl_add_rules(ctx,
        (const struct rte_acl_rule *)acl_rules, g_n_rules);
    rte_free(acl_rules);

    if (rc != 0) {
        RTE_LOG_FW_ERR("rte_acl_add_rules failed: %d\n", rc);
        rte_acl_free(ctx);
        return NULL;
    }

    struct rte_acl_config cfg = {
        .num_categories = FW_NUM_ACL_CATEGORIES,
        .num_fields     = FW_NUM_ACL_FIELDS,
    };
    memcpy(cfg.defs, fw_acl_defs, sizeof(fw_acl_defs));

    rc = rte_acl_build(ctx, &cfg);
    if (rc != 0) {
        RTE_LOG_FW_ERR("rte_acl_build failed: %d\n", rc);
        rte_acl_free(ctx);
        return NULL;
    }

    return ctx;
}

/* ─── Публичный API ─────────────────────────────────────────────────────── */

int
rule_engine_init(void)
{
    rte_rwlock_init(&g_acl_rwlock);
    g_acl_ctx       = NULL;
    g_rebuild_count = 0;
    g_next_id       = 0;

    /* Скопировать правила из глобального конфига */
    g_n_rules = g_fw_config.n_rules;
    if (g_n_rules > MAX_RULES)
        g_n_rules = MAX_RULES;

    memcpy(g_rules, g_fw_config.rules, g_n_rules * sizeof(struct fw_rule));

    /* Отслеживать максимальный назначенный ID, чтобы rule_add выдавал уникальные ID */
    for (uint32_t i = 0; i < g_n_rules; i++) {
        if (g_rules[i].id > g_next_id)
            g_next_id = g_rules[i].id;
    }

    RTE_LOG_FW_INFO("rule_engine: init with %u rules\n", g_n_rules);
    return rule_engine_rebuild();
}

int
rule_engine_rebuild(void)
{
    struct rte_acl_ctx *new_ctx = build_acl_ctx();

    if (new_ctx == NULL && g_n_rules > 0) {
        RTE_LOG_FW_ERR("rule_engine_rebuild: build_acl_ctx failed\n");
        return -1;
    }

    /* Атомарно заменить указатель контекста под блокировкой записи.
     * Lcores пересылки удерживают блокировку чтения только во время rte_acl_classify
     * (наносекунды), поэтому конкуренция за блокировку записи минимальна. */
    rte_rwlock_write_lock(&g_acl_rwlock);
    struct rte_acl_ctx *old_ctx = g_acl_ctx;
    g_acl_ctx = new_ctx;
    rte_rwlock_write_unlock(&g_acl_rwlock);

    if (old_ctx != NULL)
        rte_acl_free(old_ctx);

    RTE_LOG_FW_INFO("rule_engine: rebuilt ACL with %u rules\n", g_n_rules);
    return 0;
}

fw_action_t
rule_match(struct pkt_meta *m, uint32_t *rule_id_out, uint32_t pkt_len)
{
    rte_rwlock_read_lock(&g_acl_rwlock);
    struct rte_acl_ctx *ctx = g_acl_ctx;

    if (ctx == NULL) {
        /* Правила не загружены: применить политику по умолчанию */
        rte_rwlock_read_unlock(&g_acl_rwlock);
        if (rule_id_out)
            *rule_id_out = 0;
        return g_default_policy;
    }

    /*
     * ПРИМЕЧАНИЕ: rte_acl_classify() возвращает result=0 для всех входных данных на
     * DPDK 24.11.3 / ARM64 Ubuntu (оба пути — scalar и NEON — не работают).
     * Причина: неизвестна — вероятно платформо-специфическая проблема сборки.
     *
     * Обходное решение: линейный перебор g_rules[] в порядке приоритетов.
     * Семантика идентична rte_acl: побеждает наименьший номер fw_priority.
     * O(n) на пакет — приемлемо для MAX_RULES=1024 и типичного
     * активного набора правил в несколько десятков.
     *
     * ACL-контекст rte_acl всё ещё строится выше (для сохранения реализации),
     * но путь classify здесь обходится.
     */
    rte_rwlock_read_unlock(&g_acl_rwlock);

    uint32_t result       = 0;          /* 0 = нет совпадения (политика по умолчанию) */
    uint32_t best_prio    = UINT32_MAX; /* меньший fw_priority = более высокая важность */

    for (uint32_t i = 0; i < g_n_rules; i++) {
        const struct fw_rule *r = &g_rules[i];

        /* Ранний выход: нельзя превзойти текущий лучший результат */
        if (r->priority >= best_prio)
            continue;

        /* src_ip CIDR (mask=0 → wildcard, совпадает с любым) */
        if (r->src_mask && (m->src_ip & r->src_mask) != (r->src_ip & r->src_mask))
            continue;
        /* dst_ip CIDR (совпадение по маске) */
        if (r->dst_mask && (m->dst_ip & r->dst_mask) != (r->dst_ip & r->dst_mask))
            continue;
        /* proto (0 = любой) */
        if (r->proto && m->proto != r->proto)
            continue;
        /* TCP-флаги (mask=0 означает что правило не фильтрует по флагам) */
        if (r->tcp_flags_mask &&
            (m->tcp_flags & r->tcp_flags_mask) != r->tcp_flags_val)
            continue;
        /* диапазоны портов */
        if (m->src_port < r->src_port_min || m->src_port > r->src_port_max)
            continue;
        if (m->dst_port < r->dst_port_min || m->dst_port > r->dst_port_max)
            continue;
        /* тип/код ICMP (255 = любой) */
        if (r->icmp_type != 255 && m->icmp_type != r->icmp_type)
            continue;
        if (r->icmp_code != 255 && m->icmp_code != r->icmp_code)
            continue;

        best_prio = r->priority;
        result    = i + 1; /* с единицы, 0 зарезервирован для "нет совпадения" */
    }

    RTE_LOG_FW_DEBUG("rule_match: src=%08x proto=%u result=%u\n",
                     m->src_ip, m->proto, result);

    if (result == 0) {
        /* Ни одно правило не совпало: применить политику по умолчанию */
        if (rule_id_out)
            *rule_id_out = 0;
        return g_default_policy;
    }

    /* result — индекс в g_rules[] начиная с 1 */
    uint32_t idx = result - 1;
    if (idx >= g_n_rules) {
        if (rule_id_out)
            *rule_id_out = 0;
        return g_default_policy;
    }

    struct fw_rule *matched = &g_rules[idx];
    __atomic_fetch_add(&matched->pkt_count,  1,       __ATOMIC_RELAXED);
    __atomic_fetch_add(&matched->byte_count, pkt_len, __ATOMIC_RELAXED);

    if (rule_id_out)
        *rule_id_out = matched->id;
    return matched->action;
}

int
rule_add(struct fw_rule *r)
{
    if (g_n_rules >= MAX_RULES) {
        RTE_LOG_FW_ERR("rule_add: max rules (%d) reached\n", MAX_RULES);
        return -ENOSPC;
    }

    r->id         = ++g_next_id;
    r->pkt_count  = 0;
    r->byte_count = 0;

    memcpy(&g_rules[g_n_rules++], r, sizeof(*r));

    int rc = rule_engine_rebuild();
    return (rc == 0) ? (int)r->id : rc;
}

int
rule_del(uint32_t id)
{
    for (uint32_t i = 0; i < g_n_rules; i++) {
        if (g_rules[i].id == id) {
            memmove(&g_rules[i], &g_rules[i + 1],
                (g_n_rules - i - 1) * sizeof(struct fw_rule));
            g_n_rules--;
            return rule_engine_rebuild();
        }
    }
    return -ENOENT;
}

int
rule_engine_reload_from_config(void)
{
    /*
     * Синхронизировать внутренний g_rules[] rule_engine из глобального конфига.
     * Вызывается из config_reload() после повторного разбора конфига в g_fw_config.
     * Динамически добавленные правила через rule_add/del здесь отбрасываются
     * (они не сохраняются в файл конфига).
     */
    g_n_rules = g_fw_config.n_rules;
    if (g_n_rules > MAX_RULES)
        g_n_rules = MAX_RULES;

    memcpy(g_rules, g_fw_config.rules, g_n_rules * sizeof(struct fw_rule));

    /* Удерживать g_next_id выше наибольшего ID из конфига для избежания повторного использования */
    for (uint32_t i = 0; i < g_n_rules; i++) {
        if (g_rules[i].id > g_next_id)
            g_next_id = g_rules[i].id;
    }

    RTE_LOG_FW_INFO("rule_engine: synced %u rule(s) from config\n", g_n_rules);
    return rule_engine_rebuild();
}

int
rule_flush(void)
{
    g_n_rules = 0;
    RTE_LOG_FW_INFO("rule_engine: all rules flushed\n");
    return rule_engine_rebuild();
}

int
rule_list(struct fw_rule *out, uint32_t *n_out)
{
    if (out == NULL || n_out == NULL)
        return -EINVAL;

    *n_out = g_n_rules;
    memcpy(out, g_rules, g_n_rules * sizeof(struct fw_rule));
    return 0;
}
