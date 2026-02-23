# PRD: Высокопроизводительный межсетевой экран для встраиваемых систем на основе DPDK

**Автор:** Бутов А.В., А-07-22
**Тема диплома:** Разработка высокопроизводительного межсетевого экрана для встраиваемых систем на основе технологии DPDK
**Репозиторий:** https://github.com/antbtv/dpdk_firewall

---

## Содержание

1. [Контекст и цель проекта](#1-контекст-и-цель-проекта)
2. [Аппаратная платформа](#2-аппаратная-платформа)
3. [Программный стек и рабочий процесс](#3-программный-стек)
4. [Режим работы](#4-режим-работы)
5. [Архитектура системы](#5-архитектура-системы)
6. [Структура проекта](#6-структура-проекта)
7. [Описание модулей](#7-описание-модулей)
8. [Пайплайн обработки пакетов](#8-пайплайн-обработки-пакетов)
9. [Движок правил фильтрации](#9-движок-правил-фильтрации)
10. [Защита от DDoS-атак](#10-защита-от-ddos-атак)
11. [Интерфейс управления](#11-интерфейс-управления)
12. [Формат конфигурации](#12-формат-конфигурации)
13. [Ключевые библиотеки DPDK](#13-ключевые-библиотеки-dpdk)
14. [Требования к производительности](#14-требования-к-производительности)
15. [Этапы разработки](#15-этапы-разработки)
16. [Тестирование и бенчмаркинг](#16-тестирование-и-бенчмаркинг)


---

## 1. Контекст и цель проекта

### Проблема

Традиционные межсетевые экраны на базе Linux (netfilter/iptables) обрабатывают пакеты через сетевой стек ядра. Для каждого пакета выполняются множественные переключения контекста, прерывания от NIC и копирование данных между пространством ядра и пользователя. На встраиваемых ARM-платформах (Raspberry Pi 5) это ограничивает пропускную способность и вносит непредсказуемые задержки, несовместимые с требованиями к межсетевому экрану для защиты сети.

eBPF/XDP — более современная альтернатива, работающая в ядре на уровне драйвера. Однако для сложной обработки (DDoS-детектирование с состоянием, гибкий движок правил, динамическое управление) она требует значительных усилий и имеет ограничения: верификатор eBPF ограничивает сложность программ, циклы по таблицам правил запрещены.

### Решение

**DPDK (Data Plane Development Kit)** — технология обхода ядра (kernel bypass). NIC передаётся под управление DPDK PMD (Poll Mode Driver), пакеты принимаются напрямую в пользовательское пространство через опрос (polling), без прерываний. Это позволяет:

- Достичь задержки обработки пакета ≤ 10 мкс
- Обрабатывать ≥ 1 Mpps для 64-байтных пакетов
- Гибко реализовать любую логику фильтрации без ограничений верификатора eBPF

### Цель

Создать протип межсетевого экрана, работающего непосредственно на Raspberry Pi 5 с сетевым адаптером Intel I210, способного фильтровать трафик 1 Гбит/с с задержкой ≤ 10 мкс, обнаруживать и блокировать DDoS-атаки, допускать управление без перезапуска.

---

## 2. Аппаратная платформа

### Целевое устройство: Raspberry Pi 5

| Параметр | Значение |
|---|---|
| SoC | Broadcom BCM2712 |
| CPU | ARM Cortex-A76 × 4, 2.4 GHz |
| Архитектура | ARMv8-A (AArch64, 64-bit) |
| ОЗУ | 8 GB LPDDR4X |
| ОС | Ubuntu Server 25, ARM64 |
| PCIe | PCIe 2.0 × 1 (через плату расширения) |
| Встроенный Ethernet | BCM54213PE, 1 Гбит/с (через RP1, интерфейс `eth0`) |

### Плата расширения PCIe для RPi5

Raspberry Pi 5 не имеет стандартного PCIe-слота. Для подключения Intel I210 используется плата расширения (PCIe HAT или M.2 HAT+), которая предоставляет PCIe × 1 через разъём RPi5. Плата расширения и Intel I210 уже установлены и подключены.

### Сетевой адаптер: Intel I210-T1

| Параметр | Значение |
|---|---|
| PCI-адрес | `0001:01:00.0` |
| Интерфейс ядра | `enP1p1s0` (переименован из `eth0` драйвером `igb`) |
| MAC-адрес | `a0:37:9f:a5:0b:02` |
| PCIe link | 2.5 Гбит/с × 1 (физический канал) |
| Скорость Ethernet | 1 Гбит/с (1000BASE-T) |
| Очереди RX/TX | 4 очереди (4 rx queue(s), 4 tx queue(s)) |
| DPDK PMD | `net_e1000_igb` |
| Текущий драйвер ядра | `igb` — перед запуском DPDK требует переключения на `vfio-pci` |

### Встроенный Ethernet (LAN-порт)

| Параметр | Значение |
|---|---|
| PCI-адрес | `0002:01:00.0` (RP1 PCIe 2.0 South Bridge) |
| Интерфейс ядра | `eth0` |
| MAC-адрес | `2c:cf:67:b6:fc:c2` |
| Скорость | 1 Гбит/с (1000BASE-T) |
| DPDK PMD | `net_genet` (DPDK ≥ 23.11) или `tap` PMD как fallback |

### Топология сети

```
Интернет / WAN
      |
[ Intel I210 ]  ← порт 0 (DPDK)
  PCI: 0001:01:00.0
  kernel iface: enP1p1s0
  MAC: a0:37:9f:a5:0b:02
      |
[ Raspberry Pi 5 — dpdk_firewall ]
      |
[ BCM54213PE ] ← порт 1 (DPDK)
  PCI: 0002:01:00.0 (через RP1)
  kernel iface: eth0
  MAC: 2c:cf:67:b6:fc:c2
      |
Локальная сеть / LAN
```

> **Важно:** Встроенный NIC (BCM54213PE через RP1) использует PMD `net_genet` (DPDK ≥ 23.11). Если PMD недоступен в установленном пакете Ubuntu Server 25, использовать `tap` PMD как fallback для LAN-порта — производительность WAN (I210) при этом не ограничивается.

### Hugepages на RPi5

ARM64 поддерживает страницы по 1 ГБ. Для DPDK нужно добавить в `/boot/firmware/cmdline.txt`:

```
hugepagesz=1G hugepages=1 iommu.passthrough=0
```

Параметр `iommu.passthrough=0` включает IOMMU (SMMU на BCM2712) — необходим для VFIO.

### Привязка NIC к DPDK

Intel I210 сейчас использует ядерный драйвер `igb`. Перед запуском DPDK его нужно передать под управление `vfio-pci`:

```bash
# Загрузить модуль vfio-pci
sudo modprobe vfio-pci

# Отвязать от igb и привязать к vfio-pci
sudo dpdk-devbind.py -b vfio-pci 0001:01:00.0

# Проверить статус
sudo dpdk-devbind.py --status
```

Чтобы вернуть под управление ядра:
```bash
sudo dpdk-devbind.py -b igb 0001:01:00.0
```

---

## 3. Программный стек

### Рабочий процесс разработки

```
[ ПК разработчика (x86_64) ]          [ Raspberry Pi 5 (ARM64) ]
  Написание кода в IDE/редакторе
  git add / git commit / git push  →   git pull
                                        meson setup build --optimization=3
                                        ninja -C build
                                        sudo ./build/dpdk_firewall --config ...
```

- **Разработка** (редактирование кода, git) — ведётся на ПК разработчика
- **Сборка** — нативно на RPi5 (не cross-compilation; ARM Cortex-A76 @ 2.4 ГГц достаточен)
- **Запуск и тестирование** — на RPi5 с подключёнными NIC

> DPDK и зависимости устанавливаются только на RPi5. На ПК разработчика нужны лишь git и редактор кода.

### Окружение разработки (ПК)

| Компонент | Назначение |
|---|---|
| git | Версионирование кода |
| Редактор / IDE | VSCode, CLion или любой другой |
| Язык C11 | Написание исходного кода |

### Целевая платформа (RPi5)

| Компонент | Версия | Назначение |
|---|---|---|
| OS | Ubuntu 23.10 / Debian 12 ARM64 | Целевая ОС |
| DPDK | ≥ 23.11 (LTS) | Kernel bypass, PMD, утилиты |
| libjansson | ≥ 2.14 | Парсинг конфигурации и протокола управления |
| Meson + Ninja | актуальная | Система сборки |
| GCC 13 / Clang 16 | актуальная | Компилятор AArch64 |

### Установка зависимостей на RPi5

```bash
sudo apt install dpdk dpdk-dev libdpdk-dev libjansson-dev \
                 meson ninja-build pkg-config build-essential
```

### Сборка проекта (на RPi5)

```bash
git pull                              # получить последние изменения с ПК
meson setup build --optimization=3   # первый раз
ninja -C build                        # сборка
sudo ninja -C build install           # устанавливает в /usr/local/bin/
```

---

## 4. Режим работы

Устройство работает исключительно в **Bridge Mode (L2, прозрачный)**.

```
WAN → [port 0] → classify/filter → [port 1] → LAN
LAN → [port 1] → classify/filter → [port 0] → WAN
```

- Устройство работает как невидимый фильтр на уровне канала данных
- Ethernet-кадры пересылаются без изменений (не затрагиваются IP-заголовки)
- Нет требований к ARP-таблицам, маршрутизации, TTL-декременту
- Устройство не имеет IP-адреса на сетевых интерфейсах DPDK
- Прозрачно встраивается в существующую сеть без изменения IP-адресации

В `rules.json`:
```json
"mode": "bridge"
```

---

## 5. Архитектура системы

### 5.1 Lcore-модель

DPDK запускает выделенные потоки (lcore) на физических ядрах CPU. Рекомендуемое распределение для RPi5 (4 ядра):

| lcore | Ядро | Роль |
|---|---|---|
| 0 | Core 0 | Плоскость управления: mgmt-сокет, перезагрузка конфига, сбор статистики |
| 1 | Core 1 | Пересылка WAN→LAN: RX port0 → pipeline → TX port1 |
| 2 | Core 2 | Пересылка LAN→WAN: RX port1 → pipeline → TX port0 |
| 3 | Core 3 | Резерв / агрегация статистики |

lcore 0 — главный (main lcore), запускает остальные через `rte_eal_remote_launch()`.

### 5.2 Взаимодействие компонентов

```
                  ┌─────────────────────────────┐
                  │         rules.json           │
                  └─────────────┬───────────────┘
                                │ SIGHUP / config_reload()
                  ┌─────────────▼───────────────┐
                  │         config.c             │
                  │  Загрузка, валидация, хранение│
                  └─────────────┬───────────────┘
                                │
          ┌─────────────────────▼─────────────────────┐
          │                rule_engine.c               │
          │  rte_acl_ctx (rebuild под rwlock)          │
          │  struct fw_rule[MAX_RULES]                  │
          └─────────────────────┬─────────────────────┘
                                │ rule_match()
  I210 port0 ──RX──► ┌──────────▼──────────┐ ──TX──► eth0 port1
                     │     pipeline.c        │
  eth0 port1 ──RX──► │  (lcores 1 и 2)      │ ──TX──► I210 port0
                     └──────────┬────────────┘
                                │
          ┌─────────────────────▼─────────────────────┐
          │                 ddos.c                      │
          │  rte_hash (per-IP counters)                 │
          │  Sliding window + blacklist                 │
          │  rte_meter (token bucket)                   │
          └─────────────────────────────────────────────┘

  lcore 0:
  ┌────────────────────────────────────────────────────┐
  │  mgmt.c — UNIX socket сервер                        │
  │  stats.c — периодический дамп счётчиков             │
  │  config.c — проверка флага перезагрузки             │
  └────────────────────────────────────────────────────┘
       ▲
       │ JSON over UNIX socket
  ┌────┴────────────────┐
  │    cli/fw_ctl.c      │
  │  (отдельный бинарь)  │
  └─────────────────────┘
```

---

## 6. Структура проекта

```
dpdk_firewall/
├── meson.build                  # Главный файл сборки
├── meson_options.txt            # Опции сборки (режим, max_rules, debug)
├── PRD.md                       # Этот документ
├── README.md                    # Краткое описание и инструкция по запуску
│
├── config/
│   └── rules.json               # Пример конфигурации (поставляется с проектом)
│
├── include/
│   ├── firewall.h               # Центральные типы: fw_rule, fw_config, pkt_meta, fw_mode_t
│   ├── config.h                 # API загрузки конфигурации
│   ├── rule_engine.h            # API движка правил: rule_match(), rule_rebuild()
│   ├── ddos.h                   # API DDoS-детектора: ddos_update(), blacklist_*()
│   ├── pipeline.h               # Объявления стадий пайплайна
│   ├── stats.h                  # API сбора статистики
│   ├── mgmt.h                   # API сервера управления
│   └── log.h                    # Макросы логирования поверх rte_log
│
├── src/
│   ├── main.c                   # Точка входа: EAL init, аргументы, запуск lcore
│   ├── config.c                 # Парсинг rules.json (libjansson), перезагрузка по SIGHUP
│   ├── rule_engine.c            # rte_acl контекст, структуры правил, reload под rwlock
│   ├── ddos.c                   # rte_hash, sliding window, blacklist, rte_meter
│   ├── pipeline.c               # Главный цикл lcore: 7 стадий обработки пакетов
│   ├── port.c                   # Инициализация ethdev: mempool, очереди, запуск портов
│   ├── stats.c                  # Атомарные счётчики, периодический дамп
│   ├── mgmt.c                   # UNIX socket сервер, epoll, JSON-диспетчер команд
│   └── log.c                    # Регистрация типа лога rte_log
│
├── cli/
│   ├── meson.build
│   └── fw_ctl.c                 # CLI-утилита (без DPDK, только POSIX + jansson)
│
└── tests/
    ├── meson.build
    ├── test_rule_engine.c       # Юнит-тесты движка правил
    ├── test_ddos.c              # Юнит-тесты DDoS-детектора
    └── test_config.c            # Юнит-тесты парсера конфигурации
```

---

## 7. Описание модулей

### `include/firewall.h` — центральные типы

Главный заголовочный файл. Определяет все типы, используемые более чем в одном модуле. **Разрабатывается первым.**

```c
/* Действие правила */
typedef enum {
    ACTION_ACCEPT     = 0,
    ACTION_DROP       = 1,
    ACTION_RATE_LIMIT = 2,
} fw_action_t;

/* Метаданные пакета — заполняются на стадии classifier */
struct pkt_meta {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;         /* IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP */
    uint8_t  tcp_flags;     /* флаги TCP (SYN, ACK, RST, FIN, ...) */
    uint8_t  icmp_type;
    uint8_t  icmp_code;
    uint8_t  is_ipv4;       /* 1 если IPv4, 0 — не IPv4 (пропустить) */
};

/* Правило фильтрации */
#define MAX_RULES 1024

struct fw_rule {
    uint32_t      id;
    uint32_t      priority;       /* меньше = выше приоритет (rte_acl) */
    uint32_t      src_ip;
    uint32_t      src_mask;       /* /N → маска, 0 = wildcard */
    uint32_t      dst_ip;
    uint32_t      dst_mask;
    uint16_t      src_port_min;
    uint16_t      src_port_max;   /* == src_port_min для точного совпадения */
    uint16_t      dst_port_min;
    uint16_t      dst_port_max;
    uint8_t       proto;          /* 0 = any */
    uint8_t       tcp_flags_mask;
    uint8_t       tcp_flags_val;
    uint8_t       icmp_type;      /* 255 = any */
    uint8_t       icmp_code;      /* 255 = any */
    fw_action_t   action;
    uint64_t      rate_cir;       /* bytes/sec, только для RATE_LIMIT */
    uint64_t      rate_cbs;       /* burst bytes */
    alignas(64) uint64_t pkt_count;
    uint64_t      byte_count;
    char          comment[64];
};
```

### `src/main.c` — точка входа

- Разбирает аргументы командной строки: `--config <path>`, `--log-level <level>`
- Собирает аргументы EAL программно (список PCI-адресов портов из конфига)
- Вызывает `rte_eal_init()`
- Загружает конфигурацию через `config_load()`
- Инициализирует порты через `port_init()`
- Устанавливает обработчик сигнала `SIGHUP` (устанавливает volatile-флаг)
- Запускает forwarding lcores через `rte_eal_remote_launch(pipeline_lcore_main, ...)`
- Запускает control plane на lcore 0: `mgmt_server_run()` (блокирующий цикл)

### `src/port.c` — инициализация DPDK-портов

```c
#define RX_RING_SIZE  1024
#define TX_RING_SIZE  1024
#define NUM_MBUFS     8192     /* на порт */
#define MBUF_CACHE    256

/* Конфигурация порта */
static const struct rte_eth_conf port_conf = {
    .rxmode = { .mq_mode = RTE_ETH_MQ_RX_NONE },
    .txmode = { .mq_mode = RTE_ETH_MQ_TX_NONE },
};
```

Функции: `port_init_all()`, `port_stop_all()`, `port_stats_get(uint16_t port_id)`.

Глобальный mempool `g_mbuf_pool` создаётся здесь и разделяется между всеми портами.

### `src/config.c` — загрузка конфигурации

- Использует **libjansson** для парсинга `rules.json`
- Заполняет структуру `struct fw_config` (хранит правила, DDoS-параметры, режим работы)
- `config_load(const char *path)` — первичная загрузка при старте
- `config_reload()` — вызывается из lcore 0 при установке SIGHUP-флага; выполняет rebuild `rte_acl_ctx` через `rule_engine_rebuild()`
- Валидирует JSON-схему (обязательные поля, допустимые значения)

### `src/pipeline.c` — главный цикл обработки пакетов

Функция `pipeline_lcore_main(void *arg)` — запускается на каждом forwarding lcore.

Содержит главный цикл с 7 стадиями (см. раздел 8). Это **самый производительно-критичный файл** проекта. Все аллокации — на стеке (массивы `rx_pkts`, `tx_pkts`, `meta` — stack-allocated). Пакеты обрабатываются пачками (burst) по 32 штуки. В bridge mode пакет всегда пересылается на противоположный порт (port 0 ↔ port 1).

### `src/rule_engine.c` — движок правил

- Хранит `struct fw_rule rules[MAX_RULES]` и `struct rte_acl_ctx *acl_ctx`
- `rule_engine_rebuild()` — создаёт новый `rte_acl_ctx` из текущего набора правил, атомарно заменяет указатель (rwlock)
- `rule_match(struct pkt_meta *m, uint32_t *rule_id)` — классифицирует пакет, возвращает `fw_action_t`
- Атомарно обновляет `pkt_count` и `byte_count` для сработавшего правила

### `src/ddos.c` — обнаружение и блокировка DDoS

- Два `rte_hash`: `ddos_tracker` (per-IP счётчики трафика) и `blacklist` (заблокированные IP)
- `ddos_update()` — sliding window для SYN/UDP/ICMP flood
- `blacklist_check()` — O(1) проверка, вызывается до ACL
- `blacklist_add()` / `blacklist_del()` — управление блокировкой
- `rte_meter_srtcm` — экземпляры для каждого правила с `ACTION_RATE_LIMIT`

### `src/stats.c` — статистика

- Атомарные глобальные счётчики: `total_rx_pkts`, `total_tx_pkts`, `total_dropped_pkts`, `total_rx_bytes`, `total_tx_bytes`
- `stats_periodic_dump()` — вызывается из lcore 0 каждые N секунд (через `rte_timer` или `nanosleep`)
- `stats_get_snapshot()` — возвращает снимок для отправки через mgmt-сокет

### `src/mgmt.c` — сервер управления

- UNIX domain socket: `/var/run/dpdk_firewall/mgmt.sock`
- Модель: один запрос на соединение (connect → request → response → close)
- `epoll`-цикл на lcore 0
- Диспетчеризация команд через таблицу обработчиков
- Таймаут чтения через `SO_RCVTIMEO` (500 мс) — защита от медленных клиентов

### `cli/fw_ctl.c` — CLI-утилита

Отдельный бинарь. Не зависит от DPDK. Зависит только от libjansson и POSIX.

```
fw_ctl rule add --proto tcp --dst-port 80 --action drop
fw_ctl rule del --id 5
fw_ctl rule list
fw_ctl stats
fw_ctl blacklist add --ip 1.2.3.4 --duration 300
fw_ctl blacklist list
fw_ctl config reload
fw_ctl set-policy drop
```

---

## 8. Пайплайн обработки пакетов

Стадии выполняются последовательно для каждой пачки (burst) пакетов:

```
[ СТАДИЯ 1: RX BURST ]
rte_eth_rx_burst(port_in, 0, rx_pkts, MAX_BURST=32)
         │
         ▼
[ СТАДИЯ 2: CLASSIFIER ]
Парсинг Ethernet → IPv4 → TCP/UDP/ICMP
Заполнение struct pkt_meta meta[burst_size]
Не-IPv4 пакеты: в bridge-режиме — пропустить (forward as-is)
         │
         ▼
[ СТАДИЯ 3: BLACKLIST CHECK ]  ← самый быстрый путь отброса
rte_hash_lookup(blacklist, &src_ip)
Если найден и TTL не истёк → DROP (rte_pktmbuf_free)
         │
         ▼
[ СТАДИЯ 4: RULE ENGINE ]
rte_acl_classify(acl_ctx, data[], results[], burst)
→ ACTION_ACCEPT: пакет идёт дальше
→ ACTION_DROP: rte_pktmbuf_free, счётчик правила++
→ ACTION_RATE_LIMIT: переход на стадию 5
         │
         ▼
[ СТАДИЯ 5: RATE LIMIT ]  (только для ACTION_RATE_LIMIT)
rte_meter_srtcm_color_blind_check(...)
Если RTE_COLOR_RED → DROP
         │
         ▼
[ СТАДИЯ 6: DDOS UPDATE ]
Обновление скользящего окна для src_ip
Если порог превышен → blacklist_add(src_ip, TTL)
         │
         ▼
[ СТАДИЯ 7: TX BURST ]
rte_eth_tx_burst(port_out, 0, tx_pkts, n_accepted)
Неотправленные пакеты → rte_pktmbuf_free_bulk()
```

### Ключевые принципы производительности

1. **Burst-обработка**: никогда не обрабатывать по одному пакету. Всегда `rte_eth_rx_burst(burst=32)`.
2. **Stack-аллокация**: массивы `rx_pkts`, `tx_pkts`, `meta` объявляются на стеке lcore, не в куче.
3. **Zero-copy**: пакеты не копируются между стадиями, передаются указатели на `rte_mbuf`.
4. **Prefetch**: перед обработкой выполнять `rte_prefetch0(rte_pktmbuf_mtod(pkts[i], void*))` для следующего пакета в burst.
5. **Avoid false sharing**: per-rule счётчики выровнены по 64 байта (`alignas(64)`).

---

## 9. Движок правил фильтрации

### 9.1 Выбор алгоритма: rte_acl

`rte_acl` (DPDK ACL library) — SIMD-векторизованный алгоритм классификации пакетов (алгоритм DFA + bit-vector). Обрабатывает 8 пакетов одновременно на NEON (ARM) или SSE (x86). Нативно поддерживает:

- IP-адреса с маской (prefix match)
- Диапазоны портов
- Точные совпадения по протоколу
- Битовые маски (TCP-флаги)

**Альтернатива для малых наборов правил (< 16 правил):** линейный перебор в tight loop — конкурентоспособен с ACL из-за нулевых накладных расходов на rebuild. Реализовать оба пути, по умолчанию — `rte_acl`.

### 9.2 5-tuple ACL fields

```c
/* Описание полей для rte_acl_classify */
struct rte_acl_field_def fw_acl_defs[] = {
    /* src IP — prefix match */
    { .type=RTE_ACL_FIELD_TYPE_MASK,    .size=4, .field_index=0, .input_index=0,
      .offset = offsetof(struct rte_ipv4_hdr, src_addr) },
    /* dst IP — prefix match */
    { .type=RTE_ACL_FIELD_TYPE_MASK,    .size=4, .field_index=1, .input_index=1,
      .offset = offsetof(struct rte_ipv4_hdr, dst_addr) },
    /* protocol — bitmask */
    { .type=RTE_ACL_FIELD_TYPE_BITMASK, .size=1, .field_index=2, .input_index=2,
      .offset = offsetof(struct rte_ipv4_hdr, next_proto_id) },
    /* src port — range */
    { .type=RTE_ACL_FIELD_TYPE_RANGE,   .size=2, .field_index=3, .input_index=3,
      .offset=0 },   /* относительно начала L4-заголовка */
    /* dst port — range */
    { .type=RTE_ACL_FIELD_TYPE_RANGE,   .size=2, .field_index=4, .input_index=3,
      .offset=2 },
};
```

### 9.3 Горячая замена правил (zero-downtime reload)

```
lcore 0 (config_reload):          lcores 1,2 (pipeline):
1. rte_rwlock_write_lock()     →  ожидание
2. Создать new_acl_ctx            держат read_lock на время classify
3. Заменить указатель
4. rte_acl_free(old_ctx)
5. rte_rwlock_write_unlock()
```

Rebuild ACL-контекста занимает ~1–10 мс в зависимости от количества правил. Forwarding lcores блокируются только на время swap (наносекунды).

### 9.4 Политика по умолчанию

Если `rte_acl_classify` возвращает 0 (нет совпадения) — применяется `g_default_policy` (`ACTION_ACCEPT` или `ACTION_DROP`), заданная в конфиге. По умолчанию рекомендуется `ACTION_DROP` (whitelist-модель).

---

## 10. Защита от DDoS-атак

### 10.1 Отслеживаемые типы атак

| Тип атаки | Метрика | Порог по умолчанию |
|---|---|---|
| SYN flood | TCP SYN / 100 мс / src_ip | 10 000 пакетов |
| UDP flood | UDP пакеты / 100 мс / src_ip | 50 000 пакетов |
| ICMP flood | ICMP пакеты / 100 мс / src_ip | 5 000 пакетов |

### 10.2 Структура per-IP трекера

```c
/* Таблица: src_ip → счётчики трафика */
struct ddos_entry {
    uint64_t syn_count;
    uint64_t udp_count;
    uint64_t icmp_count;
    uint64_t window_start_ns;  /* rte_get_tsc_cycles() в начале окна */
};

/* Хэш-таблица: до 65536 IP-адресов одновременно */
struct rte_hash *g_ddos_hash;   /* флаг: RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY */
```

### 10.3 Алгоритм скользящего окна (sliding window)

```c
void ddos_update(struct ddos_entry *e, struct pkt_meta *m,
                 uint64_t now_ns, const struct ddos_config *cfg)
{
    if (now_ns - e->window_start_ns > cfg->window_ns) {
        e->syn_count = e->udp_count = e->icmp_count = 0;
        e->window_start_ns = now_ns;
    }
    if (m->proto == IPPROTO_TCP && (m->tcp_flags & TCP_FLAG_SYN))
        e->syn_count++;
    else if (m->proto == IPPROTO_UDP)
        e->udp_count++;
    else if (m->proto == IPPROTO_ICMP)
        e->icmp_count++;

    if (e->syn_count  > cfg->syn_threshold  ||
        e->udp_count  > cfg->udp_threshold  ||
        e->icmp_count > cfg->icmp_threshold)
        blacklist_add(m->src_ip, now_ns + cfg->block_duration_ns);
}
```

### 10.4 Динамический чёрный список

```c
/* Вызывается ДО ACL — самый быстрый путь отброса */
int blacklist_check(uint32_t src_ip, uint64_t now_cycles)
{
    int pos = rte_hash_lookup(g_blacklist_hash, &src_ip);
    if (pos >= 0) {
        if (g_blacklist_expires[pos] > now_cycles)
            return 1;   /* заблокирован */
        rte_hash_del_key(g_blacklist_hash, &src_ip);  /* TTL истёк */
    }
    return 0;
}
```

TTL блокировки по умолчанию: 300 секунд (настраивается в конфиге). Максимум записей: 65536 (определяется при создании хэш-таблицы).

### 10.5 Ограничение скорости (token bucket)

Для правил с `ACTION_RATE_LIMIT` используется `rte_meter_srtcm`:

```c
#include <rte_meter.h>

/* При загрузке правила */
struct rte_meter_srtcm_params params = {
    .cir = rule->rate_cir,   /* bytes/sec */
    .cbs = rule->rate_cbs,
    .ebs = rule->rate_cbs,
};
rte_meter_srtcm_profile_config(&meter_profile[rule_id], &params);
rte_meter_srtcm_config(&meter[rule_id], &meter_profile[rule_id]);

/* В пайплайне (стадия 5) */
enum rte_color color = rte_meter_srtcm_color_blind_check(
    &meter[rule_id], &meter_profile[rule_id],
    rte_get_tsc_cycles(), pkt_len
);
if (color == RTE_COLOR_RED) { /* DROP */ }
```

---

## 11. Интерфейс управления

### 11.1 UNIX Domain Socket

- Путь: `/var/run/dpdk_firewall/mgmt.sock`
- Протокол: newline-delimited JSON (один объект = одна строка)
- Модель соединения: одна команда на соединение (connect → send → recv → close)
- Доступен для отладки: `echo '{"cmd":"stats_get","args":{}}' | socat - UNIX-CONNECT:/var/run/dpdk_firewall/mgmt.sock`

```
Запрос:  {"cmd": "<команда>", "args": {...}}\n
Ответ:   {"status": "ok"|"error", "data": {...}, "msg": "<текст>"}\n
```

### 11.2 Таблица команд

| Команда | Аргументы | Описание |
|---|---|---|
| `rule_add` | `{rule object}` | Добавить правило, вернуть назначенный ID |
| `rule_del` | `{"id": N}` | Удалить правило, перестроить ACL |
| `rule_list` | `{}` | Вернуть все правила со статистикой |
| `rule_flush` | `{}` | Удалить все правила (сброс) |
| `stats_get` | `{}` | Глобальные счётчики и per-port статистика |
| `blacklist_add` | `{"ip": "x.x.x.x", "duration_s": N}` | Заблокировать IP вручную |
| `blacklist_del` | `{"ip": "x.x.x.x"}` | Разблокировать IP |
| `blacklist_list` | `{}` | Список заблокированных IP с TTL |
| `config_reload` | `{}` | Перезагрузить rules.json |
| `set_default_policy` | `{"action": "accept"\|"drop"}` | Изменить политику по умолчанию |

### 11.3 Архитектура сервера (mgmt.c)

```c
/* lcore 0 — control plane loop */
void mgmt_server_run(void)
{
    int server_fd = create_unix_socket("/var/run/dpdk_firewall/mgmt.sock");
    int epoll_fd  = epoll_create1(0);
    epoll_add(epoll_fd, server_fd, EPOLLIN);

    while (!g_force_quit) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, /*timeout_ms=*/100);
        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == server_fd) {
                int client = accept(server_fd, NULL, NULL);
                /* setsockopt(SO_RCVTIMEO = 500ms) — защита от медленных клиентов */
                handle_client(client);  /* read JSON, dispatch, write response, close */
            }
        }
        stats_periodic_update();     /* каждые 100 мс */
        config_reload_if_needed();   /* проверить volatile-флаг от SIGHUP */
    }
}
```

---

## 12. Формат конфигурации

### 12.1 Полная схема rules.json

```json
{
  "version": 1,
  "mode": "bridge",
  "ports": {
    "wan": "0001:01:00.0",
    "lan": "builtin"
  },
  "default_policy": "drop",
  "hugepages": {
    "size_mb": 1024
  },
  "ddos": {
    "enabled": true,
    "window_ms": 100,
    "syn_pps_threshold": 10000,
    "udp_pps_threshold": 50000,
    "icmp_pps_threshold": 5000,
    "block_duration_s": 300
  },
  "logging": {
    "level": "info",
    "file": "/var/log/dpdk_firewall.log"
  },
  "rules": [
    {
      "id": 1,
      "priority": 100,
      "comment": "Разрешить SSH из управляющей сети",
      "proto": "tcp",
      "src_ip": "192.168.1.0/24",
      "dst_port": "22",
      "tcp_flags": "ACK",
      "action": "accept"
    },
    {
      "id": 2,
      "priority": 200,
      "comment": "Ограничить ICMP глобально",
      "proto": "icmp",
      "action": "rate_limit",
      "rate": {
        "cir_kbps": 1000,
        "cbs_bytes": 65536
      }
    },
    {
      "id": 3,
      "priority": 300,
      "comment": "Заблокировать вредоносную подсеть",
      "src_ip": "10.99.0.0/16",
      "action": "drop"
    },
    {
      "id": 4,
      "priority": 65000,
      "comment": "Разрешить весь трафик из LAN",
      "src_ip": "192.168.1.0/24",
      "action": "accept"
    }
  ]
}
```

### 12.2 Правила парсинга полей

| Поле JSON | Тип | Формат | Пример |
|---|---|---|---|
| `src_ip` / `dst_ip` | строка | CIDR или отсутствие (wildcard) | `"192.168.0.0/24"` |
| `src_port` / `dst_port` | строка | число или диапазон | `"80"`, `"1024-65535"` |
| `proto` | строка | `"tcp"`, `"udp"`, `"icmp"`, `"any"` | `"tcp"` |
| `tcp_flags` | строка | через запятую | `"SYN"`, `"SYN,ACK"` |
| `action` | строка | `"accept"`, `"drop"`, `"rate_limit"` | `"drop"` |
| `rate.cir_kbps` | число | килобит/сек | `1000` |
| `priority` | число | меньше = выше приоритет | `100` |

---

## 13. Ключевые библиотеки DPDK

| Библиотека | Заголовок | Назначение в проекте |
|---|---|---|
| `rte_eal` | `rte_eal.h` | Инициализация DPDK EAL, запуск lcore |
| `rte_ethdev` | `rte_ethdev.h` | Открытие портов, RX/TX burst, статистика |
| `rte_mbuf` | `rte_mbuf.h` | Управление пакетными буферами |
| `rte_mempool` | `rte_mempool.h` | Создание пула буферов |
| `rte_acl` | `rte_acl.h` | SIMD-классификация пакетов (движок правил) |
| `rte_hash` | `rte_hash.h` | O(1) поиск IP (blacklist, DDoS tracker) |
| `rte_meter` | `rte_meter.h` | srTCM token bucket для RATE_LIMIT |
| `rte_timer` | `rte_timer.h` | Периодическая задача сбора статистики |
| `rte_log` | `rte_log.h` | Структурированное логирование с уровнями |
| `rte_atomic` | `rte_atomic.h` | Lock-free обновление счётчиков |
| `rte_cycles` | `rte_cycles.h` | TSC-тайминг для DDoS-окон |
| `rte_ring` | `rte_ring.h` | Lock-free очередь control→data plane |

> **Не использовать:** `rte_flow` (аппаратный offload I210 ограничен), `rte_distributor` (не нужен для 2 lcore), `rte_lpm` (router mode исключён из scope).

---

## 14. Требования к производительности

### 14.1 Целевые показатели

| Метрика | Целевое значение | Условия |
|---|---|---|
| Пропускная способность | ≥ 900 Мбит/с | Пакеты 1500 байт, 64-байтные правила |
| Задержка (latency) | ≤ 10 мкс | Нормальная нагрузка, p99 |
| Джиттер | ≤ 5 мкс | p99 |
| DDoS-производительность | ≥ 1 Mpps | Пакеты 64 байта, атака с одного IP |
| Потребление CPU | ≤ 2 ядра | Для пропускной способности 900 Мбит/с |

### 14.2 Ожидаемые ограничения платформы

- **Bottleneck:** PCIe 2.0 × 1 ограничивает I210 до ~500 Мбит/с эффективной пропускной способности в bridge-режиме (два направления по PCIe). Фактический bottleneck — PCIe, а не CPU.
- **CPU:** ARM Cortex-A76 способен обрабатывать 2–5 Mpps в simple forwarding. CPU не является ограничением.
- **Hugepages:** обязательны. Без них TLB-промахи снижают производительность на 30–50%.

---

## 15. Этапы разработки

### Фаза 1: Фундамент — DPDK init + сквозная пересылка

**Цель:** пакеты проходят сквозь устройство без фильтрации.

Задачи:
1. Настроить RPi5: hugepages в `cmdline.txt`, привязать I210 к VFIO
2. Написать `port.c`: init EAL, открыть оба порта, создать mempool
3. Написать `main.c`: разбор аргументов, запуск lcore
4. Написать `pipeline.c`: минимальный RX→TX цикл (forwarding без фильтрации)
5. Написать `config.c`: загрузка `rules.json` (только базовые поля)
6. Написать `log.h` / `log.c`

**Milestone:** `sudo ./dpdk_firewall --config config/rules.json` пересылает все пакеты. Базовый `iperf3` показывает ≥ 900 Мбит/с.

### Фаза 2: Движок правил — статическая фильтрация

**Цель:** правила из конфига применяются корректно.

Задачи:
1. Написать `rule_engine.h` / `rule_engine.c`: структуры, ACL-контекст
2. Написать стадию CLASSIFIER в `pipeline.c`
3. Интегрировать `rte_acl_classify` в пайплайн (стадия 4)
4. Добавить атомарные счётчики per-rule
5. Написать `test_rule_engine.c`
6. Тестировать: `nmap`, `iperf3`, `tcpdump` на LAN-порту

**Milestone:** DROP-правила блокируют трафик. ACCEPT-правила пропускают. Статистика корректна.

### Фаза 3: Защита от DDoS

**Цель:** автоматическое обнаружение и блокировка flood-атак.

Задачи:
1. Написать `ddos.h` / `ddos.c`: rte_hash, sliding window, blacklist
2. Интегрировать `rte_meter` для RATE_LIMIT
3. Интегрировать стадии BLACKLIST CHECK (3) и DDOS UPDATE (6) в пайплайн
4. Написать `test_ddos.c`

**Milestone:** SYN flood с одного IP обнаруживается за ≤ 100 мс и блокируется на настроенный TTL. Легитимный трафик не затронут.

### Фаза 4: Интерфейс управления

**Цель:** управление без перезапуска процесса.

Задачи:
1. Написать `mgmt.h` / `mgmt.c`: UNIX socket, epoll, JSON-диспетчер
2. Реализовать все команды из таблицы (раздел 11.2)
3. Реализовать обработчик SIGHUP → `config_reload()`
4. Написать `cli/fw_ctl.c`

**Milestone:** `fw_ctl rule add ...` добавляет правило в работающий firewall. `fw_ctl stats` отображает статистику. `fw_ctl blacklist list` показывает заблокированные IP.

### Фаза 5: Бенчмаркинг и документация

**Цель:** валидация производительности, подготовка к защите диплома.

Задачи:
1. Измерить throughput: `dpdk-testpmd` или `iperf3`
2. Измерить latency/jitter: `pktgen-dpdk` в timestamp-режиме
3. Тест DDoS: `hping3 --flood --syn`, `iperf3 -u` (UDP flood)
4. Построить графики для дипломной работы
5. Обновить README: инструкция по сборке и запуску на RPi5

---

## 16. Тестирование и бенчмаркинг

### Функциональное тестирование

- Фильтрация по протоколу, IP/CIDR, портам, TCP-флагам
- Действия ACCEPT / DROP / RATE_LIMIT
- Перезагрузка правил без прерывания трафика (SIGHUP / `fw_ctl config reload`)
- Ручная блокировка и разблокировка IP
- Смена политики по умолчанию на лету

### Тестирование DDoS-защиты

- SYN flood: `hping3 -S --flood -p 80 <target>`
- UDP flood: `iperf3 -u -b 1G -t 30 <target>`
- ICMP flood: `ping -f <target>`
- Проверка: заблокированный IP не может слать трафик; TTL истекает корректно

### Бенчмаркинг производительности

| Тест | Инструмент | Метрика |
|---|---|---|
| Throughput (1500 байт) | iperf3 TCP | Мбит/с |
| Throughput (64 байт) | pktgen-dpdk / dpdk-testpmd | Mpps |
| Latency p99 | pktgen-dpdk --latency | мкс |
| Jitter | pktgen-dpdk --latency | мкс |
| DDoS 1 Mpps | pktgen-dpdk (64-byte burst) | pps dropped |
| CPU utilization | `top` / `perf stat` | % per core |

### Юнит-тесты (tests/)

- `test_rule_engine.c`: синтетические `rte_mbuf`, проверка ACL-классификации
- `test_ddos.c`: инъекция SYN-burst, проверка добавления в blacklist
- `test_config.c`: парсинг корректных и некорректных JSON-файлов

---

## Приложение: полезные команды для разработки на RPi5

### Аппаратные идентификаторы (подтверждены на устройстве)

| Компонент | Интерфейс ядра | PCI-адрес |
|---|---|---|
| Intel I210 (WAN/порт 0) | `enP1p1s0` | `0001:01:00.0` |
| BCM54213PE / RP1 (LAN/порт 1) | `eth0` | `0002:01:00.0` |

### Команды управления DPDK

```bash
# Проверить статус всех портов
sudo dpdk-devbind.py --status

# Привязать I210 к VFIO (перед запуском dpdk_firewall)
sudo modprobe vfio-pci
sudo dpdk-devbind.py -b vfio-pci 0001:01:00.0

# Вернуть I210 под управление ядра (после остановки dpdk_firewall)
sudo dpdk-devbind.py -b igb 0001:01:00.0

# Проверка hugepages
grep -i huge /proc/meminfo
```

### Запуск и управление firewall

```bash
# Запуск
sudo ./build/dpdk_firewall --config config/rules.json --log-level info

# Мониторинг в реальном времени
fw_ctl stats
fw_ctl blacklist list

# Перезагрузка конфигурации без остановки
fw_ctl config reload
# или через сигнал:
sudo kill -HUP $(pgrep dpdk_firewall)
```

### Тестирование производительности

```bash
# Throughput (на RPi5 — сервер, на другой машине — клиент)
iperf3 -s &
iperf3 -c <rpi5_ip> -t 30 -i 1

# SYN flood тест (с другой машины)
sudo hping3 -S --flood -p 80 <rpi5_wan_ip>

# UDP flood
iperf3 -u -b 1G -t 30 -c <rpi5_wan_ip>
```
