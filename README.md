# dpdk_firewall

## Постановка задачи

Цель работы — реализовать прозрачный сетевой экран в режиме bridge (L2, без маршрутизации),
работающий в пространстве пользователя на основе технологии DPDK. Устройство должно выполнять:

- фильтрацию трафика по набору ACL-правил (IP-адреса, порты, протокол);
- защиту от DDoS-атак (SYN flood, UDP flood) со скользящим окном на источник;
- ограничение скорости трафика (rate limiting) на уровне правил;
- оперативное управление через CLI без перезапуска процесса;
- горячую перезагрузку конфигурации без прерывания пересылки пакетов.

Целевая платформа: Raspberry Pi 5 (BCM2712, ARM Cortex-A76, 4 ядра, 8 ГБ).
Интерфейсы: Intel I210 (WAN, PCI 0001:01:00.0) и BCM54213PE (LAN, eth0).

---

## Ограничения платформы и путь к производительности

### Первоначальный план: нативный PMD через vfio-pci

Стандартный путь kernel bypass в DPDK выглядит так:

```
NIC → vfio-pci (IOMMU) → DPDK PMD → userspace
```

Пакеты поступают в приложение напрямую через DMA, минуя ядро ОС полностью.

### Препятствие: BCM2712 PCIe без IOMMU

Контроллер PCIe в SoC BCM2712 не имеет IOMMU-групп для подключённых устройств:

- `vfio-pci` требует изоляции DMA через IOMMU — недоступен;
- `uio_pci_generic` использует физические адреса (PA mode). Однако в BCM2712 таблица
  `dma-ranges` задаёт смещение 64 ГБ: PCI-адрес `0x10_0000_0000` отображается в CPU phys `0x0`.
  DPDK передаёт I210 сырые физические адреса без учёта этого смещения — DMA молча
  записывает данные мимо памяти. Аппаратные счётчики растут, но `rte_eth_rx_burst`
  возвращает 0.

Единственный способ принять пакеты на этой платформе — оставить NIC под штатным драйвером
ядра и использовать соответствующий PMD.

### AF_PACKET PMD, ~12 Мбит/с

AF_PACKET PMD открывает `SOCK_RAW` + `PACKET_MMAP` (TPACKET_V2) сокет на существующем
сетевом интерфейсе, не требуя перепривязки драйвера. Это единственный способ получить
доступ к NIC в обход IP-стека без IOMMU.

Накладные расходы: каждый пакет проходит полный путь через ядро — аллокация sk_buff,
NAPI, копирование в ring AF_PACKET. Измеренная пропускная способность: **~12 Мбит/с**.

Попытка тюнинга AF_PACKET (`framecnt=4096`, `qdisc_bypass=1`) не дала эффекта: узкое место
находится в самом механизме копирования ядра, а не в размере кольца.

### AF_XDP PMD, 895 Мбит/с

AF_XDP — механизм ядра Linux (начиная с 4.18), позволяющий перехватить пакет прямо
в XDP-хуке драйвера — до аллокации sk_buff — и передать его в userspace через
разделяемую область памяти (UMEM-кольцо):

```
Без AF_XDP (AF_PACKET):             С AF_XDP (net_af_xdp PMD):
NIC -> NAPI -> sk_buff alloc ->     NIC -> NAPI -> XDP hook ->
  netif_receive_skb ->                bpf_redirect -> AF_XDP socket ->
  packet_rcv() -> copy ->             UMEM ring (shared memory) ->
  AF_PACKET ring -> DPDK              DPDK (один батч = один syscall)
```

IOMMU не требуется: пакет перехватывается внутри ядра после того, как DMA-операция
уже завершена корректно (igb использует Linux DMA API, который знает о 64 ГБ смещении).
Вся логика фильтрации по-прежнему выполняется в userspace DPDK.

Intel igb поддерживает AF_XDP native mode начиная с Linux 5.9. Попытка zero-copy оказалась
неуспешной из-за той же DMA-проблемы BCM2712 (UMEM-страницы не регистрируются для DMA).
Применяется режим `force_copy=1` (copy mode), при котором XDP-хук всё равно обеспечивает
перехват до sk_buff, а UMEM-транспорт управляется ядром.

LAN-порт (eth0, macb) не поддерживает XDP native mode — остаётся на AF_PACKET.

Итог: **895 Мбит/с** (×89 относительно AF_PACKET), 0 ретрансмитов, задержка 0.35 мс.

---

## Реализация

### Фундамент

Реализована основа проекта: инициализация DPDK EAL, управление lcore-ами, конфигурация
портов. Добавлен модуль `config.c` для загрузки правил из JSON через libjansson.
Прописана базовая структура `fw_rule` (IP, маска, порт, протокол, действие, приоритет).

В процессе обнаружены ограничения BCM2712 PCIe. Переход на AF_PACKET PMD — оба порта
остаются под штатными kernel-драйверами. В `main.c` реализовано автоматическое
определение: если в конфиге указано имя интерфейса (не PCI-адрес), добавляются
`--vdev eth_af_packet0,iface=<wan>` / `--vdev eth_af_packet1,iface=<lan>`.

### Движок правил

Реализован модуль `rule_engine.c` на базе `rte_acl`. В процессе обнаружена критическая
проблема: `rte_acl_classify()` в пакете DPDK 24.11.3 для ARM64 (Ubuntu RPi5) всегда
возвращает 0 — и для скалярного, и для NEON-пути. Предположительно ошибка в конкретной
сборке пакета.

Решение: `rte_acl_ctx` по-прежнему создаётся (жизненный цикл сохранён для совместимости),
но `rte_acl_classify()` заменён на приоритетный линейный сканер в `rule_match()`.
Семантика: меньший номер приоритета = выше важность, ранний выход при первом совпадении,
O(n) на пакет.

Отдельно отлажен порядок байт для `rte_acl` на LE ARM. Тип поля `RTE_ACL_FIELD_TYPE_MASK`
применяет префикс от старшего бита целочисленного значения. Если IP хранится в NBO
(`10.99.0.0` = `0x0000630a`), биты 31:8 соответствуют неверным октетам. Правильно —
host byte order (`0x0a630000`): тогда биты 31:8 совпадают с первыми тремя октетами адреса.
Конвертация: `rte_be_to_cpu_32()` в классификаторе и `ntohl()` в парсере CIDR.

### DDoS-защита и ограничение скорости

Реализован модуль `ddos.c`:
- хеш-таблица `rte_hash` (65536 записей) для чёрного списка IP — O(1) проверка;
- DDoS-трекер: скользящее окно на каждый IP-источник, счётчики SYN и UDP;
- автоматическая блокировка при превышении порога (`syn_threshold`, `udp_threshold`);
- TTL блокировки: запись удаляется автоматически по истечении `block_duration_s`.

Ограничение скорости реализовано через `rte_meter_srtcm` (single rate three color marker)
на уровне правил. Пакеты, получившие метку RED, отбрасываются.

В `pipeline.c` завершены все 7 стадий: проверка чёрного списка, rate limit,
обновление DDoS-трекера.

### Управление и CLI

Реализован модуль `mgmt.c`: UNIX-сокет `/var/run/dpdk_firewall/mgmt.sock` с epoll
и протоколом JSON (newline-delimited). Команды выполняются на lcore 0 (управляющем ядре).

Реализованы команды: `rule add`, `rule del`, `rule list`, `rule flush`, `stats`,
`blacklist add`, `blacklist del`, `blacklist list`, `config reload`, `set-policy`.

Добавлен `fw_ctl` — автономный CLI-инструмент (`cli/fw_ctl.c`) без зависимости от DPDK.
Собирается отдельно, использует только POSIX + libjansson.

Реализована горячая перезагрузка конфигурации. Сигнал `SIGHUP` устанавливает
`volatile g_sighup_flag`. Lcore 0 подхватывает флаг в основном цикле и вызывает
`config_reload()` + `rule_engine_rebuild()` под `rte_rwlock_write_lock()`.
Пересылающие lcores удерживают read-lock только на время вызова `rule_match()` —
задержка не превышает нескольких наносекунд.

### Исследование производительности

Выдвинуты и проверены три гипотезы:

**H1 — тюнинг AF_PACKET** (`framecnt=4096`, `qdisc_bypass=1`): результат отрицательный.
Все три конфигурации дают ~10.5 Мбит/с в пределах погрешности. Узкое место — путь
копирования в ядре, который нельзя устранить настройкой параметров AF_PACKET.

**H2 — AF_XDP PMD (copy mode)**: WAN-порт переведён на `net_af_xdp0` с `force_copy=1`.
Без этого флага в гибридном режиме (AF_XDP WAN + AF_PACKET LAN) происходит UMEM
starvation: DPDK не возвращает UMEM-фреймы в fill ring при пересылке на AF_PACKET-порт,
freelist истощается, TX молча дропает пакеты. С `force_copy=1` ядро управляет UMEM
lifecycle самостоятельно. Результат: **895 Мбит/с, 0 ретрансмитов** — гипотеза
подтверждена.

**H3 — AF_XDP zero-copy** (igb Linux 6.14+): попытка отключить `force_copy`. igb не
объявляет возможность `xdp-zerocopy` в `ethtool -k`. Причина та же: BCM2712 не позволяет
зарегистрировать UMEM-страницы как DMA-буферы через `xsk_pool_dma_map()` из-за 64 ГБ
PCIe DMA offset. Результат отрицательный, откат к `force_copy=1`.

Дополнительно задокументированы два специфических ограничения платформы:
- igb по умолчанию имеет 4 combined-очереди. AF_XDP привязан к очереди 0. RSS
  распределяет TCP по очередям 1–3 (XDP_PASS -> дроп). Исправление: `ethtool -L enP1p1s0 combined 1`.
- При некорректном завершении DPDK старая XDP-программа остаётся на интерфейсе и
  перенаправляет трафик в закрытый сокет. Исправление: `ip link set enP1p1s0 xdp off`
  перед каждым запуском.

---

## Топология тестового стенда

Сравнительный бенчмарк использует hairpin-топологию: два namespace на Dev PC с macvlan VEPA
на интерфейсе `eno1`. Трафик уходит на RPi5, отражается обратно (hairpin) и возвращается
в `ns_recv`. Raspi4 исключён из пути.

```
Dev PC                                      Raspberry Pi 5
┌──────────────────────────────┐            ┌─────────────────────┐
│  ns_send  (10.50.0.1/24)     │            │                     │
│  vns_send ──┐                │            │  Linux bridge br0   │
│             ├── eno1 ────────┼────────────┼── enP1p1s0          │
│  vns_recv ──┘                │            │    (hairpin on)     │
│  ns_recv  (10.50.0.2/24)     │            │                     │
└──────────────────────────────┘            │  DPDK AF_XDP        │
                                            │  (--hairpin mode)   │
                                            └─────────────────────┘
```

Путь пакета: `ns_send → vns_send → eno1 → enP1p1s0 → [hairpin] → enP1p1s0 → eno1 → vns_recv → ns_recv`

### Подготовка Dev PC (один раз после перезагрузки)

```bash
# Создать namespaces + macvlan VEPA интерфейсы:
sudo ./scripts/setup_hairpin_devpc.sh setup

# Проверить:
sudo ip netns list   # → ns_recv, ns_send
```

---

## Архитектура

### Модель lcore

| lcore | Роль | Описание |
|-------|------|----------|
| 0 | Управляющая плоскость | mgmt-сокет, перезагрузка конфига, дамп статистики |
| 1 | WAN→LAN | порт 0 RX -> pipeline -> порт 1 TX |
| 2 | LAN→WAN | порт 1 RX -> pipeline -> порт 0 TX |
| 3 | Резерв | не используется |

В hairpin-режиме (`--hairpin`) используется один порт и два lcore: lcore 0 (управление)
и lcore 1 (RX → pipeline → TX на тот же порт).

### Пайплайн (7 стадий, burst = 32 пакета)

```
1. RX BURST         rte_eth_rx_burst(port_in, 0, rx_pkts, 32)
2. CLASSIFIER       разбор Ethernet/IPv4/L4, заполнение pkt_meta[]
3. BLACKLIST CHECK  rte_hash_lookup(g_blacklist_hash, &src_ip) -> DROP
4. RULE ENGINE      приоритетный линейный сканер -> ACCEPT / DROP / RATE_LIMIT
5. RATE LIMIT       rte_meter_srtcm_color_blind_check() -> DROP если RED
6. DDOS UPDATE      скользящее окно per src_ip, auto-blacklist при превышении порога
7. TX BURST         rte_eth_tx_burst(port_out, 0, tx_pkts, n)
```

Не-IPv4 фреймы (ARP и др.) пересылаются без фильтрации — корректное поведение для L2-моста.

### Модули

| Файл | Назначение |
|------|------------|
| `src/main.c` | Инициализация EAL, аргументы, запуск lcore, обработчики сигналов |
| `src/port.c` | Создание mempool, настройка и запуск ethdev, `port_stats_get()` |
| `src/config.c` | Парсинг JSON (libjansson), `config_load()` / `config_reload()` |
| `src/pipeline.c` | 7-стадийный цикл пересылки на каждом lcore |
| `src/rule_engine.c` | Жизненный цикл rte_acl_ctx, `rule_match()`, перестройка под rwlock |
| `src/ddos.c` | rte_hash-blacklist + DDoS-трекер, rte_meter_srtcm для RATE_LIMIT |
| `src/stats.c` | Атомарные счётчики, `stats_get_snapshot()`, периодический лог |
| `src/mgmt.c` | epoll UNIX-сокет, диспетчер JSON-команд |
| `cli/fw_ctl.c` | CLI без DPDK, POSIX + libjansson |
| `include/firewall.h` | Общие типы: `fw_rule`, `pkt_meta`, `fw_mode_t`, `fw_action_t`, `MAX_RULES` |

---

## Конфигурация

Правила описываются в JSON-файле (`config/rules.json`):

```json
{
  "mode": "bridge",
  "ports": { "wan": "enP1p1s0", "lan": "builtin" },
  "default_policy": "drop",
  "ddos": {
    "enabled": true,
    "window_ms": 100,
    "syn_threshold": 100,
    "udp_threshold": 500,
    "block_duration_s": 30
  },
  "rules": [
    { "id": 1, "priority": 100, "proto": "tcp", "dst_port": "22",
      "action": "accept" },
    { "id": 2, "priority": 200, "proto": "icmp",
      "action": "rate_limit", "rate": { "cir_kbps": 1000, "cbs_bytes": 65536 } },
    { "id": 3, "priority": 300, "src_ip": "10.0.0.0/8",
      "proto": "tcp", "dst_port": "80", "action": "accept" }
  ]
}
```

Поддерживаемые поля правила: `src_ip` / `dst_ip` (CIDR), `src_port` / `dst_port`
(одиночный или диапазон), `proto` (`tcp`, `udp`, `icmp`, `any`), `action`
(`accept`, `drop`, `rate_limit`), `priority`.

Горячая перезагрузка: `sudo kill -HUP $(pgrep dpdk_firewall)` или `fw_ctl config reload`.

Для hairpin-бенчмарка используется `config/bench_hairpin.json` — один порт (`enP1p1s0`),
0 правил, default policy ACCEPT.

---

## Сборка

Сборка выполняется нативно на RPi5 (не кросс-компиляция):

```bash
sudo apt install dpdk dpdk-dev libdpdk-dev libjansson-dev libxdp-dev libbpf-dev \
                 meson ninja-build pkg-config build-essential

meson setup build --optimization=3
ninja -C build
```

---

## Запуск

Рекомендуется использовать `run.sh`, который автоматически выполняет все
подготовительные шаги (hugepages, igb, интерфейсы, RSS queue, сброс XDP, сборка):

```bash
# Только подготовка (без запуска):
./run.sh setup

# Подготовка + запуск с конфигом по умолчанию:
./run.sh start

# Подготовка + запуск с кастомным конфигом:
./run.sh start config/bench_baseline.json

# Подготовка + запуск в hairpin-режиме (один порт, для бенчмарка):
./run.sh hairpin

# Hairpin с кастомным конфигом:
./run.sh hairpin config/bench_hairpin.json
```

При ручном запуске необходимо соблюдать следующий порядок:

```bash
# 1. Выделить hugepages (2 МБ, 512 штук = 1 ГБ):
echo 512 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# 2. Загрузить драйвер и поднять интерфейсы:
sudo modprobe igb
sudo ip link set enP1p1s0 up
sudo ip link set eth0 up

# 3. Сбросить igb до 1 очереди (обязательно для AF_XDP):
sudo ethtool -L enP1p1s0 combined 1

# 4. Сбросить старую XDP-программу (обязательно перед каждым запуском):
sudo ip link set enP1p1s0 xdp off

# 5. Запустить:
sudo ./build/dpdk_firewall --config config/rules.json --log-level info
```

---

## Управление

`fw_ctl` — CLI без зависимости от DPDK. Взаимодействует через UNIX-сокет.

```bash
# Статистика
fw_ctl stats

# Правила
fw_ctl rule list
fw_ctl rule add --proto tcp --dst-port 80 --action accept --priority 100
fw_ctl rule del --id 3
fw_ctl rule flush

# Чёрный список
fw_ctl blacklist add --ip 192.168.1.100 --duration 300
fw_ctl blacklist del --ip 192.168.1.100
fw_ctl blacklist list

# Конфигурация
fw_ctl config reload
fw_ctl set-policy drop
```

---

## Бенчмарк: Linux bridge vs DPDK

Сравниваются два способа hairpin-форвардинга на RPi5:

- **Linux bridge**: `br0` + `bridge link set dev enP1p1s0 hairpin on`
- **DPDK**: `./run.sh hairpin` (AF_XDP PMD, `--hairpin`)

Инструмент: [t-raf](https://github.com/aguinet/t-raf), RAW-режим (IP proto 253),
deterministic distribution, 60 секунд. Конфиги: `config/traf/traf_hairpin_*.yml`.

```bash
# Подготовка Dev PC (один раз):
sudo ./scripts/setup_hairpin_devpc.sh setup

# Запуск сервера (ns_recv):
sudo ip netns exec ns_recv ~/diploma/t-raf/build/t-raf \
  config/traf/traf_hairpin_64.yml server1

# Запуск клиента (ns_send):
sudo ip netns exec ns_send ~/diploma/t-raf/build/t-raf \
  config/traf/traf_hairpin_64.yml client1
```

Результаты и графики — в папке `results/`. Построить графики:

```bash
python3 scripts/plot_hairpin.py
```

---

## Известные ограничения платформы

BCM2712 PCIe накладывает фундаментальные ограничения, устранить которые штатными
средствами невозможно:

- нет IOMMU-групп для PCIe endpoint-устройств -> vfio-pci недоступен;
- 64 ГБ DMA offset в dma-ranges -> uio_pci_generic + DPDK PA mode работают некорректно;
- AF_XDP zero-copy требует регистрации UMEM-страниц как DMA-буферов (xsk_pool_dma_map),
  что завершается с ошибкой по той же причине;
- macb (eth0, LAN) не поддерживает XDP native mode -> LAN остаётся на AF_PACKET.

Тот же код на x86 с vfio-pci на нативном PMD обеспечивает линейную скорость 10+ Гбит/с.
Результат 895 Мбит/с на RPi5 достигнут исключительно за счёт AF_XDP как транспортного
слоя при сохранении полной логики фильтрации в DPDK userspace.
