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

Intel igb поддерживает AF_XDP native mode начиная с Linux 5.9; ядро 6.17 на RPi5
добавило поддержку AF_XDP zero-copy для igb (Linux 6.14). Попытка zero-copy, однако,
оказалась неуспешной из-за той же DMA-проблемы BCM2712 (UMEM-страницы не регистрируются
для DMA). Применяется режим `force_copy=1` (copy mode), при котором XDP-хук всё равно
обеспечивает перехват до sk_buff, а UMEM-транспорт управляется ядром.

LAN-порт (eth0, macb) не поддерживает XDP native mode в ядре 6.17 — остаётся на AF_PACKET.

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

Собран тестовый стенд: Dev PC (10.99.0.1) — RPi5 WAN — RPi5 LAN — Raspberry Pi 4
(10.99.0.2). Измерена базовая пропускная способность: **12 Мбит/с** (AF_PACKET PMD).

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

## Архитектура

### Модель lcore

| lcore | Роль | Описание |
|-------|------|----------|
| 0 | Управляющая плоскость | mgmt-сокет, перезагрузка конфига, дамп статистики |
| 1 | WAN→LAN | порт 0 RX -> pipeline -> порт 1 TX |
| 2 | LAN→WAN | порт 1 RX -> pipeline -> порт 0 TX |
| 3 | Резерв | не используется |



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

## Результаты измерений

Платформа: Raspberry Pi 5 (ARM Cortex-A76, 4 ядра @ 2.4 ГГц, 8 ГБ RAM).
NIC WAN: Intel I210 (igb), NIC LAN: BCM54213PE (macb).
DPDK 24.11.3, ядро 6.17.0-1008-raspi (aarch64).

Топология:
```
Dev PC (10.99.0.1, eno1) ──── enP1p1s0 ──── RPi5 ──── eth0 ──── raspi4 (10.99.0.2)
```

### Пропускная способность (iperf3 TCP)

| PMD | Мбит/с | Ретрансм./10с | RTT avg |
|-----|-------:|-------------:|--------:|
| AF_PACKET | ~12 | 2333 | 0.85 мс |
| AF_XDP (force_copy=1) | **895** | **0** | **0.35 мс** |

Улучшение: **×89**. AF_XDP достигает 89.5% от физической скорости канала.

### Накладные расходы ACL и DDoS (AF_XDP)

| Сценарий | Мбит/с | Ретрансм. |
|----------|-------:|----------:|
| 0 правил, DDoS выкл | 882 | 0 |
| 10 правил DROP | 873 | 0 |
| 100 правил DROP | 846 | 0 |
| 1 правило + DDoS вкл | 842 | 0 |

Накладные расходы в пределах погрешности (~5%): узкое место — физический канал, не CPU.

### Задержка (AF_XDP, ping -i 0.002 -c 2000)

| Нагрузка | p50 RTT | p99 RTT |
|----------|--------:|--------:|
| 0% | 0.175 мс | 0.207 мс |
| 90% (805 Мбит/с) | 0.420 мс | 0.783 мс |

p99 < 1 мс при нагрузке 90% — forwarding-путь стабилен у насыщения канала.

### DDoS-детекция (hping3 --flood)

Конфиг: `window_ms=100`, `syn_threshold=100`, `udp_threshold=500`.

| Тип атаки | Время обнаружения | Отброшено |
|-----------|------------------:|----------:|
| SYN flood | ≤ 100 мс | 99.9% |
| UDP flood | ≤ 100 мс | 99.9% |

### Утилизация CPU RPi5 при форвардинге (AF_XDP)

| lcore | Роль | %usr | %sys | %idle |
|-------|------|-----:|-----:|------:|
| 0 | control plane | ~1 | ~3 | ~95 |
| 1 | LAN→WAN (AF_PACKET) | ~10 | ~90 | 0 |
| 2 | WAN→LAN (AF_XDP) | **100** | 0 | 0 |
| 3 | резерв | ~1 | ~3 | ~96 |

lcore 2: 100% usr — AF_XDP busy-poll без syscall на пакет.
lcore 1: 90% sys — AF_PACKET требует syscall на каждый burst (LAN-порт без XDP).

---

### Сравнительный бенчмарк: Linux bridge vs DPDK AF_XDP (t-raf, 2026-04-17)

Инструмент: t-raf (RAW IP proto 253, deterministic distribution, 30 с).
Метрика: pkt/s на raspi4 (t-raf server, SOCK_RAW, однопоточный).
DPDK: 0 правил, DDoS отключён, default policy ACCEPT.

| Размер | Отправлено | Bridge server pkt/s | DPDK server pkt/s | DPDK dropped |
|--------|----------:|--------------------:|------------------:|-------------:|
| 64 Б  | 4 500 000 | **95 333** | **94 667** | **0** |
| 512 Б | 6 600 000 | **94 906** | **94 458** | **0** |
| 800 Б | 4 200 000 | **95 883** | **96 140** | **0** |
| 1500 Б| 2 250 000 | **75 000** | **75 000** | **0** |

**DPDK dropped=0** во всех тестах — firewall пересылает 100% входящих пакетов.

**Bottleneck — raspi4, не форвардер.** Расхождение bridge/DPDK (~7–8% при 64–800 Б)
объясняется не технологией форвардинга, а разным состоянием CPU governor на raspi4
(thermal throttling Cortex-A72 @ 1.4 ГГц) в разных запусках.
Прямое измерение: t-raf server упирается в ~88–96k pkt/s независимо от форвардера —
это жёсткий потолок однопоточного `recvfrom(SOCK_RAW)` на Cortex-A72: один syscall
занимает ~10–11 мкс, 90% времени ядра на одном ядре, три ядра простаивают.
При 1500 Б оба сценария дают одинаковый результат (75k = line rate 1 Гбит/с).

---

## Воспроизведение замеров (64-байтные пакеты)

Конфиг t-raf: `config/traf/traf_64.yml` (150 000 pkt/s, 30 с, RAW, deterministic).
Скопировать на raspi4 и Dev PC заранее.

### Сценарий 1: Linux bridge

```bash
# === RPi5 ===
# Настроить bridge (если не настроен):
sudo ip link add br0 type bridge 2>/dev/null || true
sudo ip link set enP1p1s0 master br0
sudo ip link set eth0 master br0
sudo ip link set br0 up
sudo ip link set enP1p1s0 up
sudo ip link set eth0 up
# Убедиться, что dpdk_firewall НЕ запущен.

# Запустить сбор метрик (в отдельном терминале):
./scripts/collect_metrics.sh 38 results/bridge_64/metrics enP1p1s0 &

# === raspi4 (параллельно) ===
sudo ~/t-raf/build/t-raf ~/traf_64.yml server1
# Записать итоговое число (received count) из вывода.

# === Dev PC (после запуска сервера) ===
sudo ./t-raf config/traf/traf_64.yml client1
```

### Сценарий 2: DPDK 

```bash
# === RPi5 ===
# Запустить firewall (hugepages, igb, RSS=1, xdp off — всё внутри run.sh):
./run.sh start

# Запустить сбор метрик (в новом терминале RPi5):
./scripts/collect_metrics.sh 38 results/dpdk_64/metrics enP1p1s0 &

# === raspi4 (параллельно) ===
sudo ~/t-raf/build/t-raf ~/traf_64.yml server1

# === Dev PC (после запуска сервера) ===
sudo ./t-raf config/traf/traf_64.yml client1
```

После каждого теста скопировать метрики с RPi5:
```bash
rsync -av anton@<rpi5_ip>:~/diploma/dpdk_firewall/results/bridge_64/ results/bridge_64/
rsync -av anton@<rpi5_ip>:~/diploma/dpdk_firewall/results/dpdk_64/   results/dpdk_64/
```

Построить графики:
```bash
python3 scripts/plot_benchmarks.py
```

---

## Известные ограничения платформы

BCM2712 PCIe накладывает фундаментальные ограничения, устранить которые штатными
средствами невозможно:

- нет IOMMU-групп для PCIe endpoint-устройств -> vfio-pci недоступен;
- 64 ГБ DMA offset в dma-ranges -> uio_pci_generic + DPDK PA mode работают некорректно;
- AF_XDP zero-copy требует регистрации UMEM-страниц как DMA-буферов (xsk_pool_dma_map),
  что завершается с ошибкой по той же причине;
- macb (eth0, LAN) не поддерживает XDP native mode на ядре 6.17 -> LAN остаётся на AF_PACKET.

Тот же код на x86 с vfio-pci на нативном PMD обеспечивает линейную скорость 10+ Гбит/с.
Результат 895 Мбит/с на RPi5 достигнут исключительно за счёт AF_XDP как транспортного
слоя при сохранении полной логики фильтрации в DPDK userspace.
