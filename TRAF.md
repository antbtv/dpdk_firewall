# T-RAF — Документация по запуску

Источник: `t-raf/` (репозиторий https://gitflic.ru/project/mpei-vmss/t-raf)

## Что такое t-raf

Генератор трафика в режиме клиент-сервер. Клиент отправляет пакеты с зашитым
номером и временной меткой, сервер принимает и записывает сквозную задержку
(end-to-end latency). Дополнительно выводит throughput (пакет/с, MB/s).

Поддерживает три вида сокетов:

| Режим     | `port` | `use_pfring` | Уровень | Root? |
|-----------|--------|--------------|---------|-------|
| UDP       | >0     | False        | L4 (UDP)| нет  |
| RAW       | 0      | False        | L3 (IP) | да   |
| PF_RING   | 0      | True         | L2      | да   |

**Для нашего стенда используем RAW или UDP.**

- **RAW** (`port: 0`) — лучше для throughput-тестов: нет UDP-overhead, работает
  с любым IP-пакетом. Требует `sudo`.
- **UDP** (`port: 50001`) — проще, не нужен root на клиенте. Допустим для latency.

## Параметр `length` — это IP-длина

`length` в конфиге = **total IP packet length** (заголовок IP + payload).

Для наших целевых размеров:

| `length` | Ethernet frame (length+14) | Описание |
|----------|---------------------------|----------|
| 64       | 78 байт                   | min IP (стандартный тест на мелких пакетах) |
| 512      | 526 байт                  | средний пакет |
| 800      | 814 байт                  | средний пакет |
| 1500     | 1514 байт                 | стандартный MTU (Jumbo-free) |

Минимально допустимое значение: `64` (ограничение `Buf::minLength`).

## Топология для наших тестов

```
Dev PC (10.99.0.1, eno1)
    |   [клиент t-raf]
    |
[RPi5 — dpdk_firewall (AF_XDP) ИЛИ Linux bridge]
    |
raspi4 (10.99.0.2, eth0)
    |   [сервер t-raf]
```

## Сборка t-raf на каждом узле

```bash
# На Dev PC и raspi4 (одинаково):
cd t-raf
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j4
# Результат: build/t-raf
```

PF_RING не нужен — RAW/UDP сокеты работают без него.

## Структура конфиг-файла

Один YAML-файл на оба узла. Роль (`client` / `server`) задаётся при запуске.

```yaml
---
experiment:
  time: 30                          # длительность теста в секундах
  output_directory: './results/'

  network:
    server1:                        # роль: сервер (raspi4)
      ip: "10.99.0.2"
      int: 'eth0'
      traffic:
        server:
          enabled: 'True'
          use_pfring: 'False'
          disable_output: 'False'
          ports: [0]                # 0 = RAW сокет
          length: 64                # размер пакетов синхронизации

    client1:                        # роль: клиент (Dev PC)
      ip: "10.99.0.1"
      int: 'eno1'
      traffic:
        client:
          distribution: 'max'       # max = без задержек, максимальный throughput
          npackets: 0               # 0 = работать по времени (experiment.time)
          length: 64                # РАЗМЕР IP-ПАКЕТА (меняем для каждого теста)
          direction: '10.99.0.2'
          direction_mac: 'XX:XX:XX:XX:XX:XX'  # MAC raspi4 eth0 (узнать: ip neigh)
          port: 0                   # 0 = RAW сокет
          use_pfring: 'False'
          single_thread: 'True'
          disable_output: 'False'
          disable_timestamps: 'False'
        server:
          enabled: 'False'
```

### Параметры distribution

| `distribution` | Поведение |
|----------------|-----------|
| `max`          | Минимальная задержка между пакетами — throughput-тест |
| `deterministic`| Равные интервалы — задаётся через `intensity` (pkt/s) |
| `exponential`  | Пуассоновский поток — задаётся через `intensity` (pkt/s) |
| `none`         | Только синхронизация часов |

Для throughput-тестов (как у нас): `distribution: 'deterministic'` с `intensity` = 90% от line rate.
**Не использовать `max`** для пакетов ≥ 800 байт: при single_thread `max` превышает 1 Гбит/с →
sendbuf saturation на клиенте → generation_time > 30 с, нестабильные результаты.

## Узнать MAC-адрес raspi4

На Dev PC после того, как оба узла в сети:
```bash
ping -c1 10.99.0.2
ip neigh show 10.99.0.2
# → 10.99.0.2 dev eno1 lladdr dc:a6:32:XX:XX:XX REACHABLE
```

## Запуск теста (порядок имеет значение)

### 1. На raspi4 (сервер — запускать первым):
```bash
mkdir -p results
sudo ./t-raf/build/t-raf config.yml server1
```

Сервер стартует сразу и ждёт подключения клиента.

### 2. На Dev PC (клиент — запускать вторым):
```bash
mkdir -p results
sudo ./t-raf/build/t-raf config.yml client1
```

Клиент ждёт **10 секунд** (hardcoded в `main.cpp`: `sleep(10)`), затем
выполняет синхронизацию часов, затем начинает генерацию.

Итого реальное время запуска: 10 с (ожидание) + `experiment.time` секунд.

## Результаты

Файлы создаются в `output_directory`:

**На клиенте** (`client1-sent.csv`):
```
<время_отправки_нс>, <интервал_нс>, <номер_пакета>
```

**На сервере** (`server1-0-rcv.csv` для RAW, `server1-50001-rcv.csv` для UDP):
```
<время_получения_нс>, <номер_пакета>, <сквозная_задержка_нс>
```

**В stdout клиента** — итоговый throughput:
```
Speed: 892341 packet/s, 57.1 MB/s
```

**Задержка** считается как `время_получения_сервера − время_отправки_клиента`,
скорректированная на разницу часов (TimeCorrector: NTP-like обмен перед тестом).

## Готовые конфиги для наших тестов

Файлы лежат в `config/traf/`:

| Файл                      | `length` | `distribution`  | `intensity` | Расчёт (90% × 1 Гбит/с) |
|---------------------------|----------|-----------------|-------------|--------------------------|
| `traf_64.yml`             | 64       | deterministic   | 150,000     | ≤ single_thread cap ~170k pkt/s |
| `traf_512.yml`            | 512      | deterministic   | 220,000     | ÷ (512×8) |
| `traf_800.yml`            | 800      | deterministic   | 140,000     | ÷ (800×8) |
| `traf_1500.yml`           | 1500     | deterministic   | 75,000      | ÷ (1500×8) |

t-raf при `single_thread=True` физически ограничен ~170–200k pkt/s — intensity 1.75M для 64 байт
недостижима, но это нормально: клиент работает на максимуме, не превышая line rate.

## Типичные ошибки

| Ошибка | Причина | Решение |
|--------|---------|---------|
| `cannot create client socket` | нет root | `sudo` |
| `cannot bind client socket` | IP не назначен на eno1 | `sudo ip addr add 10.99.0.1/24 dev eno1` |
| Клиент шлёт, сервер получает 0 | firewall дропает proto 0xFD | добавить правило ACCEPT для proto 253 |
| Все пакеты с задержкой > 1с | неправильный `direction_mac` (00:00:00) | узнать MAC через `ip neigh` |

### Про протокол 0xFD в RAW-режиме

T-raf использует нестандартный IP-протокол `0xFD` (253) для RAW-пакетов.
Это протокол "для экспериментов" (RFC 3692).

**При тесте через dpdk_firewall** нужно убедиться, что правила не дропают proto 253.
В `bench_baseline.json` (0 правил) — пройдёт. В конфигах с DROP-правилами —
добавить ACCEPT для proto 253 перед DROP-правилами.

**При тесте без DPDK** (Linux bridge) — проходит без ограничений.

## Команды для подготовки стенда (Linux bridge — "без DPDK")

```bash
# На RPi5: убрать dpdk_firewall, создать kernel bridge
sudo pkill dpdk_firewall || true
sudo ip link add br0 type bridge
sudo ip link set enP1p1s0 master br0
sudo ip link set eth0 master br0
sudo ip link set br0 up
sudo ip link set enP1p1s0 up
sudo ip link set eth0 up

# Проверка: Dev PC должен пинговать raspi4
ping -c3 10.99.0.2
```

```bash
# Убрать bridge (вернуть к DPDK-режиму):
sudo ip link set enP1p1s0 nomaster
sudo ip link set eth0 nomaster
sudo ip link del br0
```

---

## P10-04: Запуск всех 8 тестов (4 размера × 2 сценария)

Скрипт `scripts/run_p1004_client.sh` автоматизирует Dev PC сторону и даёт
пошаговые инструкции для RPi5 и raspi4.

### Порядок для каждого теста

#### На RPi5 (запустить в фоне перед каждым тестом):
```bash
# Метрики нужно запустить ДО старта t-raf сервера:
./scripts/collect_metrics.sh 38 results/<scenario>_<size>/metrics enP1p1s0 &
```

#### На raspi4 (запустить до Dev PC):
```bash
sudo ~/t-raf/build/t-raf ~/traf_<size>.yml server1
```

#### На Dev PC (клиент):
```bash
./scripts/run_p1004_client.sh ~/diploma/t-raf/build/t-raf
# Скрипт делает паузы и ждёт Enter перед каждым тестом
```

### Файлы конфигов на raspi4

Конфиги должны быть скопированы в `~/` на raspi4:
```bash
# С Dev PC или RPi5:
scp config/traf/traf_*.yml raspi4:~/
```

### Структура результатов

После 8 тестов в `results/` будет:
```
results/
  bridge_64/
    client.txt           ← вывод t-raf client (Speed: X pkt/s, Y MB/s + total_delay)
    summary.txt          ← ключевые цифры (автоматически)
    server_received.txt  ← вручную после теста (последнее число t-raf server)
    metrics_cpu.log      ← mpstat по ядрам (скопировать с RPi5)
    metrics_psi.log      ← /proc/pressure
    metrics_netdev.log   ← /proc/net/dev
    metrics_io.log       ← iostat -x
    metrics_mem.log      ← /proc/meminfo
  bridge_512/ ... bridge_800/ ... bridge_1500/
  dpdk_64/ ... dpdk_512/ ... dpdk_800/ ... dpdk_1500/
```

### Копирование метрик с RPi5 на Dev PC

```bash
# После каждого теста (или после всех):
scp -r rpi5:~/dev/dpdk_firewall/results/bridge_64/ results/
scp -r rpi5:~/dev/dpdk_firewall/results/dpdk_64/ results/
# и т.д.
```
