#!/bin/bash
# run.sh — скрипт запуска dpdk_firewall на RPi5
#
# Использование:
#   ./run.sh setup                — git pull, сборка, подготовка интерфейсов (без запуска брандмауэра)
#   ./run.sh start [config]       — setup + запуск брандмауэра (конфиг по умолчанию: config/rules.json)
#   ./run.sh hairpin [config]     — setup + запуск в hairpin-режиме (один порт, lcore 0+1)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEFAULT_CONFIG="config/rules.json"
CONFIG="${2:-$DEFAULT_CONFIG}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
die()   { echo -e "${RED}[x]${NC} $*" >&2; exit 1; }

cd "$SCRIPT_DIR"

# --- 1. git pull ---
info "Обновление репозитория..."
git pull

# --- 2. Hugepages ---
info "Выделение hugepages..."
HUGE=$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages)
if [ "$HUGE" -lt 512 ]; then
    echo 512 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages > /dev/null
    info "Hugepages выделены: 512 x 2MB"
else
    info "Hugepages уже выделены: $HUGE"
fi

# --- 3. igb driver ---
info "Загрузка драйвера igb..."
sudo modprobe igb 2>/dev/null || warn "igb уже загружен или недоступен"

# --- 4. Bring up interfaces ---
info "Поднятие интерфейсов..."
sudo ip link set enP1p1s0 up || die "Не удалось поднять enP1p1s0"
sudo ip link set eth0 up     || die "Не удалось поднять eth0"

# Проверка
ip link show enP1p1s0 | grep -q "UP" || die "enP1p1s0 не активен (не UP)"
ip link show eth0     | grep -q "UP" || die "eth0 не активен (не UP)"
info "enP1p1s0: UP, eth0: UP"

# --- 5. igb RSS queues: reduce to 1 (required for AF_XDP) ---
info "Установка igb combined queues в 1..."
sudo ethtool -L enP1p1s0 combined 1 || warn "ethtool -L не удался (возможно, уже установлено)"
QUEUES=$(sudo ethtool -l enP1p1s0 2>/dev/null | grep -A5 "Current" | grep "Combined" | awk '{print $2}')
info "igb combined queues: ${QUEUES:-unknown}"

# --- 6. Clear stale XDP program ---
info "Очистка устаревшей XDP-программы на enP1p1s0..."
sudo ip link set enP1p1s0 xdp off 2>/dev/null || true

# --- 7. Build ---
info "Сборка..."
ninja -C build

info "Сборка завершена"
echo ""

if [ "${1:-}" = "setup" ]; then
    info "Настройка завершена. Запустите './run.sh start [config]' для запуска брандмауэра."
    exit 0
fi

if [ "${1:-}" = "start" ]; then
    [ -f "$CONFIG" ] || die "Конфиг не найден: $CONFIG"
    info "Запуск брандмауэра с конфигом: $CONFIG"
    echo ""
    exec sudo ./build/dpdk_firewall --config "$CONFIG" --log-level info
fi

if [ "${1:-}" = "hairpin" ]; then
    HAIRPIN_CONFIG="${2:-config/bench_hairpin.json}"
    [ -f "$HAIRPIN_CONFIG" ] || die "Конфиг не найден: $HAIRPIN_CONFIG"
    info "Запуск брандмауэра в hairpin-режиме с конфигом: $HAIRPIN_CONFIG"
    echo ""
    exec sudo ./build/dpdk_firewall --config "$HAIRPIN_CONFIG" --log-level info --hairpin
fi

echo "Usage: $0 setup | start [config] | hairpin [config]"
exit 1
