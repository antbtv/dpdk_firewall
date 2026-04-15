#!/usr/bin/env bash
# collect_metrics.sh — сбор метрик ресурсов во время t-raf теста
#
# Использование:
#   ./scripts/collect_metrics.sh <duration_seconds> <output_prefix> [interface]
#
# Пример:
#   ./scripts/collect_metrics.sh 35 results/bridge_64/metrics enP1p1s0
#
# Собирает параллельно:
#   <prefix>_cpu.log     — mpstat -P ALL 1 (загрузка по ядрам)
#   <prefix>_psi.log     — /proc/pressure/{cpu,memory,io} раз в секунду
#   <prefix>_netdev.log  — /proc/net/dev раз в секунду (все поля)
#   <prefix>_io.log      — iostat -x 1 (расширенная статистика блочных устройств)
#   <prefix>_mem.log     — /proc/meminfo раз в секунду

set -euo pipefail

DURATION=${1:?"Usage: $0 <duration_seconds> <output_prefix> [interface]"}
PREFIX=${2:?"Usage: $0 <duration_seconds> <output_prefix> [interface]"}
IFACE=${3:-""}

# Создать директорию для вывода если не существует
mkdir -p "$(dirname "$PREFIX")"

echo "[collect_metrics] start: duration=${DURATION}s prefix=${PREFIX}"

# --- 1. CPU load (mpstat) ---
mpstat -P ALL 1 "$DURATION" > "${PREFIX}_cpu.log" 2>&1 &
PID_CPU=$!

# --- 2. PSI (Pressure Stall Information) ---
(
    echo "# timestamp cpu_some_avg10 cpu_some_avg60 cpu_full_avg10 cpu_full_avg60 mem_some_avg10 mem_some_avg60 mem_full_avg10 mem_full_avg60 io_some_avg10 io_some_avg60 io_full_avg10 io_full_avg60"
    END=$((SECONDS + DURATION))
    while [ $SECONDS -lt $END ]; do
        TS=$(date +%s.%N)
        CPU_SOME=""
        CPU_FULL=""
        MEM_SOME=""
        MEM_FULL=""
        IO_SOME=""
        IO_FULL=""
        if [ -f /proc/pressure/cpu ]; then
            CPU_SOME=$(grep "^some" /proc/pressure/cpu | awk '{print $2,$3}' | tr -d 'avg10= avg60=')
            CPU_FULL=$(grep "^full" /proc/pressure/cpu 2>/dev/null | awk '{print $2,$3}' | tr -d 'avg10= avg60=' || echo "N/A N/A")
        fi
        if [ -f /proc/pressure/memory ]; then
            MEM_SOME=$(grep "^some" /proc/pressure/memory | awk '{print $2,$3}' | tr -d 'avg10= avg60=')
            MEM_FULL=$(grep "^full" /proc/pressure/memory | awk '{print $2,$3}' | tr -d 'avg10= avg60=')
        fi
        if [ -f /proc/pressure/io ]; then
            IO_SOME=$(grep "^some" /proc/pressure/io | awk '{print $2,$3}' | tr -d 'avg10= avg60=')
            IO_FULL=$(grep "^full" /proc/pressure/io | awk '{print $2,$3}' | tr -d 'avg10= avg60=')
        fi
        echo "$TS $CPU_SOME $CPU_FULL $MEM_SOME $MEM_FULL $IO_SOME $IO_FULL"
        sleep 1
    done
) > "${PREFIX}_psi.log" 2>&1 &
PID_PSI=$!

# --- 3. /proc/net/dev (все поля) ---
(
    # Заголовок с описанием полей
    echo "# timestamp $(head -2 /proc/net/dev | tail -1)"
    END=$((SECONDS + DURATION))
    while [ $SECONDS -lt $END ]; do
        TS=$(date +%s.%N)
        # Пропустить первые 2 строки заголовка
        tail -n +3 /proc/net/dev | while IFS= read -r line; do
            echo "$TS $line"
        done
        sleep 1
    done
) > "${PREFIX}_netdev.log" 2>&1 &
PID_NETDEV=$!

# --- 4. iostat (расширенная статистика блочных устройств) ---
iostat -x 1 "$DURATION" > "${PREFIX}_io.log" 2>&1 &
PID_IO=$!

# --- 5. /proc/meminfo ---
(
    echo "# timestamp field value_kB"
    END=$((SECONDS + DURATION))
    while [ $SECONDS -lt $END ]; do
        TS=$(date +%s.%N)
        while IFS= read -r line; do
            echo "$TS $line"
        done < /proc/meminfo
        sleep 1
    done
) > "${PREFIX}_mem.log" 2>&1 &
PID_MEM=$!

# --- Ожидание завершения всех коллекторов ---
wait $PID_CPU $PID_PSI $PID_NETDEV $PID_IO $PID_MEM

echo "[collect_metrics] done: files written to ${PREFIX}_*.log"

# --- Краткая сводка в stdout ---
echo ""
echo "=== CPU summary (avg across duration) ==="
grep "^Average" "${PREFIX}_cpu.log" | head -8

if [ -n "$IFACE" ]; then
    echo ""
    echo "=== Net interface ${IFACE} (last snapshot) ==="
    grep "$IFACE" "${PREFIX}_netdev.log" | tail -1
fi
