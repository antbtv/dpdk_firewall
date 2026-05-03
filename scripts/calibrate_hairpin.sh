#!/usr/bin/env bash
# calibrate_hairpin.sh — измеряет максимальный pkt/s t-raf для каждого размера пакета
#
# Запускает 30-секундные тесты с distribution: max через hairpin-топологию.
# Выводит рекомендуемые значения intensity (90% от max) для deterministic конфигов.
#
# Использование:
#   ./scripts/calibrate_hairpin.sh <traf_binary>
#
# Требования (должно быть готово перед запуском):
#   - namespaces ns_send / ns_recv настроены (setup_hairpin_devpc.sh setup)
#   - RPi5: bridge hairpin активен (стандартный сценарий)
#
# После запуска скрипт обновит intensity в config/traf/traf_hairpin_*.yml.

set -euo pipefail

TRAF_BIN=${1:?"Usage: $0 <traf_binary>"}
SIZES=(64 512 800 1500)
CALIB_DURATION=30

# Временные конфиги (max distribution, 30с)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

make_calib_config() {
    local SIZE=$1
    local OUT="${TMP_DIR}/calib_${SIZE}.yml"
    cat > "$OUT" <<EOF
---
experiment:
 time: ${CALIB_DURATION}
 output_directory: '${TMP_DIR}/results/'
network:
 server1:
  ip: '10.50.0.2'
  int: 'vns_recv'
  traffic:
   server:
     use_pfring: 'False'
     enabled: 'True'
     disable_output: 'True'
     disable_time_corrector: 'False'
     ports: [0]
     length: ${SIZE}
 client1:
  ip: '10.50.0.1'
  int: 'vns_send'
  traffic:
   client:
     distribution: 'max'
     intensity: 2000000
     npackets: 0
     length: ${SIZE}
     direction: '10.50.0.2'
     direction_mac: '02:00:00:00:00:02'
     port: 0
     use_pfring: 'False'
     single_thread: 'True'
     disable_output: 'True'
     disable_timestamps: 'True'
     measure_latency: 'False'
     sync_time: 0
   server:
     enabled: 'False'
EOF
    echo "$OUT"
}

echo "========================================================"
echo "Hairpin calibration: измерение max pkt/s для каждого размера"
echo "Тест ${CALIB_DURATION}с × 4 размера ≈ $((CALIB_DURATION * 4 / 60 + 1)) мин"
echo "========================================================"
echo ""
echo "Убедись, что RPi5 настроен на bridge hairpin:"
echo "  sudo ip link add br0 type bridge 2>/dev/null || true"
echo "  sudo ip link set enP1p1s0 master br0"
echo "  sudo ip link set br0 up && sudo ip link set enP1p1s0 up"
echo "  sudo bridge link set dev enP1p1s0 hairpin on"
echo ""
echo "Нажми Enter для начала..."
read -r

declare -A MAX_PPS
mkdir -p "${TMP_DIR}/results"

for SIZE in "${SIZES[@]}"; do
    echo "--- Размер ${SIZE}B ---"
    CONFIG=$(make_calib_config "$SIZE")

    # Запускаем сервер в фоне
    sudo ip netns exec ns_recv "$TRAF_BIN" "$CONFIG" server1 > "${TMP_DIR}/srv_${SIZE}.txt" 2>&1 &
    SRV_PID=$!
    sleep 1

    # Запускаем клиент
    CLIENT_OUT=$(sudo ip netns exec ns_send "$TRAF_BIN" "$CONFIG" client1 2>&1) || true

    # Убиваем сервер
    sudo kill $SRV_PID 2>/dev/null || true
    wait $SRV_PID 2>/dev/null || true

    # Парсим pkt/s
    PPS=$(echo "$CLIENT_OUT" | awk '/^Speed:/{printf "%d\n", $2}' | head -1)
    if [ -z "$PPS" ] || [ "$PPS" -eq 0 ] 2>/dev/null; then
        echo "  ОШИБКА: не удалось получить результат"
        MAX_PPS[$SIZE]=0
    else
        MAX_PPS[$SIZE]=$PPS
        echo "  max pkt/s = ${MAX_PPS[$SIZE]}"
    fi
done

echo ""
echo "========================================================"
echo "Результаты калибровки:"
echo ""
printf "  %-8s  %-14s  %-14s\n" "Размер" "max pkt/s" "90% intensity"
echo "  ----------------------------------------"
for SIZE in "${SIZES[@]}"; do
    MAX=${MAX_PPS[$SIZE]:-0}
    if [ "$MAX" -gt 0 ]; then
        TARGET=$(( MAX * 9 / 10 ))
    else
        TARGET=0
    fi
    printf "  %-8s  %-14s  %-14s\n" "${SIZE}B" "$MAX" "$TARGET"
done

echo ""
echo "Обновляю config/traf/traf_hairpin_*.yml..."
echo ""

for SIZE in "${SIZES[@]}"; do
    MAX=${MAX_PPS[$SIZE]:-0}
    if [ "$MAX" -eq 0 ]; then
        echo "  ${SIZE}B: пропущено (нет данных)"
        continue
    fi
    TARGET=$(( MAX * 9 / 10 ))
    CFG="config/traf/traf_hairpin_${SIZE}.yml"
    if [ ! -f "$CFG" ]; then
        echo "  ${SIZE}B: файл $CFG не найден, пропущено"
        continue
    fi
    # Заменяем строку intensity:
    sed -i "s/^\( *intensity:\) .*/\1 ${TARGET}/" "$CFG"
    echo "  ${SIZE}B: intensity = ${TARGET} (90% от ${MAX})"
done

echo ""
echo "Готово. Теперь запускай полные тесты:"
echo "  ./scripts/run_hairpin_bench.sh ~/diploma/t-raf/build/t-raf"
