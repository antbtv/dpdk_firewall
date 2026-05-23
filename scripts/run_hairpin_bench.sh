#!/usr/bin/env bash
# run_hairpin_bench.sh — сравнительные тесты hairpin: Linux bridge vs DPDK
#
# Топология: Dev PC ns_send → macvlan vepa → eno1 → RPi5 enP1p1s0 → [hairpin] → eno1 → macvlan vepa → ns_recv
#
# Использование:
#   ./scripts/run_hairpin_bench.sh <traf_binary> [scenario]
#
#   scenario: "bridge" | "dpdk" | "all" (по умолчанию "all")
#
# Примеры:
#   ./scripts/run_hairpin_bench.sh ~/diploma/t-raf/build/t-raf
#   ./scripts/run_hairpin_bench.sh ~/diploma/t-raf/build/t-raf bridge
#   ./scripts/run_hairpin_bench.sh ~/diploma/t-raf/build/t-raf dpdk
#
# Результаты:
#   results/hairpin_bridge_{64,512,800,1500}/
#   results/hairpin_dpdk_{64,512,800,1500}/
#
# Предварительные требования (Dev PC):
#   sudo ./scripts/setup_hairpin_devpc.sh setup   # ns_send, ns_recv, macvlan vepa
#   sudo ip netns list  # → ns_recv, ns_send

set -euo pipefail

TRAF_BIN=${1:?"Usage: $0 <traf_binary> [bridge|dpdk|all]"}
FILTER=${2:-all}

CONFIGS=(
    "config/traf/traf_hairpin_64.yml:64"
    "config/traf/traf_hairpin_512.yml:512"
    "config/traf/traf_hairpin_800.yml:800"
    "config/traf/traf_hairpin_1500.yml:1500"
)

METRICS_DURATION=70  # 60с теста + 10с запас

echo "========================================================"
echo "Hairpin bench: bridge vs DPDK (4 размера пакетов)"
echo "t-raf: $TRAF_BIN"
echo "========================================================"
echo ""

run_scenario() {
    local SCENARIO=$1

    echo ""
    echo "###################################################"
    if [ "$SCENARIO" = "bridge" ]; then
        echo "### СЦЕНАРИЙ: Linux bridge hairpin"
        echo "###"
        echo "### На RPi5 выполни ПЕРЕД тестами:"
        echo "###   sudo ip link set enP1p1s0 nomaster 2>/dev/null || true"
        echo "###   sudo ip link del br0 2>/dev/null || true"
        echo "###   sudo ip link add br0 type bridge"
        echo "###   sudo ip link set enP1p1s0 master br0"
        echo "###   sudo ip link set br0 up"
        echo "###   sudo ip link set enP1p1s0 up"
        echo "###   sudo bridge link set dev enP1p1s0 hairpin on"
    else
        echo "### СЦЕНАРИЙ: DPDK hairpin"
        echo "###"
        echo "### На RPi5 выполни ПЕРЕД тестами:"
        echo "###   sudo ip link set enP1p1s0 nomaster 2>/dev/null || true"
        echo "###   sudo ip link del br0 2>/dev/null || true"
        echo "###   ./run.sh hairpin"
    fi
    echo "###################################################"
    echo ""
    echo "Нажми Enter, когда RPi5 готов..."
    read -r

    for ENTRY in "${CONFIGS[@]}"; do
        local CONFIG="${ENTRY%%:*}"
        local SIZE="${ENTRY##*:}"
        local OUTDIR="results/hairpin_${SCENARIO}_${SIZE}"

        mkdir -p "$OUTDIR"
        mkdir -p "results/${SIZE}"   # t-raf пишет CSV сюда (output_directory в конфиге)

        echo "--------------------------------------------------------"
        echo "Тест: hairpin_${SCENARIO} / ${SIZE}B"
        echo "Вывод: $OUTDIR/"
        echo ""

        # Инструкция для RPi5: сбор метрик
        echo "  >>> На RPi5 запусти сбор метрик (в отдельном терминале):"
        echo "      ./scripts/collect_metrics.sh ${METRICS_DURATION} ${OUTDIR}/metrics enP1p1s0"
        echo ""
        echo "  Нажми Enter после запуска collect_metrics.sh на RPi5..."
        read -r

        echo "  Запускаю t-raf server в ns_recv..."
        local SRV_TMP
        SRV_TMP=$(mktemp)
        sudo ip netns exec ns_recv "$TRAF_BIN" "$CONFIG" server1 > "$SRV_TMP" 2>&1 &
        local SERVER_PID=$!

        sleep 2  # дать серверу время подняться

        echo "  Запускаю t-raf client в ns_send (60с)..."
        sudo ip netns exec ns_send "$TRAF_BIN" "$CONFIG" client1 2>&1 | tee "${OUTDIR}/client.txt" || true

        # Сервер не завершается сам — убиваем его после клиента
        sleep 2
        sudo kill -SIGINT $SERVER_PID 2>/dev/null || true
        sleep 2
        sudo kill -SIGTERM $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true

        # Сохраняем только число принятых пакетов
        RECEIVED=$(grep -oP '\d+' "$SRV_TMP" 2>/dev/null | tail -1 || echo "0")
        rm -f "$SRV_TMP"
        echo "$RECEIVED" > "${OUTDIR}/server_received.txt"
        echo "  Сервер принял: $RECEIVED пакетов"

        # Перекладываем CSV-файлы t-raf в папку теста
        mv -f "results/${SIZE}/client1-sent.csv"  "${OUTDIR}/traf_sent.csv"  2>/dev/null && \
            echo "  Сохранён: ${OUTDIR}/traf_sent.csv" || true
        mv -f "results/${SIZE}/server1-0-rcv.csv" "${OUTDIR}/traf_rcv.csv"   2>/dev/null && \
            echo "  Сохранён: ${OUTDIR}/traf_rcv.csv"  || true

        # Ключевые цифры клиента
        CLIENT_PPS=$(awk '/^Speed:/{print $2}' "${OUTDIR}/client.txt" || echo "N/A")
        SENT=$(awk '/packets sent/{for(i=1;i<=NF;i++) if($i=="packets") print $(i-1)}' "${OUTDIR}/client.txt" || echo "N/A")

        {
            echo "scenario=hairpin_${SCENARIO} size=${SIZE}"
            echo "client_pps=${CLIENT_PPS}"
            echo "sent_total=${SENT}"
            echo "server_received=${RECEIVED}"
        } > "${OUTDIR}/summary.txt"

        echo "  Результат: pkt/s=${CLIENT_PPS}  sent=${SENT}  received=${RECEIVED}"
        echo ""
    done

    echo "Сценарий '${SCENARIO}' завершён. Файлы в results/hairpin_${SCENARIO}_*/"
    echo ""
}

if [ "$FILTER" = "all" ] || [ "$FILTER" = "bridge" ]; then
    run_scenario "bridge"
fi

if [ "$FILTER" = "all" ] || [ "$FILTER" = "dpdk" ]; then
    run_scenario "dpdk"
fi

echo "========================================================"
echo "Все тесты завершены."
echo ""
echo "Не забудь скопировать metrics_*.log с RPi5:"
for ENTRY in "${CONFIGS[@]}"; do
    SIZE="${ENTRY##*:}"
    for SC in bridge dpdk; do
        echo "  scp rpi5:~/dev/dpdk_firewall/results/hairpin_${SC}_${SIZE}/metrics_*.log results/hairpin_${SC}_${SIZE}/"
    done
done
echo ""
echo "Затем построй графики:"
echo "  python3 scripts/plot_hairpin.py"
