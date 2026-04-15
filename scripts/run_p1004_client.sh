#!/usr/bin/env bash
# run_p1004_client.sh — Dev PC сторона для P10-04 бенчмарков
#
# Запускает t-raf клиент для всех 8 комбинаций (4 размера × 2 сценария).
# Сохраняет вывод клиента в results/<scenario>_<size>/client.txt.
#
# ПЕРЕД ЗАПУСКОМ:
#   На RPi5 и raspi4 нужно параллельно вручную запустить collect_metrics.sh
#   и t-raf server (инструкция печатается для каждого теста).
#
# Использование (на Dev PC):
#   ./scripts/run_p1004_client.sh <traf_binary>
#
# Пример:
#   ./scripts/run_p1004_client.sh ~/diploma/t-raf/build/t-raf
#
# Результаты:
#   results/bridge_64/client.txt   results/dpdk_64/client.txt
#   results/bridge_512/client.txt  results/dpdk_512/client.txt
#   results/bridge_800/client.txt  results/dpdk_800/client.txt
#   results/bridge_1500/client.txt results/dpdk_1500/client.txt

set -euo pipefail

TRAF_BIN=${1:?"Usage: $0 <traf_binary>"}

CONFIGS=(
    "config/traf/traf_64.yml:64"
    "config/traf/traf_512.yml:512"
    "config/traf/traf_800.yml:800"
    "config/traf/traf_1500.yml:1500"
)

SCENARIOS=("bridge" "dpdk")

# Длительность теста + запас для метрик
TRAF_DURATION=30
METRICS_DURATION=38   # 30с теста + 8с запаса (sync + завершение)

echo "========================================================"
echo "P10-04: t-raf comparative benchmarks (4 sizes × 2 scenarios)"
echo "t-raf binary: $TRAF_BIN"
echo "========================================================"
echo ""
echo "ВНИМАНИЕ: скрипт делает паузы перед каждым тестом и ждёт,"
echo "пока ты запустишь collect_metrics.sh + t-raf server на нужных машинах."
echo ""

for SCENARIO in "${SCENARIOS[@]}"; do
    echo "###################################################"
    if [ "$SCENARIO" = "bridge" ]; then
        echo "### СЦЕНАРИЙ: Linux bridge (без DPDK)"
        echo "###   RPi5: dpdk_firewall НЕ запущен, br0 активен"
    else
        echo "### СЦЕНАРИЙ: DPDK AF_XDP firewall"
        echo "###   RPi5: dpdk_firewall запущен (./run.sh start)"
    fi
    echo "###################################################"
    echo ""

    for ENTRY in "${CONFIGS[@]}"; do
        CONFIG="${ENTRY%%:*}"
        SIZE="${ENTRY##*:}"
        OUTDIR="results/${SCENARIO}_${SIZE}"

        mkdir -p "$OUTDIR"

        echo "--------------------------------------------------------"
        echo "Тест: $SCENARIO / $SIZE байт"
        echo "Конфиг: $CONFIG"
        echo "Вывод: $OUTDIR/"
        echo ""

        if [ "$SCENARIO" = "bridge" ]; then
            echo "  >>> На RPi5 выполни (bridge режим):"
            echo "      sudo ip link set enP1p1s0 up && sudo ip link set eth0 up"
            echo "      # убедись что dpdk_firewall НЕ запущен, br0 настроен"
            echo "      ./scripts/collect_metrics.sh ${METRICS_DURATION} ${OUTDIR}/metrics enP1p1s0 &"
        else
            echo "  >>> На RPi5 выполни (DPDK режим):"
            echo "      ./run.sh start   # (если ещё не запущен)"
            echo "      # В новом терминале:"
            echo "      ./scripts/collect_metrics.sh ${METRICS_DURATION} ${OUTDIR}/metrics enP1p1s0 &"
        fi
        echo ""
        echo "  >>> На raspi4 выполни:"
        echo "      sudo ~/t-raf/build/t-raf ~/${CONFIG##config/traf/} server1"
        echo ""
        echo "  Нажми Enter, когда сервер и метрики запущены..."
        read -r

        echo "  Запускаю t-raf клиент..."
        OUTPUT=$(sudo "$TRAF_BIN" "$CONFIG" client1 2>&1)
        echo "$OUTPUT" | tee "${OUTDIR}/client.txt"

        # Извлечь ключевые числа
        CLIENT_PPS=$(echo "$OUTPUT" | awk '/^Speed:/{print $2}')
        CLIENT_MBS=$(echo "$OUTPUT" | awk '/^Speed:/{print $4}')
        SENT=$(echo "$OUTPUT" | awk '/^total_delay/{print $5}')
        GEN_TIME=$(echo "$OUTPUT" | awk '/^generation_time/{print $3}')

        echo ""
        echo "  Результат: pkt/s=${CLIENT_PPS:-N/A}  MB/s=${CLIENT_MBS:-N/A}  sent=${SENT:-N/A}  gen_time=${GEN_TIME:-N/A}s"

        # Записать сводку в отдельный файл
        {
            echo "scenario=${SCENARIO} size=${SIZE}"
            echo "client_pps=${CLIENT_PPS:-N/A}"
            echo "client_mbs=${CLIENT_MBS:-N/A}"
            echo "sent_total=${SENT:-N/A}"
            echo "generation_time=${GEN_TIME:-N/A}"
        } > "${OUTDIR}/summary.txt"

        echo ""
        echo "  >>> На raspi4 выполни после завершения сервера:"
        echo "      # Запиши последнее число из вывода t-raf server (= received count)"
        echo "      # Сохрани в файл: echo '<N>' > ${OUTDIR}/server_received.txt"
        echo "      # и скопируй на Dev PC: scp raspi4:${OUTDIR}/server_received.txt ${OUTDIR}/"
        echo ""
        echo "  Нажми Enter для следующего теста (или Ctrl+C для выхода)..."
        read -r
        echo ""
    done

    echo ""
    echo "Сценарий '$SCENARIO' завершён. Файлы в results/${SCENARIO}_*/"
    echo ""
    echo "  Нажми Enter для следующего сценария..."
    read -r
    echo ""
done

echo "========================================================"
echo "Все 8 тестов завершены."
echo ""
echo "Структура результатов:"
for SCENARIO in "${SCENARIOS[@]}"; do
    for ENTRY in "${CONFIGS[@]}"; do
        SIZE="${ENTRY##*:}"
        OUTDIR="results/${SCENARIO}_${SIZE}"
        echo "  ${OUTDIR}/"
        echo "    client.txt         — полный вывод t-raf client"
        echo "    summary.txt        — ключевые цифры (pkt/s, MB/s, sent, gen_time)"
        echo "    server_received.txt — количество принятых пакетов на raspi4"
        echo "    metrics_*.log      — CPU/PSI/netdev/io/mem (скопировать с RPi5)"
    done
done
echo ""
echo "Далее: P10-05 — построить гистограммы (scripts/plot_benchmarks.py)"
