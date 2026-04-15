#!/usr/bin/env bash
# sattest_client.sh — измерение предела приёма raspi4
#
# Запускает t-raf с нарастающей интенсивностью и выводит таблицу:
#   intensity → client_pkt/s → sent_total
#
# Использование (на Dev PC):
#   ./scripts/sattest_client.sh <traf_binary> <config_template>
#
# Пример:
#   ./scripts/sattest_client.sh \
#       ~/diploma/t-raf/build/t-raf \
#       config/traf/traf_sattest.yml
#
# Перед запуском на raspi4 должен работать server loop (сохраняет каждый запуск в отдельный файл):
#   RUN=0
#   while true; do
#       RUN=$((RUN+1))
#       sudo ~/t-raf/build/t-raf ~/traf_sattest.yml server1 2>&1 \
#           | tee /tmp/sattest_run${RUN}.log
#       echo "--- run ${RUN} done ---"
#   done
#
# После теста на raspi4: grep -h "^[0-9]" /tmp/sattest_run*.log | sort -n | uniq
# — выводит последнее число каждого запуска (= server received count)

set -euo pipefail

TRAF_BIN=${1:?"Usage: $0 <traf_binary> <config_template>"}
CONFIG=${2:?"Usage: $0 <traf_binary> <config_template>"}

INTENSITIES=(50000 80000 100000 120000 150000 200000 250000 300000)
TMPCONFIG="/tmp/sattest_$$.yml"

mkdir -p results/sattest

echo "========================================"
echo "raspi4 receive saturation test"
echo "Config template: $CONFIG"
echo "t-raf binary:    $TRAF_BIN"
echo "========================================"
echo ""
printf "%-12s %-16s %-14s %-12s\n" "intensity" "client_pkt/s" "client_MB/s" "sent_total"
echo "--------------------------------------------------------------------"

RUN=0
for INTENSITY in "${INTENSITIES[@]}"; do
    RUN=$((RUN + 1))

    # Подставить intensity в конфиг
    sed "s/intensity: [0-9]*/intensity: ${INTENSITY}/" "$CONFIG" > "$TMPCONFIG"

    # Запустить клиент, захватить stdout
    OUTPUT=$(sudo "$TRAF_BIN" "$TMPCONFIG" client1 2>&1)

    # "Speed: 99999.9 packet/s, 6.39999 MB/s"
    CLIENT_PPS=$(echo "$OUTPUT" | awk '/^Speed:/{print $2}')
    CLIENT_MBS=$(echo "$OUTPUT" | awk '/^Speed:/{print $4}')

    # "total_delay = 0 ns, 749985 packets sent"
    #  $1=$2=$3=$4  $5=749985  $6=packets  $7=sent
    SENT=$(echo "$OUTPUT" | awk '/^total_delay/{print $5}')

    printf "%-12s %-16s %-14s %-12s\n" \
        "$INTENSITY" "${CLIENT_PPS:-N/A}" "${CLIENT_MBS:-N/A}" "${SENT:-N/A}"

    # Сохранить полный вывод с номером запуска
    {
        echo "# run=${RUN} intensity=${INTENSITY}"
        echo "$OUTPUT"
    } > "results/sattest/client_run${RUN}_${INTENSITY}.txt"

    # Пауза — сервер успевает завершить запуск и перезапуститься
    echo "  [пауза 5с, сервер перезапускается — это запуск №${RUN}]"
    sleep 5
done

rm -f "$TMPCONFIG"

echo ""
echo "========================================"
echo "Клиентские результаты в results/sattest/"
echo ""
echo "Теперь на raspi4 выполни:"
echo "  for f in \$(ls /tmp/sattest_run*.log | sort -V); do"
echo "      echo -n \"\$f: \"; tail -1 \$f"
echo "  done"
echo ""
echo "Последнее число каждого файла = server received count для этого запуска."
echo "Сопоставь с таблицей выше по порядку запусков (run1=50k, run2=80k, ...)."
