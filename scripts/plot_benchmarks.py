#!/usr/bin/env python3
"""
P10-05: Plot benchmarks for bridge vs DPDK scenarios.

Reads data from results/{bridge,dpdk}_{64,512,800,1500}/.
Outputs PNG files to results/plots/.

Usage: python3 scripts/plot_benchmarks.py
"""

import os
import re
import sys
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SIZES = [64, 512, 800, 1500]
SCENARIOS = ['bridge', 'dpdk']
RESULTS_DIR = 'results'
PLOTS_DIR = os.path.join(RESULTS_DIR, 'plots')

# Cumulative server counters: prev[scenario][size] = cumulative count BEFORE this test
CUMULATIVE_PREV = {
    'bridge': {64: 0,         512: 2_860_000,  800: 6_400_000,  1500: 9_310_000},
    'dpdk':   {64: 0,         512: 2_660_000,  800: 5_780_000,  1500: 8_450_000},
}

# Hardcoded bridge CPU data (metrics not copied from RPi5; values from terminal output)
# bridge_64: Core 0 handles all forwarding via softirq/NAPI
BRIDGE_CPU_HARDCODED = {
    0: {'usr': 0.5,  'sys': 1.0,  'soft': 28.0, 'idle': 70.5},
    1: {'usr': 1.0,  'sys': 1.0,  'soft': 0.0,  'idle': 98.0},
    2: {'usr': 1.0,  'sys': 1.0,  'soft': 0.0,  'idle': 98.0},
    3: {'usr': 1.0,  'sys': 1.0,  'soft': 0.0,  'idle': 98.0},
}

# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def parse_client_txt(path):
    """Return (client_pps, client_mbit, sent, gen_time_s)."""
    client_pps = client_mbit = sent = gen_time_s = None
    try:
        with open(path) as f:
            text = f.read()
        m = re.search(r'Generation time is:\s*([\d.]+)\s*ms', text)
        if m:
            gen_time_s = float(m.group(1)) / 1000.0
        m = re.search(r'Speed:\s*([\d.]+)\s*packet/s,\s*([\d.]+)\s*MB/s', text)
        if m:
            client_pps = float(m.group(1))
            client_mbit = float(m.group(2)) * 8
        m = re.search(r'(\d+)\s*packets sent', text)
        if m:
            sent = int(m.group(1))
    except FileNotFoundError:
        pass
    return client_pps, client_mbit, sent, gen_time_s


def parse_server_received(path):
    try:
        with open(path) as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return None


def parse_cpu_averages(path):
    """
    Parse mpstat Average: lines from metrics_cpu.log.
    Returns dict: {core_id: {'usr', 'sys', 'soft', 'idle'}} or None if file missing.
    core_id 'all' also included.
    """
    result = {}
    try:
        with open(path) as f:
            for line in f:
                if not line.startswith('Average:'):
                    continue
                parts = line.split()
                # Average:  CPU  %usr  %nice  %sys  %iowait  %irq  %soft  %steal  %guest  %gnice  %idle
                # index:     0    1     2      3      4        5     6      7       8       9       10    11
                if len(parts) < 12:
                    continue
                cpu_id = parts[1]
                try:
                    usr  = float(parts[2])
                    sys_ = float(parts[4])
                    soft = float(parts[7])
                    idle = float(parts[11])
                    key = int(cpu_id) if cpu_id != 'all' else 'all'
                    result[key] = {'usr': usr, 'sys': sys_, 'soft': soft, 'idle': idle}
                except (ValueError, IndexError):
                    continue
    except FileNotFoundError:
        pass
    return result if result else None


def parse_netdev_timeseries(path, iface):
    """
    Parse per-second snapshots of /proc/net/dev for a given interface.
    Returns list of (timestamp, rx_bytes, rx_packets, tx_bytes, tx_packets).
    """
    rows = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Format: timestamp  iface: rx_bytes rx_pkts rx_errs rx_drop ... tx_bytes tx_pkts ...
                m = re.match(
                    r'([\d.]+)\s+' + re.escape(iface) +
                    r':\s*(\d+)\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+'
                    r'\s+(\d+)\s+(\d+)', line)
                if m:
                    rows.append((
                        float(m.group(1)),
                        int(m.group(2)), int(m.group(3)),
                        int(m.group(4)), int(m.group(5)),
                    ))
    except FileNotFoundError:
        pass
    return rows


def load_all_data():
    data = {}
    for scenario in SCENARIOS:
        data[scenario] = {}
        for size in SIZES:
            d = os.path.join(RESULTS_DIR, f'{scenario}_{size}')
            client_pps, client_mbit, sent, gen_time = parse_client_txt(
                os.path.join(d, 'client.txt'))
            cumul = parse_server_received(os.path.join(d, 'server_received.txt'))
            prev = CUMULATIVE_PREV[scenario][size]
            server_recv = (cumul - prev) if cumul is not None else None
            server_pps = (server_recv / gen_time) if (server_recv and gen_time) else None
            loss_pct = ((sent - server_recv) / sent * 100
                        if (sent and server_recv is not None) else None)
            data[scenario][size] = {
                'client_pps':  client_pps,
                'client_mbit': client_mbit,
                'sent':        sent,
                'gen_time':    gen_time,
                'server_recv': server_recv,
                'server_pps':  server_pps,
                'loss_pct':    loss_pct,
            }
    return data


# ---------------------------------------------------------------------------
# Plot helpers
# ---------------------------------------------------------------------------

COLORS = {'bridge': '#4C72B0', 'dpdk': '#DD8452'}
LABELS = {'bridge': 'Linux bridge', 'dpdk': 'DPDK'}


def bar_chart(ax, values_b, values_d, ylabel, title, fmt='{:.0f}', ylim=None):
    x = np.arange(len(SIZES))
    w = 0.35
    bars_b = ax.bar(x - w/2, values_b, w, label=LABELS['bridge'],
                    color=COLORS['bridge'], edgecolor='white', linewidth=0.5)
    bars_d = ax.bar(x + w/2, values_d, w, label=LABELS['dpdk'],
                    color=COLORS['dpdk'],   edgecolor='white', linewidth=0.5)
    ax.set_xticks(x)
    ax.set_xticklabels([f'{s} Б' for s in SIZES])
    ax.set_xlabel('Размер пакета')
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.legend()
    ax.grid(axis='y', linestyle='--', alpha=0.4)
    if ylim:
        ax.set_ylim(ylim)
    for bars, vals in [(bars_b, values_b), (bars_d, values_d)]:
        for bar, val in zip(bars, vals):
            if val is not None:
                ax.text(bar.get_x() + bar.get_width() / 2,
                        bar.get_height() * 1.01,
                        fmt.format(val), ha='center', va='bottom', fontsize=7)


def safe(data, scenario, key):
    return [data[scenario][s][key] for s in SIZES]


# ---------------------------------------------------------------------------
# Figure functions
# ---------------------------------------------------------------------------

def fig1_client_throughput(data):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    fig.suptitle('Рис. 1 — Пропускная способность клиента\n'
                 '(Dev PC → RPi5 → raspi4, RAW IP proto 253, deterministic)', fontsize=11)
    bar_chart(ax1, safe(data, 'bridge', 'client_pps'),
              safe(data, 'dpdk', 'client_pps'),
              'Пакет/с', 'Клиент: пропускная способность (пакет/с)',
              fmt='{:,.0f}')
    bar_chart(ax2, safe(data, 'bridge', 'client_mbit'),
              safe(data, 'dpdk', 'client_mbit'),
              'Мбит/с', 'Клиент: пропускная способность (Мбит/с)',
              fmt='{:.0f}', ylim=(0, 1050))
    fig.tight_layout()
    return fig


def fig2_server_and_loss(data):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    fig.suptitle('Рис. 2 — Приём на raspi4 и потери пакетов', fontsize=11)
    bar_chart(ax1, safe(data, 'bridge', 'server_pps'),
              safe(data, 'dpdk', 'server_pps'),
              'Пакет/с', 'raspi4: скорость приёма (пакет/с)',
              fmt='{:,.0f}', ylim=(0, 130_000))
    ax1.axhline(95_000, color='red', linestyle='--', linewidth=0.9, alpha=0.7,
                label='Предел raspi4 (~95k pkt/s)')
    ax1.legend(fontsize=8)
    bar_chart(ax2, safe(data, 'bridge', 'loss_pct'),
              safe(data, 'dpdk', 'loss_pct'),
              '% потерь', 'Потери пакетов (%)',
              fmt='{:.1f}%', ylim=(0, 70))
    fig.tight_layout()
    return fig


def fig3_cpu_per_lcore(data):
    """CPU bar chart per lcore: dpdk from metrics_cpu.log, bridge hardcoded."""
    dpdk_cpu = parse_cpu_averages(
        os.path.join(RESULTS_DIR, 'dpdk_64', 'metrics_cpu.log'))
    if dpdk_cpu is None:
        print('WARNING: dpdk_64/metrics_cpu.log not found, using hardcoded values',
              file=sys.stderr)
        dpdk_cpu = {
            0: {'usr': 3.9,  'sys': 3.9,  'soft': 1.7,  'idle': 90.5},
            1: {'usr': 12.5, 'sys': 87.4, 'soft': 0.1,  'idle': 0.0},
            2: {'usr': 100.0,'sys': 0.0,  'soft': 0.0,  'idle': 0.0},
            3: {'usr': 2.8,  'sys': 3.4,  'soft': 0.0,  'idle': 93.8},
        }

    bridge_cpu = BRIDGE_CPU_HARDCODED

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    fig.suptitle('Рис. 3 — Загрузка CPU по ядрам (тест 64 Б)\n'
                 'DPDK: данные из metrics_cpu.log (mpstat);  '
                 'Linux bridge: из вывода терминала', fontsize=10)

    core_labels = ['Core 0\n(control)', 'Core 1\n(LAN→WAN)',
                   'Core 2\n(WAN→LAN)', 'Core 3\n(резерв)']
    x = np.arange(4)
    w = 0.25
    bar_colors = {'usr': '#4C72B0', 'sys': '#DD8452', 'soft': '#55A868'}

    for ax, (scenario, cpu) in zip(axes, [('bridge', bridge_cpu), ('dpdk', dpdk_cpu)]):
        cores = [0, 1, 2, 3]
        usr_v  = [cpu[c]['usr']  for c in cores]
        sys_v  = [cpu[c]['sys']  for c in cores]
        soft_v = [cpu[c]['soft'] for c in cores]

        b_usr  = ax.bar(x - w, usr_v,  w, label='%usr',  color=bar_colors['usr'],  edgecolor='white')
        b_sys  = ax.bar(x,     sys_v,  w, label='%sys',  color=bar_colors['sys'],  edgecolor='white')
        b_soft = ax.bar(x + w, soft_v, w, label='%soft', color=bar_colors['soft'], edgecolor='white')

        ax.set_xticks(x)
        ax.set_xticklabels(core_labels, fontsize=8)
        ax.set_ylabel('%')
        ax.set_ylim(0, 115)
        ax.set_title(LABELS[scenario])
        ax.legend(fontsize=8)
        ax.grid(axis='y', linestyle='--', alpha=0.4)

        for bars in [b_usr, b_sys, b_soft]:
            for bar in bars:
                h = bar.get_height()
                if h > 2:
                    ax.text(bar.get_x() + bar.get_width() / 2, h + 1,
                            f'{h:.0f}', ha='center', va='bottom', fontsize=7)

    fig.tight_layout()
    return fig


def fig4_netdev_timeseries():
    """RX throughput over time on enP1p1s0 during the dpdk_1500 test."""
    path = os.path.join(RESULTS_DIR, 'dpdk_64', 'metrics_netdev.log')
    rows = parse_netdev_timeseries(path, 'enP1p1s0')
    if len(rows) < 3:
        return None

    # Compute per-second deltas
    times, rx_mbits, rx_pps = [], [], []
    for i in range(1, len(rows)):
        dt = rows[i][0] - rows[i-1][0]
        if dt <= 0:
            continue
        d_bytes = rows[i][1] - rows[i-1][1]
        d_pkts  = rows[i][3] - rows[i-1][3]  # wait, check column order
        # Format: ts  iface: rx_bytes rx_pkts ... tx_bytes tx_pkts
        # rows[i] = (ts, rx_bytes, rx_pkts, tx_bytes, tx_pkts)
        d_rx_bytes = rows[i][1] - rows[i-1][1]
        d_rx_pkts  = rows[i][2] - rows[i-1][2]
        if d_rx_bytes < 0 or d_rx_pkts < 0:
            continue
        times.append(rows[i][0] - rows[0][0])
        rx_mbits.append(d_rx_bytes * 8 / dt / 1e6)
        rx_pps.append(d_rx_pkts / dt)

    if not times:
        return None

    # Determine test label from avg packet size
    total_bytes = rows[-1][1] - rows[0][1]
    total_pkts  = rows[-1][2] - rows[0][2]
    avg_pkt = (total_bytes / total_pkts) if total_pkts > 0 else 0
    if avg_pkt > 1400:
        test_label = '1500 Б'
    elif avg_pkt > 700:
        test_label = '800 Б'
    elif avg_pkt > 400:
        test_label = '512 Б'
    else:
        test_label = '64 Б'

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 7), sharex=True)
    fig.suptitle(f'Рис. 4 — Трафик на WAN интерфейсе enP1p1s0 (RPi5)\n'
                 f'DPDK сценарий, пакет {test_label}', fontsize=11)

    ax1.plot(times, rx_mbits, color=COLORS['dpdk'], linewidth=1.2)
    ax1.set_ylabel('RX Мбит/с')
    ax1.set_title('Входящий трафик (Мбит/с)')
    ax1.grid(linestyle='--', alpha=0.4)

    ax2.plot(times, rx_pps, color=COLORS['bridge'], linewidth=1.2)
    ax2.set_ylabel('RX пакет/с')
    ax2.set_xlabel('Время (с)')
    ax2.set_title('Входящий трафик (пакет/с)')
    ax2.grid(linestyle='--', alpha=0.4)

    # Reference line: expected send rate
    expected_pps = {'64 Б': 150_000, '512 Б': 187_000, '800 Б': 140_000, '1500 Б': 75_000}
    if test_label in expected_pps:
        ax2.axhline(expected_pps[test_label], color='red', linestyle='--',
                    linewidth=0.8, alpha=0.7, label=f'Отправка клиента')
        ax2.legend(fontsize=8)

    fig.tight_layout()
    return fig


def fig5_summary_table(data):
    fig, ax = plt.subplots(figsize=(13, 4))
    ax.axis('off')
    fig.suptitle('Рис. 5 — Сводная таблица результатов (Linux bridge vs DPDK)', fontsize=11)

    col_labels = ['Размер\n(Б)',
                  'Bridge\nclient pkt/s', 'DPDK\nclient pkt/s',
                  'Bridge\nМбит/с',       'DPDK\nМбит/с',
                  'Bridge\nserver pkt/s', 'DPDK\nserver pkt/s',
                  'Bridge\nпотери %',     'DPDK\nпотери %']
    rows = []
    for size in SIZES:
        b = data['bridge'][size]
        d = data['dpdk'][size]
        rows.append([
            str(size),
            f"{b['client_pps']:,.0f}" if b['client_pps'] else '-',
            f"{d['client_pps']:,.0f}" if d['client_pps'] else '-',
            f"{b['client_mbit']:.0f}" if b['client_mbit'] else '-',
            f"{d['client_mbit']:.0f}" if d['client_mbit'] else '-',
            f"{b['server_pps']:,.0f}" if b['server_pps'] else '-',
            f"{d['server_pps']:,.0f}" if d['server_pps'] else '-',
            f"{b['loss_pct']:.1f}%" if b['loss_pct'] is not None else '-',
            f"{d['loss_pct']:.1f}%" if d['loss_pct'] is not None else '-',
        ])

    tbl = ax.table(cellText=rows, colLabels=col_labels,
                   loc='center', cellLoc='center')
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(9)
    tbl.scale(1, 2.2)
    for j in range(len(col_labels)):
        tbl[0, j].set_facecolor('#2C3E50')
        tbl[0, j].set_text_props(color='white', fontweight='bold')
    for i in range(1, len(rows) + 1):
        for j in range(len(col_labels)):
            tbl[i, j].set_facecolor('#EAF2FB' if i % 2 == 0 else 'white')

    fig.tight_layout()
    return fig


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    os.makedirs(PLOTS_DIR, exist_ok=True)
    data = load_all_data()

    figures = [
        ('fig1_client_throughput.png',  fig1_client_throughput(data)),
        ('fig2_server_rx_and_loss.png', fig2_server_and_loss(data)),
        ('fig3_cpu_per_lcore_64b.png',  fig3_cpu_per_lcore(data)),
        ('fig5_summary_table.png',      fig5_summary_table(data)),
    ]

    f4 = fig4_netdev_timeseries()
    if f4:
        figures.append(('fig4_netdev_timeseries.png', f4))
    else:
        print('INFO: fig4 skipped (no netdev data)', file=sys.stderr)

    for fname, fig in figures:
        out = os.path.join(PLOTS_DIR, fname)
        fig.savefig(out, dpi=150, bbox_inches='tight')
        print(f'Saved: {out}')
        plt.close(fig)

    print(f'\nAll plots saved to {PLOTS_DIR}/')
    print('\nData summary:')
    for scenario in SCENARIOS:
        print(f'  {LABELS[scenario]}:')
        for size in SIZES:
            d = data[scenario][size]
            print(f'    {size:4d}B: client={d["client_pps"]:>8,.0f} pkt/s '
                  f'{d["client_mbit"]:>6.0f} Mbit/s  '
                  f'server={d["server_pps"]:>8,.0f} pkt/s  '
                  f'loss={d["loss_pct"]:>5.1f}%')


if __name__ == '__main__':
    main()
