#!/usr/bin/env python3
"""
plot_hairpin.py — Сравнительные графики: Linux bridge hairpin vs DPDK hairpin.

Читает данные из results/hairpin_{bridge,dpdk}_{64,512,800,1500}/.
Выводит PNG-файлы в results/plots/.

Использование:
  python3 scripts/plot_hairpin.py
"""

import os
import re
import sys
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np

SIZES = [64, 512, 800, 1500]
SCENARIOS = ['bridge', 'dpdk']
RESULTS_DIR = 'results'
PLOTS_DIR = os.path.join(RESULTS_DIR, 'plots')

COLORS = {
    'bridge': '#5b8dd9',   # синий
    'dpdk':   '#e05c5c',   # красный
}
LABELS = {
    'bridge': 'Linux bridge (kernel)',
    'dpdk':   'DPDK AF_XDP hairpin',
}

# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def parse_client(path):
    """Возвращает (pps, mbit_s, sent)."""
    pps = mbit = sent = None
    try:
        text = open(path).read()
        m = re.search(r'Speed:\s*([\d.]+)\s*packet/s,\s*([\d.]+)\s*MB/s', text)
        if m:
            pps   = float(m.group(1))
            mbit  = float(m.group(2)) * 8
        m = re.search(r'(\d+)\s*packets sent', text)
        if m:
            sent = int(m.group(1))
    except FileNotFoundError:
        pass
    return pps, mbit, sent


def parse_received(path):
    try:
        return int(open(path).read().strip())
    except (FileNotFoundError, ValueError):
        return None


def parse_cpu(path):
    """
    Парсит Average: строки из metrics_cpu.log (mpstat).
    Возвращает dict {cpu_id: {'usr','sys','soft','idle'}} или None.
    """
    result = {}
    try:
        for line in open(path):
            if not line.startswith('Average:'):
                continue
            p = line.split()
            if len(p) < 12:
                continue
            cid = p[1]
            try:
                result[cid] = {
                    'usr':  float(p[2]),
                    'sys':  float(p[4]),
                    'soft': float(p[7]),
                    'idle': float(p[11]),
                }
            except (IndexError, ValueError):
                pass
    except FileNotFoundError:
        pass
    return result or None


# ---------------------------------------------------------------------------
# Load all data
# ---------------------------------------------------------------------------

def parse_summary(path):
    """Возвращает dict с полями из summary.txt (generation_ms, sent_total, и др.)."""
    result = {}
    try:
        for line in open(path):
            line = line.strip()
            if '=' in line:
                k, _, v = line.partition('=')
                result[k.strip()] = v.strip()
    except FileNotFoundError:
        pass
    return result


def load_data():
    data = {}
    for scenario in SCENARIOS:
        data[scenario] = {}
        for size in SIZES:
            d = os.path.join(RESULTS_DIR, f'hairpin_{scenario}_{size}')
            pps, mbit, sent = parse_client(os.path.join(d, 'client.txt'))
            recv = parse_received(os.path.join(d, 'server_received.txt'))
            cpu  = parse_cpu(os.path.join(d, 'metrics_cpu.log'))
            summ = parse_summary(os.path.join(d, 'summary.txt'))

            # summary.txt может переопределить recv и sent
            if 'server_received' in summ:
                recv = int(summ['server_received'])

            # Если в summary.txt есть generation_ms — используем delivered pps/mbit
            # (сатурационный тест: клиент шлёт быстрее, чем может, важна доставка)
            if 'generation_ms' in summ and recv is not None:
                gen_s = float(summ['generation_ms']) / 1000.0
                if 'sent_total' in summ:
                    sent = int(summ['sent_total'])
                if gen_s > 0:
                    pps  = recv / gen_s
                    mbit = pps * size * 8 / 1e6

            loss = None
            if sent and recv is not None and sent > 0:
                loss = max(0.0, (sent - recv) / sent * 100)

            data[scenario][size] = {
                'pps':  pps,
                'mbit': mbit,
                'sent': sent,
                'recv': recv,
                'loss': loss,
                'cpu':  cpu,
            }
    return data


def has_any(data, scenario, field):
    return any(data[scenario][s][field] is not None for s in SIZES)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def bar_positions(n_groups, n_bars, width=0.35):
    x = np.arange(n_groups)
    offsets = np.linspace(-(n_bars - 1) / 2, (n_bars - 1) / 2, n_bars) * width
    return x, offsets


def save(fig, name):
    os.makedirs(PLOTS_DIR, exist_ok=True)
    path = os.path.join(PLOTS_DIR, name)
    fig.savefig(path, dpi=150, bbox_inches='tight')
    print(f'  → {path}')
    plt.close(fig)


# ---------------------------------------------------------------------------
# Fig 1: Throughput (kpps) — bar chart
# ---------------------------------------------------------------------------

def plot_throughput_pps(data):
    x, offs = bar_positions(len(SIZES), len(SCENARIOS))
    fig, ax = plt.subplots(figsize=(9, 5))

    for i, scenario in enumerate(SCENARIOS):
        vals = [
            (data[scenario][s]['pps'] or 0) / 1e3
            for s in SIZES
        ]
        bars = ax.bar(x + offs[i], vals, width=0.35,
                      color=COLORS[scenario], label=LABELS[scenario],
                      edgecolor='white', linewidth=0.5)
        for bar, v in zip(bars, vals):
            if v > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5,
                        f'{v:.0f}k', ha='center', va='bottom', fontsize=8)

    ax.set_xticks(x)
    ax.set_xticklabels([f'{s}B' for s in SIZES])
    ax.set_xlabel('Размер пакета')
    ax.set_ylabel('Пропускная способность, kpkt/s')
    ax.set_title('Пропускная способность: Linux bridge vs DPDK (пакеты/с)')
    ax.legend()
    ax.yaxis.set_minor_locator(mticker.AutoMinorLocator())
    ax.grid(axis='y', alpha=0.3)
    fig.tight_layout()
    save(fig, 'hairpin_fig1_throughput_pps.png')


# ---------------------------------------------------------------------------
# Fig 2: Throughput (Mbit/s)
# ---------------------------------------------------------------------------

def plot_throughput_mbit(data):
    x, offs = bar_positions(len(SIZES), len(SCENARIOS))
    fig, ax = plt.subplots(figsize=(9, 5))

    for i, scenario in enumerate(SCENARIOS):
        vals = [data[scenario][s]['mbit'] or 0 for s in SIZES]
        bars = ax.bar(x + offs[i], vals, width=0.35,
                      color=COLORS[scenario], label=LABELS[scenario],
                      edgecolor='white', linewidth=0.5)
        for bar, v in zip(bars, vals):
            if v > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                        f'{v:.0f}', ha='center', va='bottom', fontsize=8)

    ax.axhline(1000, color='gray', linestyle='--', linewidth=0.8, label='1 Gbps (теор.)')
    ax.set_xticks(x)
    ax.set_xticklabels([f'{s}B' for s in SIZES])
    ax.set_xlabel('Размер пакета')
    ax.set_ylabel('Пропускная способность, Mbit/s')
    ax.set_title('Пропускная способность: Linux bridge vs DPDK (Mbit/s)')
    ax.legend()
    ax.yaxis.set_minor_locator(mticker.AutoMinorLocator())
    ax.grid(axis='y', alpha=0.3)
    fig.tight_layout()
    save(fig, 'hairpin_fig2_throughput_mbit.png')


# ---------------------------------------------------------------------------
# Fig 3: Packet loss (%)
# ---------------------------------------------------------------------------

def plot_loss(data):
    x, offs = bar_positions(len(SIZES), len(SCENARIOS))
    fig, ax = plt.subplots(figsize=(9, 5))

    for i, scenario in enumerate(SCENARIOS):
        vals = [data[scenario][s]['loss'] or 0 for s in SIZES]
        bars = ax.bar(x + offs[i], vals, width=0.35,
                      color=COLORS[scenario], label=LABELS[scenario],
                      edgecolor='white', linewidth=0.5)
        for bar, v in zip(bars, vals):
            if v > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.002,
                        f'{v:.2f}%', ha='center', va='bottom', fontsize=7.5)

    ax.set_xticks(x)
    ax.set_xticklabels([f'{s}B' for s in SIZES])
    ax.set_xlabel('Размер пакета')
    ax.set_ylabel('Потери пакетов, %')
    ax.set_title('Потери пакетов: Linux bridge vs DPDK')
    ax.legend()
    ax.yaxis.set_minor_locator(mticker.AutoMinorLocator())
    ax.grid(axis='y', alpha=0.3)
    fig.tight_layout()
    save(fig, 'hairpin_fig3_packet_loss.png')


# ---------------------------------------------------------------------------
# Fig 4: DPDK advantage ratio
# ---------------------------------------------------------------------------

def plot_advantage(data):
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    # Left: ratio pps
    ax = axes[0]
    ratios_pps = []
    for s in SIZES:
        b = data['bridge'][s]['pps']
        d = data['dpdk'][s]['pps']
        ratios_pps.append(d / b if (b and d and b > 0) else 0)

    bars = ax.bar([f'{s}B' for s in SIZES], ratios_pps,
                  color='#4caf50', edgecolor='white', linewidth=0.5)
    ax.axhline(1.0, color='gray', linestyle='--', linewidth=0.8, label='bridge = 1×')
    for bar, v in zip(bars, ratios_pps):
        if v > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.02,
                    f'{v:.2f}×', ha='center', va='bottom', fontsize=9, fontweight='bold')
    ax.set_ylabel('DPDK / bridge (по pkt/s)')
    ax.set_title('Преимущество DPDK (pkt/s)')
    ax.legend()
    ax.grid(axis='y', alpha=0.3)

    # Right: ratio loss (bridge_loss / dpdk_loss, how much less loss in DPDK)
    ax = axes[1]
    ratios_loss = []
    labels_loss = []
    for s in SIZES:
        b_loss = data['bridge'][s]['loss']
        d_loss = data['dpdk'][s]['loss']
        if b_loss and d_loss and d_loss > 0:
            ratios_loss.append(b_loss / d_loss)
            labels_loss.append(f'{s}B')
        elif b_loss and b_loss > 0 and (d_loss is None or d_loss == 0):
            ratios_loss.append(float('inf'))
            labels_loss.append(f'{s}B')
        else:
            ratios_loss.append(0)
            labels_loss.append(f'{s}B')

    display_vals = [min(v, 200) if v != float('inf') else 200 for v in ratios_loss]
    bars = ax.bar(labels_loss, display_vals,
                  color='#ff9800', edgecolor='white', linewidth=0.5)
    ax.axhline(1.0, color='gray', linestyle='--', linewidth=0.8)
    for bar, v, dv in zip(bars, ratios_loss, display_vals):
        if dv > 0:
            label = f'{v:.1f}×' if v != float('inf') else '∞'
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5,
                    label, ha='center', va='bottom', fontsize=9, fontweight='bold')
    ax.set_ylabel('bridge_loss / dpdk_loss')
    ax.set_title('Снижение потерь в DPDK (во сколько раз)')
    ax.grid(axis='y', alpha=0.3)

    fig.suptitle('Преимущество DPDK над Linux bridge', fontsize=13, fontweight='bold')
    fig.tight_layout()
    save(fig, 'hairpin_fig4_advantage.png')


# ---------------------------------------------------------------------------
# Fig 5: CPU utilization
# ---------------------------------------------------------------------------

def plot_cpu(data):
    bridge_has = has_any(data, 'bridge', 'cpu')
    dpdk_has   = has_any(data, 'dpdk', 'cpu')
    if not (bridge_has or dpdk_has):
        print('  CPU данные отсутствуют, fig5 пропущен')
        return

    fig, axes = plt.subplots(1, 2, figsize=(13, 5), sharey=False)

    for ax, scenario in zip(axes, SCENARIOS):
        cores_data = []
        for s in SIZES:
            cpu = data[scenario][s]['cpu']
            if cpu is None:
                cores_data.append(None)
            else:
                total_active = {
                    cid: v['usr'] + v['sys'] + v['soft']
                    for cid, v in cpu.items() if cid != 'all'
                }
                cores_data.append(total_active)

        if all(c is None for c in cores_data):
            ax.text(0.5, 0.5, 'Нет данных', ha='center', va='center',
                    transform=ax.transAxes, fontsize=12)
            ax.set_title(LABELS[scenario])
            continue

        # Find all core IDs
        core_ids = sorted(
            {cid for c in cores_data if c for cid in c},
            key=lambda x: int(x) if str(x).lstrip('-').isdigit() else 999
        )

        x = np.arange(len(SIZES))
        width = 0.8 / max(len(core_ids), 1)
        cmap = plt.cm.Set2
        for j, cid in enumerate(core_ids):
            vals = [(c.get(cid, 0) if c else 0) for c in cores_data]
            offset = (j - (len(core_ids) - 1) / 2) * width
            ax.bar(x + offset, vals, width=width * 0.9,
                   color=cmap(j / max(len(core_ids), 1)),
                   label=f'CPU {cid}', edgecolor='white', linewidth=0.3)

        ax.set_xticks(x)
        ax.set_xticklabels([f'{s}B' for s in SIZES])
        ax.set_xlabel('Размер пакета')
        ax.set_ylabel('CPU, % (usr+sys+softirq)')
        ax.set_title(f'CPU: {LABELS[scenario]}')
        ax.set_ylim(0, 105)
        ax.legend(fontsize=8)
        ax.grid(axis='y', alpha=0.3)

    fig.suptitle('Загрузка CPU при hairpin-тесте', fontsize=13, fontweight='bold')
    fig.tight_layout()
    save(fig, 'hairpin_fig5_cpu.png')


# ---------------------------------------------------------------------------
# Fig 6: Summary table as PNG
# ---------------------------------------------------------------------------

def plot_summary_table(data):
    rows = []
    for s in SIZES:
        b = data['bridge'][s]
        d = data['dpdk'][s]

        b_pps  = f"{b['pps']/1e3:.0f}k"   if b['pps']  else '—'
        d_pps  = f"{d['pps']/1e3:.0f}k"   if d['pps']  else '—'
        b_mbit = f"{b['mbit']:.0f}"        if b['mbit'] else '—'
        d_mbit = f"{d['mbit']:.0f}"        if d['mbit'] else '—'
        b_loss = f"{b['loss']:.2f}%"       if b['loss'] is not None else '—'
        d_loss = f"{d['loss']:.4f}%"       if d['loss'] is not None else '—'

        ratio = '—'
        if b['pps'] and d['pps'] and b['pps'] > 0:
            ratio = f"{d['pps']/b['pps']:.2f}×"

        rows.append([f'{s}B', b_pps, d_pps, b_mbit, d_mbit, b_loss, d_loss, ratio])

    cols = [
        'Пакет', 'bridge\npkt/s', 'DPDK\npkt/s',
        'bridge\nMbit/s', 'DPDK\nMbit/s',
        'bridge\nloss', 'DPDK\nloss', 'DPDK/bridge\n(pkt/s)'
    ]

    fig, ax = plt.subplots(figsize=(13, 3))
    ax.axis('off')
    tbl = ax.table(cellText=rows, colLabels=cols,
                   loc='center', cellLoc='center')
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(10)
    tbl.scale(1.2, 1.8)

    for (row, col), cell in tbl.get_celld().items():
        if row == 0:
            cell.set_facecolor('#2c3e50')
            cell.set_text_props(color='white', fontweight='bold')
        elif row % 2 == 0:
            cell.set_facecolor('#ecf0f1')
        # Выделить DPDK pkt/s колонку
        if col == 2 and row > 0:
            cell.set_facecolor('#fde8e8')
        if col == 1 and row > 0:
            cell.set_facecolor('#e8effe')

    ax.set_title('Итоговые результаты: Linux bridge vs DPDK hairpin',
                 fontsize=12, fontweight='bold', pad=15)
    fig.tight_layout()
    save(fig, 'hairpin_fig6_summary_table.png')


# ---------------------------------------------------------------------------
# Time-series parsers
# ---------------------------------------------------------------------------

from datetime import datetime

SIZE_COLORS = {64: '#1f77b4', 512: '#ff7f0e', 800: '#2ca02c', 1500: '#d62728'}


def parse_netdev_ts(path, iface='enP1p1s0'):
    rows = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                m = re.match(
                    r'([\d.]+)\s+' + re.escape(iface) +
                    r':\s*(\d+)\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+'
                    r'\s+(\d+)\s+(\d+)', line)
                if m:
                    rows.append((float(m.group(1)),
                                 int(m.group(2)), int(m.group(3)),
                                 int(m.group(4)), int(m.group(5))))
    except FileNotFoundError:
        pass
    return rows


def netdev_rates(rows):
    times, rx_mbits, rx_pps = [], [], []
    for i in range(1, len(rows)):
        dt = rows[i][0] - rows[i-1][0]
        if dt <= 0:
            continue
        drb = rows[i][1] - rows[i-1][1]
        drp = rows[i][2] - rows[i-1][2]
        if drb < 0 or drp < 0:
            continue
        times.append(rows[i][0] - rows[0][0])
        rx_mbits.append(drb * 8 / dt / 1e6)
        rx_pps.append(drp / dt)
    return times, rx_mbits, rx_pps


def parse_cpu_ts(path):
    result = {}
    first_ts = None
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('Linux') or \
                   line.startswith('Average') or 'CPU' in line:
                    continue
                parts = line.split()
                if len(parts) < 12:
                    continue
                try:
                    t = datetime.strptime(parts[0], '%H:%M:%S')
                    if first_ts is None:
                        first_ts = t
                    t_sec = (t - first_ts).seconds
                    cid = parts[1]
                    if cid == 'all':
                        continue
                    core = int(cid)
                    entry = (t_sec, float(parts[2]), float(parts[4]),
                             float(parts[7]), float(parts[11]))
                    result.setdefault(core, []).append(entry)
                except (ValueError, IndexError):
                    pass
    except FileNotFoundError:
        pass
    return result


# ---------------------------------------------------------------------------
# Fig A: RX over time — один сценарий, все размеры
# ---------------------------------------------------------------------------

def plot_ts_figA(scenario):
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 7), sharex=True)
    label = LABELS[scenario]
    fig.suptitle(f'Входящий трафик на RPi5 enP1p1s0 — {label}\nВсе размеры пакетов', fontsize=11)

    found = False
    for size in SIZES:
        path = os.path.join(RESULTS_DIR, f'hairpin_{scenario}_{size}', 'metrics_netdev.log')
        rows = parse_netdev_ts(path)
        if len(rows) < 3:
            continue
        found = True
        times, rx_mbits, rx_pps = netdev_rates(rows)
        c = SIZE_COLORS[size]
        ax1.plot(times, rx_mbits, color=c, linewidth=1.2, label=f'{size} Б')
        ax2.plot(times, rx_pps,   color=c, linewidth=1.2, label=f'{size} Б')

    if not found:
        plt.close(fig)
        return

    ax1.set_ylabel('RX Мбит/с')
    ax1.legend(fontsize=9)
    ax1.grid(linestyle='--', alpha=0.4)
    ax2.set_ylabel('RX пакет/с')
    ax2.set_xlabel('Время (с)')
    ax2.legend(fontsize=9)
    ax2.grid(linestyle='--', alpha=0.4)
    fig.tight_layout()
    save(fig, f'hairpin_figA_netdev_{scenario}.png')


# ---------------------------------------------------------------------------
# Fig B: bridge vs DPDK по времени — один размер пакета
# ---------------------------------------------------------------------------

def plot_ts_figB(size):
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 6), sharex=True)
    fig.suptitle(f'RX трафик на enP1p1s0: bridge vs DPDK hairpin — {size} Б', fontsize=11)

    found = False
    for scenario in SCENARIOS:
        path = os.path.join(RESULTS_DIR, f'hairpin_{scenario}_{size}', 'metrics_netdev.log')
        rows = parse_netdev_ts(path)
        if len(rows) < 3:
            continue
        found = True
        times, rx_mbits, rx_pps = netdev_rates(rows)
        c = COLORS[scenario]
        ax1.plot(times, rx_mbits, color=c, linewidth=1.4, label=LABELS[scenario])
        ax2.plot(times, rx_pps,   color=c, linewidth=1.4, label=LABELS[scenario])

    if not found:
        plt.close(fig)
        return

    for ax in (ax1, ax2):
        ax.legend(fontsize=9)
        ax.grid(linestyle='--', alpha=0.4)
    ax1.set_ylabel('RX Мбит/с')
    ax2.set_ylabel('RX пакет/с')
    ax2.set_xlabel('Время (с)')
    fig.tight_layout()
    save(fig, f'hairpin_figB_compare_{size}b.png')


# ---------------------------------------------------------------------------
# Fig C: CPU по ядрам — один сценарий, один размер
# ---------------------------------------------------------------------------

CORE_LABELS = {
    0: 'Core 0 (control / softirq)',
    1: 'Core 1 (WAN→LAN / data)',
    2: 'Core 2 (LAN→WAN / data)',
    3: 'Core 3 (резерв)',
}
CPU_COLORS = {'usr': '#4C72B0', 'sys': '#DD8452', 'soft': '#55A868'}


def plot_ts_figC(scenario, size):
    path = os.path.join(RESULTS_DIR, f'hairpin_{scenario}_{size}', 'metrics_cpu.log')
    cpu_data = parse_cpu_ts(path)
    if not cpu_data:
        return

    fig, axes = plt.subplots(4, 1, figsize=(11, 10), sharex=True)
    fig.suptitle(f'Загрузка CPU по ядрам — {LABELS[scenario]}, {size} Б', fontsize=11)

    for core in range(4):
        ax = axes[core]
        data = cpu_data.get(core, [])
        if data:
            ts   = [d[0] for d in data]
            usr  = [d[1] for d in data]
            sys_ = [d[2] for d in data]
            soft = [d[3] for d in data]
            ax.plot(ts, usr,  color=CPU_COLORS['usr'],  linewidth=1.2, label='%usr')
            ax.plot(ts, sys_, color=CPU_COLORS['sys'],  linewidth=1.2, label='%sys')
            ax.plot(ts, soft, color=CPU_COLORS['soft'], linewidth=1.0, label='%soft', alpha=0.7)
        ax.set_ylim(0, 110)
        ax.set_ylabel('%')
        ax.set_title(CORE_LABELS.get(core, f'Core {core}'), fontsize=9)
        ax.legend(fontsize=8, loc='upper right')
        ax.grid(linestyle='--', alpha=0.3)

    axes[-1].set_xlabel('Время (с)')
    fig.tight_layout()
    save(fig, f'hairpin_figC_{scenario}_{size}b.png')


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print('Загружаю данные...')
    data = load_data()

    missing = []
    for scenario in SCENARIOS:
        for size in SIZES:
            d = data[scenario][size]
            if d['pps'] is None:
                missing.append(f'hairpin_{scenario}_{size}')

    if missing:
        print(f'\nВНИМАНИЕ: данные отсутствуют для: {", ".join(missing)}')
        print('Запусти ./scripts/run_hairpin_bench.sh для сбора результатов.\n')
        if all(data[s][sz]['pps'] is None for s in SCENARIOS for sz in SIZES):
            print('Нет ни одного результата — выход.')
            sys.exit(1)

    os.makedirs(PLOTS_DIR, exist_ok=True)
    print('Строю графики...')

    # Bar charts
    plot_throughput_pps(data)
    plot_throughput_mbit(data)
    plot_loss(data)
    plot_advantage(data)
    plot_cpu(data)
    plot_summary_table(data)

    # Time-series: Fig A
    for scenario in SCENARIOS:
        plot_ts_figA(scenario)

    # Time-series: Fig B (bridge vs DPDK per size)
    for size in SIZES:
        plot_ts_figB(size)

    # Time-series: Fig C (CPU per core)
    for scenario in SCENARIOS:
        for size in SIZES:
            plot_ts_figC(scenario, size)

    print(f'\nГотово. Файлы в {PLOTS_DIR}/')


if __name__ == '__main__':
    main()
