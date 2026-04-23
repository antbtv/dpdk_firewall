#!/usr/bin/env python3
"""
P11-02: Time-series plots for bridge vs DPDK scenarios.

Reads metrics_cpu.log and metrics_netdev.log from results/{scenario}_{size}/.
Outputs PNG files to results/plots/.

Usage: python3 scripts/plot_timeseries.py
"""

import os
import re
import sys
from datetime import datetime
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

SIZES = [64, 512, 800, 1500]
RESULTS_DIR = 'results'
PLOTS_DIR = os.path.join(RESULTS_DIR, 'plots')

COLORS = {
    64:   '#1f77b4',
    512:  '#ff7f0e',
    800:  '#2ca02c',
    1500: '#d62728',
}
LINESTYLES = {'bridge': '-', 'dpdk': '--'}
LABELS = {'bridge': 'Linux bridge', 'dpdk': 'DPDK'}


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def parse_cpu_timeseries(path):
    """
    Parse per-second CPU data from mpstat -P ALL log.
    Returns dict: {cpu_id: [(t_sec, usr, sys, soft, idle), ...]}
    t_sec starts at 0 from first data timestamp.
    """
    result = {}  # cpu_id -> list of (t, usr, sys, soft, idle)
    first_ts = None

    try:
        with open(path) as f:
            lines = f.readlines()
    except FileNotFoundError:
        return {}

    i = 0
    while i < len(lines):
        line = lines[i].strip()
        # Skip header lines and Average lines
        if not line or line.startswith('Linux') or line.startswith('Average') or 'CPU' in line:
            i += 1
            continue
        # Data line: "HH:MM:SS  cpu_id  %usr  %nice  %sys  %iowait  %irq  %soft  %steal  %guest  %gnice  %idle"
        parts = line.split()
        if len(parts) < 12:
            i += 1
            continue
        # First field: time HH:MM:SS
        try:
            t = datetime.strptime(parts[0], '%H:%M:%S')
            if first_ts is None:
                first_ts = t
            t_sec = (t - first_ts).seconds
            cpu_id = parts[1]
            if cpu_id == 'all':
                i += 1
                continue
            cpu_num = int(cpu_id)
            usr  = float(parts[2])
            sys_ = float(parts[4])
            soft = float(parts[7])
            idle = float(parts[11])
            if cpu_num not in result:
                result[cpu_num] = []
            result[cpu_num].append((t_sec, usr, sys_, soft, idle))
        except (ValueError, IndexError):
            pass
        i += 1

    return result


def parse_netdev_timeseries(path, iface):
    """
    Parse /proc/net/dev snapshots. Returns [(t_unix, rx_bytes, rx_pkts, tx_bytes, tx_pkts)].
    """
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


def netdev_to_rates(rows):
    """Convert cumulative /proc/net/dev rows to per-second rates."""
    times, rx_mbits, rx_pps = [], [], []
    for i in range(1, len(rows)):
        dt = rows[i][0] - rows[i-1][0]
        if dt <= 0:
            continue
        d_rx_bytes = rows[i][1] - rows[i-1][1]
        d_rx_pkts  = rows[i][2] - rows[i-1][2]
        if d_rx_bytes < 0 or d_rx_pkts < 0:
            continue
        times.append(rows[i][0] - rows[0][0])
        rx_mbits.append(d_rx_bytes * 8 / dt / 1e6)
        rx_pps.append(d_rx_pkts / dt)
    return times, rx_mbits, rx_pps


# ---------------------------------------------------------------------------
# Figures
# ---------------------------------------------------------------------------

def fig_netdev_by_scenario(scenario):
    """RX Мбит/с over time for one scenario, 4 sizes on one plot."""
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 7), sharex=True)
    label = LABELS[scenario]
    fig.suptitle(f'Рис. A — Входящий трафик на enP1p1s0 (RPi5 WAN)\n{label}, все размеры пакетов', fontsize=11)

    for size in SIZES:
        path = os.path.join(RESULTS_DIR, f'{scenario}_{size}', 'metrics_netdev.log')
        rows = parse_netdev_timeseries(path, 'enP1p1s0')
        if len(rows) < 3:
            continue
        times, rx_mbits, rx_pps = netdev_to_rates(rows)
        color = COLORS[size]
        ax1.plot(times, rx_mbits, color=color, linewidth=1.2, label=f'{size} Б')
        ax2.plot(times, rx_pps,   color=color, linewidth=1.2, label=f'{size} Б')

    ax1.set_ylabel('RX Мбит/с')
    ax1.legend(fontsize=9)
    ax1.grid(linestyle='--', alpha=0.4)
    ax1.set_title('Пропускная способность (Мбит/с)')

    ax2.set_ylabel('RX пакет/с')
    ax2.set_xlabel('Время (с)')
    ax2.legend(fontsize=9)
    ax2.grid(linestyle='--', alpha=0.4)
    ax2.set_title('Интенсивность (пакет/с)')

    fig.tight_layout()
    return fig


def fig_netdev_compare(size):
    """RX Мбит/с over time: bridge vs DPDK for one packet size."""
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 6), sharex=True)
    fig.suptitle(f'Рис. B — Входящий трафик на enP1p1s0: bridge vs DPDK\nРазмер пакета {size} Б', fontsize=11)

    for scenario in ['bridge', 'dpdk']:
        path = os.path.join(RESULTS_DIR, f'{scenario}_{size}', 'metrics_netdev.log')
        rows = parse_netdev_timeseries(path, 'enP1p1s0')
        if len(rows) < 3:
            continue
        times, rx_mbits, rx_pps = netdev_to_rates(rows)
        color = '#4C72B0' if scenario == 'bridge' else '#DD8452'
        ax1.plot(times, rx_mbits, color=color, linewidth=1.4, label=LABELS[scenario])
        ax2.plot(times, rx_pps,   color=color, linewidth=1.4, label=LABELS[scenario])

    for ax in (ax1, ax2):
        ax.legend(fontsize=9)
        ax.grid(linestyle='--', alpha=0.4)
    ax1.set_ylabel('RX Мбит/с')
    ax2.set_ylabel('RX пакет/с')
    ax2.set_xlabel('Время (с)')
    fig.tight_layout()
    return fig


def fig_cpu_timeseries_dpdk(size):
    """Per-core CPU usage over time for DPDK scenario."""
    path = os.path.join(RESULTS_DIR, f'dpdk_{size}', 'metrics_cpu.log')
    cpu_data = parse_cpu_timeseries(path)
    if not cpu_data:
        return None

    core_labels = {0: 'Core 0 (control)', 1: 'Core 1 (LAN→WAN)', 2: 'Core 2 (WAN→LAN)', 3: 'Core 3 (резерв)'}
    colors_cpu = {'usr': '#4C72B0', 'sys': '#DD8452', 'soft': '#55A868'}

    fig, axes = plt.subplots(4, 1, figsize=(11, 10), sharex=True)
    fig.suptitle(f'Рис. C — Загрузка CPU по ядрам (DPDK, {size} Б)\nmpstat per second', fontsize=11)

    for core in range(4):
        ax = axes[core]
        data = cpu_data.get(core, [])
        if not data:
            continue
        ts   = [d[0] for d in data]
        usr  = [d[1] for d in data]
        sys_ = [d[2] for d in data]
        soft = [d[3] for d in data]

        ax.plot(ts, usr,  color=colors_cpu['usr'],  linewidth=1.2, label='%usr')
        ax.plot(ts, sys_, color=colors_cpu['sys'],  linewidth=1.2, label='%sys')
        ax.plot(ts, soft, color=colors_cpu['soft'], linewidth=1.0, label='%soft', alpha=0.7)

        ax.set_ylim(0, 110)
        ax.set_ylabel('%')
        ax.set_title(core_labels.get(core, f'Core {core}'), fontsize=9)
        ax.legend(fontsize=8, loc='upper right')
        ax.grid(linestyle='--', alpha=0.3)

    axes[-1].set_xlabel('Время (с)')
    fig.tight_layout()
    return fig


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    os.makedirs(PLOTS_DIR, exist_ok=True)

    # Fig A: RX over time per scenario (all 4 sizes)
    for scenario in ['bridge', 'dpdk']:
        fig = fig_netdev_by_scenario(scenario)
        out = os.path.join(PLOTS_DIR, f'figA_netdev_{scenario}.png')
        fig.savefig(out, dpi=150, bbox_inches='tight')
        print(f'Saved: {out}')
        plt.close(fig)

    # Fig B: bridge vs DPDK per size
    for size in SIZES:
        fig = fig_netdev_compare(size)
        out = os.path.join(PLOTS_DIR, f'figB_netdev_compare_{size}b.png')
        fig.savefig(out, dpi=150, bbox_inches='tight')
        print(f'Saved: {out}')
        plt.close(fig)

    # Fig C: CPU per core over time (DPDK only, all sizes)
    for size in SIZES:
        fig = fig_cpu_timeseries_dpdk(size)
        if fig:
            out = os.path.join(PLOTS_DIR, f'figC_cpu_dpdk_{size}b.png')
            fig.savefig(out, dpi=150, bbox_inches='tight')
            print(f'Saved: {out}')
            plt.close(fig)
        else:
            print(f'INFO: figC skipped for {size}B (no cpu data)', file=sys.stderr)


if __name__ == '__main__':
    main()
