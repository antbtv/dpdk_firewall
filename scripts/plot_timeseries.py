#!/usr/bin/env python3
"""
Time-series plots for bridge vs DPDK hairpin scenarios.

Data sources per test (results/hairpin_{scenario}_{size}/):
  metrics_netdev.log  — /proc/net/dev snapshots from RPi5 (enP1p1s0 RX+TX)
  metrics_cpu.log     — mpstat per-core from RPi5
  traf_sent.csv       — t-raf client: timestamp_ns, interval_ns, packet_number
  traf_rcv.csv        — t-raf server: timestamp_ns, packet_number, latency_ns

Figures produced:
  figA_netdev_{scenario}.png           — NIC RX pps over time, all 4 sizes
  figB_compare_{size}b.png             — bridge vs DPDK NIC RX over time
  figC_{scenario}_{size}b.png          — per-core CPU over time
  figD_pipeline_{scenario}_{size}b.png — 4-line pipeline view (t-raf TX, NIC RX, NIC TX, t-raf RX)
  figE_latency_{scenario}_{size}b.png  — latency over time from t-raf rcv.csv
  figF_errors_{scenario}_{size}b.png   — netdev error counters over time (drop/errs/fifo/frame)

Usage: python3 scripts/plot_timeseries.py
"""

import os
import re
import sys
from collections import defaultdict
from datetime import datetime

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

SIZES      = [64, 512, 800, 1500]
RESULTS_DIR = 'results'
PLOTS_DIR   = os.path.join(RESULTS_DIR, 'plots')

COLORS = {64: '#1f77b4', 512: '#ff7f0e', 800: '#2ca02c', 1500: '#d62728'}
LABELS = {'bridge': 'Linux bridge', 'dpdk': 'DPDK'}

C_TRAF_TX  = '#1f77b4'   # t-raf client TX   — синий
C_NIC_RX   = '#2ca02c'   # NIC RX (вход)     — зелёный
C_NIC_TX   = '#ff7f0e'   # NIC TX (выход)    — оранжевый
C_TRAF_RX  = '#d62728'   # t-raf server RX   — красный


def result_dir(scenario, size):
    return os.path.join(RESULTS_DIR, f'hairpin_{scenario}_{size}')


# ── Parsers ──────────────────────────────────────────────────────────────────

def parse_netdev(path, iface):
    """
    Parse /proc/net/dev snapshots. Captures all error counters.

    /proc/net/dev fields per interface:
      rx: bytes pkts errs drop fifo frame compressed multicast
      tx: bytes pkts errs drop fifo colls carrier compressed

    Returns list of tuples:
      (t, rx_bytes, rx_pkts, rx_errs, rx_drop, rx_fifo, rx_frame, rx_multicast,
             tx_bytes, tx_pkts, tx_errs, tx_drop)
    indices: 0  1        2       3       4       5       6         7
                                                                    8        9        10      11
    """
    rows = []
    pat = re.compile(
        r'([\d.]+)\s+' + re.escape(iface) +
        r':\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+\d+\s+(\d+)'
        r'\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)')
    try:
        with open(path) as f:
            for line in f:
                m = pat.match(line.strip())
                if m:
                    rows.append((
                        float(m.group(1)),
                        int(m.group(2)),  # rx_bytes
                        int(m.group(3)),  # rx_pkts
                        int(m.group(4)),  # rx_errs
                        int(m.group(5)),  # rx_drop
                        int(m.group(6)),  # rx_fifo
                        int(m.group(7)),  # rx_frame
                        int(m.group(8)),  # rx_multicast
                        int(m.group(9)),  # tx_bytes
                        int(m.group(10)), # tx_pkts
                        int(m.group(11)), # tx_errs
                        int(m.group(12)), # tx_drop
                    ))
    except FileNotFoundError:
        pass
    return rows


def netdev_rates(rows):
    """
    Convert cumulative netdev rows to per-second rates.
    Returns (times, rx_pps, tx_pps, rx_mbits, tx_mbits).
    """
    times, rx_pps, tx_pps, rx_mb, tx_mb = [], [], [], [], []
    for i in range(1, len(rows)):
        dt = rows[i][0] - rows[i-1][0]
        if dt <= 0:
            continue
        drx_b = rows[i][1] - rows[i-1][1]
        drx_p = rows[i][2] - rows[i-1][2]
        dtx_b = rows[i][8] - rows[i-1][8]
        dtx_p = rows[i][9] - rows[i-1][9]
        if min(drx_b, drx_p, dtx_b, dtx_p) < 0:
            continue
        t = rows[i][0] - rows[0][0]
        times.append(t)
        rx_pps.append(drx_p / dt)
        tx_pps.append(dtx_p / dt)
        rx_mb.append(drx_b * 8 / dt / 1e6)
        tx_mb.append(dtx_b * 8 / dt / 1e6)
    return times, rx_pps, tx_pps, rx_mb, tx_mb


def netdev_error_deltas(rows):
    """
    Convert cumulative error counters to per-second deltas.
    Returns (times, rx_drop, rx_errs, rx_fifo, rx_frame, tx_drop, tx_errs).
    """
    times, rx_drop, rx_errs, rx_fifo, rx_frame, tx_drop, tx_errs = [], [], [], [], [], [], []
    for i in range(1, len(rows)):
        dt = rows[i][0] - rows[i-1][0]
        if dt <= 0:
            continue
        times.append(rows[i][0] - rows[0][0])
        rx_drop.append((rows[i][4]  - rows[i-1][4])  / dt)
        rx_errs.append((rows[i][3]  - rows[i-1][3])  / dt)
        rx_fifo.append((rows[i][5]  - rows[i-1][5])  / dt)
        rx_frame.append((rows[i][6] - rows[i-1][6])  / dt)
        tx_drop.append((rows[i][11] - rows[i-1][11]) / dt)
        tx_errs.append((rows[i][10] - rows[i-1][10]) / dt)
    return times, rx_drop, rx_errs, rx_fifo, rx_frame, tx_drop, tx_errs


def parse_traf_sent(path):
    """
    Parse t-raf client1-sent.csv (timestamp_ns, interval_ns, packet_number).
    Returns list of (t_sec, pps) aggregated per second.
    """
    bins = defaultdict(int)
    t0 = None
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(',')
                if not parts:
                    continue
                try:
                    ts = int(parts[0].strip())
                except ValueError:
                    continue
                if t0 is None:
                    t0 = ts
                bins[int((ts - t0) / 1_000_000_000)] += 1
    except FileNotFoundError:
        return []
    return [(t, bins[t]) for t in sorted(bins)]


def parse_traf_rcv(path):
    """
    Parse t-raf server1-0-rcv.csv (timestamp_ns, packet_number, latency_ns).
    Returns (pps_series, latency_series) where each is list of (t_sec, value).
    latency values are in ms (average per second).
    """
    pps_bins = defaultdict(int)
    lat_bins = defaultdict(list)
    t0 = None
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(',')
                if len(parts) < 3:
                    continue
                try:
                    ts  = int(parts[0].strip())
                    lat = int(parts[2].strip())
                except ValueError:
                    continue
                if t0 is None:
                    t0 = ts
                sec = int((ts - t0) / 1_000_000_000)
                pps_bins[sec] += 1
                if lat > 0:
                    lat_bins[sec].append(lat / 1e6)
    except FileNotFoundError:
        return [], []

    times = sorted(pps_bins)
    pps = [(t, pps_bins[t]) for t in times]
    lat = [(t, sum(lat_bins[t]) / len(lat_bins[t])) for t in times if lat_bins[t]]
    return pps, lat


def parse_cpu(path):
    """
    Parse mpstat -P ALL log.
    Returns {cpu_num: [(t_sec, usr, sys, soft, idle), ...]}.
    """
    result = {}
    first_ts = None
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('Linux') or line.startswith('Average') or 'CPU' in line:
                    continue
                parts = line.split()
                if len(parts) < 12:
                    continue
                try:
                    t = datetime.strptime(parts[0], '%H:%M:%S')
                    if first_ts is None:
                        first_ts = t
                    t_sec = (t - first_ts).seconds
                    cpu_id = parts[1]
                    if cpu_id == 'all':
                        continue
                    cpu_num = int(cpu_id)
                    usr  = float(parts[2])
                    sys_ = float(parts[4])
                    soft = float(parts[7])
                    idle = float(parts[11])
                    result.setdefault(cpu_num, []).append((t_sec, usr, sys_, soft, idle))
                except (ValueError, IndexError):
                    pass
    except FileNotFoundError:
        pass
    return result


# ── Figures ──────────────────────────────────────────────────────────────────

def fig_netdev_by_scenario(scenario):
    """Fig A — NIC RX over time for one scenario, all 4 sizes."""
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 7), sharex=True)
    fig.suptitle(f'Рис. A — Входящий трафик enP1p1s0 (RPi5)\n{LABELS[scenario]}, все размеры пакетов', fontsize=11)

    for size in SIZES:
        path = os.path.join(result_dir(scenario, size), 'metrics_netdev.log')
        rows = parse_netdev(path, 'enP1p1s0')
        if len(rows) < 3:
            continue
        times, rx_pps, _, rx_mb, _ = netdev_rates(rows)
        c = COLORS[size]
        ax1.plot(times, rx_mb,  color=c, linewidth=1.2, label=f'{size} Б')
        ax2.plot(times, rx_pps, color=c, linewidth=1.2, label=f'{size} Б')

    ax1.set_ylabel('RX Мбит/с')
    ax1.legend(fontsize=9); ax1.grid(linestyle='--', alpha=0.4)
    ax2.set_ylabel('RX пакет/с')
    ax2.set_xlabel('Время (с)')
    ax2.legend(fontsize=9); ax2.grid(linestyle='--', alpha=0.4)
    fig.tight_layout()
    return fig


def fig_compare(size):
    """Fig B — bridge vs DPDK NIC RX over time for one packet size."""
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 6), sharex=True)
    fig.suptitle(f'Рис. B — Входящий трафик enP1p1s0: bridge vs DPDK\nРазмер пакета {size} Б', fontsize=11)

    colors = {'bridge': '#4C72B0', 'dpdk': '#DD8452'}
    for sc in ('bridge', 'dpdk'):
        path = os.path.join(result_dir(sc, size), 'metrics_netdev.log')
        rows = parse_netdev(path, 'enP1p1s0')
        if len(rows) < 3:
            continue
        times, rx_pps, _, rx_mb, _ = netdev_rates(rows)
        c = colors[sc]
        ax1.plot(times, rx_mb,  color=c, linewidth=1.4, label=LABELS[sc])
        ax2.plot(times, rx_pps, color=c, linewidth=1.4, label=LABELS[sc])

    for ax in (ax1, ax2):
        ax.legend(fontsize=9); ax.grid(linestyle='--', alpha=0.4)
    ax1.set_ylabel('RX Мбит/с')
    ax2.set_ylabel('RX пакет/с')
    ax2.set_xlabel('Время (с)')
    fig.tight_layout()
    return fig


def fig_cpu(scenario, size):
    """Fig C — per-core CPU over time."""
    path = os.path.join(result_dir(scenario, size), 'metrics_cpu.log')
    cpu_data = parse_cpu(path)
    if not cpu_data:
        return None

    core_labels = {
        0: 'Core 0 (управление)',
        1: 'Core 1 (WAN→LAN)',
        2: 'Core 2 (LAN→WAN)',
        3: 'Core 3 (резерв)',
    }
    fig, axes = plt.subplots(4, 1, figsize=(11, 10), sharex=True)
    fig.suptitle(f'Рис. C — Загрузка CPU по ядрам ({LABELS[scenario]}, {size} Б)', fontsize=11)

    for core in range(4):
        ax = axes[core]
        data = cpu_data.get(core, [])
        if not data:
            continue
        ts   = [d[0] for d in data]
        usr  = [d[1] for d in data]
        sys_ = [d[2] for d in data]
        soft = [d[3] for d in data]
        ax.plot(ts, usr,  color='#4C72B0', linewidth=1.2, label='%usr')
        ax.plot(ts, sys_, color='#DD8452', linewidth=1.2, label='%sys')
        ax.plot(ts, soft, color='#55A868', linewidth=1.0, label='%soft', alpha=0.7)
        ax.set_ylim(0, 110)
        ax.set_ylabel('%')
        ax.set_title(core_labels.get(core, f'Core {core}'), fontsize=9)
        ax.legend(fontsize=8, loc='upper right')
        ax.grid(linestyle='--', alpha=0.3)

    axes[-1].set_xlabel('Время (с)')
    fig.tight_layout()
    return fig


def fig_pipeline(scenario, size):
    """
    Fig D — 4-line pipeline view:
      t-raf client TX  (traf_sent.csv)
      NIC RX           (metrics_netdev.log, enP1p1s0 RX)
      NIC TX           (metrics_netdev.log, enP1p1s0 TX)
      t-raf server RX  (traf_rcv.csv)
    Shows where in the hairpin chain packets are lost.
    """
    rdir = result_dir(scenario, size)

    traf_tx = parse_traf_sent(os.path.join(rdir, 'traf_sent.csv'))
    traf_rx, _ = parse_traf_rcv(os.path.join(rdir, 'traf_rcv.csv'))
    rows = parse_netdev(os.path.join(rdir, 'metrics_netdev.log'), 'enP1p1s0')

    has_any = traf_tx or traf_rx or len(rows) >= 3
    if not has_any:
        return None

    fig, ax = plt.subplots(figsize=(11, 5))
    fig.suptitle(
        f'Рис. D — Пропускная способность по точкам измерения\n'
        f'{LABELS[scenario]}, {size} Б',
        fontsize=11)

    if traf_tx:
        xs = [t for t, _ in traf_tx]
        ys = [v for _, v in traf_tx]
        ax.plot(xs, ys, color=C_TRAF_TX, linewidth=1.6,
                label='t-raf TX (клиент, ns_send)', zorder=4)

    if len(rows) >= 3:
        times, rx_pps, tx_pps, _, _ = netdev_rates(rows)
        ax.plot(times, rx_pps, color=C_NIC_RX, linewidth=1.6,
                label='NIC RX (enP1p1s0, вход)', zorder=3)
        ax.plot(times, tx_pps, color=C_NIC_TX, linewidth=1.6,
                linestyle='--', label='NIC TX (enP1p1s0, выход)', zorder=3)

    if traf_rx:
        xs = [t for t, _ in traf_rx]
        ys = [v for _, v in traf_rx]
        ax.plot(xs, ys, color=C_TRAF_RX, linewidth=1.6,
                label='t-raf RX (сервер, ns_recv)', zorder=4)

    ax.set_xlabel('Время (с)')
    ax.set_ylabel('Пакет/с')
    ax.legend(fontsize=10)
    ax.grid(linestyle='--', alpha=0.4)
    fig.tight_layout()
    return fig


def fig_netdev_errors(scenario, size):
    """
    Fig F — netdev error counters over time (per second delta).
    Shows rx_drop, rx_errs, rx_fifo, rx_frame, tx_drop, tx_errs.
    For DPDK scenario these will be zero (AF_XDP bypasses kernel counters) — that is expected.
    Most informative for bridge scenario where kernel processes all packets.
    """
    rdir = result_dir(scenario, size)
    rows = parse_netdev(os.path.join(rdir, 'metrics_netdev.log'), 'enP1p1s0')
    if len(rows) < 3:
        return None

    times, rx_drop, rx_errs, rx_fifo, rx_frame, tx_drop, tx_errs = netdev_error_deltas(rows)

    # Skip if all counters are zero throughout (e.g. DPDK scenario)
    all_zero = all(
        v == 0
        for series in (rx_drop, rx_errs, rx_fifo, rx_frame, tx_drop, tx_errs)
        for v in series
    )
    if all_zero:
        return None

    fig, (ax_rx, ax_tx) = plt.subplots(2, 1, figsize=(11, 6), sharex=True)
    fig.suptitle(
        f'Рис. F — Счётчики ошибок enP1p1s0 по времени\n{LABELS[scenario]}, {size} Б',
        fontsize=11)

    ax_rx.plot(times, rx_drop,  color='#d62728', linewidth=1.4, label='rx_drop (буфер переполнен)')
    ax_rx.plot(times, rx_errs,  color='#ff7f0e', linewidth=1.4, label='rx_errs (аппаратные ошибки)')
    ax_rx.plot(times, rx_fifo,  color='#9467bd', linewidth=1.2, label='rx_fifo (FIFO overflow)', alpha=0.8)
    ax_rx.plot(times, rx_frame, color='#8c564b', linewidth=1.2, label='rx_frame (выравнивание кадра)', alpha=0.8)
    ax_rx.set_ylabel('событий/с')
    ax_rx.set_title('RX ошибки')
    ax_rx.legend(fontsize=9)
    ax_rx.grid(linestyle='--', alpha=0.4)

    ax_tx.plot(times, tx_drop, color='#d62728', linewidth=1.4, label='tx_drop')
    ax_tx.plot(times, tx_errs, color='#ff7f0e', linewidth=1.4, label='tx_errs')
    ax_tx.set_ylabel('событий/с')
    ax_tx.set_xlabel('Время (с)')
    ax_tx.set_title('TX ошибки')
    ax_tx.legend(fontsize=9)
    ax_tx.grid(linestyle='--', alpha=0.4)

    fig.tight_layout()
    return fig


def fig_latency(scenario, size):
    """Fig E — latency over time from t-raf traf_rcv.csv."""
    rdir = result_dir(scenario, size)
    _, lat = parse_traf_rcv(os.path.join(rdir, 'traf_rcv.csv'))
    if not lat:
        return None

    fig, ax = plt.subplots(figsize=(10, 4))
    fig.suptitle(
        f'Рис. E — Сквозная задержка\n{LABELS[scenario]}, {size} Б',
        fontsize=11)

    xs = [t for t, _ in lat]
    ys = [v for _, v in lat]
    ax.plot(xs, ys, color='#9467bd', linewidth=1.4)
    ax.set_xlabel('Время (с)')
    ax.set_ylabel('Задержка (мс)')
    ax.grid(linestyle='--', alpha=0.4)
    fig.tight_layout()
    return fig


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    os.makedirs(PLOTS_DIR, exist_ok=True)

    for scenario in ('bridge', 'dpdk'):
        fig = fig_netdev_by_scenario(scenario)
        out = os.path.join(PLOTS_DIR, f'figA_netdev_{scenario}.png')
        fig.savefig(out, dpi=150, bbox_inches='tight')
        print(f'Saved: {out}')
        plt.close(fig)

    for size in SIZES:
        fig = fig_compare(size)
        out = os.path.join(PLOTS_DIR, f'figB_compare_{size}b.png')
        fig.savefig(out, dpi=150, bbox_inches='tight')
        print(f'Saved: {out}')
        plt.close(fig)

    for scenario in ('bridge', 'dpdk'):
        for size in SIZES:
            fig = fig_cpu(scenario, size)
            if fig:
                out = os.path.join(PLOTS_DIR, f'figC_{scenario}_{size}b.png')
                fig.savefig(out, dpi=150, bbox_inches='tight')
                print(f'Saved: {out}')
                plt.close(fig)
            else:
                print(f'INFO: figC skipped {scenario}/{size}B (no cpu data)', file=sys.stderr)

    for scenario in ('bridge', 'dpdk'):
        for size in SIZES:
            fig = fig_pipeline(scenario, size)
            if fig:
                out = os.path.join(PLOTS_DIR, f'figD_pipeline_{scenario}_{size}b.png')
                fig.savefig(out, dpi=150, bbox_inches='tight')
                print(f'Saved: {out}')
                plt.close(fig)
            else:
                print(f'INFO: figD skipped {scenario}/{size}B (no data)', file=sys.stderr)

    for scenario in ('bridge', 'dpdk'):
        for size in SIZES:
            fig = fig_latency(scenario, size)
            if fig:
                out = os.path.join(PLOTS_DIR, f'figE_latency_{scenario}_{size}b.png')
                fig.savefig(out, dpi=150, bbox_inches='tight')
                print(f'Saved: {out}')
                plt.close(fig)
            else:
                print(f'INFO: figE skipped {scenario}/{size}B (no latency data)', file=sys.stderr)

    for scenario in ('bridge', 'dpdk'):
        for size in SIZES:
            fig = fig_netdev_errors(scenario, size)
            if fig:
                out = os.path.join(PLOTS_DIR, f'figF_errors_{scenario}_{size}b.png')
                fig.savefig(out, dpi=150, bbox_inches='tight')
                print(f'Saved: {out}')
                plt.close(fig)
            else:
                print(f'INFO: figF skipped {scenario}/{size}B (all zero or no data)', file=sys.stderr)


if __name__ == '__main__':
    main()
