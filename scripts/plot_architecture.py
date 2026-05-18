#!/usr/bin/env python3
"""
Generates three architecture diagrams in the same visual style as
scripts/plot_topology.py:

  * pipeline.png  — packet processing algorithm (DPDK 7-stage pipeline)
  * modules.png   — module / file structure of the firewall application
  * lcores.png    — lcore model (control plane vs data plane on RPi5 cores)
"""

import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Patch

PLOTS_DIR = 'results/plots'

# ── palette (matches topology) ──────────────────────────────────────────────
C_BG       = '#F0F3F4'
C_DARK     = '#1C2833'
C_PC       = '#2C3E50'
C_RPI      = '#1A5276'
C_TEXT     = 'white'
C_ARROW    = '#5D6D7E'
C_ACCEPT   = '#1E8449'   # green
C_DROP     = '#922B21'   # red
C_RATE     = '#E67E22'   # orange / yellow
C_CTRL     = '#1F618D'   # blue
C_DATA     = '#145A32'   # dark green
C_INFRA    = '#5D6D7E'
C_LIGHT    = '#ECF0F1'


def box(ax, x, y, w, h, color, radius=0.04, zorder=3, alpha=1.0, edge='white'):
    p = FancyBboxPatch((x - w / 2, y - h / 2), w, h,
                       boxstyle=f'round,pad=0,rounding_size={radius}',
                       facecolor=color, edgecolor=edge,
                       linewidth=1.5, zorder=zorder, alpha=alpha)
    ax.add_patch(p)
    return p


def arrow(ax, x1, y1, x2, y2, color=C_ARROW, lw=2.0, zorder=2,
          style='->', mutation=14, rad=0):
    ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle=style, color=color, lw=lw,
                                mutation_scale=mutation,
                                connectionstyle=f'arc3,rad={rad}'),
                zorder=zorder)


# ════════════════════════════════════════════════════════════════════════════
#  1. PIPELINE — packet processing algorithm
# ════════════════════════════════════════════════════════════════════════════
def plot_pipeline():
    fig, ax = plt.subplots(figsize=(14, 11))
    ax.set_xlim(-0.3, 14.5)
    ax.set_ylim(0, 12)
    ax.axis('off')
    fig.patch.set_facecolor(C_BG)
    ax.set_facecolor(C_BG)

    # darker orange for text on light background — readable contrast
    C_RATE_DARK = '#A04000'

    ax.text(7.0, 11.55,
            'Алгоритм обработки пакета (DPDK, burst = 32)',
            ha='center', va='center', fontsize=19, fontweight='bold',
            color=C_DARK, zorder=5)

    # central column x = 4.8; drop column x = 11.8
    cx = 4.8
    drop_x = 11.8
    box_w, box_h = 6.0, 1.05

    stages = [
        # (y, title, subtitle, color, drop_label)
        (10.50, '1. RX BURST',          'приём пакетов из сетевой карты (по 32 шт.)',       C_CTRL, None),
        ( 9.15, '2. CLASSIFIER',        'разбор Ethernet / IPv4 / L4\nзаполнение pkt_meta[]', C_CTRL, None),
        ( 7.80, '3. BLACKLIST CHECK',   'поиск IP в хеш-таблице',                       C_DATA, 'совпадение → DROP'),
        ( 6.45, '4. RULE ENGINE',       'обход правил по приоритету (до 1024)',                C_DATA, 'нет совпадения → DROP'),
        ( 5.10, '5. RATE LIMITER',      'измерение скорости; превышение: RED',                C_DATA, 'RED → DROP'),
        ( 3.75, '6. DDoS UPDATE',       'скользящее окно на src_ip\nпревышение → авто-блокировка', C_DATA, None),
        ( 2.40, '7. TX BURST',          'отправка пакетов в выходной порт',      C_CTRL, None),
    ]

    for (y, title, sub, color, drop) in stages:
        box(ax, cx, y, box_w, box_h, color, radius=0.06, zorder=5)
        ax.text(cx, y + 0.22, title, ha='center', va='center',
                fontsize=15, fontweight='bold', color='white', zorder=6)
        ax.text(cx, y - 0.28, sub, ha='center', va='center',
                fontsize=11.5, color='white', zorder=6,
                fontstyle='italic', fontweight='bold')

    # vertical arrows between stages
    for i in range(len(stages) - 1):
        y_top = stages[i][0] - box_h / 2
        y_bot = stages[i + 1][0] + box_h / 2
        arrow(ax, cx, y_top, cx, y_bot, color=C_ARROW, lw=2.4, mutation=18)

    # output ✓
    y_last = stages[-1][0] - box_h / 2
    arrow(ax, cx, y_last, cx, 1.25, color=C_ACCEPT, lw=2.6, mutation=20)
    box(ax, cx, 0.85, 2.6, 0.70, C_ACCEPT, radius=0.05, zorder=5)
    ax.text(cx, 0.85, 'forwarded', ha='center', va='center',
            fontsize=15, fontweight='bold', color='white', zorder=6)

    # ── DROP side column ─────────────────────────────────────────────────────
    # combined DROP block (расширен по высоте под крупный шрифт)
    drop_cy = 6.45   # center of DROP block (aligned to middle 3 stages)
    box(ax, drop_x, drop_cy, 3.4, 2.8, C_DROP, radius=0.07, zorder=4, alpha=0.94)
    ax.text(drop_x, drop_cy + 1.20, 'ОТБРАСЫВАНИЕ ПАКЕТА', ha='center', va='center',
            fontsize=14, fontweight='bold', color='white', zorder=6)
    ax.text(drop_x, drop_cy + 0.60, 'освобождение памяти mbuf', ha='center', va='center',
            fontsize=12, color='white', fontstyle='italic',
            fontweight='bold', zorder=6)
    ax.text(drop_x, drop_cy - 0.10, 'счётчик отброшенных\nпакетов увеличивается', ha='center', va='center',
            fontsize=12, color='white', fontstyle='italic',
            fontweight='bold', zorder=6)

    # side arrows from each drop-capable stage
    for (y, _, _, _, drop_lbl) in stages:
        if drop_lbl is None:
            continue
        x1 = cx + box_w / 2
        x2 = drop_x - 1.70
        arrow(ax, x1, y, x2, y, color=C_DROP, lw=2.4, mutation=16)
        # label sits ABOVE the arrow, just over the stage box top edge
        ax.text((x1 + x2) / 2, y + box_h / 2 + 0.08, drop_lbl,
                ha='center', va='bottom',
                fontsize=12, color='white', fontweight='bold', zorder=7,
                bbox=dict(boxstyle='round,pad=0.18', facecolor=C_DROP,
                          edgecolor='none', alpha=0.92))

    # ── feedback loop: ddos auto-blacklist → blacklist hash ──────────────────
    # маршрут: правый край DDoS → дугой влево вокруг конвейера → левый край BLACKLIST
    ax.annotate('',
                xy=(cx - box_w / 2, 7.80),         # → BLACKLIST left edge
                xytext=(cx - box_w / 2, 3.75),     # ← DDoS left edge
                arrowprops=dict(arrowstyle='->', color=C_RATE, lw=2.6,
                                mutation_scale=18,
                                connectionstyle='arc3,rad=-0.55'),
                zorder=4)
    ax.text(0.80, 5.78, 'авто-\nблокировка',
            ha='center', va='center', fontsize=13,
            color=C_RATE_DARK, fontweight='bold', fontstyle='italic', zorder=6,
            bbox=dict(boxstyle='round,pad=0.18', facecolor=C_BG,
                      edgecolor='none', alpha=0.85))

    fig.tight_layout(pad=0.3)
    out = os.path.join(PLOTS_DIR, 'pipeline.png')
    fig.savefig(out, dpi=180, bbox_inches='tight', facecolor=fig.get_facecolor())
    print(f'Saved: {out}')
    plt.close(fig)


# ════════════════════════════════════════════════════════════════════════════
#  2. MODULES — application module structure
# ════════════════════════════════════════════════════════════════════════════
def plot_modules():
    fig, ax = plt.subplots(figsize=(14, 9.5))
    ax.set_xlim(0, 16)
    ax.set_ylim(0, 9.5)
    ax.axis('off')
    fig.patch.set_facecolor(C_BG)
    ax.set_facecolor(C_BG)

    C_RATE_DARK = '#A04000'

    ax.text(8.0, 9.10,
            'Структура приложения (модули)',
            ha='center', va='center', fontsize=20, fontweight='bold',
            color=C_DARK, zorder=5)

    # ── main.c at the top ────────────────────────────────────────────────────
    box(ax, 8.0, 8.0, 8.4, 1.05, C_PC, radius=0.06, zorder=5)
    ax.text(8.0, 8.25, 'main.c', ha='center', va='center',
            fontsize=16, fontweight='bold', color='white', zorder=6)
    ax.text(8.0, 7.75,
            'EAL init  •  argparse  •  signal handlers  •  rte_eal_remote_launch',
            ha='center', va='center', fontsize=12.5, color='white',
            fontstyle='italic', fontweight='bold', zorder=6)

    # ── three layers ─────────────────────────────────────────────────────────
    layer_y = 4.7
    layer_h = 4.5
    # control plane
    box(ax, 3.0, layer_y, 5.0, layer_h, C_CTRL, radius=0.08, zorder=3, alpha=0.92)
    ax.text(3.0, layer_y + layer_h / 2 - 0.32, 'Control plane',
            ha='center', va='center', fontsize=15, fontweight='bold',
            color='white', zorder=5)

    # data plane
    box(ax, 8.0, layer_y, 4.6, layer_h, C_DATA, radius=0.08, zorder=3, alpha=0.92)
    ax.text(8.0, layer_y + layer_h / 2 - 0.32, 'Data plane',
            ha='center', va='center', fontsize=15, fontweight='bold',
            color='white', zorder=5)

    # infra
    box(ax, 12.7, layer_y, 4.0, layer_h, C_INFRA, radius=0.08, zorder=3, alpha=0.92)
    ax.text(12.7, layer_y + layer_h / 2 - 0.32, 'Infrastructure',
            ha='center', va='center', fontsize=15, fontweight='bold',
            color='white', zorder=5)

    def mod(ax, x, y, name, sub, w=3.8):
        box(ax, x, y, w, 1.05, '#FDFEFE', radius=0.05, zorder=5,
            edge='#BDC3C7')
        ax.text(x, y + 0.24, name, ha='center', va='center',
                fontsize=14, fontweight='bold', color=C_DARK, zorder=6)
        ax.text(x, y - 0.24, sub, ha='center', va='center',
                fontsize=11, color=C_DARK, fontstyle='italic',
                fontweight='bold', zorder=6)

    # control plane modules
    mod(ax, 3.0, 6.05, 'config.c',
        'libjansson • hot-reload')
    mod(ax, 3.0, 4.95, 'mgmt.c',
        'UNIX socket • epoll • JSON')
    mod(ax, 3.0, 3.85, 'stats.c',
        'атомарные счётчики')

    # data plane modules
    mod(ax, 8.0, 6.05, 'pipeline.c',
        '7 стадий • burst = 32', w=3.6)
    mod(ax, 8.0, 4.95, 'rule_engine.c',
        'priority scan • rwlock', w=3.6)
    mod(ax, 8.0, 3.85, 'ddos.c',
        'rte_hash • rte_meter', w=3.6)

    # infra modules
    mod(ax, 12.7, 6.05, 'port.c',
        'mempool • ethdev cfg', w=3.2)
    mod(ax, 12.7, 4.95, 'firewall.h',
        'fw_rule • pkt_meta', w=3.2)
    mod(ax, 12.7, 3.85, 'DPDK libs',
        'EAL • mbuf • hash • acl', w=3.2)

    # ── CLI off to the left ──────────────────────────────────────────────────
    box(ax, 2.2, 1.50, 3.6, 1.25, C_RPI, radius=0.06, zorder=5)
    ax.text(2.2, 1.80, 'cli/fw_ctl.c', ha='center', va='center',
            fontsize=15, fontweight='bold', color='white', zorder=6)
    ax.text(2.2, 1.25, 'standalone CLI (без DPDK)',
            ha='center', va='center', fontsize=12, color='white',
            fontstyle='italic', fontweight='bold', zorder=6)

    # arrow CLI → mgmt.c — вертикально через зазор между stats.c и CLI
    arrow(ax, 2.20, 2.15, 2.20, 4.48, color=C_RATE, lw=2.6, mutation=18)
    ax.text(2.20, 3.05, 'UNIX socket\n/var/run/.../mgmt.sock',
            ha='center', va='center', fontsize=11.5, color='white',
            fontweight='bold', zorder=7,
            bbox=dict(boxstyle='round,pad=0.30', facecolor=C_RATE,
                      edgecolor='white', alpha=0.97, linewidth=1.2))

    # ── tests / config files ─────────────────────────────────────────────────
    box(ax, 8.0, 1.50, 4.8, 1.25, '#7F8C8D', radius=0.06, zorder=5)
    ax.text(8.0, 1.80, 'tests/ • config/ • scripts/',
            ha='center', va='center', fontsize=15, fontweight='bold',
            color='white', zorder=6)
    ax.text(8.0, 1.25, 'unit-тесты, rules.json, t-raf YAML, run.sh',
            ha='center', va='center', fontsize=11.5, color='white',
            fontstyle='italic', fontweight='bold', zorder=6)

    # arrows main → layers
    arrow(ax, 6.0, 7.55, 3.5, 7.05, color=C_ARROW, lw=2.2, mutation=16, rad=-0.1)
    arrow(ax, 8.0, 7.50, 8.0, 7.05, color=C_ARROW, lw=2.2, mutation=16)
    arrow(ax, 10.0, 7.55, 12.2, 7.05, color=C_ARROW, lw=2.2, mutation=16, rad=0.1)

    # ── reload feedback (config.c → rule_engine.c) ──────────────────────────
    ax.annotate('',
                xy=(6.30, 4.95), xytext=(4.80, 6.30),
                arrowprops=dict(arrowstyle='->', color=C_RATE, lw=2.4,
                                mutation_scale=16,
                                connectionstyle='arc3,rad=0.35'),
                zorder=6)
    ax.text(5.55, 6.65, 'SIGHUP → reload',
            ha='center', va='center', fontsize=12, color=C_RATE_DARK,
            fontweight='bold', fontstyle='italic', zorder=7,
            bbox=dict(boxstyle='round,pad=0.25', facecolor=C_BG,
                      edgecolor='none', alpha=0.9))

    fig.tight_layout(pad=0.3)
    out = os.path.join(PLOTS_DIR, 'modules.png')
    fig.savefig(out, dpi=180, bbox_inches='tight', facecolor=fig.get_facecolor())
    print(f'Saved: {out}')
    plt.close(fig)


# ════════════════════════════════════════════════════════════════════════════
#  3. LCORES — execution model on RPi5
# ════════════════════════════════════════════════════════════════════════════
def plot_lcores():
    fig, ax = plt.subplots(figsize=(15, 10))
    ax.set_xlim(0, 16)
    ax.set_ylim(0, 9.5)
    ax.axis('off')
    fig.patch.set_facecolor(C_BG)
    ax.set_facecolor(C_BG)

    C_RATE_DARK = '#A04000'

    ax.text(8.0, 9.15,
            'Модель исполнения: распределение работы по lcore (RPi5, 4 ядра)',
            ha='center', va='center', fontsize=19, fontweight='bold',
            color=C_DARK, zorder=5)

    # ── outer SoC box ────────────────────────────────────────────────────────
    box(ax, 8.0, 5.7, 14.8, 5.9, C_RPI, radius=0.06, zorder=2, alpha=0.94)
    ax.text(8.0, 8.35, 'Raspberry Pi 5  •  ARM Cortex-A76 × 4',
            ha='center', va='center', fontsize=14, fontweight='bold',
            color='white', zorder=5)

    # ── 4 lcores ─────────────────────────────────────────────────────────────
    lcore_w = 3.30
    lcore_h = 4.6
    lcore_y = 5.30
    xs = [2.40, 6.15, 9.85, 13.55]

    lcores = [
        # (color, title, role, lines)
        (C_CTRL, 'lcore 0', 'control plane',
         ['mgmt_server_run()',
          '  – epoll socket',
          '  – JSON команды',
          '',
          'stats dump',
          'SIGHUP → reload',
          'rule_engine_rebuild',
          'busy: ~0%']),
        (C_DATA, 'lcore 1', 'WAN → LAN',
         ['pipeline_run(0→1)',
          '',
          'while (!quit):',
          '  rx_burst(port 0)',
          '  → 7 стадий →',
          '  tx_burst(port 1)',
          '',
          'busy: 100%']),
        (C_DATA, 'lcore 2', 'LAN → WAN',
         ['pipeline_run(1→0)',
          '',
          'while (!quit):',
          '  rx_burst(port 1)',
          '  → 7 стадий →',
          '  tx_burst(port 0)',
          '',
          'busy: 100%']),
        ('#7F8C8D', 'lcore 3', 'reserve',
         ['idle / reserved',
          '',
          '(в hairpin-режиме',
          'не используется:',
          'оба направления',
          'идут через один',
          'порт, достаточно',
          'одного data lcore)']),
    ]

    for (color, title, role, lines), x in zip(lcores, xs):
        box(ax, x, lcore_y, lcore_w, lcore_h, color, radius=0.07, zorder=4)
        ax.text(x, lcore_y + lcore_h / 2 - 0.35, title,
                ha='center', va='center', fontsize=16, fontweight='bold',
                color='white', zorder=6)
        ax.text(x, lcore_y + lcore_h / 2 - 0.80, role,
                ha='center', va='center', fontsize=13,
                color='white', fontstyle='italic', fontweight='bold',
                zorder=6)
        # body text
        body_y = lcore_y + lcore_h / 2 - 1.40
        for i, line in enumerate(lines):
            ax.text(x - lcore_w / 2 + 0.25, body_y - i * 0.34, line,
                    ha='left', va='center', fontsize=12,
                    color='white', fontweight='bold',
                    zorder=6, family='monospace')

    # ── shared state below ───────────────────────────────────────────────────
    box(ax, 8.0, 1.90, 13.0, 1.55, '#34495E', radius=0.06, zorder=3)
    ax.text(8.0, 2.40, 'Разделяемое состояние (под rte_rwlock_t)',
            ha='center', va='center', fontsize=15, fontweight='bold',
            color='white', zorder=6)
    ax.text(8.0, 1.90,
            'g_acl_ctx  •  g_rules[]  •  g_blacklist_hash  •  g_ddos_hash  •  g_default_policy',
            ha='center', va='center', fontsize=12, color='white',
            family='monospace', fontweight='bold', zorder=6)
    ax.text(8.0, 1.45,
            'lcore 0 — writer (write-lock ~µs при reload);   lcore 1, 2 — readers (read-lock per burst)',
            ha='center', va='center', fontsize=12,
            color='#F4D03F', fontstyle='italic', fontweight='bold',
            zorder=6)

    # arrows from data lcores to shared state (read)
    arrow(ax, 6.15, 3.00, 7.0, 2.70, color=C_ACCEPT, lw=2.2, mutation=14, rad=-0.1)
    arrow(ax, 9.85, 3.00, 9.0, 2.70, color=C_ACCEPT, lw=2.2, mutation=14, rad=0.1)
    # arrow from control lcore (write)
    arrow(ax, 2.40, 3.00, 2.8, 2.70, color=C_RATE, lw=2.4, mutation=16)

    # ── side: ports ──────────────────────────────────────────────────────────
    # left port
    box(ax, 0.60, 5.30, 0.75, 2.6, '#2E4057', radius=0.05, zorder=3)
    ax.text(0.60, 6.30, 'port 0', ha='center', va='center', rotation=90,
            fontsize=14, fontweight='bold', color='white', zorder=6)
    ax.text(0.60, 4.30, 'WAN', ha='center', va='center', rotation=90,
            fontsize=13, color='white', fontweight='bold', zorder=6)
    # right port
    box(ax, 15.40, 5.30, 0.75, 2.6, '#2E4057', radius=0.05, zorder=3)
    ax.text(15.40, 6.30, 'port 1', ha='center', va='center', rotation=90,
            fontsize=14, fontweight='bold', color='white', zorder=6)
    ax.text(15.40, 4.30, 'LAN', ha='center', va='center', rotation=90,
            fontsize=13, color='white', fontweight='bold', zorder=6)

    # port ↔ lcore arrows
    arrow(ax, 1.00, 5.80, 4.55, 5.80, color=C_ACCEPT, lw=2.2, mutation=16)
    arrow(ax, 4.55, 4.80, 1.00, 4.80, color=C_ACCEPT, lw=2.2, mutation=16)
    arrow(ax, 11.50, 5.80, 15.00, 5.80, color=C_ACCEPT, lw=2.2, mutation=16)
    arrow(ax, 15.00, 4.80, 11.50, 4.80, color=C_ACCEPT, lw=2.2, mutation=16)

    fig.tight_layout(pad=0.3)
    out = os.path.join(PLOTS_DIR, 'lcores.png')
    fig.savefig(out, dpi=180, bbox_inches='tight', facecolor=fig.get_facecolor())
    print(f'Saved: {out}')
    plt.close(fig)


if __name__ == '__main__':
    os.makedirs(PLOTS_DIR, exist_ok=True)
    plot_pipeline()
    plot_modules()
    plot_lcores()
