#!/usr/bin/env python3
"""
Generates a network topology diagram for the test stand.
Output: results/plots/topology.png
"""

import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

PLOTS_DIR = 'results/plots'

# ── colours ──────────────────────────────────────────────────────────────────
C_PC    = '#2C3E50'   # dark blue-grey  — devices
C_RPI   = '#1A5276'   # deep blue       — RPi5
C_RASPI = '#2C3E50'
C_SCEN1 = '#1E8449'   # green           — Linux bridge
C_SCEN2 = '#922B21'   # red             — DPDK
C_ARROW = '#5D6D7E'
C_DATA  = '#E67E22'   # orange          — traffic arrow
C_PORT  = '#ECF0F1'   # light           — port labels
C_TEXT  = 'white'
C_DARK  = '#1C2833'

def box(ax, x, y, w, h, color, radius=0.04, zorder=3, alpha=1.0):
    p = FancyBboxPatch((x - w/2, y - h/2), w, h,
                       boxstyle=f'round,pad=0,rounding_size={radius}',
                       facecolor=color, edgecolor='white',
                       linewidth=1.5, zorder=zorder, alpha=alpha)
    ax.add_patch(p)
    return p

def port_label(ax, x, y, iface, ip=None, color='white', size=7.5):
    label = iface if ip is None else f'{iface}\n{ip}'
    ax.text(x, y, label, ha='center', va='center',
            fontsize=size, color=color, fontweight='bold',
            zorder=6, linespacing=1.4)

def arrow(ax, x1, y1, x2, y2, color=C_ARROW, lw=2, zorder=2,
          style='->', mutation=12):
    ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle=style,
                                color=color, lw=lw,
                                connectionstyle='arc3,rad=0'),
                zorder=zorder)

def main():
    os.makedirs(PLOTS_DIR, exist_ok=True)

    fig, ax = plt.subplots(figsize=(14, 7))
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 7)
    ax.axis('off')
    fig.patch.set_facecolor('#F0F3F4')
    ax.set_facecolor('#F0F3F4')

    # ── title ────────────────────────────────────────────────────────────────
    ax.text(7, 6.65, 'Конфигурация стенда',
            ha='center', va='center', fontsize=13, fontweight='bold',
            color=C_DARK, zorder=5)

    # ─────────────────────────────────────────────────────────────────────────
    # Dev PC  (x=1.5)
    # ─────────────────────────────────────────────────────────────────────────
    box(ax, 1.5, 3.5, 2.2, 2.6, C_PC, radius=0.08)
    ax.text(1.5, 4.55, 'Dev PC', ha='center', va='center',
            fontsize=11, fontweight='bold', color=C_TEXT, zorder=5)
    ax.text(1.5, 4.12, 'x86-64', ha='center', va='center',
            fontsize=8, color='#BDC3C7', zorder=5)

    # port
    box(ax, 1.5, 3.3, 1.7, 0.52, '#5D6D7E', radius=0.04, zorder=4)
    port_label(ax, 1.5, 3.3, 'eno1  •  10.99.0.1')

    # t-raf client badge
    box(ax, 1.5, 2.55, 1.7, 0.45, '#E67E22', radius=0.04, zorder=4)
    ax.text(1.5, 2.55, 't-raf client', ha='center', va='center',
            fontsize=8.5, color='white', fontweight='bold', zorder=5)

    # ─────────────────────────────────────────────────────────────────────────
    # RPi5  (x=5.5 … 8.5, wide box)
    # ─────────────────────────────────────────────────────────────────────────
    box(ax, 7.0, 3.5, 5.0, 2.8, C_RPI, radius=0.1)
    ax.text(7.0, 4.65, 'Raspberry Pi 5', ha='center', va='center',
            fontsize=11, fontweight='bold', color=C_TEXT, zorder=5)
    ax.text(7.0, 4.27, 'ARM Cortex-A76 × 4  •  8 ГБ RAM  •  Linux 6.17',
            ha='center', va='center', fontsize=7.5, color='#BDC3C7', zorder=5)

    # WAN port  (left side of RPi5)

    box(ax, 5.35, 3.5, 1.55, 0.9, '#2E4057', radius=0.04, zorder=4)
    ax.text(5.35, 3.75, 'WAN', ha='center', va='center',
            fontsize=7, color='#AAB7B8', zorder=5)
    ax.text(5.35, 3.45, 'enP1p1s0', ha='center', va='center',
            fontsize=8, color='white', fontweight='bold', zorder=5)
    ax.text(5.35, 3.18, 'Intel I210  (igb)', ha='center', va='center',
            fontsize=7, color='#BDC3C7', zorder=5)

    # LAN port  (right side of RPi5)
    box(ax, 8.65, 3.5, 1.55, 0.9, '#2E4057', radius=0.04, zorder=4)
    ax.text(8.65, 3.75, 'LAN', ha='center', va='center',
            fontsize=7, color='#AAB7B8', zorder=5)
    ax.text(8.65, 3.45, 'eth0', ha='center', va='center',
            fontsize=8, color='white', fontweight='bold', zorder=5)
    ax.text(8.65, 3.18, 'BCM54213PE  (macb)', ha='center', va='center',
            fontsize=7, color='#BDC3C7', zorder=5)

    # ─────────────────────────────────────────────────────────────────────────
    # raspi4  (x=12.5)
    # ─────────────────────────────────────────────────────────────────────────
    box(ax, 12.5, 3.5, 2.2, 2.6, C_RASPI, radius=0.08)
    ax.text(12.5, 4.55, 'raspi4', ha='center', va='center',
            fontsize=11, fontweight='bold', color=C_TEXT, zorder=5)
    ax.text(12.5, 4.12, 'Raspberry Pi 4', ha='center', va='center',
            fontsize=8, color='#BDC3C7', zorder=5)

    # port
    box(ax, 12.5, 3.3, 1.7, 0.52, '#5D6D7E', radius=0.04, zorder=4)
    port_label(ax, 12.5, 3.3, 'eth0  •  10.99.0.2')

    # t-raf server badge
    box(ax, 12.5, 2.55, 1.7, 0.45, '#27AE60', radius=0.04, zorder=4)
    ax.text(12.5, 2.55, 't-raf server', ha='center', va='center',
            fontsize=8.5, color='white', fontweight='bold', zorder=5)

    # ─────────────────────────────────────────────────────────────────────────
    # Cables / arrows
    # ─────────────────────────────────────────────────────────────────────────
    # Dev PC eno1 → RPi5 WAN
    ax.annotate('', xy=(4.57, 3.5), xytext=(2.61, 3.5),
                arrowprops=dict(arrowstyle='->', color='#AAB7B8',
                                lw=2.5, mutation_scale=14), zorder=2)
    ax.text(3.59, 3.68, 'Ethernet', ha='center', va='bottom',
            fontsize=7.5, color='#7F8C8D', style='italic')

    # RPi5 LAN → raspi4
    ax.annotate('', xy=(11.39, 3.5), xytext=(9.43, 3.5),
                arrowprops=dict(arrowstyle='->', color='#AAB7B8',
                                lw=2.5, mutation_scale=14), zorder=2)
    ax.text(10.41, 3.68, 'Ethernet', ha='center', va='bottom',
            fontsize=7.5, color='#7F8C8D', style='italic')

    # traffic direction arrow (big, orange, curved above)
    ax.annotate('', xy=(11.4, 4.1), xytext=(2.6, 4.1),
                arrowprops=dict(arrowstyle='->', color=C_DATA,
                                lw=2.0, mutation_scale=16,
                                connectionstyle='arc3,rad=-0.25'), zorder=2)
    ax.text(7.0, 5.45, 'трафик t-raf',
            ha='center', va='center', fontsize=8.5,
            color=C_DATA, fontweight='bold', zorder=5)

    fig.tight_layout(pad=0.5)
    out = os.path.join(PLOTS_DIR, 'topology.png')
    fig.savefig(out, dpi=180, bbox_inches='tight', facecolor=fig.get_facecolor())
    print(f'Saved: {out}')
    plt.close(fig)


if __name__ == '__main__':
    main()
