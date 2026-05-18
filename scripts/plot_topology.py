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

def port_label(ax, x, y, iface, ip=None, color='white', size=10.5):
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

def main_v2():
    """Hairpin topology: macvlan vepa namespaces on Dev PC."""
    os.makedirs(PLOTS_DIR, exist_ok=True)

    fig, ax = plt.subplots(figsize=(18, 9))
    ax.set_xlim(0, 16)
    ax.set_ylim(0, 8)
    ax.axis('off')
    fig.patch.set_facecolor('#F0F3F4')
    ax.set_facecolor('#F0F3F4')

    ax.text(8.0, 7.65, 'Конфигурация стенда',
            ha='center', va='center', fontsize=17, fontweight='bold',
            color=C_DARK, zorder=5)

    # ─── Dev PC outer box  x: 0.3–6.8,  y: 0.6–7.2 ──────────────────────────
    box(ax, 3.55, 3.9, 6.5, 6.6, C_PC, radius=0.12, alpha=0.92)
    ax.text(3.55, 7.0, 'Dev PC  (x86-64, AMD Ryzen 7 4800H)',
            ha='center', va='center', fontsize=13, fontweight='bold',
            color=C_TEXT, zorder=5)

    # ── ns_send  x: 0.4–2.8,  y: 3.8–6.8 ─────────────────────────────────────
    box(ax, 1.6, 5.3, 2.4, 3.0, '#154360', radius=0.07, zorder=4)
    ax.text(1.6, 6.65, 'ns_send', ha='center', va='center',
            fontsize=12.5, fontweight='bold', color='#AED6F1', zorder=5)
    box(ax, 1.6, 6.0, 2.0, 0.52, '#1F618D', radius=0.04, zorder=5)
    port_label(ax, 1.6, 6.0, 'vns_send', '10.50.0.1/24', size=9.5)
    ax.text(1.6, 5.55, 'macvlan vepa', ha='center', va='center',
            fontsize=9.5, color='#85C1E9', zorder=5)
    box(ax, 1.6, 4.0, 1.9, 0.48, '#E67E22', radius=0.04, zorder=5)
    ax.text(1.6, 4.0, 't-raf client', ha='center', va='center',
            fontsize=11.5, color='white', fontweight='bold', zorder=6)

    # ── ns_recv  x: 4.3–6.7,  y: 3.8–6.8 ─────────────────────────────────────
    box(ax, 5.5, 5.3, 2.4, 3.0, '#145A32', radius=0.07, zorder=4)
    ax.text(5.5, 6.65, 'ns_recv', ha='center', va='center',
            fontsize=12.5, fontweight='bold', color='#A9DFBF', zorder=5)
    box(ax, 5.5, 6.0, 2.0, 0.52, '#196F3D', radius=0.04, zorder=5)
    port_label(ax, 5.5, 6.0, 'vns_recv', '10.50.0.2/24', size=9.5)
    ax.text(5.5, 5.55, 'macvlan vepa', ha='center', va='center',
            fontsize=9.5, color='#82E0AA', zorder=5)
    box(ax, 5.5, 4.0, 1.9, 0.48, '#27AE60', radius=0.04, zorder=5)
    ax.text(5.5, 4.0, 't-raf server', ha='center', va='center',
            fontsize=11.5, color='white', fontweight='bold', zorder=6)

    # ── eno1  center (3.5, 1.9) ────────────────────────────────────────────────
    box(ax, 3.5, 1.9, 2.6, 0.62, '#5D6D7E', radius=0.04, zorder=5)
    port_label(ax, 3.5, 1.9, 'eno1  (Intel I219)', size=11)

    # ns_send → eno1
    ax.annotate('', xy=(2.6, 2.19), xytext=(1.6, 3.8),
                arrowprops=dict(arrowstyle='<->', color='#AAB7B8',
                                lw=1.5, mutation_scale=10,
                                connectionstyle='arc3,rad=0.15'), zorder=3)
    # ns_recv → eno1
    ax.annotate('', xy=(4.4, 2.19), xytext=(5.5, 3.8),
                arrowprops=dict(arrowstyle='<->', color='#AAB7B8',
                                lw=1.5, mutation_scale=10,
                                connectionstyle='arc3,rad=-0.15'), zorder=3)

    # ── Ethernet cable  (eno1 right → enP1p1s0 left edge) ────────────────────
    C_ETH = '#F39C12'   # оранжевый — хорошо виден на любом фоне
    ax.annotate('', xy=(11.1, 1.9), xytext=(4.72, 1.9),
                arrowprops=dict(arrowstyle='<->', color=C_ETH,
                                lw=3.5, mutation_scale=18), zorder=4)
    ax.text(7.9, 2.22, 'Ethernet  1 Гбит/с', ha='center', va='bottom',
            fontsize=12, color=C_ETH, fontweight='bold')

    # ─── RPi5 outer box  x: 9.3–15.7,  y: 0.6–7.2 ────────────────────────────
    box(ax, 12.5, 3.9, 6.4, 6.6, C_RPI, radius=0.1)
    ax.text(12.5, 7.0, 'Raspberry Pi 5',
            ha='center', va='center', fontsize=13, fontweight='bold',
            color=C_TEXT, zorder=5)
    ax.text(12.5, 6.55, 'ARM Cortex-A76 × 4  •  8 ГБ RAM  •  Linux 6.17',
            ha='center', va='center', fontsize=10, color='#AED6F1', zorder=5)

    # ── enP1p1s0  center (12.5, 1.9) ──────────────────────────────────────────
    box(ax, 12.5, 1.9, 3.2, 0.62, '#2E4057', radius=0.04, zorder=5)
    port_label(ax, 12.5, 1.9, 'enP1p1s0  (Intel I210 / igb)', size=10.5)

    # ── Linux bridge block  center (10.8, 4.8) ─────────────────────────────────
    box(ax, 10.8, 4.8, 2.2, 1.6, C_SCEN1, radius=0.07, zorder=5)
    ax.text(10.8, 5.25, 'Linux bridge', ha='center', va='center',
            fontsize=12, color='white', fontweight='bold', zorder=6)
    ax.text(10.8, 4.75, 'br0', ha='center', va='center',
            fontsize=11, color='white', zorder=6)
    ax.text(10.8, 4.25, 'hairpin on', ha='center', va='center',
            fontsize=10, color='#A9DFBF', zorder=6)

    # ── DPDK block  center (14.2, 4.8) ────────────────────────────────────────
    box(ax, 14.2, 4.8, 2.2, 1.6, C_SCEN2, radius=0.07, zorder=5)
    ax.text(14.2, 5.25, 'DPDK', ha='center', va='center',
            fontsize=12, color='white', fontweight='bold', zorder=6)
    ax.text(14.2, 4.75, 'AF_XDP PMD', ha='center', va='center',
            fontsize=11, color='white', zorder=6)
    ax.text(14.2, 4.25, 'hairpin mode', ha='center', va='center',
            fontsize=10, color='#F1948A', zorder=6)

    # "или" between bridge and DPDK  (gap: 10.8+1.1=11.9 … 14.2-1.1=13.1)
    ax.text(12.5, 4.8, 'или', ha='center', va='center',
            fontsize=13, color='#BDC3C7', fontstyle='italic', zorder=6)

    # enP1p1s0 → bridge
    ax.annotate('', xy=(10.8, 4.0), xytext=(11.3, 2.19),
                arrowprops=dict(arrowstyle='<->', color='#AAB7B8',
                                lw=1.5, mutation_scale=10,
                                connectionstyle='arc3,rad=0.15'), zorder=3)
    # enP1p1s0 → DPDK
    ax.annotate('', xy=(14.2, 4.0), xytext=(13.7, 2.19),
                arrowprops=dict(arrowstyle='<->', color='#AAB7B8',
                                lw=1.5, mutation_scale=10,
                                connectionstyle='arc3,rad=-0.15'), zorder=3)

    # ── traffic path label at bottom ───────────────────────────────────────────
    ax.text(8.0, 0.28,
            'ns_send → vns_send → eno1 → enP1p1s0 → [hairpin] → enP1p1s0 → eno1 → vns_recv → ns_recv',
            ha='center', va='center', fontsize=10, color='#5D6D7E',
            style='italic', zorder=5)

    # ── legend ─────────────────────────────────────────────────────────────────
    from matplotlib.patches import Patch
    legend_els = [
        Patch(facecolor=C_SCEN1, label='Linux bridge (сценарий 1)'),
        Patch(facecolor=C_SCEN2, label='DPDK (сценарий 2)'),
    ]
    ax.legend(handles=legend_els, loc='lower right', fontsize=11.5,
              framealpha=0.88, edgecolor='#BDC3C7')

    fig.tight_layout(pad=0.3)
    out = os.path.join(PLOTS_DIR, 'topology_v2.png')
    fig.savefig(out, dpi=180, bbox_inches='tight', facecolor=fig.get_facecolor())
    print(f'Saved: {out}')
    plt.close(fig)


if __name__ == '__main__':
    main_v2()
