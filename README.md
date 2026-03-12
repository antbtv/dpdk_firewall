# dpdk_firewall

High-performance DPDK-based stateless firewall for Raspberry Pi 5.
Diploma thesis — Butov A.V., A-07-22, 2026.

## Overview

dpdk_firewall is a packet filtering bridge built on DPDK that runs on Raspberry Pi 5
(BCM2712 SoC, ARM Cortex-A76). It forwards traffic between WAN (Intel I210, `enP1p1s0`)
and LAN (BCM54213PE, `eth0`) while applying ACL rules, rate limiting, and DDoS protection.

Due to BCM2712 PCIe having no IOMMU for external devices, native DPDK PMD (vfio-pci)
is unavailable. The firewall uses **AF_XDP PMD** for WAN and **AF_PACKET PMD** for LAN,
achieving near-line-rate performance without kernel driver rebinding.

## Performance

Measured on RPi5, kernel 6.17, DPDK 24.11.3 (iperf3 TCP, 1500-byte frames):

| PMD configuration           | Throughput    | Retransmits | Latency (ping) |
|-----------------------------|---------------|-------------|----------------|
| AF_PACKET (baseline)        | ~12 Mbit/s    | 2333/10s    | 0.85 ms        |
| **AF_XDP (force_copy=1)**   | **895 Mbit/s**| **0/10s**   | **0.35 ms**    |

AF_XDP provides **×89 improvement** over AF_PACKET — 89.5% of the 1 Gbit/s physical link.

## Features

- **7-stage packet pipeline**: RX → Classifier → Blacklist → ACL rules → Rate limit → DDoS → TX
- **ACL rule engine**: priority-ordered rules with ACCEPT / DROP / RATE_LIMIT actions
- **DDoS protection**: sliding window per source IP, auto-blacklist on threshold breach
- **Rate limiting**: token bucket (`rte_meter_srtcm`) per rule
- **Hot reload**: `SIGHUP` reloads config under rwlock with zero forwarding downtime
- **Management CLI**: UNIX socket (`/var/run/dpdk_firewall/mgmt.sock`), JSON protocol
- **fw_ctl**: standalone CLI tool (no DPDK dependency)

## Build

Natively on RPi5:
```bash
sudo apt install dpdk dpdk-dev libdpdk-dev libjansson-dev libxdp-dev libbpf-dev \
                 meson ninja-build pkg-config build-essential
meson setup build --optimization=3
ninja -C build
```

## Quick Start

```bash
# 1. Hugepages (do once per boot):
echo 512 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# 2. Load igb driver and bring up interfaces:
sudo modprobe igb
sudo ip link set enP1p1s0 up
sudo ip link set eth0 up

# 3. Reduce igb to 1 combined queue (required for AF_XDP):
sudo ethtool -L enP1p1s0 combined 1

# 4. Clear any stale XDP program:
sudo ip link set enP1p1s0 xdp off

# 5. Run:
sudo ./build/dpdk_firewall --config config/rules.json --log-level info
```

## Configuration

Rules are defined in JSON (`config/rules.json`):

```json
{
  "ports": { "wan": "enP1p1s0", "lan": "builtin" },
  "default_policy": "drop",
  "ddos": { "enabled": true, "syn_pps_threshold": 10000, "block_duration_s": 300 },
  "rules": [
    { "id": 1, "priority": 100, "proto": "tcp", "dst_port": "22", "action": "accept" },
    { "id": 2, "priority": 200, "proto": "icmp", "action": "rate_limit",
      "rate": { "cir_kbps": 1000, "cbs_bytes": 65536 } }
  ]
}
```

Hot reload: `sudo kill -HUP $(pgrep dpdk_firewall)` or `fw_ctl config reload`.

## Management CLI

```bash
fw_ctl stats                          # RX/TX/dropped counters
fw_ctl rule list                      # list ACL rules
fw_ctl rule add --proto tcp --dst-port 80 --action accept
fw_ctl blacklist add --ip 192.168.1.1 --duration 300
fw_ctl config reload
```

## Architecture

```
[WAN] enP1p1s0 (I210/igb) ──AF_XDP──► lcore 1 ──► [LAN] eth0 (BCM54213PE/macb) ──AF_PACKET──►
[LAN] eth0 (BCM54213PE/macb) ──AF_PACKET──► lcore 2 ──► [WAN] enP1p1s0 (I210/igb) ──AF_XDP──►

lcore 0: control plane (mgmt socket, config reload, stats)
```

Pipeline per burst of 32 packets:
1. RX BURST
2. CLASSIFIER (Ethernet/IPv4/L4 → pkt_meta)
3. BLACKLIST CHECK (rte_hash, O(1))
4. RULE ENGINE (priority-ordered linear scan)
5. RATE LIMIT (rte_meter_srtcm)
6. DDOS UPDATE (sliding window, auto-blacklist)
7. TX BURST

## Why AF_XDP, not native PMD

BCM2712 (RPi5 SoC) has no IOMMU for the external PCIe slot. The PCIe `dma-ranges`
encodes a 64 GB DMA offset that DPDK's PA-mode uio drivers cannot handle — DMA fails
silently. vfio-pci requires IOMMU groups which BCM2712 does not provide for PCIe.

AF_XDP intercepts packets at the XDP hook in the igb driver (before sk_buff allocation)
and transfers them to DPDK via a shared UMEM ring. No DMA remapping is needed — the
kernel's Linux DMA API correctly handles the 64 GB offset for I210 receive DMA.

See `RESEARCH_ARM_PERFORMANCE.md` and `BENCHMARKS.md` for detailed analysis.
