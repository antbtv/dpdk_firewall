# DPDK Firewall — Benchmarks

Platform: Raspberry Pi 5 (ARM Cortex-A76, 4 cores, 8 GB RAM)
NIC WAN: Intel I210 (PCI 0001:01:00.0, igb driver, AF_PACKET PMD)
NIC LAN: BCM54213PE (eth0, rp1 driver, AF_PACKET PMD)
DPDK: 24.11.3 (Ubuntu package)
Kernel: 6.8.0-101-generic (aarch64)
Build: meson --optimization=3

Test topology:
  Dev PC (10.99.0.1) ──[eno1]── RPi5 WAN(enP1p1s0) ──[bridge]── RPi5 LAN(eth0) ──[eth0]── raspi4 (10.99.0.2)

iperf3 command: `iperf3 -c 10.99.0.2 -t 30` (from Dev PC)

---

## P6-01: Throughput Benchmarking (TCP, 1500-byte frames)

| Scenario                  | Config                  | n_rules | DDoS | Mbit/s | Retransmits | Notes |
|---------------------------|-------------------------|---------|------|--------|-------------|-------|
| 1. Baseline (no rules)    | bench_baseline.json     | 0       | off  | TBD    | TBD         |       |
| 2. 10 DROP rules          | bench_10rules.json      | 10      | off  | TBD    | TBD         |       |
| 3. 100 DROP rules         | bench_100rules.json     | 100     | off  | TBD    | TBD         |       |
| 4. Baseline + DDoS        | bench_ddos.json         | 1       | on   | TBD    | TBD         |       |

### Run procedure

```bash
# On RPi5 — run each scenario in sequence, record iperf3 output

# Scenario 1: baseline
sudo ./build/dpdk_firewall --config config/bench_baseline.json --log-level info
# On Dev PC: iperf3 -c 10.99.0.2 -t 30

# Scenario 2: 10 rules
sudo ./build/dpdk_firewall --config config/bench_10rules.json --log-level info
# On Dev PC: iperf3 -c 10.99.0.2 -t 30

# Scenario 3: 100 rules
sudo ./build/dpdk_firewall --config config/bench_100rules.json --log-level info
# On Dev PC: iperf3 -c 10.99.0.2 -t 30

# Scenario 4: DDoS enabled
sudo ./build/dpdk_firewall --config config/bench_ddos.json --log-level info
# On Dev PC: iperf3 -c 10.99.0.2 -t 30
```

---

## P6-02: Latency / Jitter (pending)

| Load     | p50 latency | p99 latency | Jitter (p99) |
|----------|-------------|-------------|--------------|
| 10% LR   | TBD         | TBD         | TBD          |
| 50% LR   | TBD         | TBD         | TBD          |
| 90% LR   | TBD         | TBD         | TBD          |

---

## P6-03: DDoS Benchmark (pending)

| Attack type | Tool  | Time to blacklist | Legit throughput during attack |
|-------------|-------|-------------------|-------------------------------|
| SYN flood   | hping3 | TBD              | TBD Mbit/s                    |
| UDP flood   | iperf3 -u | TBD          | TBD Mbit/s                    |

---

## Notes on Platform Limitations

AF_PACKET PMD throughput is limited to ~12 Mbit/s on RPi5 because:
- BCM2712 PCIe root complex has no IOMMU for PCIe endpoint devices
- DPDK uio_pci_generic fails (64 GB DMA offset in dma-ranges, PA mode gets wrong addresses)
- vfio-pci unavailable (no IOMMU groups for BCM2712 PCIe)
- AF_PACKET requires kernel involvement per frame (copy through kernel socket layer), no DMA bypass
- The same code on x86 + vfio-pci achieves line rate (10+ Gbit/s)

Phase 7 explores optimizations: AF_PACKET tuning (framecnt, qdisc_bypass) and AF_XDP PMD.
