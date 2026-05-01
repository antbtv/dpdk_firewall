#!/bin/bash
# run.sh — RPi5 dpdk_firewall launch script
#
# Usage:
#   ./run.sh setup                — pull, build, prepare interfaces (no firewall start)
#   ./run.sh start [config]       — setup + start firewall (default config: config/rules.json)
#   ./run.sh hairpin [config]     — setup + start in hairpin mode (single port, lcore 0+1)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEFAULT_CONFIG="config/rules.json"
CONFIG="${2:-$DEFAULT_CONFIG}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
die()   { echo -e "${RED}[x]${NC} $*" >&2; exit 1; }

cd "$SCRIPT_DIR"

# --- 1. git pull ---
info "git pull..."
git pull

# --- 2. Hugepages ---
info "Allocating hugepages..."
HUGE=$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages)
if [ "$HUGE" -lt 512 ]; then
    echo 512 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages > /dev/null
    info "Hugepages allocated: 512 x 2MB"
else
    info "Hugepages already allocated: $HUGE"
fi

# --- 3. igb driver ---
info "Loading igb driver..."
sudo modprobe igb 2>/dev/null || warn "igb already loaded or not available"

# --- 4. Bring up interfaces ---
info "Bringing up interfaces..."
sudo ip link set enP1p1s0 up || die "Failed to bring up enP1p1s0"
sudo ip link set eth0 up     || die "Failed to bring up eth0"

# Verify
ip link show enP1p1s0 | grep -q "UP" || die "enP1p1s0 is not UP"
ip link show eth0     | grep -q "UP" || die "eth0 is not UP"
info "enP1p1s0: UP, eth0: UP"

# --- 5. igb RSS queues: reduce to 1 (required for AF_XDP) ---
info "Setting igb combined queues to 1..."
sudo ethtool -L enP1p1s0 combined 1 || warn "ethtool -L failed (may be already set)"
QUEUES=$(sudo ethtool -l enP1p1s0 2>/dev/null | grep -A5 "Current" | grep "Combined" | awk '{print $2}')
info "igb combined queues: ${QUEUES:-unknown}"

# --- 6. Clear stale XDP program ---
info "Clearing stale XDP program on enP1p1s0..."
sudo ip link set enP1p1s0 xdp off 2>/dev/null || true

# --- 7. Build ---
info "Building..."
ninja -C build

info "Build OK"
echo ""

if [ "${1:-}" = "setup" ]; then
    info "Setup complete. Run './run.sh start [config]' to launch the firewall."
    exit 0
fi

if [ "${1:-}" = "start" ]; then
    [ -f "$CONFIG" ] || die "Config not found: $CONFIG"
    info "Starting firewall with config: $CONFIG"
    echo ""
    exec sudo ./build/dpdk_firewall --config "$CONFIG" --log-level info
fi

if [ "${1:-}" = "hairpin" ]; then
    HAIRPIN_CONFIG="${2:-config/bench_hairpin.json}"
    [ -f "$HAIRPIN_CONFIG" ] || die "Config not found: $HAIRPIN_CONFIG"
    info "Starting firewall in hairpin mode with config: $HAIRPIN_CONFIG"
    echo ""
    exec sudo ./build/dpdk_firewall --config "$HAIRPIN_CONFIG" --log-level info --hairpin
fi

echo "Usage: $0 setup | start [config] | hairpin [config]"
exit 1
