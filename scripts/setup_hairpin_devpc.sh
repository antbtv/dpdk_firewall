#!/bin/bash
# Setup macvlan-vepa namespaces on Dev PC for hairpin benchmarking.
# Traffic: ns_send → eno1 (wire) → RPi5 → eno1 (wire) → ns_recv
#
# Usage:
#   sudo ./scripts/setup_hairpin_devpc.sh setup   — create namespaces
#   sudo ./scripts/setup_hairpin_devpc.sh teardown — remove namespaces

set -e

PARENT_IF="${PARENT_IF:-eno1}"
NS_SEND="ns_send"
NS_RECV="ns_recv"
IF_SEND="vns_send"
IF_RECV="vns_recv"
MAC_SEND="02:00:00:00:00:01"
MAC_RECV="02:00:00:00:00:02"
IP_SEND="10.50.0.1/24"
IP_RECV="10.50.0.2/24"

teardown() {
    echo "[teardown] removing namespaces and macvlan interfaces..."
    ip netns del "$NS_SEND" 2>/dev/null || true
    ip netns del "$NS_RECV" 2>/dev/null || true
    ip link del "$IF_SEND"  2>/dev/null || true
    ip link del "$IF_RECV"  2>/dev/null || true
    echo "[teardown] done"
}

setup() {
    teardown 2>/dev/null || true

    echo "[setup] creating namespaces..."
    ip netns add "$NS_SEND"
    ip netns add "$NS_RECV"

    echo "[setup] creating macvlan interfaces (vepa mode) on $PARENT_IF..."
    ip link add "$IF_SEND" link "$PARENT_IF" type macvlan mode vepa
    ip link add "$IF_RECV" link "$PARENT_IF" type macvlan mode vepa

    echo "[setup] assigning static MACs..."
    ip link set "$IF_SEND" address "$MAC_SEND"
    ip link set "$IF_RECV" address "$MAC_RECV"

    echo "[setup] moving interfaces to namespaces..."
    ip link set "$IF_SEND" netns "$NS_SEND"
    ip link set "$IF_RECV" netns "$NS_RECV"

    echo "[setup] configuring IPs..."
    ip netns exec "$NS_SEND" ip link set "$IF_SEND" up
    ip netns exec "$NS_SEND" ip addr add "$IP_SEND" dev "$IF_SEND"

    ip netns exec "$NS_RECV" ip link set "$IF_RECV" up
    ip netns exec "$NS_RECV" ip addr add "$IP_RECV" dev "$IF_RECV"

    echo "[setup] done"
    echo ""
    echo "  ns_send: $IP_SEND  MAC $MAC_SEND  (iface: $IF_SEND)"
    echo "  ns_recv: $IP_RECV  MAC $MAC_RECV  (iface: $IF_RECV)"
    echo ""
    echo "  t-raf server: sudo ip netns exec $NS_RECV <t-raf> traf_hairpin_64.yml server1"
    echo "  t-raf client: sudo ip netns exec $NS_SEND <t-raf> traf_hairpin_64.yml client1"
}

case "${1:-}" in
    setup)    setup ;;
    teardown) teardown ;;
    *)
        echo "Usage: $0 setup|teardown"
        exit 1
        ;;
esac
