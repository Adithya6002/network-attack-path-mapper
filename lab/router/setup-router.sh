#!/bin/sh
# One-shot setup for lab-router. Run on lab-router while its NAT adapter is connected:
#   wget http://10.0.5.2:8000/lab/router/setup-router.sh && sudo sh setup-router.sh
# (VirtualBox NAT on adapter N puts the host at 10.0.(N+1).2; the router's NAT is adapter 4.)
set -e
HOST=$(ip route | awk '/^default/ {print $3; exit}')
SRC=http://$HOST:8000/lab/router
cd "$(mktemp -d)"
wget -q "$SRC/01-lab-router.yaml" "$SRC/firewall-baseline.sh" "$SRC/firewall-segmented.sh"

echo "== Interfaces"
install -m 600 01-lab-router.yaml /etc/netplan/01-lab-router.yaml
netplan apply
sleep 2

echo "== IP forwarding"
echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-lab.conf
sysctl -q --system

echo "== Firewall tools"
DEBIAN_FRONTEND=noninteractive apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables iptables-persistent

echo "== Baseline policy"
install -m 755 firewall-baseline.sh firewall-segmented.sh /usr/local/sbin/
/usr/local/sbin/firewall-baseline.sh
netfilter-persistent save

echo
ip -br addr
echo
echo "lab-router ready. Switch policy later with:"
echo "  sudo firewall-segmented.sh   or   sudo firewall-baseline.sh"
