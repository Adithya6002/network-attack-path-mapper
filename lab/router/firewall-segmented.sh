#!/bin/sh
# Generated from firewall_segmented.json by lab/json_to_iptables.py - do not edit by hand.
set -e
iptables -F FORWARD
iptables -P FORWARD DROP
# Isolation guard: nothing is routed to or from the temporary internet adapter.
iptables -A FORWARD -i enp0s10 -j DROP
iptables -A FORWARD -o enp0s10 -j DROP
# Stateful: replies to connections the policy allowed are always let back.
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -s 10.10.10.0/24 -d 10.10.20.10/32 -p tcp -m multiport --dports 80,443 -j ACCEPT
iptables -A FORWARD -s 10.10.10.0/24 -d 10.10.20.10/32 -p udp -m multiport --dports 80,443 -j ACCEPT
iptables -A FORWARD -s 10.10.20.10/32 -d 10.10.30.20/32 -p tcp -m multiport --dports 5432 -j ACCEPT
iptables -A FORWARD -s 10.10.20.10/32 -d 10.10.30.20/32 -p udp -m multiport --dports 5432 -j ACCEPT
iptables -A FORWARD -j DROP
echo "Firewall policy applied:"
iptables -L FORWARD -n -v --line-numbers
