#!/bin/sh
# Generated from network.json by lab/json_to_iptables.py - do not edit by hand.
set -e
iptables -F FORWARD
iptables -P FORWARD DROP
# Isolation guard: nothing is routed to or from the temporary internet adapter.
iptables -A FORWARD -i enp0s10 -j DROP
iptables -A FORWARD -o enp0s10 -j DROP
# Stateful: replies to connections the policy allowed are always let back.
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -s 10.10.10.0/24 -d 10.10.20.0/24 -j ACCEPT
iptables -A FORWARD -s 10.10.10.0/24 -d 10.10.30.0/24 -p tcp -m multiport --dports 22,445 -j ACCEPT
iptables -A FORWARD -s 10.10.10.0/24 -d 10.10.30.0/24 -p udp -m multiport --dports 22,445 -j ACCEPT
iptables -A FORWARD -s 10.10.20.0/24 -d 10.10.30.0/24 -j ACCEPT
iptables -A FORWARD -s 10.10.30.0/24 -j ACCEPT
echo "Firewall policy applied:"
iptables -L FORWARD -n -v --line-numbers
