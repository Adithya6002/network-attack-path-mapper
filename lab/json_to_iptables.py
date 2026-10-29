"""Turn a firewall policy from the project's JSON format into an iptables script.

The lab router applies the generated script, so the real network enforces
exactly the policy the analyzer models. Usage:

    python lab/json_to_iptables.py data/network.json lab/router/firewall-baseline.sh
    python lab/json_to_iptables.py data/firewall_segmented.json lab/router/firewall-segmented.sh
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from analyzer.validation import validate_firewall  # noqa: E402

# lab-router's temporary NAT adapter (VirtualBox NIC4). Lab traffic must never be
# forwarded through it, whatever the policy says, so it is blocked before any rule.
UPLINK_IFACE = "enp0s10"


def _addr(flag, spec):
    return [] if spec in (None, "any", "*") else [flag, spec]


def rule_lines(rule):
    validate_firewall({"default": "deny", "rules": [rule]})
    target = "ACCEPT" if rule["action"] == "allow" else "DROP"
    base = ["iptables", "-A", "FORWARD", *_addr("-s", rule.get("src")), *_addr("-d", rule.get("dst"))]
    ports = rule.get("ports")
    proto = rule.get("proto", "any")

    if ports in (None, "any", "*"):
        if proto == "any":
            return [" ".join([*base, "-j", target])]
        return [" ".join([*base, "-p", proto, "-j", target])]

    protos = ["tcp", "udp"] if proto == "any" else [proto]
    return [
        " ".join([*base, "-p", p, "-m", "multiport", "--dports", ",".join(str(n) for n in ports[i:i + 15]), "-j", target])
        for p in protos
        for i in range(0, len(ports), 15)
    ]


def to_script(policy, source_name):
    validate_firewall(policy)
    source_name = str(source_name).replace("\n", " ").replace("\r", " ")
    default = "ACCEPT" if policy.get("default", "allow") == "allow" else "DROP"
    lines = [
        "#!/bin/sh",
        f"# Generated from {source_name} by lab/json_to_iptables.py - do not edit by hand.",
        "set -e",
        "iptables -F FORWARD",
        f"iptables -P FORWARD {default}",
        "# Isolation guard: nothing is routed to or from the temporary internet adapter.",
        f"iptables -A FORWARD -i {UPLINK_IFACE} -j DROP",
        f"iptables -A FORWARD -o {UPLINK_IFACE} -j DROP",
        "# Stateful: replies to connections the policy allowed are always let back.",
        "iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    ]
    for rule in policy.get("rules", []):
        lines.extend(rule_lines(rule))
    lines.append('echo "Firewall policy applied:"')
    lines.append("iptables -L FORWARD -n -v --line-numbers")
    return "\n".join(lines) + "\n"


def main():
    if len(sys.argv) not in (2, 3):
        sys.exit("usage: python lab/json_to_iptables.py <network.json | firewall.json> [out.sh]")
    path = Path(sys.argv[1])
    data = json.loads(path.read_text(encoding="utf-8"))
    # Accept either a full network file or a bare firewall policy file.
    policy = data.get("firewall", data)
    script = to_script(policy, path.name)
    if len(sys.argv) == 3:
        # Always LF line endings: the script runs on Linux even when generated on Windows.
        with open(sys.argv[2], "w", encoding="ascii", newline="\n") as out:
            out.write(script)
    else:
        sys.stdout.write(script)


if __name__ == "__main__":
    main()
