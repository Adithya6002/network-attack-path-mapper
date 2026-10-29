"""Build a directed reachability graph from network.json.

An edge A -> B means: from host A, at least one open service on B is reachable
at the network layer. Hosts in the same subnet reach each other directly (same
L2 segment). Traffic between subnets passes the router/firewall, where the
rules are evaluated first-match, falling back to the default policy.
"""

import ipaddress
from copy import deepcopy
from functools import lru_cache

import networkx as nx

from analyzer.validation import ipv4, validate_firewall, validate_network, validate_port


ANY = (None, "any", "*")


def _compile_addr(spec):
    """CIDR string -> (network int, mask int); None matches anything."""
    if spec in ANY:
        return None
    net = ipaddress.ip_network(spec, strict=False)
    return int(net.network_address), int(net.netmask)


def compile_firewall(firewall):
    """Pre-parse a policy once so large graphs don't re-parse CIDRs per check.

    Returns (rules, default_allow); each rule is
    (src, dst, ports-or-None, proto, allow, one-based rule number).
    """
    validate_firewall(firewall)
    rules = [
        (
            _compile_addr(rule.get("src")),
            _compile_addr(rule.get("dst")),
            None if rule.get("ports") in ANY else frozenset(rule["ports"]),
            rule.get("proto", "any"),
            rule["action"] == "allow",
            number,
        )
        for number, rule in enumerate(firewall.get("rules", []), 1)
    ]
    return rules, firewall.get("default", "allow") == "allow"


def _addr_match(addr_int, compiled):
    return compiled is None or (addr_int & compiled[1]) == compiled[0]


def _rules_for_pair(rules, src_int, dst_int):
    """The rules whose source and destination match this host pair, in order."""
    return [r for r in rules if _addr_match(src_int, r[0]) and _addr_match(dst_int, r[1])]


def _decide(pair_rules, default_allow, port, proto):
    return _decision(pair_rules, default_allow, port, proto)[0]


def _decision(pair_rules, default_allow, port, proto):
    for _, _, ports, rule_proto, allow, number in pair_rules:
        if (ports is None or port in ports) and rule_proto in ("any", proto):
            return allow, number
    return default_allow, None


@lru_cache(maxsize=512)
def _reason(number, default_allow, prefix="network"):
    return (f"{prefix} rule {number} ({'allow' if default_allow else 'deny'})" if number is not None
            else f"{prefix} default ({'allow' if default_allow else 'deny'})")


def explain_connection(graph, src, dst, port, proto="tcp"):
    """Explain a direct service connection, including why a removed service is blocked."""
    validate_port(port)
    if proto not in ("tcp", "udp"):
        raise ValueError("Service protocol must be tcp or udp.")
    if src not in graph or dst not in graph:
        return "host absent from inventory"
    if not any(p["port"] == port and p.get("proto", "tcp") == proto for p in graph.nodes[dst]["ports"]):
        return "no observed listening service on destination"
    same = graph.nodes[src]["subnet"] != "unknown" and graph.nodes[src]["subnet"] == graph.nodes[dst]["subnet"]
    reason = "same segment (router bypassed)"
    policies = [] if same else [(graph.graph["firewall"], "network")]
    host_fw = graph.nodes[dst].get("inbound_firewall")
    if host_fw is not None:
        policies.append((host_fw, "host inbound"))
    for policy, prefix in policies:
        rules, default = compile_firewall(policy)
        pair = _rules_for_pair(rules, int(ipv4(src)), int(ipv4(dst)))
        allowed, number = _decision(pair, default, port, proto)
        decision = _reason(number, allowed, prefix)
        reason = reason + "; " + decision if same or prefix == "host inbound" else decision
        if not allowed:
            return reason
    return reason


def is_allowed(firewall, src_ip, dst_ip, port, proto="tcp"):
    """Evaluate firewall rules first-match; unmatched traffic gets the default."""
    validate_port(port)
    if proto not in ("tcp", "udp"):
        raise ValueError("Service protocol must be tcp or udp.")
    rules, default_allow = compile_firewall(firewall)
    pair_rules = _rules_for_pair(
        rules, int(ipv4(src_ip)), int(ipv4(dst_ip))
    )
    return _decide(pair_rules, default_allow, port, proto)


def subnet_of(ip, subnets):
    addr = int(ipv4(ip))
    for subnet in subnets:
        ipv4(subnet["cidr"], "Subnet CIDR", network=True)
        if _addr_match(addr, _compile_addr(subnet["cidr"])):
            return subnet["name"]
    return None


def predict_connection(network, firewall, src_ip, dst_ip, port, proto="tcp"):
    """Predicted outcome of one connection attempt, as the lab measures it.

    timeout = the firewall drops it; refused = allowed, but nothing listens on
    that port; open = allowed, and the destination runs a service there.
    """
    validate_port(port)
    if proto not in ("tcp", "udp"):
        raise ValueError("Service protocol must be tcp or udp.")
    validate_firewall(firewall)
    destination = next((host for host in network["hosts"] if host["ip"] == dst_ip), None)
    if destination is None or not any(host["ip"] == src_ip for host in network["hosts"]):
        raise ValueError("Prediction source and destination must exist in the inventory.")
    subnets = network.get("subnets", [])
    src_net, dst_net = subnet_of(src_ip, subnets), subnet_of(dst_ip, subnets)
    same_segment = src_net is not None and src_net == dst_net
    if not (same_segment or is_allowed(firewall, src_ip, dst_ip, port, proto)):
        return "timeout"
    if "firewall" in destination and not is_allowed(destination["firewall"], src_ip, dst_ip, port, proto):
        return "timeout"
    listening = any(
        p["port"] == port and p.get("proto", "tcp") == proto
        for h in network["hosts"] if h["ip"] == dst_ip
        for p in h.get("ports", [])
    )
    return "open" if listening else "refused"


def build_graph(network, firewall=None):
    """Return a networkx.DiGraph of hosts and reachable-service edges.

    Pass `firewall` to override the rules stored in the network file, e.g. to
    simulate a segmentation change.
    """
    validate_network(network, firewall)
    # Reports must describe the policy used at build time, even if a caller
    # subsequently edits its input to construct an after graph.
    network = deepcopy(network)
    firewall = deepcopy(firewall)
    fw = firewall if firewall is not None else network["firewall"]
    rules, default_allow = compile_firewall(fw)
    subnets = network.get("subnets", [])
    addr = {h["ip"]: int(ipaddress.ip_address(h["ip"])) for h in network["hosts"]}
    graph = nx.DiGraph()
    host_firewalls = {
        h["ip"]: compile_firewall(h["firewall"])
        for h in network["hosts"] if "firewall" in h
    }
    graph.graph["firewall"] = fw
    graph.graph["warnings"] = list(network.get("model_warnings", []))
    if not subnets:
        graph.graph["warnings"].append("No subnets declared: all traffic is treated as routed.")

    for host in network["hosts"]:
        graph.add_node(
            host["ip"],
            hostname=host.get("hostname", ""),
            os=host.get("os", ""),
            role=host.get("role", ""),
            critical=bool(host.get("critical", False)),
            subnet=subnet_of(host["ip"], subnets) or "unknown",
            ports=host.get("ports", []),
            inbound_firewall=host.get("firewall"),
        )

    for src in network["hosts"]:
        src_subnet = graph.nodes[src["ip"]]["subnet"]
        for dst in network["hosts"]:
            if src["ip"] == dst["ip"]:
                continue
            same_segment = (
                src_subnet != "unknown" and src_subnet == graph.nodes[dst["ip"]]["subnet"]
            )
            pair_rules = [] if same_segment else _rules_for_pair(rules, addr[src["ip"]], addr[dst["ip"]])
            host_fw = host_firewalls.get(dst["ip"])
            host_rules = (_rules_for_pair(host_fw[0], addr[src["ip"]], addr[dst["ip"]])
                          if host_fw else [])
            services, reasons = [], []
            for service in dst.get("ports", []):
                port, proto = service["port"], service.get("proto", "tcp")
                allowed, number = (True, None) if same_segment else _decision(pair_rules, default_allow, port, proto)
                if not allowed:
                    continue
                reason = "same segment (router bypassed)" if same_segment else _reason(number, True)
                if host_fw:
                    allowed, number = _decision(host_rules, host_fw[1], port, proto)
                    if not allowed:
                        continue
                    reason += "; " + _reason(number, True, "host inbound")
                services.append(service)
                reasons.append(reason)
            if services:
                graph.add_edge(
                    src["ip"],
                    dst["ip"],
                    services=services,
                    reasons=reasons,
                    same_segment=same_segment,
                    weight=1,
                )
    return graph


def service_label(service):
    name = service.get("service") or "?"
    return f"{service['port']}/{service.get('proto', 'tcp')} {name}"
