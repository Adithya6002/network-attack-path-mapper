"""Build a directed reachability graph from network.json.

An edge A -> B means: from host A, at least one open service on B is reachable
at the network layer. Hosts in the same subnet reach each other directly (same
L2 segment). Traffic between subnets passes the router/firewall, where the
rules are evaluated first-match, falling back to the default policy.
"""

import ipaddress

import networkx as nx


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
    (src, dst, ports-or-None, proto, allow).
    """
    rules = [
        (
            _compile_addr(rule.get("src")),
            _compile_addr(rule.get("dst")),
            None if rule.get("ports") in ANY else frozenset(rule["ports"]),
            rule.get("proto", "any"),
            rule["action"] == "allow",
        )
        for rule in firewall.get("rules", [])
    ]
    return rules, firewall.get("default", "allow") == "allow"


def _addr_match(addr_int, compiled):
    return compiled is None or (addr_int & compiled[1]) == compiled[0]


def _rules_for_pair(rules, src_int, dst_int):
    """The rules whose source and destination match this host pair, in order."""
    return [r for r in rules if _addr_match(src_int, r[0]) and _addr_match(dst_int, r[1])]


def _decide(pair_rules, default_allow, port, proto):
    for _, _, ports, rule_proto, allow in pair_rules:
        if (ports is None or port in ports) and rule_proto in ("any", proto):
            return allow
    return default_allow


def is_allowed(firewall, src_ip, dst_ip, port, proto="tcp"):
    """Evaluate firewall rules first-match; unmatched traffic gets the default."""
    rules, default_allow = compile_firewall(firewall)
    pair_rules = _rules_for_pair(
        rules, int(ipaddress.ip_address(src_ip)), int(ipaddress.ip_address(dst_ip))
    )
    return _decide(pair_rules, default_allow, port, proto)


def subnet_of(ip, subnets):
    addr = int(ipaddress.ip_address(ip))
    for subnet in subnets:
        if _addr_match(addr, _compile_addr(subnet["cidr"])):
            return subnet["name"]
    return None


def predict_connection(network, firewall, src_ip, dst_ip, port, proto="tcp"):
    """Predicted outcome of one connection attempt, as the lab measures it.

    timeout = the firewall drops it; refused = allowed, but nothing listens on
    that port; open = allowed, and the destination runs a service there.
    """
    subnets = network.get("subnets", [])
    src_net, dst_net = subnet_of(src_ip, subnets), subnet_of(dst_ip, subnets)
    same_segment = src_net is not None and src_net == dst_net
    if not (same_segment or is_allowed(firewall, src_ip, dst_ip, port, proto)):
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
    fw = firewall if firewall is not None else network.get("firewall", {})
    rules, default_allow = compile_firewall(fw)
    subnets = network.get("subnets", [])
    addr = {h["ip"]: int(ipaddress.ip_address(h["ip"])) for h in network["hosts"]}
    graph = nx.DiGraph()

    for host in network["hosts"]:
        graph.add_node(
            host["ip"],
            hostname=host.get("hostname", ""),
            os=host.get("os", ""),
            role=host.get("role", ""),
            critical=bool(host.get("critical", False)),
            subnet=subnet_of(host["ip"], subnets) or "unknown",
            ports=host.get("ports", []),
        )

    for src in network["hosts"]:
        src_subnet = graph.nodes[src["ip"]]["subnet"]
        for dst in network["hosts"]:
            if src["ip"] == dst["ip"]:
                continue
            same_segment = (
                src_subnet != "unknown" and src_subnet == graph.nodes[dst["ip"]]["subnet"]
            )
            if same_segment:
                services = list(dst.get("ports", []))
            else:
                pair_rules = _rules_for_pair(rules, addr[src["ip"]], addr[dst["ip"]])
                services = [
                    p for p in dst.get("ports", [])
                    if _decide(pair_rules, default_allow, p["port"], p.get("proto", "tcp"))
                ]
            if services:
                graph.add_edge(
                    src["ip"],
                    dst["ip"],
                    services=services,
                    same_segment=same_segment,
                    weight=1,
                )
    return graph


def service_label(service):
    name = service.get("service") or "?"
    return f"{service['port']}/{service.get('proto', 'tcp')} {name}"
