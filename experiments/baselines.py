"""Two common ways of judging exposure, re-implemented for comparison.

single_vantage: what an Nmap scan from the start host shows - the hosts with
    at least one service directly reachable from it (one hop, no pivoting).
zone_level: firewall-rule review at subnet granularity - a subnet-to-subnet
    graph where an edge exists if any rule (or the default) lets traffic
    through on any port; every host in a reachable subnet counts as exposed,
    whether or not it runs a service on an allowed port. With
    transitive=False it is a direct rule review (one hop: "is there a rule
    from my zone to theirs?").
"""

import ipaddress

import networkx as nx

from analyzer.graph import is_allowed

# Ports checked when deciding whether a subnet pair is "open" at all. A rule
# reviewer looks at the rules, not the hosts, so any of these opening counts.
PROBE_PORTS = [22, 25, 80, 443, 445, 3306, 3389, 5432, 8080, 49152]


def single_vantage(graph, start):
    return set(graph.successors(start))


def zone_level(network, firewall, start, transitive=True):
    """Hosts in subnets reachable from the start's subnet at the rule level.

    transitive=False is a direct rule review: only subnets with a rule straight
    from the start's subnet (plus the start's own subnet) count.
    """
    subnets = network["subnets"]
    rep = {s["name"]: str(ipaddress.ip_network(s["cidr"]).network_address + 1) for s in subnets}
    zone_graph = nx.DiGraph()
    zone_graph.add_nodes_from(rep)
    for a in subnets:
        for b in subnets:
            if a is not b and any(
                is_allowed(firewall, rep[a["name"]], rep[b["name"]], p) for p in PROBE_PORTS
            ):
                zone_graph.add_edge(a["name"], b["name"])

    def subnet_name(ip):
        addr = ipaddress.ip_address(ip)
        return next(s["name"] for s in subnets if addr in ipaddress.ip_network(s["cidr"]))

    start_subnet = subnet_name(start)
    if transitive:
        reach = nx.descendants(zone_graph, start_subnet) | {start_subnet}
    else:
        reach = set(zone_graph.successors(start_subnet)) | {start_subnet}
    return {h["ip"] for h in network["hosts"] if h["ip"] != start and subnet_name(h["ip"]) in reach}
