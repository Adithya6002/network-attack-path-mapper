"""Rank independent connection-block simulations, preserving declared business flows.

This bounded heuristic is advisory: it neither applies policies nor claims a
globally optimal cut. Each candidate blocks every service on one directed edge.
"""

import networkx as nx

from analyzer.validation import ipv4, validate_port


def recommend(graph, start, required=None, limit=5, max_candidates=200):
    if start not in graph:
        raise ValueError(f"Start host {start} is not in the network data.")
    if type(limit) is not int or limit < 1 or type(max_candidates) is not int or max_candidates < 1:
        raise ValueError("Recommendation and candidate limits must be positive integers.")
    required = [] if required is None else required
    if not isinstance(required, list):
        raise ValueError("Required connections must be a JSON list.")
    protected_edges = set()
    for flow in required:
        if not isinstance(flow, dict) or set(flow) - {"source", "destination", "port", "proto"}:
            raise ValueError("Required connections need source, destination, port and optional proto.")
        src, dst = flow.get("source"), flow.get("destination")
        ipv4(src, "Required source")
        ipv4(dst, "Required destination")
        validate_port(flow.get("port"), "Required port")
        proto = flow.get("proto", "tcp")
        if proto not in ("tcp", "udp"):
            raise ValueError("Required connection protocol must be tcp or udp.")
        edge = graph.get_edge_data(src, dst, {})
        if not any(p["port"] == flow["port"] and p.get("proto", "tcp") == proto for p in edge.get("services", [])):
            raise ValueError(f"Required connection {src} -> {dst} {flow['port']}/{proto} is not currently allowed.")
        protected_edges.add((src, dst))
    baseline = nx.single_source_shortest_path_length(graph, start)
    critical = {n for n, d in graph.nodes(data=True) if d.get("critical") and n != start and n in baseline}
    leads_to_critical = set(critical)
    reverse = graph.reverse(copy=False)
    for target in critical:
        leads_to_critical.update(nx.descendants(reverse, target))
    candidates = sorted(
        (src, dst) for src, dst in graph.edges
        if src in baseline and dst in leads_to_critical and (src, dst) not in protected_edges
    )
    suggestions = []
    for src, dst in candidates[:max_candidates]:
        view = nx.subgraph_view(graph, filter_edge=lambda a, b: (a, b) != (src, dst))
        distances = nx.single_source_shortest_path_length(view, start)
        protected = sorted(critical - distances.keys())
        farther = sum(distances[n] > baseline[n] for n in critical & distances.keys())
        if not protected and not farther:
            continue
        suggestions.append({
            "source": src, "destination": dst,
            "placement": "host inbound firewall" if graph.edges[src, dst]["same_segment"] else "network firewall",
            "rule": {"action": "deny", "src": f"{src}/32", "dst": f"{dst}/32", "ports": "any"},
            "critical_hosts_protected": protected,
            "critical_hosts_farther": farther,
            "reachable_hosts_removed": len(baseline.keys() - distances.keys()),
        })
    suggestions.sort(key=lambda item: (-len(item["critical_hosts_protected"]), -item["critical_hosts_farther"], item["source"], item["destination"]))
    return {
        "start": start, "required_connections": required,
        "candidate_count": len(candidates), "evaluated_candidates": min(len(candidates), max_candidates),
        "candidates_truncated": len(candidates) > max_candidates,
        "recommendations": suggestions[:limit],
        "assumptions": [
            "Each suggestion is simulated independently and blocks all services on one directed connection.",
            "Only declared direct business connections are protected; undeclared dependencies may be disrupted.",
            "Prepend a suggested rule to the indicated policy. Host inbound rules apply on the destination host.",
            "Results are potential pivot reachability, assuming intermediate hosts can be compromised; they do not prove exploitability."
        ],
    }
