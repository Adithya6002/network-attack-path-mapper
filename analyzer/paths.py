"""Reachability and multi-hop path analysis on the host graph."""

import networkx as nx

from analyzer.graph import explain_connection

PATH_LIMIT = 50


def reachable_hosts(graph, start):
    """Hosts reachable from start, mapped to their minimum hop count."""
    distances = nx.single_source_shortest_path_length(graph, start)
    distances.pop(start, None)
    return dict(sorted(distances.items(), key=lambda item: (item[1], item[0])))


def paths_to(graph, start, target, max_hops=4, limit=PATH_LIMIT):
    """Simple paths from start to target of at most max_hops edges, shortest first
    (capped at limit).

    Uses hop distances *to* the target to prune any branch that cannot arrive
    within the remaining hops, so large segmented graphs stay fast. Paths are
    enumerated length by length, so when the cap is hit the shortest are kept.
    """
    if type(max_hops) is not int or max_hops < 1:
        raise ValueError("max_hops must be a positive integer.")
    if type(limit) is not int or limit < 1:
        raise ValueError("Path limit must be a positive integer.")
    max_hops = min(max_hops, max(1, graph.number_of_nodes() - 1))
    to_target = nx.single_source_shortest_path_length(
        graph.reverse(copy=False), target, cutoff=max_hops
    )
    if start not in to_target:
        return []
    if start == target:
        return [[start]]
    paths = []
    exhausted = object()
    for length in range(to_target[start], max_hops + 1):
        if len(paths) >= limit:
            break
        # Explicit stack avoids Python's recursion limit on long valid paths.
        path, on_path = [start], {start}
        stack = [iter(graph.successors(start))]
        while stack and len(paths) < limit:
            nxt = next(stack[-1], exhausted)
            if nxt is exhausted:
                stack.pop()
                on_path.remove(path.pop())
                continue
            remaining = length - len(path)
            dist = to_target.get(nxt)
            if nxt in on_path or dist is None or dist > remaining:
                continue
            if nxt == target:
                if remaining == 0:
                    paths.append([*path, nxt])
                continue
            if remaining > 0:
                path.append(nxt)
                on_path.add(nxt)
                stack.append(iter(graph.successors(nxt)))
    return paths


def choke_points(graph, start):
    """Hosts that every path from start must pass through to reach some other host.

    Uses the dominator tree: if host D immediately dominates host T (and D is not
    the start), then T can only be reached by going through D.
    """
    dominators = nx.immediate_dominators(graph, start)
    guarded = {}
    for node, dom in dominators.items():
        if node != start and dom != start:
            guarded.setdefault(dom, []).append(node)
    return {dom: sorted(nodes) for dom, nodes in guarded.items()}


CENTRALITY_SAMPLE = 64


def key_nodes(graph, top=5):
    """Hosts ranked by betweenness centrality (how often they sit on shortest paths).

    Exact for small graphs; above CENTRALITY_SAMPLE hosts it is estimated from
    that many sampled source hosts (fixed seed, so results are repeatable).
    """
    n = graph.number_of_nodes()
    k = CENTRALITY_SAMPLE if n > CENTRALITY_SAMPLE else None
    scores = nx.betweenness_centrality(graph, k=k, seed=0)
    ranked = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    return [(node, score) for node, score in ranked[:top] if score > 0]


def critical_targets(graph):
    return [node for node, data in graph.nodes(data=True) if data.get("critical")]


def analyze(graph, start, max_hops=4):
    """Collect every result the CLI and visualizer need into one dict."""
    if start not in graph:
        raise ValueError(f"Start host {start} is not in the network data.")
    if type(max_hops) is not int or max_hops < 1:
        raise ValueError("max_hops must be a positive integer.")

    reachable = reachable_hosts(graph, start)
    targets = critical_targets(graph)
    target_paths = {
        target: paths_to(graph, start, target, max_hops, limit=PATH_LIMIT + 1)
        for target in targets
        if target in reachable
    }
    truncated = {target: len(paths) > PATH_LIMIT for target, paths in target_paths.items()}
    target_paths = {target: paths[:PATH_LIMIT] for target, paths in target_paths.items()}
    return {
        "start": start,
        "host_count": graph.number_of_nodes(),
        "edge_count": graph.number_of_edges(),
        "reachable": reachable,
        "unreachable": sorted(set(graph.nodes) - set(reachable) - {start}),
        "critical_targets": targets,
        "target_paths": target_paths,
        "paths_truncated": truncated,
        "max_hops": max_hops,
        "path_limit": PATH_LIMIT,
        "warnings": graph.graph.get("warnings", []),
        "choke_points": choke_points(graph, start),
        "key_nodes": key_nodes(graph),
    }


def compare(before, after, before_graph=None, after_graph=None):
    """Compare analyses; supply both graphs to include per-connection service changes."""
    if (before_graph is None) != (after_graph is None):
        raise ValueError("Supply both before and after graphs for service comparison.")
    lost = sorted(set(before["reachable"]) - set(after["reachable"]))
    gained = sorted(set(after["reachable"]) - set(before["reachable"]))
    hop_changes = {
        host: (before["reachable"][host], after["reachable"][host])
        for host in set(before["reachable"]) & set(after["reachable"])
        if before["reachable"][host] != after["reachable"][host]
    }
    target_changes = {}
    for target in sorted(set(before["critical_targets"]) | set(after["critical_targets"])):
        b = len(before["target_paths"].get(target, []))
        a = len(after["target_paths"].get(target, []))
        if a != b or before.get("paths_truncated", {}).get(target, False) != after.get("paths_truncated", {}).get(target, False):
            target_changes[target] = (b, a)
    service_changes = []
    if before_graph is not None:
        for src, dst in sorted(set(before_graph.edges) | set(after_graph.edges)):
            def services(graph):
                edge = graph.get_edge_data(src, dst, {})
                reasons = edge.get("reasons", [])
                return {
                    (p["port"], p.get("proto", "tcp")): dict(p, reason=reasons[i] if i < len(reasons) else "")
                    for i, p in enumerate(edge.get("services", []))
                }
            old, new = services(before_graph), services(after_graph)
            removed = [old[key] for key in sorted(old.keys() - new.keys())]
            added = [new[key] for key in sorted(new.keys() - old.keys())]
            for service in removed:
                service["after_reason"] = explain_connection(after_graph, src, dst, service["port"], service.get("proto", "tcp"))
            for service in added:
                service["before_reason"] = explain_connection(before_graph, src, dst, service["port"], service.get("proto", "tcp"))
            if added or removed:
                service_changes.append({"source": src, "destination": dst, "added": added, "removed": removed})
    return {
        "edges": (before["edge_count"], after["edge_count"]),
        "reachable_count": (len(before["reachable"]), len(after["reachable"])),
        "no_longer_reachable": lost,
        "newly_reachable": gained,
        "hop_changes": dict(sorted(hop_changes.items())),
        "target_path_counts": target_changes,
        "target_path_truncation": {
            target: (before.get("paths_truncated", {}).get(target, False), after.get("paths_truncated", {}).get(target, False))
            for target in target_changes
        },
        "service_changes": service_changes,
        "services_compared": before_graph is not None,
    }
