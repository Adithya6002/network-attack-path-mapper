"""Reachability and multi-hop path analysis on the host graph."""

import networkx as nx

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
    to_target = nx.single_source_shortest_path_length(
        graph.reverse(copy=False), target, cutoff=max_hops
    )
    if start not in to_target:
        return []
    paths = []

    def extend(path, on_path, remaining):
        node = path[-1]
        if remaining == 0:
            if node == target:
                paths.append(list(path))
            return
        for nxt in graph.successors(node):
            if len(paths) >= limit:
                return
            dist = to_target.get(nxt)
            if nxt in on_path or dist is None or dist > remaining - 1:
                continue
            if nxt == target and remaining > 1:
                continue  # the target may only appear as the last hop
            path.append(nxt)
            on_path.add(nxt)
            extend(path, on_path, remaining - 1)
            on_path.discard(nxt)
            path.pop()

    for length in range(to_target[start], max_hops + 1):
        if len(paths) >= limit:
            break
        extend([start], {start}, length)
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

    reachable = reachable_hosts(graph, start)
    targets = critical_targets(graph)
    target_paths = {
        target: paths_to(graph, start, target, max_hops)
        for target in targets
        if target in reachable
    }
    return {
        "start": start,
        "host_count": graph.number_of_nodes(),
        "edge_count": graph.number_of_edges(),
        "reachable": reachable,
        "unreachable": sorted(set(graph.nodes) - set(reachable) - {start}),
        "critical_targets": targets,
        "target_paths": target_paths,
        "choke_points": choke_points(graph, start),
        "key_nodes": key_nodes(graph),
    }


def compare(before, after):
    """Summarize what changed between two analyze() results."""
    lost = sorted(set(before["reachable"]) - set(after["reachable"]))
    gained = sorted(set(after["reachable"]) - set(before["reachable"]))
    hop_changes = {
        host: (before["reachable"][host], after["reachable"][host])
        for host in set(before["reachable"]) & set(after["reachable"])
        if before["reachable"][host] != after["reachable"][host]
    }
    target_changes = {}
    for target in before["critical_targets"]:
        b = len(before["target_paths"].get(target, []))
        a = len(after["target_paths"].get(target, []))
        if a != b:
            target_changes[target] = (b, a)
    return {
        "edges": (before["edge_count"], after["edge_count"]),
        "reachable_count": (len(before["reachable"]), len(after["reachable"])),
        "no_longer_reachable": lost,
        "newly_reachable": gained,
        "hop_changes": dict(sorted(hop_changes.items())),
        "target_path_counts": target_changes,
    }
