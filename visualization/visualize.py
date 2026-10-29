"""Offline interactive reports with bounded graph displays and full path details."""

import json
from html import escape
from pathlib import Path

import pyvis
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pyvis.network import Network

from analyzer.graph import service_label

SUBNET_COLORS = ["#4C78A8", "#59A14F", "#B07AA1", "#9C755F", "#76B7B2", "#EDC948"]
START_COLOR, CRITICAL_COLOR = "#E15759", "#F28E2B"
TEMPLATES = Path(__file__).parent / "templates"


def _environment():
    return Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html"]),
                       trim_blocks=True, lstrip_blocks=True)


def _path_edges(result):
    return {edge for paths in result["target_paths"].values() for path in paths for edge in zip(path, path[1:])}


def _write(path, html):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return path


def render(graph, result, out_path, title="Network Attack Path Mapper", max_edges=1500):
    """Render at most max_edges connections; analysis/path details remain complete."""
    if type(max_edges) is not int or max_edges < 1:
        raise ValueError("Maximum visual edges must be a positive integer.")
    net = Network(height="680px", width="100%", directed=True)
    net.barnes_hut(gravity=-6000, spring_length=180)
    if graph.number_of_nodes() > 100:
        net.toggle_physics(False)
    subnets = sorted({data["subnet"] for _, data in graph.nodes(data=True)})
    colors = {name: SUBNET_COLORS[i % len(SUBNET_COLORS)] for i, name in enumerate(subnets)}
    start, highlighted = result["start"], _path_edges(result)
    positions = dict.fromkeys(subnets, 0)
    for node, data in graph.nodes(data=True):
        label = data["hostname"] or node
        color = START_COLOR if node == start else CRITICAL_COLOR if data["critical"] else colors[data["subnet"]]
        tooltip = "\n".join([
            f"{node} ({data['hostname'] or 'no hostname'})", f"Subnet: {data['subnet']}",
            f"Role: {data['role'] or '-'}", f"OS: {data['os'] or '-'}",
            f"Hops from start: {'start' if node == start else result['reachable'].get(node, 'unreachable')}",
            "Services: " + (", ".join(service_label(p) for p in data["ports"]) or "none observed"),
        ])
        index = positions[data["subnet"]]
        positions[data["subnet"]] += 1
        net.add_node(node, label=f"{label}\n{node}", title=escape(tooltip).replace("\n", "<br>"),
                     color=color, shape="star" if node == start else "diamond" if data["critical"] else "dot",
                     size=28 if node == start or data["critical"] else 20, subnet=data["subnet"],
                     x=subnets.index(data["subnet"]) * 650 + (index % 8) * 65, y=(index // 8) * 85)
    # Prioritize path and start-host edges, then fill the remaining display budget.
    selected = {}
    for edges in (sorted(highlighted), graph.out_edges(start), graph.edges):
        for src, dst in edges:
            if len(selected) >= max_edges:
                break
            selected[src, dst] = graph.edges[src, dst]
    for (src, dst), data in selected.items():
        services = [dict(p, reason=r) for p, r in zip(data["services"], data["reasons"])]
        tooltip = "\n".join(f"{service_label(p)}: {p['reason']}" for p in services)
        net.add_edge(src, dst, id=f"{src}->{dst}", title=escape(tooltip).replace("\n", "<br>"), services=services,
                     color=START_COLOR if (src, dst) in highlighted else "#B8C3D1",
                     width=3 if (src, dst) in highlighted else 1, dashes=not data["same_segment"])
    details = [{"source": src, "destination": dst,
                "services": [dict(p, reason=r) for p, r in zip(graph.edges[src, dst]["services"], graph.edges[src, dst]["reasons"])]}
               for src, dst in sorted(highlighted)]
    assets = Path(pyvis.__file__).parent / "templates" / "lib" / "vis-9.1.2"
    options = json.loads(net.options.to_json())
    options["layout"] = {"randomSeed": 0}
    html = _environment().get_template("graph.html").render(
        title=title, nodes=net.nodes, edges=net.edges, options=options,
        result=result, path_details=details, subnets=subnets, colors=colors,
        vis_js=(assets / "vis-network.min.js").read_text(encoding="utf-8"),
        vis_css=(assets / "vis-network.css").read_text(encoding="utf-8"),
    )
    return _write(out_path, html)


def render_comparison(diff, out_path):
    """Side-by-side reports with synchronized filters and service deltas."""
    html = _environment().get_template("comparison.html").render(diff=diff)
    return _write(out_path, html)
