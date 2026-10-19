"""Render the host graph and highlighted paths as an interactive HTML page."""

from pathlib import Path

from pyvis.network import Network

from analyzer.graph import service_label

SUBNET_COLORS = ["#4C78A8", "#59A14F", "#B07AA1", "#9C755F", "#76B7B2", "#EDC948"]
START_COLOR = "#E15759"
CRITICAL_COLOR = "#F28E2B"
PATH_EDGE_COLOR = "#E15759"
DEFAULT_EDGE_COLOR = "#BBBBBB"


def _path_edges(result):
    edges = set()
    for paths in result["target_paths"].values():
        for path in paths:
            edges.update(zip(path, path[1:]))
    return edges


def _header(title, subnet_color):
    swatch = '<span style="display:inline-block;width:12px;height:12px;background:{};margin:0 4px 0 12px;border-radius:50%"></span>{}'
    items = [swatch.format(START_COLOR, "start host"), swatch.format(CRITICAL_COLOR, "critical host")]
    items += [swatch.format(color, name) for name, color in subnet_color.items()]
    return (
        f'<div style="font-family:sans-serif;padding:8px 12px">'
        f'<h2 style="margin:0 0 6px">{title}</h2>'
        f'<div style="font-size:13px">{"".join(items)}'
        f'<span style="margin-left:16px">red edges = paths to critical hosts, '
        f'dashed = crosses the firewall</span></div></div>'
    )


def render(graph, result, out_path, title="Network Attack Path Mapper"):
    """Write an HTML visualization. Edges on paths to critical hosts are highlighted."""
    net = Network(height="800px", width="100%", directed=True, cdn_resources="remote")
    net.barnes_hut(gravity=-6000, spring_length=180)

    subnets = sorted({data["subnet"] for _, data in graph.nodes(data=True)})
    subnet_color = {
        name: SUBNET_COLORS[i % len(SUBNET_COLORS)] for i, name in enumerate(subnets)
    }
    start = result["start"]
    reachable = result["reachable"]
    highlighted = _path_edges(result)

    for node, data in graph.nodes(data=True):
        label = data["hostname"] or node
        services = ", ".join(service_label(p) for p in data["ports"]) or "no open ports"
        hops = "start" if node == start else reachable.get(node, "unreachable")
        tooltip = "\n".join([
            f"{node} ({data['hostname'] or 'no hostname'})",
            f"Subnet: {data['subnet']}",
            f"Role: {data['role'] or '-'}",
            f"OS: {data['os'] or '-'}",
            f"Hops from start: {hops}",
            f"Services: {services}",
        ])
        if node == start:
            color, shape = START_COLOR, "star"
        elif data["critical"]:
            color, shape = CRITICAL_COLOR, "diamond"
        else:
            color, shape = subnet_color[data["subnet"]], "dot"
        net.add_node(
            node,
            label=f"{label}\n{node}",
            title=tooltip,
            color=color,
            shape=shape,
            size=28 if node == start or data["critical"] else 20,
        )

    for src, dst, data in graph.edges(data=True):
        on_path = (src, dst) in highlighted
        net.add_edge(
            src,
            dst,
            title=", ".join(service_label(s) for s in data["services"]),
            color=PATH_EDGE_COLOR if on_path else DEFAULT_EDGE_COLOR,
            width=3 if on_path else 1,
            dashes=not data["same_segment"],
        )

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # pyvis's own heading option renders twice, so the header is injected here.
    html = net.generate_html().replace("<body>", "<body>" + _header(title, subnet_color), 1)
    # Explicit UTF-8 avoids pyvis's platform-default encoding on Windows.
    out_path.write_text(html, encoding="utf-8")
    return out_path
