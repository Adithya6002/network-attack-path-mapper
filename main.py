"""Network Attack Path Mapper - command-line entry point.

Results describe network *reachability*, not confirmed exploitability: an open,
reachable port does not prove a host can be compromised.
"""

import argparse
import json
import sys
from pathlib import Path

from analyzer.graph import build_graph, service_label
from analyzer.paths import PATH_LIMIT, analyze, compare


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def label(graph, ip):
    name = graph.nodes[ip]["hostname"]
    return f"{name} ({ip})" if name else ip


def print_report(graph, result):
    start = result["start"]
    print(f"\nStart host: {label(graph, start)}")
    print(f"Graph: {result['host_count']} hosts, {result['edge_count']} reachable-service edges")

    print("\nReachable hosts (min hops):")
    for ip, hops in result["reachable"].items():
        print(f"  {hops} hop(s)  {label(graph, ip)}  [{graph.nodes[ip]['subnet']}]")
    if result["unreachable"]:
        print("Not reachable: " + ", ".join(label(graph, ip) for ip in result["unreachable"]))

    print("\nPaths to critical hosts:")
    for target in result["critical_targets"]:
        paths = result["target_paths"].get(target)
        if not paths:
            print(f"  {label(graph, target)}: no path within hop limit")
            continue
        count = f"{len(paths)}+" if len(paths) >= PATH_LIMIT else str(len(paths))
        print(f"  {label(graph, target)}: {count} path(s), shortest {len(paths[0]) - 1} hop(s)")
        for path in paths[:3]:
            hops = []
            for src, dst in zip(path, path[1:]):
                svc = ", ".join(service_label(s) for s in graph.edges[src, dst]["services"][:3])
                hops.append(f"{graph.nodes[dst]['hostname'] or dst} via [{svc}]")
            print("    " + " -> ".join([graph.nodes[start]["hostname"] or start, *hops]))

    if result["choke_points"]:
        print("\nChoke points (only way in to the listed hosts):")
        for dom, guarded in result["choke_points"].items():
            print(f"  {label(graph, dom)} guards " + ", ".join(label(graph, g) for g in guarded))

    if result["key_nodes"]:
        print("\nKey intermediate hosts (betweenness centrality):")
        for ip, score in result["key_nodes"]:
            print(f"  {score:.3f}  {label(graph, ip)}")


def print_comparison(graph, diff):
    print("\n=== Before vs after firewall change ===")
    print(f"Edges:           {diff['edges'][0]} -> {diff['edges'][1]}")
    print(f"Reachable hosts: {diff['reachable_count'][0]} -> {diff['reachable_count'][1]}")
    if diff["no_longer_reachable"]:
        print("No longer reachable: " + ", ".join(label(graph, ip) for ip in diff["no_longer_reachable"]))
    if diff["newly_reachable"]:
        print("Newly reachable:     " + ", ".join(label(graph, ip) for ip in diff["newly_reachable"]))
    for ip, (b, a) in diff["hop_changes"].items():
        print(f"Hop count changed:   {label(graph, ip)} {b} -> {a}")
    capped = lambda n: f"{n}+" if n >= PATH_LIMIT else str(n)  # noqa: E731
    for ip, (b, a) in diff["target_path_counts"].items():
        print(f"Paths to critical {label(graph, ip)}: {capped(b)} -> {capped(a)}")


def cmd_scan(args):
    from collector.parser import build_network, parse_nmap_xml
    from collector.scanner import collect_routes, run_nmap

    if args.xml:
        xml_text = Path(args.xml).read_text(encoding="utf-8")
    else:
        extra = args.nmap_args.split() if args.nmap_args else None
        print(f"Scanning {', '.join(args.targets)} with nmap ...")
        xml_text = run_nmap(args.targets, extra, args.nmap_path)

    hosts = parse_nmap_xml(xml_text)
    network = build_network(hosts, args.targets, collect_routes())
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(network, indent=2), encoding="utf-8")
    print(f"Saved {len(hosts)} host(s) to {args.out}")
    print("Tip: name the subnets, add firewall rules and mark critical hosts in that file.")


def cmd_analyze(args):
    network = load_json(args.data)
    firewall = load_json(args.firewall) if args.firewall else None
    graph = build_graph(network, firewall)
    result = analyze(graph, args.start, args.max_hops)
    print_report(graph, result)
    if args.html:
        from visualization.visualize import render
        print(f"\nVisualization: {render(graph, result, args.html)}")
    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"JSON report:   {args.json}")


def cmd_compare(args):
    network = load_json(args.data)
    before_graph = build_graph(network)
    after_graph = build_graph(network, load_json(args.after))
    before = analyze(before_graph, args.start, args.max_hops)
    after = analyze(after_graph, args.start, args.max_hops)

    print("##### BEFORE #####")
    print_report(before_graph, before)
    print("\n##### AFTER #####")
    print_report(after_graph, after)
    print_comparison(before_graph, compare(before, after))

    if args.html_dir:
        from visualization.visualize import render
        out = Path(args.html_dir)
        render(before_graph, before, out / "before.html", "Before firewall change")
        render(after_graph, after, out / "after.html", "After firewall change")
        print(f"\nVisualizations: {out / 'before.html'}, {out / 'after.html'}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Graph-based analysis of potential attack paths.")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Discover lab hosts with nmap and save network.json")
    scan.add_argument("--targets", nargs="+", required=True, help="Private CIDRs, e.g. 192.168.56.0/24")
    scan.add_argument("--out", default="data/scanned.json")
    scan.add_argument("--xml", help="Parse an existing nmap -oX file instead of scanning")
    scan.add_argument("--nmap-args", help='Override nmap options, e.g. "-sV -p-"')
    scan.add_argument("--nmap-path", default="nmap")
    scan.set_defaults(func=cmd_scan)

    an = sub.add_parser("analyze", help="Build the graph and report paths from a start host")
    an.add_argument("--data", default="data/network.json")
    an.add_argument("--start", required=True, help="IP of the initial foothold")
    an.add_argument("--firewall", help="Alternate firewall policy JSON to apply")
    an.add_argument("--max-hops", type=int, default=4)
    an.add_argument("--html", default="output/graph.html")
    an.add_argument("--json", help="Also write the analysis as JSON")
    an.set_defaults(func=cmd_analyze)

    cmp_ = sub.add_parser("compare", help="Compare paths before/after a firewall change")
    cmp_.add_argument("--data", default="data/network.json")
    cmp_.add_argument("--start", required=True)
    cmp_.add_argument("--after", required=True, help="Firewall policy JSON to simulate")
    cmp_.add_argument("--max-hops", type=int, default=4)
    cmp_.add_argument("--html-dir", default="output")
    cmp_.set_defaults(func=cmd_compare)

    args = parser.parse_args(argv)
    try:
        args.func(args)
    except (ValueError, FileNotFoundError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
