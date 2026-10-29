"""Network Attack Path Mapper - command-line entry point.

Results describe network *reachability*, not confirmed exploitability: an open,
reachable port does not prove a host can be compromised.
"""

import argparse
import json
import shlex
import sys
from pathlib import Path

from analyzer.graph import build_graph, predict_connection, service_label
from analyzer.paths import analyze, compare


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path, data):
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2), encoding="utf-8")


def path_count(count, truncated):
    return f"{count}+" if truncated else str(count)


def label(graph, ip):
    if ip not in graph:
        return ip
    name = graph.nodes[ip]["hostname"]
    return f"{name} ({ip})" if name else ip


def print_report(graph, result):
    start = result["start"]
    print(f"\nStart host: {label(graph, start)}")
    print(f"Graph: {result['host_count']} hosts, {result['edge_count']} reachable-service edges")
    for warning in result.get("warnings", []):
        print(f"Model assumption: {warning}")

    print("\nReachable hosts (min hops):")
    for ip, hops in result["reachable"].items():
        print(f"  {hops} hop(s)  {label(graph, ip)}  [{graph.nodes[ip]['subnet']}]")
    if result["unreachable"]:
        print("Not reachable: " + ", ".join(label(graph, ip) for ip in result["unreachable"]))

    print("\nPaths to critical hosts:")
    for target in result["critical_targets"]:
        paths = result["target_paths"].get(target)
        if target == start:
            print(f"  {label(graph, target)}: already the start host")
            continue
        if not paths:
            status = (f"reachable in {result['reachable'][target]} hops, beyond the {result['max_hops']}-hop display limit"
                      if target in result["reachable"] else "unreachable")
            print(f"  {label(graph, target)}: {status}")
            continue
        count = path_count(len(paths), result["paths_truncated"].get(target, False))
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
    for ip, (b, a) in diff["target_path_counts"].items():
        bt, at = diff["target_path_truncation"][ip]
        print(f"Paths to critical {label(graph, ip)}: {path_count(b, bt)} -> {path_count(a, at)}")
    if diff["services_compared"]:
        print("\nService-level changes (direct source -> destination connections):")
        if not diff["service_changes"]:
            print("  None")
        for change in diff["service_changes"]:
            print(f"  {change['source']} -> {change['destination']}")
            for key in ("removed", "added"):
                for service in change[key]:
                    print(f"    {key}: {service_label(service)}; {service['reason']}")
                    other = "after_reason" if key == "removed" else "before_reason"
                    print(f"      {'Now' if key == 'removed' else 'Previously'}: {service[other]}")


def cmd_scan(args):
    from collector.parser import build_network, parse_nmap_xml
    from collector.scanner import collect_routes, run_nmap, validate_targets

    validate_targets(args.targets)

    if args.xml:
        xml_text = Path(args.xml).read_text(encoding="utf-8")
    else:
        extra = shlex.split(args.nmap_args) if args.nmap_args else None
        print(f"Scanning {', '.join(args.targets)} with nmap ...")
        xml_text = run_nmap(args.targets, extra, args.nmap_path, timeout=args.scan_timeout)

    hosts = parse_nmap_xml(xml_text)
    network = build_network(hosts, args.targets, collect_routes())
    from analyzer.validation import validate_network
    validate_network(network)
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
    if args.explain:
        print("\nWhy connections are allowed:")
        for src, dst, edge in graph.edges(data=True):
            for service, reason in zip(edge["services"], edge["reasons"]):
                print(f"  {src} -> {dst}: {service_label(service)}; {reason}")
    if args.html:
        from visualization.visualize import render
        print(f"\nVisualization: {render(graph, result, args.html, max_edges=args.max_visual_edges)}")
    if args.json:
        report = dict(result, connections=[
            {"source": src, "destination": dst, "services": [dict(p, reason=r) for p, r in zip(edge["services"], edge["reasons"])]}
            for src, dst, edge in graph.edges(data=True)
        ])
        write_json(args.json, report)
        print(f"JSON report:   {args.json}")


def cmd_compare(args):
    network = load_json(args.data)
    before_graph = build_graph(network)
    after_data = load_json(args.after)
    after_graph = (build_graph(after_data) if isinstance(after_data, dict) and "hosts" in after_data
                   else build_graph(network, after_data))
    before = analyze(before_graph, args.start, args.max_hops)
    after = analyze(after_graph, args.start, args.max_hops)

    print("##### BEFORE #####")
    print_report(before_graph, before)
    print("\n##### AFTER #####")
    print_report(after_graph, after)
    diff = compare(before, after, before_graph, after_graph)
    print_comparison(before_graph, diff)
    if args.json:
        write_json(args.json, {"before": before, "after": after, "comparison": diff})

    if args.html_dir:
        from visualization.visualize import render, render_comparison
        out = Path(args.html_dir)
        render(before_graph, before, out / "before.html", "Before firewall change", args.max_visual_edges)
        render(after_graph, after, out / "after.html", "After firewall change", args.max_visual_edges)
        render_comparison(diff, out / "comparison.html")
        print(f"\nComparison dashboard: {out / 'comparison.html'}")


def cmd_recommend(args):
    from analyzer.remediation import recommend

    network = load_json(args.data)
    required = load_json(args.required) if args.required else []
    firewall = load_json(args.firewall) if args.firewall else None
    result = recommend(build_graph(network, firewall), args.start, required, args.limit, args.max_candidates)
    print(f"Evaluated {result['evaluated_candidates']} of {result['candidate_count']} candidate connection blocks.")
    print("Suggestions are independent simulations; required direct service connections are preserved.")
    if not required:
        print("No business connections declared: suggestions may disrupt application dependencies. Use --required to protect them.")
    for i, suggestion in enumerate(result["recommendations"], 1):
        print(f"\n{i}. {suggestion['placement']}: {suggestion['source']} -> {suggestion['destination']}")
        print(f"   Critical hosts protected: {', '.join(suggestion['critical_hosts_protected']) or 'none'}")
        print(f"   Critical hosts moved farther away: {suggestion['critical_hosts_farther']}")
        print(f"   Prepend deny rule: {json.dumps(suggestion['rule'])}")
    if not result["recommendations"]:
        print("No evaluated single connection block improves critical-host reachability or minimum hops.")
    if result["candidates_truncated"]:
        print("Candidate search was capped; increase --max-candidates to explore more.")
    if args.json:
        write_json(args.json, result)


# Same ports, in the same order, as lab/measure.sh, so both lists line up row by row.
MEASURE_PORTS = [22, 80, 443, 445, 5432, 8080]


def cmd_predict(args):
    from analyzer.validation import validate_network

    network = load_json(args.data)
    firewall = load_json(args.firewall) if args.firewall else network.get("firewall", {})
    firewall = firewall.get("firewall", firewall)  # accept a network file or a bare policy
    validate_network(network, firewall)
    hosts = [h["ip"] for h in network["hosts"]]
    names = {h["ip"]: h.get("hostname") or h["ip"] for h in network["hosts"]}
    sources = args.sources or hosts

    rows = [
        (src, dst, port, predict_connection(network, firewall, src, dst, port))
        for src in sources
        for dst in hosts if dst != src
        for port in args.ports
    ]
    current = None
    for src, dst, port, result in rows:
        if src != current:
            current = src
            print(f"\nFrom {names[src]} ({src})   [compare with: bash ~/measure.sh on {names[src]}]")
        print(f"  -> {names[dst]:<12} {dst:<15} port {port:<5} PREDICT {result}")
    counts = {r: sum(1 for *_, x in rows if x == r) for r in ("open", "refused", "timeout")}
    print(f"\n{len(rows)} predictions: {counts['open']} open, {counts['refused']} refused, {counts['timeout']} timeout")

    if args.csv:
        lines = ["policy,source,destination,port,result"]
        lines += [f"{args.label},{s},{d},{p},{r}" for s, d, p, r in rows]
        Path(args.csv).write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"Saved: {args.csv}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Graph-based analysis of potential attack paths.")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Discover lab hosts with nmap and save network.json")
    scan.add_argument("--targets", nargs="+", required=True, help="Private CIDRs, e.g. 192.168.56.0/24")
    scan.add_argument("--out", default="data/scanned.json")
    scan.add_argument("--xml", help="Parse an existing nmap -oX file instead of scanning")
    scan.add_argument("--nmap-args", help='Override nmap options, e.g. "-sV -p-"')
    scan.add_argument("--nmap-path", default="nmap")
    scan.add_argument("--scan-timeout", type=float, default=300, help="Overall Nmap timeout in seconds")
    scan.set_defaults(func=cmd_scan)

    an = sub.add_parser("analyze", help="Build the graph and report paths from a start host")
    an.add_argument("--data", default="data/network.json")
    an.add_argument("--start", required=True, help="IP of the initial foothold")
    an.add_argument("--firewall", help="Alternate firewall policy JSON to apply")
    an.add_argument("--max-hops", type=int, default=4)
    an.add_argument("--html", default="output/graph.html")
    an.add_argument("--json", help="Also write the analysis as JSON")
    an.add_argument("--explain", action="store_true", help="Print the policy reason for each allowed service")
    an.add_argument("--no-html", action="store_false", dest="html", help="Skip visualization generation")
    an.add_argument("--max-visual-edges", type=int, default=1500, help="Maximum connections displayed in HTML; analysis remains complete")
    an.set_defaults(func=cmd_analyze)

    cmp_ = sub.add_parser("compare", help="Compare paths before/after a firewall change")
    cmp_.add_argument("--data", default="data/network.json")
    cmp_.add_argument("--start", required=True)
    cmp_.add_argument("--after", required=True, help="Firewall policy or complete network JSON to simulate")
    cmp_.add_argument("--max-hops", type=int, default=4)
    cmp_.add_argument("--html-dir", default="output")
    cmp_.add_argument("--json", help="Write before/after analyses and service changes as JSON")
    cmp_.add_argument("--no-html", action="store_false", dest="html_dir", help="Skip visualization generation")
    cmp_.add_argument("--max-visual-edges", type=int, default=1500)
    cmp_.set_defaults(func=cmd_compare)

    pr = sub.add_parser("predict", help="Predict open/refused/timeout for every connection, as lab/measure.sh tests them")
    pr.add_argument("--data", default="data/lab.json")
    pr.add_argument("--firewall", help="Policy JSON to apply (default: the one inside --data)")
    pr.add_argument("--sources", nargs="+", help="Only predict from these source IPs")
    pr.add_argument("--ports", nargs="+", type=int, default=MEASURE_PORTS)
    pr.add_argument("--csv", help="Also save the predictions as CSV (same format as measure.sh)")
    pr.add_argument("--label", default="custom", help="Policy label for the CSV rows")
    pr.set_defaults(func=cmd_predict)

    rec = sub.add_parser("recommend", help="Simulate connection blocks while preserving required services")
    rec.add_argument("--data", default="data/network.json")
    rec.add_argument("--start", required=True)
    rec.add_argument("--firewall", help="Override the network firewall policy before simulating changes")
    rec.add_argument("--required", help="JSON list of required direct source/destination/port/proto connections")
    rec.add_argument("--limit", type=int, default=5)
    rec.add_argument("--max-candidates", type=int, default=200)
    rec.add_argument("--json", help="Write recommendations as JSON")
    rec.set_defaults(func=cmd_recommend)

    args = parser.parse_args(argv)
    try:
        args.func(args)
    except (ValueError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
