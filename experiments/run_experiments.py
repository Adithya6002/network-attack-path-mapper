"""Broader experiments: larger synthetic networks, four firewall policies, and a
comparison with two common approaches (single-vantage scan, zone-level rule review).

Run from the project folder:
    python -m experiments.run_experiments
Writes experiments/results/{comparison,scaling,policy_change}.csv and summary.md.
"""

import csv
import random
import statistics
import time
from pathlib import Path

from analyzer.graph import build_graph
from analyzer.paths import analyze, compare
from experiments.baselines import single_vantage, zone_level
from experiments.generate import generate_network, policies

OUT = Path(__file__).resolve().parent / "results"
COMPARISON_SIZES = [100, 250, 500]
SCALING_SIZES = [50, 100, 250, 500, 1000]
SEEDS = [0, 1, 2]
STARTS_PER_NETWORK = 5


def user_hosts(network):
    return [h["ip"] for h in network["hosts"] if h["role"] == "user"]


DESIGNS = {"mixed": False, "separated": True}  # file servers share / don't share DB subnets


def comparison_rows():
    for design, separate in DESIGNS.items():
        yield from _comparison_rows(design, separate)


def _comparison_rows(design, separate):
    for n in COMPARISON_SIZES:
        for seed in SEEDS:
            net = generate_network(n, subnets_per_zone=2, seed=seed, separate_fileservers=separate)
            starts = random.Random(seed).sample(user_hosts(net), STARTS_PER_NETWORK)
            for name, fw in policies(net).items():
                graph = build_graph(net, fw)
                critical = {v for v, d in graph.nodes(data=True) if d["critical"]}
                files = {v for v, d in graph.nodes(data=True) if d["role"] == "fileserver"}
                for start in starts:
                    result = analyze(graph, start, max_hops=4)
                    ours = set(result["reachable"])
                    sv = single_vantage(graph, start)
                    direct = zone_level(net, fw, start, transitive=False)
                    zl = zone_level(net, fw, start)
                    exposed = ours & critical
                    hops = [result["reachable"][c] for c in exposed]
                    yield {
                        "design": design,
                        "hosts": len(net["hosts"]), "seed": seed, "policy": name, "start": start,
                        "critical_total": len(critical),
                        "ours_exposed_critical": len(exposed),
                        "ours_exposed_fileservers": len(exposed & files),
                        "ours_min_hops_to_critical": min(hops) if hops else "",
                        "ours_critical_within_2_hops": sum(1 for h in hops if h <= 2),
                        "ours_multi_hop_only_critical": sum(1 for h in hops if h > 1),
                        "ours_choke_points": len(result["choke_points"]),
                        "scan_exposed_critical": len(sv & critical),
                        "scan_missed_critical": len(exposed - sv),
                        "direct_exposed_critical": len(direct & critical),
                        "direct_missed_critical": len(exposed - direct),
                        "direct_false_alarm_critical": len((direct & critical) - ours),
                        "zone_exposed_critical": len(zl & critical),
                        "zone_false_alarm_critical": len((zl & critical) - ours),
                        "zone_missed_critical": len(exposed - zl),
                    }


def scaling_rows():
    for n in SCALING_SIZES:
        net = generate_network(n, subnets_per_zone=2 if n <= 500 else 4, seed=0)
        start = user_hosts(net)[0]
        for name, fw in policies(net).items():
            t0 = time.perf_counter()
            graph = build_graph(net, fw)
            t1 = time.perf_counter()
            analyze(graph, start, max_hops=4)
            t2 = time.perf_counter()
            yield {
                "hosts": len(net["hosts"]), "policy": name,
                "edges": graph.number_of_edges(),
                "build_s": round(t1 - t0, 3), "analyze_s": round(t2 - t1, 3),
                "total_s": round(t2 - t0, 3),
            }


def policy_change_rows():
    """The tool's before/after comparison applied to every pair of consecutive policies."""
    order = ["flat", "permissive", "tiered+misconfig", "tiered"]
    for seed in SEEDS:
        net = generate_network(250, subnets_per_zone=2, seed=seed)
        start = user_hosts(net)[0]
        pols = policies(net)
        results = {p: analyze(build_graph(net, pols[p]), start) for p in order}
        for before, after in zip(order, order[1:]):
            diff = compare(results[before], results[after])
            crit_b = sum(1 for c in results[before]["critical_targets"] if c in results[before]["reachable"])
            crit_a = sum(1 for c in results[after]["critical_targets"] if c in results[after]["reachable"])
            yield {
                "seed": seed, "before": before, "after": after,
                "edges_before": diff["edges"][0], "edges_after": diff["edges"][1],
                "reachable_before": diff["reachable_count"][0], "reachable_after": diff["reachable_count"][1],
                "critical_reachable_before": crit_b, "critical_reachable_after": crit_a,
                "hosts_lost": len(diff["no_longer_reachable"]), "hosts_gained": len(diff["newly_reachable"]),
            }


def write_csv(path, rows):
    rows = list(rows)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return rows


def summarize(comp, scale, change):
    lines = ["# Experiment summary", ""]
    lines += [
        f"Comparison runs: {len(comp)} (designs {list(DESIGNS)}, sizes {COMPARISON_SIZES}, "
        f"seeds {SEEDS}, {STARTS_PER_NETWORK} start hosts each, 4 policies).", "",
        "## Critical hosts exposed: tool vs. common approaches (mean per run)", "",
        "| Design | Policy | Critical total | Tool: exposed | (file servers) | within 2 hops | min hops | "
        "Scan: seen / missed | Direct rule review: flagged / missed | "
        "Zone review: flagged / false alarms |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for design, policy in [(d, p) for d in DESIGNS for p in policies(generate_network(50))]:
        rows = [r for r in comp if r["policy"] == policy and r["design"] == design]
        m = lambda k: statistics.mean(r[k] for r in rows)  # noqa: E731
        hops = [r["ours_min_hops_to_critical"] for r in rows if r["ours_min_hops_to_critical"] != ""]
        lines.append(
            f"| {design} | {policy} | {m('critical_total'):.1f} | {m('ours_exposed_critical'):.1f} | "
            f"{m('ours_exposed_fileservers'):.1f} | {m('ours_critical_within_2_hops'):.1f} | "
            f"{statistics.mean(hops) if hops else float('nan'):.1f} | "
            f"{m('scan_exposed_critical'):.1f} / {m('scan_missed_critical'):.1f} | "
            f"{m('direct_exposed_critical'):.1f} / {m('direct_missed_critical'):.1f} | "
            f"{m('zone_exposed_critical'):.1f} / {m('zone_false_alarm_critical'):.1f} |"
        )
    lines += ["", "## Running time (seed 0)", "", "| Hosts | Policy | Edges | Build (s) | Analyze (s) | Total (s) |",
              "|---|---|---|---|---|---|"]
    lines += [f"| {r['hosts']} | {r['policy']} | {r['edges']} | {r['build_s']} | {r['analyze_s']} | {r['total_s']} |"
              for r in scale]
    lines += ["", "## Policy changes (250 hosts, mean over seeds)", "",
              "| Change | Edges | Reachable hosts | Critical reachable |", "|---|---|---|---|"]
    for before, after in dict.fromkeys((r["before"], r["after"]) for r in change):
        rows = [r for r in change if r["before"] == before and r["after"] == after]
        m = lambda k: statistics.mean(r[k] for r in rows)  # noqa: E731
        lines.append(
            f"| {before} -> {after} | {m('edges_before'):.0f} -> {m('edges_after'):.0f} | "
            f"{m('reachable_before'):.0f} -> {m('reachable_after'):.0f} | "
            f"{m('critical_reachable_before'):.0f} -> {m('critical_reachable_after'):.0f} |"
        )
    return "\n".join(lines) + "\n"


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    t = time.perf_counter()
    comp = write_csv(OUT / "comparison.csv", comparison_rows())
    print(f"comparison: {len(comp)} runs ({time.perf_counter() - t:.0f}s)")
    scale = write_csv(OUT / "scaling.csv", scaling_rows())
    print(f"scaling: {len(scale)} runs ({time.perf_counter() - t:.0f}s)")
    change = write_csv(OUT / "policy_change.csv", policy_change_rows())
    print(f"policy change: {len(change)} runs ({time.perf_counter() - t:.0f}s)")
    summary = summarize(comp, scale, change)
    (OUT / "summary.md").write_text(summary, encoding="utf-8")
    print(summary)


if __name__ == "__main__":
    main()
