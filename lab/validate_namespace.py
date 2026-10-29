"""Validate complete real namespace measurements against the current model.

python lab/validate_namespace.py evidence/namespace_lab_2026-10-28
Unknown, duplicate, missing or infrastructure-error observations fail validation.
"""

import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from analyzer.graph import build_graph, is_allowed, subnet_of  # noqa: E402
from analyzer.paths import analyze  # noqa: E402
from lab.compare_results import confusion  # noqa: E402


def evaluate(folder):
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    if not manifest.get("completed"):
        raise ValueError("Lab run is incomplete; partial evidence cannot establish validation.")
    networks = {}
    graphs = {}
    for label in manifest["policies"]:
        if label not in ("flat", "segmented", "hardened"):
            raise ValueError(f"Unknown lab policy {label!r}.")
        networks[label] = json.loads((folder / f"{label}.json").read_text(encoding="utf-8"))
        graphs[label] = build_graph(networks[label])
    expected = {
        (label, src["ip"], dst["ip"], port, proto)
        for label, net in networks.items() for src in net["hosts"] for dst in net["hosts"]
        if src["ip"] != dst["ip"] for port, proto in manifest["probes"]
    }
    with (folder / "measurements.csv").open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    seen, groups, mismatches = set(), {}, []
    for row in rows:
        label, src, dst, proto = (row[k] for k in ("policy", "source", "destination", "proto"))
        port = int(row["port"])
        key = label, src, dst, port, proto
        if key not in expected or key in seen:
            raise ValueError(f"Unknown or duplicate measurement {key}.")
        seen.add(key)
        if row["result"] not in ("open", "refused", "timeout"):
            raise ValueError(f"Infrastructure error or unknown observation: {row}.")
        net, graph = networks[label], graphs[label]
        source_subnet = subnet_of(src, net["subnets"])
        same = source_subnet is not None and source_subnet == subnet_of(dst, net["subnets"])
        passes = same or is_allowed(net["firewall"], src, dst, port, proto)
        target = next(h for h in net["hosts"] if h["ip"] == dst)
        if "firewall" in target:
            passes = passes and is_allowed(target["firewall"], src, dst, port, proto)
        services = graph.get_edge_data(src, dst, {}).get("services", [])
        listening = any(p["port"] == port and p.get("proto", "tcp") == proto for p in services)
        real_pass = row["result"] in ("open", "refused")
        real_service = row["result"] == "open"
        for check, predicted, actual in (("firewall", passes, real_pass), ("service", listening, real_service)):
            groups.setdefault((label, proto, check), []).append((predicted, actual))
        if passes != real_pass or listening != real_service:
            mismatches.append(dict(row, predicted_pass=passes, predicted_service=listening))
    if seen != expected:
        raise ValueError(f"Missing {len(expected - seen)} required measurements; observed {len(seen)}/{len(expected)}.")
    lines = ["# Expanded Linux namespace lab validation", "",
             f"{len(next(iter(networks.values()))['hosts'])} endpoint namespaces, {len(next(iter(networks.values()))['subnets'])} subnets, "
             f"{len(networks)} policies; **{len(rows)} measured connections**.", "",
             "These are real TCP handshakes and UDP echo probes on a single shared Linux kernel. TCP listeners simulate service ports; they do not implement SSH, HTTPS or PostgreSQL.",
             "UDP probes target a known running echo listener; closed UDP ports are outside this experiment.", "",
             "| Policy | Protocol | Check | Tests | TP | TN | FP | FN | Accuracy |",
             "|---|---|---|---|---|---|---|---|---|"]
    for (label, proto, check), pairs in groups.items():
        counts, accuracy = confusion(pairs)
        lines.append(f"| {label} | {proto} | {check} | {len(pairs)} | {counts['TP']} | {counts['TN']} | "
                     f"{counts['FP']} | {counts['FN']} | {accuracy:.1%} |")
    lines += ["", f"**Mismatched observations: {len(mismatches)}/{len(rows)}.**", "",
              "All expected source/destination/port/protocol combinations were present exactly once; unknown/error observations are rejected.",
              "This case study does not establish universal accuracy, independent operating-system behavior, exploitability or a TRL upgrade.",
              "The same JSON specification drives the model and deployed rules; socket measurements are observed separately from model predictions.",
              "Raw measurements, policy inputs, platform metadata, and interface/routing/firewall snapshots are retained in this directory.", "",
              "| Policy | Graph edges | Reachable hosts from first user | Reachable critical assets | Min hops to critical asset |",
              "|---|---|---|---|---|"]
    analyses = {}
    for label, graph in graphs.items():
        start = networks[label]["hosts"][0]["ip"]
        result = analyze(graph, start)
        critical = [t for t in result["critical_targets"] if t in result["reachable"]]
        hops = min((result["reachable"][t] for t in critical), default="—")
        lines.append(f"| {label} | {result['edge_count']} | {len(result['reachable'])} | {len(critical)} | {hops} |")
        analyses[label] = result
    if mismatches:
        lines += ["", "## Mismatches", "", "```json", json.dumps(mismatches, indent=2), "```"]
    return {"measurement_count": len(rows), "mismatches": mismatches, "analyses": analyses}, "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    args = parser.parse_args()
    report, markdown = evaluate(args.folder)
    (args.folder / "validation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (args.folder / "validation.md").write_text(markdown, encoding="utf-8")
    print(markdown)
    return 1 if report["mismatches"] else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError) as exc:
        sys.exit(f"Validation failed: {exc}")
