"""Repeated large-network benchmarks in isolated processes with resource limits.

python -m experiments.benchmark_large --sizes 500 1000 2000 --repeats 3
This measures synthetic model scalability, not independently observed accuracy.
"""

import argparse
import csv
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parent.parent
POLICIES = ("flat", "permissive", "tiered", "tiered+misconfig")


def worker(size, policy, seed, subnets):
    from analyzer.graph import build_graph
    from analyzer.paths import analyze
    from experiments.generate import generate_network, policies

    network = generate_network(size, subnets_per_zone=subnets, seed=seed)
    if len(network["hosts"]) != size:
        raise ValueError("Actual generated host count differs from the requested size.")
    firewall = policies(network)[policy]
    digest = hashlib.sha256(json.dumps([network, firewall], sort_keys=True).encode()).hexdigest()
    start = next(h["ip"] for h in network["hosts"] if h["role"] == "user")
    t0 = time.perf_counter()
    graph = build_graph(network, firewall)
    t1 = time.perf_counter()
    result = analyze(graph, start)
    t2 = time.perf_counter()
    if sys.platform == "win32":
        peak_mb = psutil.Process(os.getpid()).memory_info().peak_wset / 1024 ** 2
        memory_method = "worker peak working set"
    else:
        import resource
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        peak_mb = peak / (1024 ** 2 if sys.platform == "darwin" else 1024)
        memory_method = "worker peak RSS"
    return {
        "actual_hosts": graph.number_of_nodes(), "edges": graph.number_of_edges(),
        "firewall_rules": len(firewall["rules"]), "input_sha256": digest,
        "build_s": round(t1 - t0, 6), "analyze_s": round(t2 - t1, 6), "total_s": round(t2 - t0, 6),
        "reachable_hosts": len(result["reachable"]),
        "critical_total": len(result["critical_targets"]),
        "critical_reachable": sum(t in result["reachable"] for t in result["critical_targets"]),
        "targets_with_truncated_paths": sum(result["paths_truncated"].values()),
        "max_hops": result["max_hops"], "path_limit": result["path_limit"],
        "peak_memory_mb": round(peak_mb, 1), "memory_method": memory_method,
    }


def stop_worker(process):
    """Also stop Windows venv redirector children, which hold the actual graph."""
    try:
        children = psutil.Process(process.pid).children(recursive=True)
    except psutil.NoSuchProcess:
        children = []
    for child in reversed(children):
        try:
            child.kill()
        except psutil.NoSuchProcess:
            pass
    if process.poll() is None:
        process.kill()


def run_case(size, policy, seed, repeat, timeout_s, max_memory_mb):
    subnets = max(4, math.ceil(size * 0.45 / 240))
    row = {"requested_hosts": size, "policy": policy, "seed": seed, "repeat": repeat,
           "subnets_per_zone": subnets, "status": "ok", "peak_memory_mb": 0.0,
           "memory_method": "worker-tree RSS sampled every 100 ms",
           "wall_s": 0.0, "error": ""}
    command = [sys.executable, "-m", "experiments.benchmark_large", "--worker", "--sizes", str(size),
               "--policies", policy, "--seeds", str(seed), "--subnets", str(subnets)]
    began = time.perf_counter()
    process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    monitored = psutil.Process(process.pid)
    try:
        while process.poll() is None:
            try:
                # On Windows .venv/python.exe redirects to a child python.exe.
                # Monitor the whole tree so its launcher cannot hide memory use.
                used = sum(p.memory_info().rss for p in [monitored, *monitored.children(recursive=True)]) / 1024 ** 2
                row["peak_memory_mb"] = max(row["peak_memory_mb"], used)
                if used > max_memory_mb:
                    row["status"] = "memory_limit"
                    stop_worker(process)
                    break
            except psutil.NoSuchProcess:
                break
            if time.perf_counter() - began > timeout_s:
                row["status"] = "timeout"
                stop_worker(process)
                break
            time.sleep(0.1)
        stdout, stderr = process.communicate(timeout=10)
    except BaseException:
        stop_worker(process)
        process.communicate()
        raise
    row["wall_s"] = round(time.perf_counter() - began, 3)
    row["peak_memory_mb"] = round(row["peak_memory_mb"], 1)
    if row["status"] == "ok":
        if process.returncode:
            row.update(status="error", error=stderr.strip()[-1500:])
        else:
            try:
                row.update(json.loads(stdout))
            except (ValueError, TypeError) as exc:
                row.update(status="error", error=f"Invalid worker output: {exc}")
    return row


def summarize(rows):
    lines = ["# Large synthetic-network benchmark", "",
             "Synthetic scalability measurements; these are not real-host connectivity validation.", "",
             "| Hosts | Policy | Completed / attempted | Median (s) | Min–max (s) | SD (s) | Peak memory (MiB) |",
             "|---|---|---|---|---|---|---|"]
    for size, policy in dict.fromkeys((r["requested_hosts"], r["policy"]) for r in rows):
        group = [r for r in rows if r["requested_hosts"] == size and r["policy"] == policy]
        good = [r for r in group if r["status"] == "ok"]
        times = [r["total_s"] for r in good]
        memory = max(r["peak_memory_mb"] for r in group)
        metrics = (f"{statistics.median(times):.2f} | {min(times):.2f}–{max(times):.2f} | "
                   f"{statistics.stdev(times) if len(times) > 1 else 0:.2f}" if times else "— | — | —")
        lines.append(f"| {size} | {policy} | {len(good)}/{len(group)} | {metrics} | {memory:.1f} |")
    failed = [r for r in rows if r["status"] != "ok"]
    lines += ["", f"Completed: {len(rows) - len(failed)}/{len(rows)} cases. Resource-limited or failed cases: {len(failed)}.",
              "", "Timing includes graph building and full analyze() (reachability, capped paths, dominators, centrality).",
              "Process startup, input generation, hashing, and JSON printing are excluded from total_s; wall_s includes them.",
              "Centrality is sampled above 64 hosts; critical paths are capped at 50 per target within four hops.",
              "Memory covers the worker interpreter, generated inventory, graph, and analysis; units are MiB (2^20 bytes).",
              "Successful workers report native peak working set (Windows) or peak RSS (Unix); failed workers report sampled process-tree RSS.",
              "Resource enforcement samples the worker and any launcher children every 100 ms; limits may be briefly exceeded between samples.",
              "Repeated runs with one seed measure timing variation for one topology, not variation across network designs.",
              "The generator uses at least four /24 subnets per zone and adds capacity for larger sizes; subnet/rule counts are recorded."]
    if failed:
        lines += ["", "## Resource limits and failures", ""]
        lines += [f"- {r['requested_hosts']} hosts, {r['policy']}, seed {r['seed']}, repeat {r['repeat']}: {r['status']} {r['error']}" for r in failed]
    return "\n".join(lines) + "\n"


def write_results(out, rows):
    fields = list(dict.fromkeys(key for row in rows for key in row))
    with (out / "runs.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    (out / "summary.md").write_text(summarize(rows), encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", type=int, nargs="+", default=[500, 1000, 2000])
    parser.add_argument("--policies", nargs="+", choices=POLICIES, default=list(POLICIES))
    parser.add_argument("--seeds", type=int, nargs="+", default=[0])
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument("--max-memory-mb", type=float, default=2048)
    parser.add_argument("--out", type=Path, default=ROOT / "experiments/results/large_2026-10-28")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--subnets", type=int, default=4, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if any(n < 10 or n > 8000 for n in args.sizes) or args.repeats < 1:
        parser.error("Use sizes from 10 to 8000 and at least one repeat.")
    if not 0 < args.timeout < math.inf or not 0 < args.max_memory_mb < math.inf:
        parser.error("Timeout and memory budget must be positive finite values.")
    if args.worker:
        print(json.dumps(worker(args.sizes[0], args.policies[0], args.seeds[0], args.subnets)))
        return 0
    args.out.mkdir(parents=True, exist_ok=True)
    if (args.out / "runs.csv").exists():
        parser.error("Output already contains runs.csv; choose a new --out to preserve recorded evidence.")
    files = sorted(path for folder in ("analyzer", "collector", "experiments") for path in (ROOT / folder).glob("*.py"))
    fingerprint = hashlib.sha256(b"".join(str(p.relative_to(ROOT)).encode() + p.read_bytes() for p in files)).hexdigest()
    environment = {"created_utc": datetime.now(timezone.utc).isoformat(), "python": sys.version,
                   "platform": platform.platform(), "cpu": platform.processor(), "logical_cpus": psutil.cpu_count(),
                   "total_memory_mb": round(psutil.virtual_memory().total / 1024 ** 2),
                   "source_sha256": fingerprint,
                   "packages": {p: importlib.metadata.version(p) for p in ("networkx", "pyvis", "psutil")},
                   "configuration": {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()}}
    (args.out / "environment.json").write_text(json.dumps(environment, indent=2), encoding="utf-8")
    rows = []
    total = len(args.sizes) * len(args.policies) * len(args.seeds) * args.repeats
    for size in args.sizes:
        for policy in args.policies:
            for seed in args.seeds:
                for repeat in range(1, args.repeats + 1):
                    row = run_case(size, policy, seed, repeat, args.timeout, args.max_memory_mb)
                    rows.append(row)
                    write_results(args.out, rows)
                    print(f"[{len(rows)}/{total}] {size} hosts {policy} seed={seed} repeat={repeat}: "
                          f"{row['status']} total={row.get('total_s', '—')}s peak={row['peak_memory_mb']} MiB", flush=True)
    print(f"Results: {args.out}")
    return 1 if any(r["status"] != "ok" for r in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
