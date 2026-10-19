"""Compare measured lab reachability with the model's predictions (TRL 3 validation).

Usage:
    python lab/compare_results.py data/lab.json evidence/measurements.csv

measurements.csv rows: policy,source,destination,port,result
  policy = "baseline" (firewall in data/lab.json) or "segmented"
           (data/firewall_segmented.json); result = open | refused | timeout

Two predictions are checked for every row:
  1. Firewall decision - does traffic reach the destination host at all?
     model: same subnet, or the policy allows it; lab: open or refused.
  2. Service reachability - can a connection to a listening service be made?
     model: (1) and the port is a known open service; lab: open.
"""

import csv
import json
import math
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from analyzer.graph import is_allowed, subnet_of  # noqa: E402

POLICY_FILES = {"segmented": ROOT / "data" / "firewall_segmented.json"}


def load_policy(network, label):
    if label in POLICY_FILES:
        return json.loads(POLICY_FILES[label].read_text(encoding="utf-8"))
    return network["firewall"]


def predict(network, firewall, src, dst, port):
    subnets = network["subnets"]
    same = subnet_of(src, subnets) is not None and subnet_of(src, subnets) == subnet_of(dst, subnets)
    passes = same or is_allowed(firewall, src, dst, port, "tcp")
    services = {
        p["port"] for h in network["hosts"] if h["ip"] == dst for p in h.get("ports", [])
    }
    return passes, passes and port in services


def _binom_cdf(k, n, p):
    return sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(k + 1))


def exact_ci(k, n, level=0.95):
    """Clopper-Pearson exact two-sided confidence interval for k successes in n."""
    alpha = 1 - level

    def solve(f):  # f is monotone increasing in p; find f(p) = 0 by bisection
        lo, hi = 0.0, 1.0
        for _ in range(60):
            mid = (lo + hi) / 2
            lo, hi = (mid, hi) if f(mid) < 0 else (lo, mid)
        return (lo + hi) / 2

    lower = 0.0 if k == 0 else solve(lambda p: (1 - _binom_cdf(k - 1, n, p)) - alpha / 2)
    upper = 1.0 if k == n else solve(lambda p: alpha / 2 - _binom_cdf(k, n, p))
    return lower, upper


def confusion(pairs):
    c = Counter()
    for predicted, actual in pairs:
        c[("T" if predicted == actual else "F") + ("P" if predicted else "N")] += 1
    total = sum(c.values())
    return c, (c["TP"] + c["TN"]) / total if total else 0.0


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: python lab/compare_results.py <lab.json> <measurements.csv>")
    network = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    rows = list(csv.reader(Path(sys.argv[2]).read_text(encoding="utf-8").splitlines()))
    rows = [r for r in rows if r and r[0] != "policy"]

    by_policy = {}
    mismatches = []
    for policy, src, dst, port, result in rows:
        port = int(port)
        fw = load_policy(network, policy)
        pred_pass, pred_service = predict(network, fw, src, dst, port)
        real_pass = result in ("open", "refused")
        real_service = result == "open"
        by_policy.setdefault(policy, {"fw": [], "svc": []})
        by_policy[policy]["fw"].append((pred_pass, real_pass))
        by_policy[policy]["svc"].append((pred_service, real_service))
        if pred_pass != real_pass or pred_service != real_service:
            mismatches.append((policy, src, dst, port, result, pred_pass, pred_service))

    print("| Policy | Check | Tests | TP | TN | FP | FN | Accuracy | 95% CI (exact) |")
    print("|---|---|---|---|---|---|---|---|---|")
    totals = {"fw": [], "svc": []}

    def row(policy, name, pairs, bold=False):
        c, acc = confusion(pairs)
        n = sum(c.values())
        lo, hi = exact_ci(c["TP"] + c["TN"], n)
        a = f"**{acc:.1%}**" if bold else f"{acc:.1%}"
        print(f"| {policy} | {name} | {n} | {c['TP']} | {c['TN']} | {c['FP']} | {c['FN']} | {a} | {lo:.1%} - {hi:.1%} |")

    for policy, checks in by_policy.items():
        for key, name in (("fw", "Firewall decision"), ("svc", "Service reachability")):
            totals[key].extend(checks[key])
            row(policy, name, checks[key])
    for key, name in (("fw", "Firewall decision"), ("svc", "Service reachability")):
        row("**all**", name, totals[key], bold=True)

    print()
    if mismatches:
        print("Mismatches (policy, source, destination, port, measured, model-passes, model-service):")
        for m in mismatches:
            print("  ", m)
    else:
        print("No mismatches: every measurement matched the model's prediction.")


if __name__ == "__main__":
    main()
