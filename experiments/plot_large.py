"""Presentation figures for repeated benchmarks; error bars show observed min/max."""

import argparse
import csv
import statistics
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import StrMethodFormatter  # noqa: E402

POLICIES = ["flat", "permissive", "tiered", "tiered+misconfig"]
COLORS = ["#2563a6", "#d7752a", "#19846d", "#865fa6"]
MARKERS = ["o", "s", "^", "D"]


def plot(folder):
    with (folder / "runs.csv").open(encoding="utf-8", newline="") as stream:
        all_rows = list(csv.DictReader(stream))
    rows = [r for r in all_rows if r["status"] == "ok"]
    if not rows:
        raise ValueError("No successful benchmark runs to plot.")
    sizes = sorted({int(r["requested_hosts"]) for r in all_rows})
    fig, axes = plt.subplots(1, 2, figsize=(12, 5.3), facecolor="white")
    for policy, color, marker in zip(POLICIES, COLORS, MARKERS):
        groups = [(size, [r for r in rows if int(r["requested_hosts"]) == size and r["policy"] == policy]) for size in sizes]
        groups = [(size, group) for size, group in groups if group]
        if not groups:
            continue
        xs = [size for size, _ in groups]
        times = [[float(r["total_s"]) for r in group] for _, group in groups]
        ys = [statistics.median(values) for values in times]
        errors = [[y - min(values) for y, values in zip(ys, times)], [max(values) - y for y, values in zip(ys, times)]]
        axes[0].errorbar(xs, ys, yerr=errors, color=color, marker=marker, linewidth=2, capsize=4, label=policy)
        memory = [max(float(r["peak_memory_mb"]) for r in group) for _, group in groups]
        axes[1].plot(xs, memory, color=color, marker=marker, linewidth=2, label=policy)
    axes[0].set_title("Analysis time", loc="left", fontweight="bold")
    axes[0].set_ylabel("Build + analysis time (seconds)")
    axes[1].set_title("Maximum measured process memory", loc="left", fontweight="bold")
    axes[1].set_ylabel("Peak worker memory (MiB)")
    for ax in axes:
        ax.set_xlabel("Actual hosts in generated network")
        ax.set_xticks(sizes)
        ax.xaxis.set_major_formatter(StrMethodFormatter("{x:,.0f}"))
        ax.set_ylim(bottom=0)
        ax.grid(axis="y", color="#dce2e8", linewidth=0.8)
        ax.spines[["top", "right"]].set_visible(False)
        ax.set_axisbelow(True)
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", ncol=4, frameon=False, bbox_to_anchor=(0.5, 0.055))
    fig.suptitle("Larger networks require more time and memory", x=0.07, ha="left", fontsize=15, fontweight="bold")
    failed = len(all_rows) - len(rows)
    fig.text(0.07, 0.015, f"Synthetic networks; medians with observed min–max error bars. {len(rows)} successful runs; {failed} resource-limited/failed.\n"
             "Four-hop/50-path cap per critical target; sampled centrality above 64 hosts. Results depend on machine and workload.", fontsize=8, color="#46586b")
    fig.tight_layout(rect=(0.02, 0.13, 0.99, 0.94))
    for extension in ("png", "svg"):
        fig.savefig(folder / f"scalability.{extension}", dpi=180, bbox_inches="tight")
    plt.close(fig)
    return folder / "scalability.png"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    print(plot(parser.parse_args().folder))
