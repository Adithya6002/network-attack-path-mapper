"""Figures for the report, from experiments/results/*.csv.

    python -m experiments.plot_results
Writes experiments/results/fig_exposure.png and fig_runtime.png.
"""

import csv
import statistics
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

RESULTS = Path(__file__).resolve().parent / "results"
POLICIES = ["flat", "permissive", "tiered", "tiered+misconfig"]
# Validated categorical slots 1-4 (dataviz reference palette, light mode).
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]
INK, INK_2, GRID, SURFACE = "#0b0b0b", "#52514e", "#e4e3df", "#fcfcfb"


def read(name):
    with open(RESULTS / name, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def style(ax):
    ax.set_facecolor(SURFACE)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)
    ax.tick_params(colors=INK_2, labelsize=9)
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def exposure_figure():
    rows = read("comparison.csv")
    approaches = [
        ("ours_exposed_critical", "This tool (host-level, multi-hop)"),
        ("scan_exposed_critical", "Network scan from start host"),
        ("direct_exposed_critical", "Direct rule review (zone to zone)"),
        ("zone_exposed_critical", "Zone-level transitive review"),
    ]
    panels = [
        ("separated", "File servers in their own subnet"),
        ("mixed", "File servers share subnets with databases"),
    ]
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.8), facecolor=SURFACE, sharey=True)
    width = 0.19
    for ax, (design, subtitle) in zip(axes, panels):
        style(ax)
        sel = [r for r in rows if r["design"] == design]
        for i, (key, label) in enumerate(approaches):
            means = [statistics.mean(float(r[key]) for r in sel if r["policy"] == p) for p in POLICIES]
            xs = [x + (i - 1.5) * (width + 0.01) for x in range(len(POLICIES))]
            ax.bar(xs, means, width, color=SERIES[i], label=label, edgecolor=SURFACE, linewidth=1)
            for x, v in zip(xs, means):
                if v == 0:
                    ax.text(x, 0.4, "0", ha="center", va="bottom", fontsize=8, color=INK_2)
        total = statistics.mean(float(r["critical_total"]) for r in sel)
        ax.axhline(total, color=INK_2, linewidth=1, linestyle=(0, (4, 3)))
        ax.text(-0.45, total + 0.8, f"all critical hosts ({total:.0f})", color=INK_2, fontsize=8.5)
        ax.set_xticks(range(len(POLICIES)), POLICIES)
        ax.set_title(subtitle, loc="left", color=INK, fontsize=10)
        ax.set_ylim(0, total * 1.18)
    axes[0].set_ylabel("Critical hosts judged reachable (mean per run)", color=INK_2, fontsize=9)
    fig.suptitle("Scans and direct rule reviews miss multi-hop exposure; zone reviews over-report "
                 "and can't see the misconfiguration", x=0.01, ha="left", color=INK,
                 fontsize=11.5, fontweight="bold")
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, frameon=False, fontsize=8.5, loc="lower center", ncol=4)
    fig.tight_layout(rect=(0, 0.07, 1, 0.97))
    out = RESULTS / "fig_exposure.png"
    fig.savefig(out, dpi=160)
    return out


def runtime_figure():
    rows = read("scaling.csv")
    fig, ax = plt.subplots(figsize=(7.5, 4.4), facecolor=SURFACE)
    style(ax)
    ax.grid(axis="x", color=GRID, linewidth=0.8)
    for i, policy in enumerate(POLICIES):
        pts = sorted((int(r["hosts"]), float(r["total_s"])) for r in rows if r["policy"] == policy)
        xs, ys = zip(*pts)
        ax.plot(xs, ys, color=SERIES[i], linewidth=2, marker="o", markersize=5,
                label=f"{policy} ({ys[-1]:.1f} s at {xs[-1]:,} hosts)")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xticks([50, 100, 250, 500, 1000], ["50", "100", "250", "500", "1000"])
    ax.set_xlim(40, 1250)
    ax.set_xlabel("Hosts in network", color=INK_2, fontsize=9)
    ax.set_ylabel("Build + full analysis time (s, log scale)", color=INK_2, fontsize=9)
    ax.set_title("A 1,000-host network is analysed in under 15 s under every policy",
                 loc="left", color=INK, fontsize=11.5, fontweight="bold")
    ax.legend(frameon=False, fontsize=8.5, loc="upper left")
    fig.tight_layout()
    out = RESULTS / "fig_runtime.png"
    fig.savefig(out, dpi=160)
    return out


if __name__ == "__main__":
    print(exposure_figure())
    print(runtime_figure())
