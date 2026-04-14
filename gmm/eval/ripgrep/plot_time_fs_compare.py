#!/usr/bin/env python3
import argparse
import re
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np


# Theme inspired by the cache_ext plotting notebook style.
dark_colors = plt.colormaps["Dark2"].colors
accent_colors = plt.colormaps["Accent"].colors
policy_color = {
    "baseline": dark_colors[0],
    "mru": dark_colors[2],
    "baseline_mglru": dark_colors[1],
    "fifo": dark_colors[3],
    "s3fifo": dark_colors[4],
    "lhd": accent_colors[4],
    "lfu": dark_colors[5],
}

plt.style.use("seaborn-v0_8-whitegrid")
plt.rcParams.update(
    {
        "font.size": 11,
        "axes.titlesize": 13,
        "axes.labelsize": 11,
        "xtick.labelsize": 10,
        "ytick.labelsize": 10,
        "figure.titlesize": 15,
    }
)


def parse_result(path: Path):
    text = path.read_text(encoding="utf-8", errors="ignore")

    blocks = re.split(r"=+\n▶▶▶ \[Progress\] Policy \[", text)
    rows = []
    for block in blocks[1:]:
        header_end = block.find("]")
        if header_end == -1:
            continue
        policy = block[:header_end].strip()

        elapsed_m = re.search(r"Elapsed \(wall clock\) time .*?:\s*([0-9]+):([0-9]+(?:\.[0-9]+)?)", block)
        fs_m = re.search(r"File system inputs:\s*([0-9]+)", block)
        if not elapsed_m or not fs_m:
            continue

        mins = int(elapsed_m.group(1))
        secs = float(elapsed_m.group(2))
        elapsed_seconds = mins * 60.0 + secs
        fs_inputs = int(fs_m.group(1))

        rows.append({
            "policy": policy,
            "elapsed_seconds": elapsed_seconds,
            "fs_inputs": fs_inputs,
        })

    if len(rows) < 2:
        raise ValueError("Could not parse both policy blocks from result file.")

    return rows


def pct_delta(base, new):
    if base == 0:
        return 0.0
    return (base - new) / base * 100.0


def render(rows, out_path: Path):
    by_policy = {r["policy"]: r for r in rows}
    order = ["linux_classic", "mru"]
    data = [by_policy[p] for p in order if p in by_policy]
    if len(data) != 2:
        raise ValueError("Expected linux_classic and mru in result file.")

    labels = [
        "Default (Linux)" if d["policy"] == "linux_classic" else "MRU (cache_ext)"
        for d in data
    ]
    elapsed = [d["elapsed_seconds"] for d in data]
    fs_inputs = [d["fs_inputs"] for d in data]

    fig, axes = plt.subplots(1, 2, figsize=(7.6, 4.8))

    # User-requested palette: blue vs orange.
    colors = ["#1f77b4", "#ff7f0e"]

    x = np.array([0.0, 0.36])
    bar_width = 0.12

    bars_t = axes[0].bar(x, elapsed, color=colors, width=bar_width)
    axes[0].set_xticks(x, labels)
    axes[0].set_xlim(-0.12, 0.48)
    axes[0].set_title("Elapsed Time", fontweight="bold")
    axes[0].set_ylabel("Seconds")
    t_max = max(elapsed)
    axes[0].set_ylim(0, t_max * 1.08)
    axes[0].grid(axis="y", linestyle="--", alpha=0.35)
    for bar, val in zip(bars_t, elapsed):
        axes[0].text(bar.get_x() + bar.get_width() / 2, bar.get_height(), f"{val:.2f}s", ha="center", va="bottom", fontsize=10)
    bars_f = axes[1].bar(x, fs_inputs, color=colors, width=bar_width)
    axes[1].set_xticks(x, labels)
    axes[1].set_xlim(-0.12, 0.48)
    axes[1].set_title("File System Inputs", fontweight="bold")
    axes[1].set_ylabel("Input blocks")
    f_max = max(fs_inputs)
    axes[1].set_ylim(0, f_max * 1.08)
    axes[1].grid(axis="y", linestyle="--", alpha=0.35)
    for bar, val in zip(bars_f, fs_inputs):
        axes[1].text(bar.get_x() + bar.get_width() / 2, bar.get_height(), f"{val}", ha="center", va="bottom", fontsize=10)
    fig.suptitle("Ripgrep Benchmark: Default vs MRU", fontweight="bold")
    fig.tight_layout()
    fig.savefig(out_path, dpi=220, bbox_inches="tight")

    # Save a vector figure alongside PNG for paper-quality usage.
    pdf_path = out_path.with_suffix(".pdf")
    fig.savefig(pdf_path, bbox_inches="tight")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plot elapsed time and file system input comparison from result.txt")
    parser.add_argument("--result", default="result.txt", help="Path to result.txt")
    parser.add_argument("--out", default="time_fs_compare.png", help="Output image path")
    args = parser.parse_args()

    result_path = Path(args.result)
    out_path = Path(args.out)

    rows = parse_result(result_path)
    render(rows, out_path)
    print(f"Saved plot to: {out_path}")
