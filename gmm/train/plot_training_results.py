#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


DEFAULT_METRICS = "/home/messidor/copy/gmm/train/artifacts/metrics.json"
DEFAULT_OUTPUT_DIR = "/home/messidor/copy/gmm/train/artifacts/figures"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate paper-ready figures and tables from supervised training metrics.")
    parser.add_argument("--metrics", default=DEFAULT_METRICS, help="Path to metrics.json")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, help="Directory for plots and tables")
    return parser.parse_args()


def load_metrics(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def save_performance_figure(metrics: dict, output_dir: Path) -> Path:
    records = pd.DataFrame(metrics["results"])
    records["display_name"] = records["model"].map(
        {
            "logistic_regression": "Logistic Regression",
            "lightgbm": "LightGBM",
        }
    )

    metric_columns = ["roc_auc", "accuracy", "positive_f1", "negative_f1"]
    metric_labels = ["ROC-AUC", "Accuracy", "Pollution F1", "Non-pollution F1"]

    fig, ax = plt.subplots(figsize=(9, 5.5))
    bar_width = 0.18
    x_positions = list(range(len(records)))
    colors = ["#1f6aa5", "#dd8452", "#55a868", "#c44e52"]

    for index, (column, label, color) in enumerate(zip(metric_columns, metric_labels, colors)):
        offset = (index - 1.5) * bar_width
        values = records[column].tolist()
        bars = ax.bar([x + offset for x in x_positions], values, width=bar_width, label=label, color=color)
        for bar, value in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, value + 0.0015, f"{value:.3f}",
                    ha="center", va="bottom", fontsize=8)

    ax.set_xticks(x_positions)
    ax.set_xticklabels(records["display_name"])
    ax.set_ylim(0.88, 1.01)
    ax.set_ylabel("Score")
    ax.set_title("Supervised Model Performance on Stream-wise Split")
    ax.grid(axis="y", linestyle="--", alpha=0.3)
    ax.legend(loc="lower right")
    fig.tight_layout()

    output_path = output_dir / "model_performance.png"
    fig.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    return output_path


def save_importance_figure(metrics: dict, output_dir: Path) -> Path:
    importance = pd.Series(metrics["lightgbm_feature_importance"]).sort_values(ascending=True)
    labels = [
        item.replace("_10000", "").replace("_", " ")
        for item in importance.index.tolist()
    ]

    fig, ax = plt.subplots(figsize=(9, 5.5))
    ax.barh(labels, importance.values, color="#1f6aa5")
    for y_pos, value in enumerate(importance.values):
        ax.text(value + 15, y_pos, str(int(value)), va="center", fontsize=8)

    ax.set_xlabel("Importance")
    ax.set_title("LightGBM Feature Importance")
    ax.grid(axis="x", linestyle="--", alpha=0.3)
    fig.tight_layout()

    output_path = output_dir / "lightgbm_feature_importance.png"
    fig.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    return output_path


def save_latex_table(metrics: dict, output_dir: Path) -> Path:
    rows = []
    display_map = {
        "logistic_regression": "Logistic Regression",
        "lightgbm": "LightGBM",
    }
    for result in metrics["results"]:
        rows.append(
            "{} & {:.4f} & {:.4f} & {:.4f} & {:.4f} \\\\".format(
                display_map.get(result["model"], result["model"]),
                result["roc_auc"],
                result["accuracy"],
                result["positive_f1"],
                result["negative_f1"],
            )
        )

    content = "\n".join([
        "\\begin{table}[t]",
        "\\centering",
        "\\caption{监督模型在按访问流分组切分测试集上的分类结果}",
        "\\label{tab:ml-training-results}",
        "\\begin{tabular}{lcccc}",
        "\\toprule",
        "Model & ROC-AUC & Accuracy & Pollution F1 & Non-pollution F1 \\\\",
        "\\midrule",
        *rows,
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}",
        "",
    ])

    output_path = output_dir / "training_results_table.tex"
    output_path.write_text(content, encoding="utf-8")
    return output_path


def main() -> int:
    args = parse_args()
    metrics_path = Path(args.metrics)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    metrics = load_metrics(metrics_path)
    perf_path = save_performance_figure(metrics, output_dir)
    importance_path = save_importance_figure(metrics, output_dir)
    table_path = save_latex_table(metrics, output_dir)

    print(f"performance_figure={perf_path}")
    print(f"importance_figure={importance_path}")
    print(f"latex_table={table_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())