#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


DEFAULT_INPUT = "/home/messidor/tmp/feature_csv_20260415_124409/all_features_ai_agent_abc_runs123_with_source.csv"
DEFAULT_OUTPUT = "/home/messidor/copy/gmm/train/labeled_stream_windows.csv"

POSITIVE_LABEL = 1
NEGATIVE_LABEL = 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate hindsight reuse labels for stream-window training samples.")
    parser.add_argument("--input", default=DEFAULT_INPUT, help="Merged CSV with source columns.")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Output labeled CSV path.")
    parser.add_argument(
        "--future-windows",
        type=int,
        default=2,
        help="Number of future windows to inspect for hindsight reuse.",
    )
    parser.add_argument(
        "--positive-revisit-max",
        type=int,
        default=200,
        help="Label as pollution if future max revisit ratio stays at or below this value.",
    )
    parser.add_argument(
        "--negative-revisit-mean",
        type=int,
        default=600,
        help="Label as non-pollution if future mean revisit ratio reaches this value.",
    )
    return parser.parse_args()


def build_future_columns(df: pd.DataFrame, future_windows: int) -> pd.DataFrame:
    group_cols = ["source_workload", "source_run", "mapping", "tgid"]
    df = df.sort_values(group_cols + ["window_id"]).copy()
    grouped = df.groupby(group_cols, sort=False)

    revisit_cols = []
    for offset in range(1, future_windows + 1):
        column = f"future_revisit_{offset}"
        df[column] = grouped["revisit_ratio_10000"].shift(-offset)
        revisit_cols.append(column)

    df["future_window_count"] = df[revisit_cols].notna().sum(axis=1)
    df["future_revisit_mean"] = df[revisit_cols].mean(axis=1, skipna=True)
    df["future_revisit_max"] = df[revisit_cols].max(axis=1, skipna=True)
    return df


def assign_labels(df: pd.DataFrame, positive_revisit_max: int,
                  negative_revisit_mean: int) -> pd.DataFrame:
    df = df.copy()
    df["label"] = pd.NA
    positive_mask = df["future_revisit_max"] <= positive_revisit_max
    negative_mask = df["future_revisit_mean"] >= negative_revisit_mean
    valid_future_mask = df["future_window_count"] > 0

    df.loc[valid_future_mask & positive_mask & ~negative_mask, "label"] = POSITIVE_LABEL
    df.loc[valid_future_mask & negative_mask & ~positive_mask, "label"] = NEGATIVE_LABEL

    ambiguous_mask = valid_future_mask & positive_mask & negative_mask
    df["is_ambiguous_label"] = ambiguous_mask.astype(int)
    return df


def main() -> int:
    args = parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)

    df = pd.read_csv(input_path)
    df = build_future_columns(df, args.future_windows)
    df = assign_labels(df, args.positive_revisit_max, args.negative_revisit_mean)

    labeled = df[df["label"].notna()].copy()
    labeled["label"] = labeled["label"].astype(int)
    labeled["stream_id"] = (
        labeled["source_workload"].astype(str)
        + ":"
        + labeled["source_run"].astype(str)
        + ":"
        + labeled["mapping"].astype(str)
        + ":"
        + labeled["tgid"].astype(str)
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    labeled.to_csv(output_path, index=False)

    positive_count = int((labeled["label"] == POSITIVE_LABEL).sum())
    negative_count = int((labeled["label"] == NEGATIVE_LABEL).sum())
    print(f"input_rows={len(df)}")
    print(f"labeled_rows={len(labeled)}")
    print(f"positive_rows={positive_count}")
    print(f"negative_rows={negative_count}")
    print(f"ambiguous_rows={int(df['is_ambiguous_label'].sum())}")
    print(f"output_path={output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())