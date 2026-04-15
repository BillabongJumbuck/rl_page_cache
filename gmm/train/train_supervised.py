#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import lightgbm as lgb
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


DEFAULT_INPUT = "/home/messidor/copy/gmm/train/labeled_stream_windows.csv"
DEFAULT_OUTPUT_DIR = "/home/messidor/copy/gmm/train/artifacts"

FEATURE_COLUMNS = [
    "sample_count",
    "mapping_nrpages",
    "seq_ratio_10000",
    "revisit_ratio_10000",
    "dirty_ratio_10000",
    "smoothed_seq_10000",
    "smoothed_revisit_10000",
    "smoothed_dirty_10000",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train logistic-regression and LightGBM classifiers on labeled stream windows.")
    parser.add_argument("--input", default=DEFAULT_INPUT, help="Labeled CSV path.")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, help="Directory for models and reports.")
    parser.add_argument("--test-size", type=float, default=0.2, help="Group-wise test split ratio.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed.")
    parser.add_argument(
        "--group-column",
        default="stream_id",
        help="Column used to group samples during train/test split.",
    )
    return parser.parse_args()


def load_dataset(path: Path, group_column: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    required = FEATURE_COLUMNS + ["label", group_column]
    missing = [column for column in required if column not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")
    return df


def split_dataset(df: pd.DataFrame, test_size: float, seed: int, group_column: str):
    splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
    train_idx, test_idx = next(splitter.split(df, y=df["label"], groups=df[group_column]))
    return df.iloc[train_idx].copy(), df.iloc[test_idx].copy()


def evaluate_binary_model(name: str, model, x_test: pd.DataFrame, y_test: pd.Series) -> dict:
    y_pred = model.predict(x_test)
    if hasattr(model, "predict_proba"):
        y_score = model.predict_proba(x_test)[:, 1]
    else:
        y_score = model.predict(x_test)

    report = classification_report(y_test, y_pred, output_dict=True)
    metrics = {
        "model": name,
        "roc_auc": roc_auc_score(y_test, y_score),
        "accuracy": report["accuracy"],
        "positive_precision": report["1"]["precision"],
        "positive_recall": report["1"]["recall"],
        "positive_f1": report["1"]["f1-score"],
        "negative_precision": report["0"]["precision"],
        "negative_recall": report["0"]["recall"],
        "negative_f1": report["0"]["f1-score"],
        "support_positive": report["1"]["support"],
        "support_negative": report["0"]["support"],
    }
    return metrics


def main() -> int:
    args = parse_args()
    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    df = load_dataset(input_path, args.group_column)
    train_df, test_df = split_dataset(df, args.test_size, args.seed, args.group_column)

    x_train = train_df[FEATURE_COLUMNS]
    y_train = train_df["label"]
    x_test = test_df[FEATURE_COLUMNS]
    y_test = test_df["label"]

    logistic = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler()),
        (
            "model",
            LogisticRegression(
                max_iter=1000,
                class_weight="balanced",
                random_state=args.seed,
            ),
        ),
    ])
    logistic.fit(x_train, y_train)

    lightgbm = lgb.LGBMClassifier(
        n_estimators=200,
        learning_rate=0.05,
        num_leaves=31,
        max_depth=6,
        min_child_samples=100,
        subsample=0.8,
        colsample_bytree=0.8,
        class_weight="balanced",
        random_state=args.seed,
        n_jobs=-1,
    )
    lightgbm.fit(x_train, y_train)

    logistic_metrics = evaluate_binary_model("logistic_regression", logistic, x_test, y_test)
    lightgbm_metrics = evaluate_binary_model("lightgbm", lightgbm, x_test, y_test)

    metrics = {
        "train_rows": len(train_df),
        "test_rows": len(test_df),
        "group_column": args.group_column,
        "train_groups": int(train_df[args.group_column].nunique()),
        "test_groups": int(test_df[args.group_column].nunique()),
        "label_balance_train": train_df["label"].value_counts().sort_index().to_dict(),
        "label_balance_test": test_df["label"].value_counts().sort_index().to_dict(),
        "feature_columns": FEATURE_COLUMNS,
        "results": [logistic_metrics, lightgbm_metrics],
        "lightgbm_feature_importance": dict(
            zip(FEATURE_COLUMNS, lightgbm.feature_importances_.tolist())
        ),
    }

    metrics_path = output_dir / "metrics.json"
    logistic_path = output_dir / "logistic_regression.joblib"
    lightgbm_path = output_dir / "lightgbm_model.joblib"

    joblib.dump(logistic, logistic_path)
    joblib.dump(lightgbm, lightgbm_path)
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print(json.dumps(metrics, indent=2))
    print(f"metrics_path={metrics_path}")
    print(f"logistic_model_path={logistic_path}")
    print(f"lightgbm_model_path={lightgbm_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())