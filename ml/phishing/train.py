"""Train and compare phishing URL classifiers.

Model selection uses validation metrics only. The held-out test set is touched
once, after a model family has been selected, and is never used for fitting.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from .features import FEATURE_NAMES

ModelChoice = Literal["random_forest", "xgboost", "lightgbm", "all"]

DEFAULT_DATASET = Path("data/processed/phishing.csv")
DEFAULT_OUTPUT_DIR = Path("models")
DEFAULT_RANDOM_SEED = 42
MODEL_FILENAME = "phishing_model.joblib"
PREPROCESSOR_FILENAME = "phishing_preprocessor.joblib"
METADATA_FILENAME = "phishing_model_metadata.json"

MODEL_DISPLAY_NAMES = {
    "random_forest": "Random Forest",
    "xgboost": "XGBoost",
    "lightgbm": "LightGBM",
}


@dataclass(frozen=True, slots=True)
class Metrics:
    accuracy: float
    precision: float
    recall: float
    f1: float
    roc_auc: float
    confusion_matrix: list[list[int]]


@dataclass(frozen=True, slots=True)
class DatasetSplits:
    X_train: pd.DataFrame
    X_validation: pd.DataFrame
    X_test: pd.DataFrame
    y_train: pd.Series
    y_validation: pd.Series
    y_test: pd.Series


def load_training_dataset(dataset_path: Path) -> tuple[pd.DataFrame, pd.Series, int]:
    if not dataset_path.is_file():
        raise FileNotFoundError(
            f"Processed dataset not found: {dataset_path}. "
            "Run Phase 2 first with python -m ml.phishing.prepare_dataset."
        )

    try:
        frame = pd.read_csv(dataset_path)
    except (UnicodeDecodeError, pd.errors.ParserError) as error:
        raise ValueError(f"Could not read processed dataset: {error}") from error

    required = [*FEATURE_NAMES, "label"]
    missing_columns = [column for column in required if column not in frame.columns]
    if missing_columns:
        raise ValueError(f"Dataset is missing required columns: {missing_columns}")
    if frame.empty:
        raise ValueError("Processed dataset is empty.")

    raw_features = frame.loc[:, list(FEATURE_NAMES)]
    numeric_features = raw_features.apply(pd.to_numeric, errors="coerce")
    non_numeric = raw_features.notna() & numeric_features.isna()
    if bool(non_numeric.any().any()):
        bad_columns = non_numeric.any()[lambda values: values].index.tolist()
        raise ValueError(f"Feature columns contain non-numeric values: {bad_columns}")
    if bool(np.isinf(numeric_features.to_numpy(dtype=float)).any()):
        raise ValueError("Feature columns contain infinite values.")
    empty_feature_columns = numeric_features.columns[numeric_features.isna().all()].tolist()
    if empty_feature_columns:
        raise ValueError(f"Feature columns contain no usable values: {empty_feature_columns}")

    numeric_label = pd.to_numeric(frame["label"], errors="coerce")
    if numeric_label.isna().any():
        raise ValueError("Label contains missing or non-numeric values.")
    unique_labels = set(numeric_label.unique().tolist())
    if not unique_labels.issubset({0, 1}) or unique_labels != {0, 1}:
        raise ValueError(f"Label must contain both binary classes 0 and 1; found: {sorted(unique_labels)}")

    labels = numeric_label.astype("int8")
    class_counts = labels.value_counts()
    if int(class_counts.min()) < 4:
        raise ValueError("Each label needs at least 4 samples for a stratified 70/15/15 split.")

    return numeric_features.astype(float), labels, int(numeric_features.isna().sum().sum())


def split_dataset(X: pd.DataFrame, y: pd.Series, random_seed: int) -> DatasetSplits:
    try:
        X_train, X_holdout, y_train, y_holdout = train_test_split(
            X,
            y,
            test_size=0.30,
            random_state=random_seed,
            stratify=y,
        )
        X_validation, X_test, y_validation, y_test = train_test_split(
            X_holdout,
            y_holdout,
            test_size=0.50,
            random_state=random_seed,
            stratify=y_holdout,
        )
    except ValueError as error:
        raise ValueError(f"Could not create stratified 70/15/15 split: {error}") from error

    return DatasetSplits(X_train, X_validation, X_test, y_train, y_validation, y_test)


def build_preprocessor() -> ColumnTransformer:
    return ColumnTransformer(
        transformers=[("numeric", SimpleImputer(strategy="median"), list(FEATURE_NAMES))],
        remainder="drop",
        verbose_feature_names_out=False,
    )


def build_model(model_name: str, random_seed: int, y_train: pd.Series):
    if model_name == "random_forest":
        return RandomForestClassifier(
            n_estimators=300,
            class_weight="balanced",
            random_state=random_seed,
            n_jobs=-1,
        )

    if model_name == "xgboost":
        try:
            from xgboost import XGBClassifier
        except ImportError as error:
            raise RuntimeError("XGBoost is unavailable. Install backend/requirements.txt.") from error

        negative, positive = np.bincount(y_train.to_numpy(dtype=int), minlength=2)
        scale_pos_weight = float(negative / positive) if positive else 1.0
        return XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.05,
            subsample=0.9,
            colsample_bytree=0.9,
            scale_pos_weight=scale_pos_weight,
            eval_metric="logloss",
            random_state=random_seed,
            n_jobs=-1,
            tree_method="hist",
        )

    if model_name == "lightgbm":
        try:
            from lightgbm import LGBMClassifier
        except ImportError as error:
            raise RuntimeError("LightGBM is unavailable. Install backend/requirements.txt.") from error

        return LGBMClassifier(
            n_estimators=300,
            learning_rate=0.05,
            class_weight="balanced",
            random_state=random_seed,
            n_jobs=-1,
            verbosity=-1,
            deterministic=True,
            force_col_wise=True,
        )

    raise ValueError(f"Unsupported model: {model_name}")


def evaluate_model(model: Any, X: np.ndarray, y: pd.Series) -> Metrics:
    predictions = model.predict(X)
    if not hasattr(model, "predict_proba"):
        raise ValueError(f"{type(model).__name__} does not provide probabilities for ROC-AUC.")
    probabilities = model.predict_proba(X)[:, 1]
    return Metrics(
        accuracy=float(accuracy_score(y, predictions)),
        precision=float(precision_score(y, predictions, zero_division=0)),
        recall=float(recall_score(y, predictions, zero_division=0)),
        f1=float(f1_score(y, predictions, zero_division=0)),
        roc_auc=float(roc_auc_score(y, probabilities)),
        confusion_matrix=confusion_matrix(y, predictions, labels=[0, 1]).astype(int).tolist(),
    )


def _selection_key(metrics: Metrics) -> tuple[float, float, float, float, float]:
    # Accuracy is deliberately the final tie-breaker, not the selection target.
    return metrics.f1, metrics.roc_auc, metrics.recall, metrics.precision, metrics.accuracy


def _requested_models(choice: ModelChoice) -> list[str]:
    if choice == "all":
        return ["random_forest", "xgboost", "lightgbm"]
    return [choice]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_joblib_dump(value: Any, destination: Path) -> None:
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    joblib.dump(value, temporary)
    os.replace(temporary, destination)


def _atomic_json_dump(value: dict[str, Any], destination: Path) -> None:
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(temporary, destination)


def train_models(
    dataset_path: Path = DEFAULT_DATASET,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    *,
    model_choice: ModelChoice = "all",
    random_seed: int = DEFAULT_RANDOM_SEED,
    dataset_name: str | None = None,
) -> dict[str, Any]:
    X, y, missing_values = load_training_dataset(dataset_path)
    splits = split_dataset(X, y, random_seed)

    # This preprocessor sees the 70% training split only during model selection.
    selection_preprocessor = build_preprocessor()
    X_train = selection_preprocessor.fit_transform(splits.X_train)
    X_validation = selection_preprocessor.transform(splits.X_validation)

    validation_results: dict[str, Metrics] = {}
    for model_name in _requested_models(model_choice):
        model = build_model(model_name, random_seed, splits.y_train)
        model.fit(X_train, splits.y_train)
        validation_results[model_name] = evaluate_model(model, X_validation, splits.y_validation)

    selected_name = max(validation_results, key=lambda name: _selection_key(validation_results[name]))

    # Selection is now locked. Refit on train+validation (85%), never on test.
    X_development = pd.concat([splits.X_train, splits.X_validation], axis=0)
    y_development = pd.concat([splits.y_train, splits.y_validation], axis=0)
    final_preprocessor = build_preprocessor()
    X_development_processed = final_preprocessor.fit_transform(X_development)
    X_test_processed = final_preprocessor.transform(splits.X_test)
    final_model = build_model(selected_name, random_seed, y_development)
    final_model.fit(X_development_processed, y_development)
    test_metrics = evaluate_model(final_model, X_test_processed, splits.y_test)

    output_dir.mkdir(parents=True, exist_ok=True)
    model_path = output_dir / MODEL_FILENAME
    preprocessor_path = output_dir / PREPROCESSOR_FILENAME
    metadata_path = output_dir / METADATA_FILENAME

    metadata: dict[str, Any] = {
        "model": MODEL_DISPLAY_NAMES[selected_name],
        "model_key": selected_name,
        "dataset": dataset_name or dataset_path.stem,
        "dataset_path": str(dataset_path),
        "dataset_sha256": _sha256_file(dataset_path),
        "random_seed": random_seed,
        "selection_strategy": "validation lexicographic: f1, roc_auc, recall, precision, accuracy",
        "total_samples": len(y),
        "training_samples": len(y_development),
        "selection_train_samples": len(splits.y_train),
        "validation_samples": len(splits.y_validation),
        "test_samples": len(splits.y_test),
        "missing_feature_values_imputed": missing_values,
        "features": list(FEATURE_NAMES),
        "accuracy": test_metrics.accuracy,
        "precision": test_metrics.precision,
        "recall": test_metrics.recall,
        "f1": test_metrics.f1,
        "roc_auc": test_metrics.roc_auc,
        "confusion_matrix": test_metrics.confusion_matrix,
        "validation_metrics": {
            MODEL_DISPLAY_NAMES[name]: asdict(metrics) for name, metrics in validation_results.items()
        },
        "artifacts": {
            "model": MODEL_FILENAME,
            "preprocessor": PREPROCESSOR_FILENAME,
        },
        "output_directory": str(output_dir.resolve()),
        "library_versions": {
            "scikit_learn": sklearn.__version__,
            "pandas": pd.__version__,
            "numpy": np.__version__,
        },
        "trained_at_utc": datetime.now(timezone.utc).isoformat(),
    }

    _atomic_joblib_dump(final_model, model_path)
    _atomic_joblib_dump(final_preprocessor, preprocessor_path)
    metadata["artifact_sha256"] = {
        "model": _sha256_file(model_path),
        "preprocessor": _sha256_file(preprocessor_path),
    }
    _atomic_json_dump(metadata, metadata_path)
    return metadata


def _format_metric(value: float) -> str:
    return f"{value:.6f}"


def print_training_report(metadata: dict[str, Any]) -> None:
    print("\nValidation comparison (test set not used):")
    print(f"  {'Model':<16} {'Accuracy':>10} {'Precision':>10} {'Recall':>10} {'F1':>10} {'ROC-AUC':>10}")
    for model_name, metrics in metadata["validation_metrics"].items():
        print(
            f"  {model_name:<16}"
            f" {metrics['accuracy']:>10.6f}"
            f" {metrics['precision']:>10.6f}"
            f" {metrics['recall']:>10.6f}"
            f" {metrics['f1']:>10.6f}"
            f" {metrics['roc_auc']:>10.6f}"
        )

    print(f"\nSelected model: {metadata['model']}")
    print("Held-out test metrics:")
    for metric in ("accuracy", "precision", "recall", "f1", "roc_auc"):
        print(f"  {metric:<10}: {_format_metric(metadata[metric])}")
    print(f"  confusion_matrix: {metadata['confusion_matrix']}")
    print(f"\nArtifacts saved in: {metadata['output_directory']}")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train phishing classifiers without test-set leakage.")
    parser.add_argument("--input", type=Path, default=DEFAULT_DATASET, help=f"Processed CSV (default: {DEFAULT_DATASET}).")
    parser.add_argument(
        "--model",
        choices=("random_forest", "xgboost", "lightgbm", "all"),
        default="all",
        help="Model family to train and compare (default: all).",
    )
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR, help="Artifact directory.")
    parser.add_argument("--dataset-name", help="Human-readable dataset name stored in metadata.")
    parser.add_argument("--seed", type=int, default=DEFAULT_RANDOM_SEED, help="Reproducible random seed.")
    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    try:
        metadata = train_models(
            args.input,
            args.output_dir,
            model_choice=args.model,
            random_seed=args.seed,
            dataset_name=args.dataset_name,
        )
    except (FileNotFoundError, RuntimeError, ValueError) as error:
        parser.error(str(error))
    print_training_report(metadata)


if __name__ == "__main__":
    main()
