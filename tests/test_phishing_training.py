import json
import hashlib
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pytest

from ml.phishing.features import FEATURE_NAMES
from ml.phishing.train import evaluate_model, load_training_dataset, split_dataset, train_models
from backend.app.services.phishing_detector import ModelUnavailableError, PhishingDetector


def _training_frame(sample_count: int = 120) -> pd.DataFrame:
    rng = np.random.default_rng(42)
    labels = np.array([0, 1] * (sample_count // 2), dtype=int)
    data: dict[str, np.ndarray] = {}
    for index, feature in enumerate(FEATURE_NAMES):
        noise = rng.normal(0, 0.2, sample_count)
        data[feature] = labels * (index + 1) + noise
    data["label"] = labels
    return pd.DataFrame(data)


def test_stratified_split_is_disjoint_and_has_expected_sizes() -> None:
    frame = _training_frame(200)
    splits = split_dataset(frame.loc[:, list(FEATURE_NAMES)], frame["label"], random_seed=42)

    assert (len(splits.y_train), len(splits.y_validation), len(splits.y_test)) == (140, 30, 30)
    assert set(splits.X_train.index).isdisjoint(splits.X_validation.index)
    assert set(splits.X_train.index).isdisjoint(splits.X_test.index)
    assert set(splits.X_validation.index).isdisjoint(splits.X_test.index)
    assert splits.y_train.mean() == pytest.approx(0.5)
    assert splits.y_validation.mean() == pytest.approx(0.5)
    assert splits.y_test.mean() == pytest.approx(0.5)


def test_training_rejects_invalid_labels(tmp_path: Path) -> None:
    dataset = tmp_path / "invalid.csv"
    frame = _training_frame()
    frame.loc[0, "label"] = 2
    frame.to_csv(dataset, index=False)

    with pytest.raises(ValueError, match="binary classes"):
        load_training_dataset(dataset)


def test_random_forest_training_writes_real_artifacts(tmp_path: Path) -> None:
    dataset = tmp_path / "phishing.csv"
    output_dir = tmp_path / "models"
    _training_frame().to_csv(dataset, index=False)

    metadata = train_models(
        dataset,
        output_dir,
        model_choice="random_forest",
        random_seed=42,
        dataset_name="unit-test-fixture",
    )

    assert (output_dir / "phishing_model.joblib").is_file()
    assert (output_dir / "phishing_preprocessor.joblib").is_file()
    assert (output_dir / "phishing_model_metadata.json").is_file()
    assert metadata["model"] == "Random Forest"
    assert metadata["selection_train_samples"] == 84
    assert metadata["validation_samples"] == 18
    assert metadata["training_samples"] == 102
    assert metadata["test_samples"] == 18
    assert 0.0 <= metadata["roc_auc"] <= 1.0
    assert sum(map(sum, metadata["confusion_matrix"])) == 18

    saved_metadata = json.loads((output_dir / "phishing_model_metadata.json").read_text(encoding="utf-8"))
    assert saved_metadata["dataset_sha256"] == metadata["dataset_sha256"]
    assert saved_metadata["artifact_sha256"]["model"] == hashlib.sha256(
        (output_dir / "phishing_model.joblib").read_bytes()
    ).hexdigest()
    assert saved_metadata["artifact_sha256"]["preprocessor"] == hashlib.sha256(
        (output_dir / "phishing_preprocessor.joblib").read_bytes()
    ).hexdigest()
    saved_model = joblib.load(output_dir / "phishing_model.joblib")
    saved_preprocessor = joblib.load(output_dir / "phishing_preprocessor.joblib")
    assert type(saved_model).__name__ == "RandomForestClassifier"
    assert saved_metadata["model_key"] == "random_forest"
    assert saved_metadata["features"] == list(FEATURE_NAMES)
    assert saved_preprocessor.n_features_in_ == len(FEATURE_NAMES)
    assert saved_model.n_features_in_ == len(FEATURE_NAMES)

    X, y, _ = load_training_dataset(dataset)
    saved_splits = split_dataset(X, y, random_seed=42)
    round_trip_metrics = evaluate_model(
        saved_model,
        saved_preprocessor.transform(saved_splits.X_test),
        saved_splits.y_test,
    )
    assert round_trip_metrics.accuracy == pytest.approx(saved_metadata["accuracy"])
    assert round_trip_metrics.precision == pytest.approx(saved_metadata["precision"])
    assert round_trip_metrics.recall == pytest.approx(saved_metadata["recall"])
    assert round_trip_metrics.f1 == pytest.approx(saved_metadata["f1"])
    assert round_trip_metrics.roc_auc == pytest.approx(saved_metadata["roc_auc"])
    assert round_trip_metrics.confusion_matrix == saved_metadata["confusion_matrix"]

    detector = PhishingDetector(
        model_path=output_dir / "phishing_model.joblib",
        preprocessor_path=output_dir / "phishing_preprocessor.joblib",
        metadata_path=output_dir / "phishing_model_metadata.json",
    )
    analysis = detector.analyze("https://login.example.com/verify?id=123")
    assert analysis.prediction in {"LEGITIMATE", "PHISHING"}
    assert 0.0 <= analysis.probability <= 1.0
    assert analysis.risk_score == round(analysis.probability * 100)
    assert tuple(analysis.features) == FEATURE_NAMES
    assert analysis.explanation.method in {"SHAP", "FEATURE_ABLATION"}
    assert analysis.explanation.increasing_risk or analysis.explanation.decreasing_risk

    saved_metadata["model"] = "XGBoost"
    saved_metadata["model_key"] = "xgboost"
    (output_dir / "phishing_model_metadata.json").write_text(
        json.dumps(saved_metadata), encoding="utf-8"
    )
    with pytest.raises(ModelUnavailableError, match="unavailable"):
        PhishingDetector(
            output_dir / "phishing_model.joblib",
            output_dir / "phishing_preprocessor.joblib",
            output_dir / "phishing_model_metadata.json",
        )._load_artifacts()
