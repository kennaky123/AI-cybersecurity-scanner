from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Sequence

import numpy as np

MODEL_IDENTITIES = {
    "random_forest": ("Random Forest", "RandomForestClassifier"),
    "xgboost": ("XGBoost", "XGBClassifier"),
    "lightgbm": ("LightGBM", "LGBMClassifier"),
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_artifact_hashes(
    metadata: dict[str, Any],
    model_path: Path,
    preprocessor_path: Path,
) -> None:
    hashes = metadata.get("artifact_sha256")
    if not isinstance(hashes, dict):
        raise TypeError("Metadata artifact_sha256 section is invalid.")
    expected_model_hash = hashes.get("model")
    expected_preprocessor_hash = hashes.get("preprocessor")
    if not isinstance(expected_model_hash, str) or not isinstance(expected_preprocessor_hash, str):
        raise TypeError("Metadata artifact hashes are invalid.")
    if sha256_file(model_path) != expected_model_hash or sha256_file(preprocessor_path) != expected_preprocessor_hash:
        raise TypeError("Artifact SHA-256 does not match model metadata.")


def validate_artifact_bundle(
    *,
    metadata: dict[str, Any],
    model: Any,
    preprocessor: Any,
    expected_features: Sequence[str],
    feature_metadata_key: str,
    model_path: Path,
    preprocessor_path: Path,
) -> list[str]:
    """Fail closed when model, preprocessor, and metadata do not describe one bundle."""
    metadata_features = metadata.get(feature_metadata_key)
    if not isinstance(metadata_features, list) or not all(isinstance(name, str) for name in metadata_features):
        raise TypeError(f"Metadata field '{feature_metadata_key}' is invalid.")
    if metadata_features != list(expected_features):
        raise TypeError("Metadata feature names or order do not match the expected schema.")

    model_key = metadata.get("model_key")
    identity = MODEL_IDENTITIES.get(model_key)
    if identity is None:
        raise TypeError("Metadata model_key is invalid.")
    display_name, class_name = identity
    if metadata.get("model") != display_name or type(model).__name__ != class_name:
        raise TypeError("Loaded model class does not match model metadata.")

    artifacts = metadata.get("artifacts")
    if not isinstance(artifacts, dict):
        raise TypeError("Metadata artifacts section is invalid.")
    if artifacts.get("model") != model_path.name or artifacts.get("preprocessor") != preprocessor_path.name:
        raise TypeError("Loaded artifact filenames do not match model metadata.")

    expected_count = len(metadata_features)
    if getattr(preprocessor, "n_features_in_", None) != expected_count:
        raise TypeError("Preprocessor input dimension does not match model metadata.")
    if getattr(model, "n_features_in_", None) != expected_count:
        raise TypeError("Model input dimension does not match model metadata.")
    if set(np.asarray(getattr(model, "classes_", [])).tolist()) != {0, 1}:
        raise TypeError("Model classes must be exactly 0 and 1.")
    return metadata_features
