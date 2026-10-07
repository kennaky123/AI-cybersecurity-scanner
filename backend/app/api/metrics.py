from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, status

PROJECT_ROOT = Path(__file__).resolve().parents[3]
MODELS_DIR = PROJECT_ROOT / "models"

router = APIRouter(prefix="/api/metrics", tags=["metrics"])


def _load_metadata(filename: str) -> dict[str, Any]:
    path = MODELS_DIR / filename
    if not path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Model metadata '{filename}' not found. Please train model first.",
        )
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to parse metadata file '{filename}': {error}",
        ) from error


def _format_model_summary(raw: dict[str, Any], model_type: str) -> dict[str, Any]:
    # Extract comparison table among algorithms
    validation_metrics = raw.get("validation_metrics", {})
    comparison = []
    for algo_name, metrics in validation_metrics.items():
        cm = metrics.get("confusion_matrix", [[0, 0], [0, 0]])
        comparison.append({
            "algorithm": algo_name,
            "accuracy": metrics.get("accuracy", 0.0),
            "precision": metrics.get("precision", 0.0),
            "recall": metrics.get("recall", 0.0),
            "f1": metrics.get("f1", 0.0),
            "roc_auc": metrics.get("roc_auc", 0.0),
            "false_positive": metrics.get("false_positive", cm[0][1] if len(cm) > 0 and len(cm[0]) > 1 else 0),
            "false_negative": metrics.get("false_negative", cm[1][0] if len(cm) > 1 and len(cm[1]) > 0 else 0),
        })

    # Confusion matrix of best / chosen model
    best_cm = raw.get("confusion_matrix", [[0, 0], [0, 0]])
    tn = best_cm[0][0] if len(best_cm) > 0 else 0
    fp = best_cm[0][1] if len(best_cm) > 0 and len(best_cm[0]) > 1 else 0
    fn = best_cm[1][0] if len(best_cm) > 1 and len(best_cm[1]) > 0 else 0
    tp = best_cm[1][1] if len(best_cm) > 1 and len(best_cm[1]) > 1 else 0

    return {
        "model_type": model_type,
        "selected_model": raw.get("model", "Unknown"),
        "model_key": raw.get("model_key", "unknown"),
        "dataset_name": raw.get("dataset", "Unknown"),
        "total_samples": raw.get("total_samples", 0),
        "training_samples": raw.get("training_samples", 0),
        "validation_samples": raw.get("validation_samples", 0),
        "test_samples": raw.get("test_samples", 0),
        "features_count": len(raw.get("features", [])) if "features" in raw else raw.get("number_of_features", 0),
        "test_metrics": {
            "accuracy": raw.get("accuracy", 0.0),
            "precision": raw.get("precision", 0.0),
            "recall": raw.get("recall", 0.0),
            "f1": raw.get("f1", 0.0),
            "roc_auc": raw.get("roc_auc", 0.0),
        },
        "confusion_matrix": {
            "matrix": best_cm,
            "true_negative": tn,
            "false_positive": fp,
            "false_negative": fn,
            "true_positive": tp,
        },
        "comparison": comparison,
        "trained_at_utc": raw.get("trained_at_utc"),
        "library_versions": raw.get("library_versions", {}),
        "artifact_sha256": raw.get("artifact_sha256", {}),
    }


@router.get("")
def get_all_metrics() -> dict[str, Any]:
    """Retrieve metadata and evaluation metrics for all trained models."""
    response: dict[str, Any] = {}
    try:
        phishing_meta = _load_metadata("phishing_model_metadata.json")
        response["phishing"] = _format_model_summary(phishing_meta, "PHISHING")
    except HTTPException:
        response["phishing"] = None

    try:
        malware_meta = _load_metadata("malware_model_metadata.json")
        response["malware"] = _format_model_summary(malware_meta, "MALWARE")
    except HTTPException:
        response["malware"] = None

    return response


@router.get("/phishing")
def get_phishing_metrics() -> dict[str, Any]:
    """Retrieve evaluation metrics for the Phishing detection model."""
    meta = _load_metadata("phishing_model_metadata.json")
    return _format_model_summary(meta, "PHISHING")


@router.get("/malware")
def get_malware_metrics() -> dict[str, Any]:
    """Retrieve evaluation metrics for the Malware detection model."""
    meta = _load_metadata("malware_model_metadata.json")
    return _format_model_summary(meta, "MALWARE")
