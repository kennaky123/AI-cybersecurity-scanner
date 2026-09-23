"""Local, model-derived explanations for binary risk classifiers.

Predictions always come from the detector's ``predict_proba`` call.  This module
only explains that already-computed model output; it never creates a verdict.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any, Sequence

import numpy as np

logger = logging.getLogger(__name__)
TOP_FEATURES_PER_DIRECTION = 5
FALLBACK_CANDIDATES = 24


@dataclass(frozen=True, slots=True)
class FeatureContribution:
    name: str
    value: float
    contribution: float


@dataclass(frozen=True, slots=True)
class ModelExplanation:
    method: str
    output_space: str
    increasing_risk: list[FeatureContribution]
    decreasing_risk: list[FeatureContribution]
    limitation: str | None

    @classmethod
    def unavailable(cls, reason: str = "This model does not expose a supported local explanation.") -> ModelExplanation:
        return cls(
            method="UNAVAILABLE",
            output_space="none",
            increasing_risk=[],
            decreasing_risk=[],
            limitation=reason,
        )


class ExplainabilityService:
    """Prefer Tree SHAP and use probability ablation as an explicit fallback."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._explainers: dict[int, Any] = {}
        try:
            import shap  # type: ignore[import-not-found]
        except ImportError:
            self._shap: Any | None = None
        else:
            self._shap = shap

    def explain(
        self,
        *,
        model: Any,
        transformed: Any,
        feature_names: Sequence[str],
        feature_values: dict[str, int | float],
        baseline: Any,
        positive_class_index: int,
        predicted_probability: float,
    ) -> ModelExplanation:
        row = self._dense_row(transformed)
        if row.shape[0] != len(feature_names):
            return ModelExplanation.unavailable("Transformed feature names do not match the model input.")

        if self._shap is not None:
            try:
                contributions = self._tree_shap(model, row, positive_class_index)
                return self._build(
                    method="SHAP",
                    output_space="model_output",
                    feature_names=feature_names,
                    feature_values=feature_values,
                    contributions=contributions,
                    limitation=(
                        "SHAP values explain the model output for this sample; units may be raw score or "
                        "probability depending on the fitted tree model. They are not causal effects."
                    ),
                )
            except Exception as error:
                logger.warning("Tree SHAP explanation failed; using feature ablation: %s", error)

        return self._feature_ablation(
            model=model,
            row=row,
            baseline=self._dense_row(baseline),
            feature_names=feature_names,
            feature_values=feature_values,
            positive_class_index=positive_class_index,
            predicted_probability=predicted_probability,
        )

    def _tree_shap(self, model: Any, row: np.ndarray, positive_class_index: int) -> np.ndarray:
        with self._lock:
            explainer = self._explainers.get(id(model))
            if explainer is None:
                explainer = self._shap.TreeExplainer(model)
                self._explainers = {id(model): explainer}
            raw_values = explainer.shap_values(row.reshape(1, -1))
        return self._select_class_values(raw_values, row.shape[0], positive_class_index)

    @staticmethod
    def _select_class_values(raw_values: Any, feature_count: int, class_index: int) -> np.ndarray:
        if isinstance(raw_values, (list, tuple)):
            if class_index >= len(raw_values):
                raise ValueError("SHAP output does not contain the positive class.")
            values = np.asarray(raw_values[class_index], dtype=float)
        else:
            values = np.asarray(getattr(raw_values, "values", raw_values), dtype=float)

        if values.ndim == 3 and values.shape == (1, feature_count, 2):
            values = values[0, :, class_index]
        elif values.ndim == 2 and values.shape == (1, feature_count):
            values = values[0]
        elif values.ndim == 2 and values.shape == (feature_count, 2):
            values = values[:, class_index]
        values = np.asarray(values, dtype=float).reshape(-1)
        if values.shape != (feature_count,) or not np.isfinite(values).all():
            raise ValueError("Unexpected or non-finite SHAP output shape.")
        return values

    def _feature_ablation(
        self,
        *,
        model: Any,
        row: np.ndarray,
        baseline: np.ndarray,
        feature_names: Sequence[str],
        feature_values: dict[str, int | float],
        positive_class_index: int,
        predicted_probability: float,
    ) -> ModelExplanation:
        if baseline.shape != row.shape:
            return ModelExplanation.unavailable("A compatible feature baseline is unavailable.")
        raw_importances = getattr(model, "feature_importances_", None)
        if raw_importances is None:
            return ModelExplanation.unavailable(
                "SHAP is unavailable and this model does not expose feature_importances_."
            )
        importances = np.asarray(raw_importances, dtype=float).reshape(-1)
        if importances.shape != row.shape or not np.isfinite(importances).all():
            return ModelExplanation.unavailable("The model's feature importance shape is incompatible.")

        candidate_indices = np.argsort(importances)[::-1][:FALLBACK_CANDIDATES]
        ablated = np.repeat(row.reshape(1, -1), len(candidate_indices), axis=0)
        for output_index, feature_index in enumerate(candidate_indices):
            ablated[output_index, int(feature_index)] = baseline[int(feature_index)]
        probabilities = np.asarray(model.predict_proba(ablated), dtype=float)
        if probabilities.shape[0] != len(candidate_indices) or positive_class_index >= probabilities.shape[1]:
            return ModelExplanation.unavailable("The model returned an invalid ablation probability matrix.")

        contributions = np.zeros_like(row, dtype=float)
        for output_index, feature_index in enumerate(candidate_indices):
            contributions[int(feature_index)] = (
                predicted_probability - float(probabilities[output_index, positive_class_index])
            )
        return self._build(
            method="FEATURE_ABLATION",
            output_space="probability_delta",
            feature_names=feature_names,
            feature_values=feature_values,
            contributions=contributions,
            limitation=(
                "SHAP was unavailable or incompatible. Values are local one-feature-at-a-time probability "
                "changes against the training median, ranked using global feature importance. Interactions "
                "are not fully represented and the values are not causal effects."
            ),
        )

    @staticmethod
    def _dense_row(values: Any) -> np.ndarray:
        if hasattr(values, "toarray"):
            values = values.toarray()
        array = np.asarray(values, dtype=float)
        if array.ndim == 2 and array.shape[0] == 1:
            array = array[0]
        return array.reshape(-1)

    @staticmethod
    def _build(
        *,
        method: str,
        output_space: str,
        feature_names: Sequence[str],
        feature_values: dict[str, int | float],
        contributions: np.ndarray,
        limitation: str,
    ) -> ModelExplanation:
        items = [
            FeatureContribution(str(name), float(feature_values[str(name)]), float(contributions[index]))
            for index, name in enumerate(feature_names)
            if np.isfinite(contributions[index]) and contributions[index] != 0
        ]
        increasing = sorted(
            (item for item in items if item.contribution > 0),
            key=lambda item: item.contribution,
            reverse=True,
        )[:TOP_FEATURES_PER_DIRECTION]
        decreasing = sorted(
            (item for item in items if item.contribution < 0),
            key=lambda item: item.contribution,
        )[:TOP_FEATURES_PER_DIRECTION]
        return ModelExplanation(method, output_space, increasing, decreasing, limitation)
