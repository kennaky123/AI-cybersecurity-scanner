from __future__ import annotations

import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier

from backend.app.services.explainability import ExplainabilityService


class UnsupportedAdditiveModel:
    """Small predict_proba fixture intentionally unsupported by TreeExplainer."""

    classes_ = np.asarray([0, 1])
    feature_importances_ = np.asarray([0.9, 0.8, 0.1])

    def predict_proba(self, X):
        values = np.asarray(X, dtype=float)
        positive = np.clip(0.5 + values[:, 0] * 0.1 - values[:, 1] * 0.1, 0, 1)
        return np.column_stack((1 - positive, positive))


def test_feature_ablation_reports_local_risk_directions() -> None:
    model = UnsupportedAdditiveModel()
    row = np.asarray([[2.0, 2.0, 1.0]])
    probability = float(model.predict_proba(row)[0, 1])

    explanation = ExplainabilityService().explain(
        model=model,
        transformed=row,
        feature_names=("raises_risk", "lowers_risk", "neutral"),
        feature_values={"raises_risk": 2.0, "lowers_risk": 2.0, "neutral": 1.0},
        baseline=np.zeros((1, 3)),
        positive_class_index=1,
        predicted_probability=probability,
    )

    assert explanation.method == "FEATURE_ABLATION"
    assert explanation.output_space == "probability_delta"
    assert explanation.increasing_risk[0].name == "raises_risk"
    assert explanation.increasing_risk[0].contribution == pytest.approx(0.2)
    assert explanation.decreasing_risk[0].name == "lowers_risk"
    assert explanation.decreasing_risk[0].contribution == pytest.approx(-0.2)
    assert "SHAP" in (explanation.limitation or "")


def test_shap_class_output_shapes_are_normalized() -> None:
    service = ExplainabilityService()
    old_style = [np.zeros((1, 3)), np.asarray([[0.3, -0.2, 0.1]])]
    new_style = np.asarray([[[0.0, 0.3], [0.0, -0.2], [0.0, 0.1]]])

    assert service._select_class_values(old_style, 3, 1).tolist() == [0.3, -0.2, 0.1]
    assert service._select_class_values(new_style, 3, 1).tolist() == [0.3, -0.2, 0.1]


def test_tree_model_uses_shap_when_dependency_is_installed() -> None:
    pytest.importorskip("shap")
    X = np.asarray([[0, 0], [0, 1], [1, 0], [1, 1]] * 8, dtype=float)
    y = np.asarray([0, 0, 1, 1] * 8)
    model = RandomForestClassifier(n_estimators=10, random_state=42).fit(X, y)
    row = np.asarray([[1.0, 0.0]])

    explanation = ExplainabilityService().explain(
        model=model,
        transformed=row,
        feature_names=("signal", "noise"),
        feature_values={"signal": 1.0, "noise": 0.0},
        baseline=np.asarray([[0.5, 0.5]]),
        positive_class_index=1,
        predicted_probability=float(model.predict_proba(row)[0, 1]),
    )

    assert explanation.method == "SHAP"
    assert explanation.output_space == "model_output"
    assert explanation.increasing_risk or explanation.decreasing_risk
