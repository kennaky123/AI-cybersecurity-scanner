from __future__ import annotations

import logging
import json
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from urllib.parse import urlsplit

from ml.phishing.features import FEATURE_NAMES

from .feature_extractor import FeatureExtractor
from .artifact_validation import validate_artifact_bundle, validate_artifact_hashes
from .explainability import ExplainabilityService, ModelExplanation
from .risk_engine import RiskEngine

logger = logging.getLogger(__name__)
PROJECT_ROOT = Path(__file__).resolve().parents[3]

# ==============================================================================
# 1. DOMAIN TRUST GUARD (LỚP PHÒNG THỦ THEO CHIỀU SÂU CHO CÁC TÊN MIỀN UY TÍN)
# ==============================================================================
# Các mô hình học máy từ vựng (lexical ML) chỉ đếm ký tự (số lượng '/', chữ số, tham số).
# Khi người dùng copy link thật từ trình duyệt (như link tin nhắn Facebook, video YouTube,
# bài báo UCI, ChatGPT), URL thường có ID dài hoặc tham số truy vấn.
# Lớp Trust Guard kiểm tra: nếu tên miền gốc thuộc danh sách uy tín và chạy trên HTTPS hợp lệ,
# hệ thống sẽ bảo vệ để không bị cảnh báo nhầm (false positive), đồng thời giải thích rõ ràng.
# Lưu ý: Các tên miền giả mạo (ví dụ: facebook.com.scam.xyz) có domain gốc là scam.xyz,
# nên sẽ bị Trust Guard loại bỏ và quét nghiêm ngặt qua mô hình ML.
TRUSTED_AUTHORITATIVE_DOMAINS: frozenset[str] = frozenset({
    "chatgpt.com",
    "openai.com",
    "claude.ai",
    "anthropic.com",
    "deepseek.com",
    "facebook.com",
    "youtube.com",
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "github.com",
    "gitlab.com",
    "linkedin.com",
    "twitter.com",
    "x.com",
    "instagram.com",
    "tiktok.com",
    "netflix.com",
    "spotify.com",
    "reddit.com",
    "wikipedia.org",
    "wikimedia.org",
    "stackoverflow.com",
    "notion.so",
    "dropbox.com",
    "slack.com",
    "zoom.us",
    "cloudflare.com",
    "uci.edu",
    "mit.edu",
    "harvard.edu",
    "stanford.edu",
    "berkeley.edu",
    "python.org",
    "pypi.org",
    "kaggle.com",
    "huggingface.co",
    "sciencedirect.com",
    "arxiv.org",
    "vnexpress.net",
    "tuoitre.vn",
    "dantri.com.vn",
    "zalo.me",
})


def _evaluate_domain_trust(url: str, features: dict[str, int | float]) -> tuple[bool, str | None]:
    """Kiểm tra xem URL có thuộc tên miền uy tín đã được xác thực qua HTTPS hay không."""
    # Bắt buộc phải dùng HTTPS chuẩn, không chứa IP, ký tự '@' hay cổng lạ
    if features.get("uses_https") != 1:
        return False, None
    if features.get("contains_ip_address", 0) != 0:
        return False, None
    if features.get("contains_at_symbol", 0) != 0:
        return False, None
    if features.get("contains_suspicious_port", 0) != 0:
        return False, None

    try:
        parsed = urlsplit(url if "://" in url else f"https://{url}")
        hostname = (parsed.hostname or "").lower().rstrip(".")
    except Exception:
        return False, None

    if not hostname:
        return False, None

    # Khớp chính xác tên miền hoặc subdomain hợp lệ (ví dụ: messages.facebook.com)
    for domain in TRUSTED_AUTHORITATIVE_DOMAINS:
        if hostname == domain or hostname.endswith("." + domain):
            return True, domain

    # Tự động nhận diện các tổ chức giáo dục (.edu) và chính phủ (.gov)
    if hostname.endswith(".edu") or hostname.endswith(".gov"):
        parts = hostname.split(".")
        if len(parts) >= 2 and all(parts):
            return True, ".".join(parts[-2:])

    return False, None



class ModelUnavailableError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class PhishingAnalysis:
    url: str
    prediction: str
    probability: float
    risk_score: int
    risk_level: str
    features: dict[str, int | float]
    reasons: list[str]
    explanation: ModelExplanation = field(default_factory=ModelExplanation.unavailable)


class PhishingDetector:
    """Load trusted local artifacts and perform deterministic model inference."""

    def __init__(
        self,
        model_path: Path | None = None,
        preprocessor_path: Path | None = None,
        metadata_path: Path | None = None,
    ) -> None:
        models_dir = PROJECT_ROOT / "models"
        self.model_path = model_path or models_dir / "phishing_model.joblib"
        self.preprocessor_path = preprocessor_path or models_dir / "phishing_preprocessor.joblib"
        self.metadata_path = metadata_path or models_dir / "phishing_model_metadata.json"
        self._model: Any | None = None
        self._preprocessor: Any | None = None
        self._artifact_signature: tuple[int, ...] | None = None
        self._lock = threading.Lock()
        self._feature_extractor = FeatureExtractor()
        self._risk_engine = RiskEngine()
        self._explainability = ExplainabilityService()

    def _signature(self) -> tuple[int, ...]:
        paths = (self.model_path, self.preprocessor_path, self.metadata_path)
        if any(not path.is_file() for path in paths):
            raise ModelUnavailableError("Phishing model unavailable. Train model first.")
        return tuple(value for path in paths for value in (path.stat().st_mtime_ns, path.stat().st_size))

    def _load_artifacts(self) -> tuple[Any, Any]:
        try:
            signature = self._signature()
            with self._lock:
                if self._model is None or self._preprocessor is None or signature != self._artifact_signature:
                    # joblib files are trusted, locally generated project artifacts.
                    metadata = json.loads(self.metadata_path.read_text(encoding="utf-8"))
                    validate_artifact_hashes(metadata, self.model_path, self.preprocessor_path)
                    model = joblib.load(self.model_path)
                    preprocessor = joblib.load(self.preprocessor_path)
                    if not hasattr(model, "predict_proba") or not hasattr(preprocessor, "transform"):
                        raise TypeError("Artifact interface is invalid.")
                    validate_artifact_bundle(
                        metadata=metadata,
                        model=model,
                        preprocessor=preprocessor,
                        expected_features=FEATURE_NAMES,
                        feature_metadata_key="features",
                        model_path=self.model_path,
                        preprocessor_path=self.preprocessor_path,
                    )
                    self._model = model
                    self._preprocessor = preprocessor
                    self._artifact_signature = signature
                return self._model, self._preprocessor
        except ModelUnavailableError:
            raise
        except Exception as error:
            logger.exception("Unable to load phishing model artifacts")
            raise ModelUnavailableError("Phishing model unavailable. Train model first.") from error

    @staticmethod
    def _important_feature_reasons(model: Any, features: dict[str, int | float]) -> list[str]:
        raw_importances = getattr(model, "feature_importances_", None)
        if raw_importances is None or len(raw_importances) != len(FEATURE_NAMES):
            return []

        importances = np.asarray(raw_importances, dtype=float)
        top_indices = np.argsort(importances)[::-1]
        reasons: list[str] = []
        for index in top_indices:
            importance = float(importances[index])
            if importance <= 0 or len(reasons) == 3:
                break
            name = FEATURE_NAMES[int(index)]
            reasons.append(
                f"{name}={features[name]} (global model importance {importance:.3f})"
            )
        return reasons

    def analyze(self, url: str) -> PhishingAnalysis:
        # BƯỚC 1: Tải mô hình và bộ tiền xử lý từ disk (kiểm tra hash SHA-256 chống can thiệp)
        model, preprocessor = self._load_artifacts()

        # BƯỚC 2: Trích xuất 18 đặc trưng từ vựng offline (không gửi request mạng đến trang đích)
        features = self._feature_extractor.extract_url_features(url)
        feature_frame = pd.DataFrame([features], columns=FEATURE_NAMES)
        transformed = preprocessor.transform(feature_frame)

        # BƯỚC 3: Dự đoán xác suất lừa đảo qua mô hình học máy (LightGBM/Random Forest)
        probabilities = np.asarray(model.predict_proba(transformed), dtype=float)
        classes = np.asarray(getattr(model, "classes_", []))
        phishing_columns = np.flatnonzero(classes == 1)
        if probabilities.shape[0] != 1 or len(phishing_columns) != 1 or not np.isfinite(probabilities).all():
            raise ModelUnavailableError("Phishing model unavailable. Train model first.")
        phishing_column = int(phishing_columns[0])
        probability = float(probabilities[0, phishing_column])
        if not 0.0 <= probability <= 1.0:
            raise ModelUnavailableError("Phishing model unavailable. Train model first.")

        # BƯỚC 4: Áp dụng Domain Trust Guard (bảo vệ tên miền uy tín chính chủ trên HTTPS)
        is_trusted, trusted_domain = _evaluate_domain_trust(url, features)
        if is_trusted and trusted_domain:
            probability = min(probability * 0.1, 0.15)

        # BƯỚC 5: Tính toán điểm rủi ro (Risk Score: 0-100) và cấp độ rủi ro (LOW, MEDIUM, HIGH, CRITICAL)
        risk = self._risk_engine.calculate(probability)
        prediction = "PHISHING" if probability >= 0.5 else "LEGITIMATE"

        # BƯỚC 6: Tính toán giải thích AI (XAI) bằng giá trị SHAP (TreeExplainer)
        explanation = self._explainability.explain(
            model=model,
            transformed=transformed,
            feature_names=FEATURE_NAMES,
            feature_values=features,
            baseline=self._baseline(preprocessor, transformed),
            positive_class_index=phishing_column,
            predicted_probability=probability,
        )

        # BƯỚC 7: Thu thập các lý do quan trọng nhất và ghi nhận bảo vệ từ Domain Trust Guard
        reasons = self._important_feature_reasons(model, features)
        if is_trusted and trusted_domain:
            reasons.insert(0, f"Domain Trust Guard: {trusted_domain} is a verified authoritative domain (HTTPS).")

        return PhishingAnalysis(
            url=url,
            prediction=prediction,
            probability=probability,
            risk_score=risk.score,
            risk_level=risk.level,
            features=features,
            reasons=reasons,
            explanation=explanation,
        )

    @staticmethod
    def _baseline(preprocessor: Any, transformed: Any) -> np.ndarray:
        try:
            numeric = preprocessor.named_transformers_["numeric"]
            statistics = np.asarray(numeric.statistics_, dtype=float)
            baseline_frame = pd.DataFrame([statistics], columns=FEATURE_NAMES)
            return np.asarray(preprocessor.transform(baseline_frame), dtype=float)
        except (AttributeError, KeyError, TypeError, ValueError):
            return np.zeros_like(np.asarray(transformed, dtype=float))

    def predict(self, url: str) -> None:
        raise NotImplementedError("Phishing detection is planned for a later phase.")
