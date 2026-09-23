from pathlib import Path
from typing import TYPE_CHECKING

from ml.phishing.features import extract_url_features

if TYPE_CHECKING:
    from .pe_feature_extractor import PEFeatureResult


class FeatureExtractor:
    """Feature extraction facade shared by API services."""

    def extract_url_features(self, url: str) -> dict[str, int | float]:
        return extract_url_features(url)

    def extract_pe_features(self, file_path: Path) -> "PEFeatureResult":
        # Lazy import keeps phishing-only API startup independent of PE parsing.
        from .pe_feature_extractor import PEFeatureExtractor

        return PEFeatureExtractor().extract(file_path)
