import os
import sys
from pathlib import Path

import pytest

from backend.app.services.pe_feature_extractor import (
    FeatureSchemaMismatchError,
    PEFeatureExtractionError,
    PEFeatureExtractor,
    validate_feature_schema,
)
from ml.malware.features import EMBER_V2_FEATURE_COUNT, EMBER_V3_FEATURE_COUNT, feature_names


def test_schema_validator_reports_missing_features() -> None:
    extracted = {"feature_a": 1.0}

    validation = validate_feature_schema(["feature_a", "feature_b"], extracted)

    assert validation.compatible is False
    assert validation.missing_features == ["feature_b"]
    assert validation.unexpected_features == []
    with pytest.raises(FeatureSchemaMismatchError, match="No zero-padding was applied"):
        validate_feature_schema(["feature_a", "feature_b"], extracted, raise_on_mismatch=True)


def test_rejects_non_pe_file(tmp_path: Path) -> None:
    text_file = tmp_path / "safe.txt"
    text_file.write_text("This is not executable code.", encoding="utf-8")

    with pytest.raises(PEFeatureExtractionError, match="MZ header"):
        PEFeatureExtractor().extract(text_file)


@pytest.mark.skipif(os.name != "nt", reason="Uses the installed benign Windows Python executable")
def test_extracts_safe_benign_python_pe_without_execution() -> None:
    sample = Path(sys.executable)
    before = sample.stat()

    result = PEFeatureExtractor().extract(sample)
    after = sample.stat()

    assert result.static_features["filename"] == sample.name
    assert result.static_features["file_size"] == sample.stat().st_size
    assert result.static_features["number_of_sections"] > 0
    assert result.static_features["number_of_imported_dlls"] >= 0
    assert result.static_features["maximum_section_entropy"] >= result.static_features["minimum_section_entropy"]
    assert len(result.sections) == result.static_features["number_of_sections"]
    assert len(result.model_features) == EMBER_V2_FEATURE_COUNT
    assert tuple(result.model_features) == feature_names(2)
    assert result.model_vector().shape == (EMBER_V2_FEATURE_COUNT,)
    assert after.st_size == before.st_size
    assert after.st_mtime_ns == before.st_mtime_ns


@pytest.mark.skipif(os.name != "nt", reason="Uses the installed benign Windows Python executable")
def test_extracts_ember2024_v3_features() -> None:
    sample = Path(sys.executable)
    result = PEFeatureExtractor().extract(sample, feature_version=3)

    assert result.schema == "EMBER-2024-2568"
    assert len(result.model_features) == EMBER_V3_FEATURE_COUNT
    assert tuple(result.model_features) == feature_names(3)
    assert result.model_vector().shape == (EMBER_V3_FEATURE_COUNT,)
