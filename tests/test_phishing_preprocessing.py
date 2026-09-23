from pathlib import Path

import pandas as pd

from ml.phishing.features import FEATURE_NAMES
from ml.phishing.prepare_dataset import prepare_dataset
from ml.phishing.preprocessing import validate_and_clean


def test_validation_summary_and_label_normalization() -> None:
    frame = pd.DataFrame(
        {
            "URL": [
                "https://example.com",
                "https://phish.test/login",
                "https://example.com",
                "not a url",
                "https://unknown.test",
            ],
            "status": ["legitimate", "phishing", "legitimate", "phishing", "unknown"],
        }
    )

    cleaned, summary = validate_and_clean(frame)

    assert cleaned["label"].tolist() == [0, 1]
    assert summary.total_samples == 5
    assert summary.legitimate == 1
    assert summary.phishing == 1
    assert summary.duplicate_removed == 1
    assert summary.invalid_removed == 2


def test_uci_minus_one_label_is_mapped_to_phishing() -> None:
    frame = pd.DataFrame({"url": ["safe.test", "phish.test"], "Result": [1, -1]})

    cleaned, summary = validate_and_clean(frame)

    assert cleaned["label"].tolist() == [0, 1]
    assert summary.legitimate == 1
    assert summary.phishing == 1


def test_phiusiil_zero_one_labels_are_inverted_to_project_convention() -> None:
    frame = pd.DataFrame(
        {"URL": ["https://legitimate.example", "https://phishing.example/login"], "label": [1, 0]}
    )

    cleaned, summary = validate_and_clean(frame, label_scheme="phiusiil")

    assert cleaned["label"].tolist() == [0, 1]
    assert summary.legitimate == 1
    assert summary.phishing == 1


def test_prepare_dataset_writes_features_and_label(tmp_path: Path) -> None:
    source = tmp_path / "source.csv"
    output = tmp_path / "processed" / "phishing.csv"
    pd.DataFrame(
        {"url": ["https://example.com", "http://login.bad.test"], "label": [0, 1]}
    ).to_csv(source, index=False)

    processed, _ = prepare_dataset(source, output)

    assert output.is_file()
    assert processed.columns.tolist() == [*FEATURE_NAMES, "label"]
    assert processed["label"].tolist() == [0, 1]
