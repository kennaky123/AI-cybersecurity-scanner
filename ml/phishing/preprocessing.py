"""CSV loading, validation, and label normalization for phishing URL data."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import pandas as pd

from .features import is_valid_url

LabelScheme = Literal["auto", "zero-one", "uci", "phiusiil"]

URL_COLUMN_CANDIDATES = ("url", "website", "link", "uri", "web_address", "webaddress")
LABEL_COLUMN_CANDIDATES = ("label", "class", "status", "type", "result", "category", "target")

LEGITIMATE_LABELS = {"0", "legitimate", "legit", "benign", "safe", "good", "normal", "false"}
PHISHING_LABELS = {"1", "phishing", "phish", "malicious", "fraud", "bad", "true"}


@dataclass(frozen=True, slots=True)
class DatasetSummary:
    total_samples: int
    legitimate: int
    phishing: int
    duplicate_removed: int
    invalid_removed: int


def load_csv(input_path: Path) -> pd.DataFrame:
    if not input_path.is_file():
        raise FileNotFoundError(f"Input CSV not found: {input_path}")
    try:
        return pd.read_csv(input_path)
    except (UnicodeDecodeError, pd.errors.ParserError) as error:
        raise ValueError(f"Could not read CSV: {error}") from error


def resolve_column(frame: pd.DataFrame, requested: str | None, candidates: tuple[str, ...], kind: str) -> str:
    columns_by_lowercase = {str(column).strip().lower(): str(column) for column in frame.columns}
    if requested:
        match = columns_by_lowercase.get(requested.strip().lower())
        if match is None:
            raise ValueError(f"{kind} column '{requested}' was not found. Available: {list(frame.columns)}")
        return match

    for candidate in candidates:
        if candidate in columns_by_lowercase:
            return columns_by_lowercase[candidate]
    raise ValueError(
        f"Could not detect the {kind} column. Use --{kind}-column. "
        f"Available columns: {list(frame.columns)}"
    )


def _uses_uci_numeric_labels(values: pd.Series, scheme: LabelScheme) -> bool:
    if scheme == "uci":
        return True
    if scheme == "zero-one":
        return False
    normalized = {str(value).strip().lower() for value in values.dropna()}
    return "-1" in normalized or "-1.0" in normalized


def normalize_label(
    value: object,
    *,
    uci_numeric_labels: bool = False,
    phiusiil_numeric_labels: bool = False,
) -> int | None:
    if pd.isna(value):
        return None

    normalized = str(value).strip().lower()
    if normalized.endswith(".0"):
        normalized = normalized[:-2]

    if uci_numeric_labels:
        if normalized == "-1":
            return 1
        if normalized == "1":
            return 0

    if phiusiil_numeric_labels:
        if normalized == "0":
            return 1
        if normalized == "1":
            return 0

    if normalized in LEGITIMATE_LABELS:
        return 0
    if normalized in PHISHING_LABELS:
        return 1
    return None


def validate_and_clean(
    frame: pd.DataFrame,
    *,
    url_column: str | None = None,
    label_column: str | None = None,
    label_scheme: LabelScheme = "auto",
) -> tuple[pd.DataFrame, DatasetSummary]:
    if frame.empty:
        raise ValueError("Input dataset is empty.")

    resolved_url = resolve_column(frame, url_column, URL_COLUMN_CANDIDATES, "url")
    resolved_label = resolve_column(frame, label_column, LABEL_COLUMN_CANDIDATES, "label")
    total_samples = len(frame)

    working = frame[[resolved_url, resolved_label]].copy()
    working.columns = ["url", "raw_label"]
    working["url"] = working["url"].map(lambda value: value.strip() if isinstance(value, str) else value)

    duplicate_mask = working["url"].notna() & working.duplicated(subset="url", keep="first")
    duplicate_removed = int(duplicate_mask.sum())
    working = working.loc[~duplicate_mask].copy()

    use_uci = _uses_uci_numeric_labels(working["raw_label"], label_scheme)
    working["label"] = working["raw_label"].map(
        lambda value: normalize_label(
            value,
            uci_numeric_labels=use_uci,
            phiusiil_numeric_labels=label_scheme == "phiusiil",
        )
    )
    valid_mask = working["url"].map(is_valid_url) & working["label"].notna()
    invalid_removed = int((~valid_mask).sum())
    cleaned = working.loc[valid_mask, ["url", "label"]].copy()
    cleaned["label"] = cleaned["label"].astype("int8")

    summary = DatasetSummary(
        total_samples=total_samples,
        legitimate=int((cleaned["label"] == 0).sum()),
        phishing=int((cleaned["label"] == 1).sum()),
        duplicate_removed=duplicate_removed,
        invalid_removed=invalid_removed,
    )
    return cleaned.reset_index(drop=True), summary
