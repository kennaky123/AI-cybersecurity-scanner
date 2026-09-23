"""CLI for creating a model-ready phishing URL feature dataset."""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from .features import FEATURE_NAMES, extract_url_features
from .preprocessing import DatasetSummary, load_csv, validate_and_clean

DEFAULT_OUTPUT = Path("data/processed/phishing.csv")


def prepare_dataset(
    input_path: Path | list[Path],
    output_path: Path = DEFAULT_OUTPUT,
    *,
    url_column: str | None = None,
    label_column: str | None = None,
    label_scheme: str = "auto",
) -> tuple[pd.DataFrame, DatasetSummary]:
    inputs = [input_path] if isinstance(input_path, Path) else input_path
    all_cleaned: list[pd.DataFrame] = []
    total_samples = 0
    duplicate_removed = 0
    invalid_removed = 0

    for path in inputs:
        raw = load_csv(path)
        cleaned, summary = validate_and_clean(
            raw,
            url_column=url_column,
            label_column=label_column,
            label_scheme=label_scheme,  # type: ignore[arg-type]
        )
        all_cleaned.append(cleaned)
        total_samples += summary.total_samples
        duplicate_removed += summary.duplicate_removed
        invalid_removed += summary.invalid_removed

    combined = pd.concat(all_cleaned, ignore_index=True)
    cross_dup = combined.duplicated(subset="url", keep="first")
    duplicate_removed += int(cross_dup.sum())
    combined = combined.loc[~cross_dup].reset_index(drop=True)

    feature_rows = [extract_url_features(url) for url in combined["url"]]
    processed = pd.DataFrame(feature_rows, columns=FEATURE_NAMES)
    processed["label"] = combined["label"].to_numpy()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    processed.to_csv(output_path, index=False)

    final_summary = DatasetSummary(
        total_samples=total_samples,
        legitimate=int((combined["label"] == 0).sum()),
        phishing=int((combined["label"] == 1).sum()),
        duplicate_removed=duplicate_removed,
        invalid_removed=invalid_removed,
    )
    return processed, final_summary


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate phishing URL data and extract offline lexical features. No model is trained."
    )
    parser.add_argument("--input", nargs="+", required=True, type=Path, help="One or more paths to source CSVs.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help=f"Output CSV (default: {DEFAULT_OUTPUT}).")
    parser.add_argument("--url-column", help="URL column name; detected automatically when omitted.")
    parser.add_argument("--label-column", help="Label column name; detected automatically when omitted.")
    parser.add_argument(
        "--label-scheme",
        choices=("auto", "zero-one", "uci", "phiusiil"),
        default="auto",
        help="Label encoding. 'uci' maps -1 to phishing; 'phiusiil' maps 0 to phishing and 1 to legitimate.",
    )
    return parser


def _print_report(output_path: Path, summary: DatasetSummary) -> None:
    print("\nFeature list:")
    for index, name in enumerate(FEATURE_NAMES, start=1):
        print(f"  {index:2}. {name}")
    print("  label")

    print("\nDataset summary:")
    print(f"  Total samples:    {summary.total_samples}")
    print(f"  Legitimate:       {summary.legitimate}")
    print(f"  Phishing:         {summary.phishing}")
    print(f"  Duplicate removed:{summary.duplicate_removed:>8}")
    print(f"  Invalid removed:  {summary.invalid_removed:>8}")
    print(f"\nSaved processed dataset to: {output_path}")
    print("No model was trained.")


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    try:
        _, summary = prepare_dataset(
            args.input,
            args.output,
            url_column=args.url_column,
            label_column=args.label_column,
            label_scheme=args.label_scheme,
        )
    except (FileNotFoundError, ValueError) as error:
        parser.error(str(error))
    _print_report(args.output, summary)


if __name__ == "__main__":
    main()
