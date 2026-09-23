"""Read-only static feature extraction for Windows PE files.

The extractor only reads bytes and parses PE metadata with ``pefile``. It never
loads the file as a module, imports executable code, launches a process, or
invokes the operating system loader.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Sequence

import numpy as np
import pefile
from sklearn.feature_extraction import FeatureHasher

from ml.malware.features import EMBER_V2_FEATURE_COUNT, EMBER_V3_FEATURE_COUNT, feature_names


class PEFeatureExtractionError(ValueError):
    pass


class FeatureSchemaMismatchError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class SectionFeatures:
    name: str
    raw_size: int
    virtual_size: int
    entropy: float
    characteristics: list[str]


@dataclass(frozen=True, slots=True)
class SchemaValidation:
    compatible: bool
    expected_count: int
    extracted_count: int
    missing_features: list[str]
    unexpected_features: list[str]
    order_matches: bool


@dataclass(frozen=True, slots=True)
class PEFeatureResult:
    static_features: dict[str, object]
    sections: list[SectionFeatures]
    model_features: dict[str, float]
    schema: str
    extraction_notes: list[str]

    def model_vector(self, expected_features: Sequence[str] | None = None) -> np.ndarray:
        if expected_features is not None:
            expected = list(expected_features)
        elif len(self.model_features) == EMBER_V3_FEATURE_COUNT:
            expected = list(feature_names(3))
        else:
            expected = list(feature_names(2))
        validate_feature_schema(expected, self.model_features, raise_on_mismatch=True)
        return np.asarray([self.model_features[name] for name in expected], dtype=np.float32)


_ALL_STRINGS = re.compile(rb"[\x20-\x7f]{5,}")
_PATHS = re.compile(rb"c:\\", re.IGNORECASE)
_URLS = re.compile(rb"https?://", re.IGNORECASE)
_REGISTRY = re.compile(rb"HKEY_")
_MZ = re.compile(rb"MZ")


def _decode(value: bytes | None) -> str:
    if not value:
        return ""
    return value.decode("utf-8", errors="replace").rstrip("\x00")


def _flag_names(value: int, mapping: Mapping[int, str], prefix: str) -> list[str]:
    names = []
    for flag, raw_name in mapping.items():
        # pefile dictionaries expose both integer->name and name->integer entries.
        if isinstance(flag, int) and isinstance(raw_name, str) and flag and value & flag == flag:
            name = raw_name.removeprefix(prefix)
            if prefix == "IMAGE_FILE_" and name == "32BIT_MACHINE":
                name = "NEED_32BIT_MACHINE"
            if name == "AGGRESIVE_WS_TRIM":
                name = "AGGRESSIVE_WS_TRIM"
            names.append(name)
    return names


def _machine_name(machine: int) -> str:
    return pefile.MACHINE_TYPE.get(machine, f"UNKNOWN_{machine:#x}").removeprefix("IMAGE_FILE_MACHINE_")


def _subsystem_name(subsystem: int) -> str:
    return pefile.SUBSYSTEM_TYPE.get(subsystem, f"UNKNOWN_{subsystem:#x}").removeprefix("IMAGE_SUBSYSTEM_")


def _magic_name(magic: int) -> str:
    return {0x10B: "PE32", 0x20B: "PE32_PLUS", 0x107: "ROM"}.get(magic, f"UNKNOWN_{magic:#x}")


def _timestamp_utc(timestamp: int) -> str | None:
    try:
        return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return None


def _hash_strings(values: list[str], size: int) -> np.ndarray:
    return FeatureHasher(size, input_type="string").transform([values]).toarray()[0]


def _hash_pairs(values: list[tuple[str, float]], size: int) -> np.ndarray:
    return FeatureHasher(size, input_type="pair").transform([values]).toarray()[0]


def _byte_histogram(file_bytes: bytes) -> np.ndarray:
    counts = np.bincount(np.frombuffer(file_bytes, dtype=np.uint8), minlength=256).astype(np.float32)
    return counts / counts.sum()


def _entropy_bin_counts(block: np.ndarray, window: int = 2048) -> tuple[int, np.ndarray]:
    counts = np.bincount(block >> 4, minlength=16)
    probabilities = counts.astype(np.float32) / window
    nonzero = np.flatnonzero(counts)
    entropy = float(np.sum(-probabilities[nonzero] * np.log2(probabilities[nonzero]))) * 2
    entropy_bin = min(int(entropy * 2), 15)
    return entropy_bin, counts


def _byte_entropy_histogram(file_bytes: bytes, window: int = 2048, step: int = 1024) -> np.ndarray:
    byte_array = np.frombuffer(file_bytes, dtype=np.uint8)
    histogram = np.zeros((16, 16), dtype=np.float32)
    if len(byte_array) < window:
        entropy_bin, counts = _entropy_bin_counts(byte_array, window)
        histogram[entropy_bin] += counts
    else:
        for offset in range(0, len(byte_array) - window + 1, step):
            entropy_bin, counts = _entropy_bin_counts(byte_array[offset : offset + window], window)
            histogram[entropy_bin] += counts
    total = histogram.sum()
    if total <= 0:
        raise PEFeatureExtractionError("Unable to calculate byte entropy histogram.")
    return (histogram / total).reshape(-1)


def _string_features(file_bytes: bytes) -> tuple[np.ndarray, dict[str, int | float]]:
    strings = _ALL_STRINGS.findall(file_bytes)
    if strings:
        lengths = [len(value) for value in strings]
        average_length = sum(lengths) / len(lengths)
        shifted = np.frombuffer(b"".join(strings), dtype=np.uint8) - 0x20
        distribution = np.bincount(shifted, minlength=96).astype(np.float32)
        printable_count = int(distribution.sum())
        probabilities = distribution / printable_count
        nonzero = np.flatnonzero(distribution)
        entropy = float(np.sum(-probabilities[nonzero] * np.log2(probabilities[nonzero])))
    else:
        average_length = 0.0
        distribution = np.zeros(96, dtype=np.float32)
        printable_count = 0
        entropy = 0.0

    divisor = float(printable_count) if printable_count else 1.0
    statistics: dict[str, int | float] = {
        "number_of_strings": len(strings),
        "average_string_length": float(average_length),
        "printable_characters": printable_count,
        "string_entropy": entropy,
        "path_occurrences": len(_PATHS.findall(file_bytes)),
        "url_occurrences": len(_URLS.findall(file_bytes)),
        "registry_occurrences": len(_REGISTRY.findall(file_bytes)),
        "mz_occurrences": len(_MZ.findall(file_bytes)),
    }
    vector = np.hstack(
        [
            statistics["number_of_strings"],
            statistics["average_string_length"],
            statistics["printable_characters"],
            distribution / divisor,
            statistics["string_entropy"],
            statistics["path_occurrences"],
            statistics["url_occurrences"],
            statistics["registry_occurrences"],
            statistics["mz_occurrences"],
        ]
    ).astype(np.float32)
    return vector, statistics


def _directory_present(pe: pefile.PE, index_name: str) -> int:
    index = pefile.DIRECTORY_ENTRY[index_name]
    directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    return int(index < len(directories) and directories[index].Size > 0)


def _extract_imports(pe: pefile.PE) -> tuple[dict[str, list[str]], int]:
    imports: dict[str, list[str]] = {}
    function_count = 0
    for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        library = _decode(descriptor.dll)
        entries = imports.setdefault(library, [])
        for imported in descriptor.imports:
            if imported.name:
                name = _decode(imported.name)[:10000]
            else:
                name = f"ordinal{imported.ordinal}"
            entries.append(name)
            function_count += 1
    return imports, function_count


def _extract_exports(pe: pefile.PE) -> list[str]:
    export_directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if export_directory is None:
        return []
    return [_decode(symbol.name)[:10000] for symbol in export_directory.symbols if symbol.name]


def _sections(pe: pefile.PE) -> list[SectionFeatures]:
    sections = [
        SectionFeatures(
            name=_decode(section.Name),
            raw_size=int(section.SizeOfRawData),
            virtual_size=int(section.Misc_VirtualSize),
            entropy=float(section.get_entropy()),
            characteristics=_flag_names(
                int(section.Characteristics), pefile.SECTION_CHARACTERISTICS, "IMAGE_SCN_"
            ),
        )
        for section in pe.sections
    ]
    if not sections:
        raise PEFeatureExtractionError("PE contains no sections; entropy features are unavailable.")
    return sections


def _header_vector(pe: pefile.PE) -> np.ndarray:
    file_header = pe.FILE_HEADER
    optional = pe.OPTIONAL_HEADER
    characteristics = _flag_names(
        int(file_header.Characteristics), pefile.IMAGE_CHARACTERISTICS, "IMAGE_FILE_"
    )
    dll_characteristics = _flag_names(
        int(optional.DllCharacteristics), pefile.DLL_CHARACTERISTICS, "IMAGE_DLLCHARACTERISTICS_"
    )
    return np.hstack(
        [
            int(file_header.TimeDateStamp),
            _hash_strings([_machine_name(int(file_header.Machine))], 10),
            _hash_strings(characteristics, 10),
            _hash_strings([_subsystem_name(int(optional.Subsystem))], 10),
            _hash_strings(dll_characteristics, 10),
            _hash_strings([_magic_name(int(optional.Magic))], 10),
            int(optional.MajorImageVersion),
            int(optional.MinorImageVersion),
            int(optional.MajorLinkerVersion),
            int(optional.MinorLinkerVersion),
            int(optional.MajorOperatingSystemVersion),
            int(optional.MinorOperatingSystemVersion),
            int(optional.MajorSubsystemVersion),
            int(optional.MinorSubsystemVersion),
            int(optional.SizeOfCode),
            int(optional.SizeOfHeaders),
            int(optional.SizeOfHeapCommit),
        ]
    ).astype(np.float32)


def _section_vector(pe: pefile.PE, sections: list[SectionFeatures]) -> np.ndarray:
    entry_section = pe.get_section_by_rva(int(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
    if entry_section is not None:
        entry_name = _decode(entry_section.Name)
    else:
        executable = next((section for section in sections if "MEM_EXECUTE" in section.characteristics), None)
        entry_name = executable.name if executable else ""

    entry_characteristics = next(
        (section.characteristics for section in sections if section.name == entry_name), []
    )
    general = [
        len(sections),
        sum(section.raw_size == 0 for section in sections),
        sum(not section.name for section in sections),
        sum(
            "MEM_READ" in section.characteristics and "MEM_EXECUTE" in section.characteristics
            for section in sections
        ),
        sum("MEM_WRITE" in section.characteristics for section in sections),
    ]
    return np.hstack(
        [
            general,
            _hash_pairs([(section.name, section.raw_size) for section in sections], 50),
            _hash_pairs([(section.name, section.entropy) for section in sections], 50),
            _hash_pairs([(section.name, section.virtual_size) for section in sections], 50),
            _hash_strings([entry_name], 50),
            _hash_strings(entry_characteristics, 50),
        ]
    ).astype(np.float32)


def _imports_vector(imports: dict[str, list[str]]) -> np.ndarray:
    libraries = list({library.lower() for library in imports})
    functions = [
        f"{library.lower()}:{function}"
        for library, entries in imports.items()
        for function in entries
    ]
    return np.hstack([_hash_strings(libraries, 256), _hash_strings(functions, 1024)]).astype(np.float32)


def _data_directory_vector(pe: pefile.PE) -> np.ndarray:
    vector = np.zeros(30, dtype=np.float32)
    for index, directory in enumerate(pe.OPTIONAL_HEADER.DATA_DIRECTORY[:15]):
        vector[index * 2] = int(directory.Size)
        vector[index * 2 + 1] = int(directory.VirtualAddress)
    return vector


def validate_feature_schema(
    expected_features: Sequence[str],
    extracted_features: Mapping[str, float],
    *,
    raise_on_mismatch: bool = False,
) -> SchemaValidation:
    expected = list(expected_features)
    extracted = list(extracted_features)
    missing = [name for name in expected if name not in extracted_features]
    unexpected = [name for name in extracted if name not in set(expected)]
    order_matches = expected == extracted
    result = SchemaValidation(
        compatible=not missing and not unexpected and order_matches,
        expected_count=len(expected),
        extracted_count=len(extracted),
        missing_features=missing,
        unexpected_features=unexpected,
        order_matches=order_matches,
    )
    if raise_on_mismatch and not result.compatible:
        raise FeatureSchemaMismatchError(
            "PE feature schema mismatch: "
            f"expected={result.expected_count}, extracted={result.extracted_count}, "
            f"missing={missing[:10]}, unexpected={unexpected[:10]}, "
            f"order_matches={order_matches}. No zero-padding was applied."
        )
    return result


def expected_features_from_metadata(metadata_path: Path) -> list[str]:
    if not metadata_path.is_file():
        raise FileNotFoundError(f"Model metadata not found: {metadata_path}")
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Could not read model metadata: {error}") from error
    expected = metadata.get("feature_names")
    if not isinstance(expected, list) or not expected or not all(isinstance(name, str) for name in expected):
        raise ValueError("Model metadata does not contain a valid feature_names list.")
    return expected


class PEFeatureExtractor:
    """Extract descriptive and EMBER v2-compatible features using read-only parsing."""

    def extract(self, file_path: Path, feature_version: int = 2) -> PEFeatureResult:
        path = file_path.resolve()
        if not path.is_file():
            raise FileNotFoundError(f"PE file not found: {path}")
        try:
            file_bytes = path.read_bytes()
        except OSError as error:
            raise PEFeatureExtractionError(f"Could not read PE file: {error}") from error
        if not file_bytes.startswith(b"MZ"):
            raise PEFeatureExtractionError("File does not contain an MZ header.")

        try:
            pe = pefile.PE(data=file_bytes, fast_load=True)
            pe.parse_data_directories(
                directories=[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                ]
            )
        except pefile.PEFormatError as error:
            raise PEFeatureExtractionError(f"Invalid PE structure: {error}") from error

        try:
            sections = _sections(pe)
            imports, imported_function_count = _extract_imports(pe)
            exports = _extract_exports(pe)
            entropies = [section.entropy for section in sections]
            string_vector, string_statistics = _string_features(file_bytes)

            if feature_version == 3:
                try:
                    import thrember
                    v3_extractor = thrember.PEFeatureExtractor()
                    model_vector = v3_extractor.feature_vector(file_bytes)
                except Exception as error:
                    raise PEFeatureExtractionError(f"EMBER2024 feature extraction failed: {error}") from error
                if len(model_vector) != EMBER_V3_FEATURE_COUNT or not np.isfinite(model_vector).all():
                    raise PEFeatureExtractionError(
                        f"Extractor produced {len(model_vector)} features; expected {EMBER_V3_FEATURE_COUNT}."
                    )
                names = feature_names(3)
                model_features = {name: float(value) for name, value in zip(names, model_vector, strict=True)}
                validate_feature_schema(names, model_features, raise_on_mismatch=True)
                schema_name = "EMBER-2024-2568"
                notes = [
                    "Extracted 2,568 EMBER2024 features including RichHeader, Authenticode signatures, and PE format warnings.",
                    "EMBER feature version 3 (thrember) using pefile parser.",
                ]
            else:
                general_vector = np.asarray(
                    [
                        len(file_bytes),
                        int(pe.OPTIONAL_HEADER.SizeOfImage),
                        _directory_present(pe, "IMAGE_DIRECTORY_ENTRY_DEBUG"),
                        len(exports),
                        imported_function_count,
                        _directory_present(pe, "IMAGE_DIRECTORY_ENTRY_BASERELOC"),
                        _directory_present(pe, "IMAGE_DIRECTORY_ENTRY_RESOURCE"),
                        _directory_present(pe, "IMAGE_DIRECTORY_ENTRY_SECURITY"),
                        _directory_present(pe, "IMAGE_DIRECTORY_ENTRY_TLS"),
                        int(pe.FILE_HEADER.NumberOfSymbols),
                    ],
                    dtype=np.float32,
                )
                model_vector = np.hstack(
                    [
                        _byte_histogram(file_bytes),
                        _byte_entropy_histogram(file_bytes),
                        string_vector,
                        general_vector,
                        _header_vector(pe),
                        _section_vector(pe, sections),
                        _imports_vector(imports),
                        _hash_strings(exports, 128).astype(np.float32),
                        _data_directory_vector(pe),
                    ]
                ).astype(np.float32)
                if len(model_vector) != EMBER_V2_FEATURE_COUNT or not np.isfinite(model_vector).all():
                    raise PEFeatureExtractionError(
                        f"Extractor produced {len(model_vector)} features; expected {EMBER_V2_FEATURE_COUNT}."
                    )

                names = feature_names(2)
                model_features = {name: float(value) for name, value in zip(names, model_vector, strict=True)}
                validate_feature_schema(names, model_features, raise_on_mismatch=True)
                schema_name = "EMBER-v2-2381"
                notes = [
                    "Optional PE structures that are genuinely absent map to zero-valued EMBER blocks by schema definition.",
                    "No missing expected feature is silently zero-padded; schema mismatch raises FeatureSchemaMismatchError.",
                    "EMBER reference data used LIEF; this pefile backend reproduces its 2,381-position layout, but parser-specific categorical differences may affect hashed bins.",
                ]

            timestamp = int(pe.FILE_HEADER.TimeDateStamp)
            formatted_timestamp = _timestamp_utc(timestamp)
            static_features: dict[str, object] = {
                "filename": path.name,
                "sha256": hashlib.sha256(file_bytes).hexdigest(),
                "file_size": len(file_bytes),
                "machine_type": _machine_name(int(pe.FILE_HEADER.Machine)),
                "timestamp": timestamp,
                "timestamp_utc": formatted_timestamp,
                "number_of_sections": len(sections),
                "entry_point": int(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                "image_base": int(pe.OPTIONAL_HEADER.ImageBase),
                "size_of_image": int(pe.OPTIONAL_HEADER.SizeOfImage),
                "size_of_headers": int(pe.OPTIONAL_HEADER.SizeOfHeaders),
                "subsystem": _subsystem_name(int(pe.OPTIONAL_HEADER.Subsystem)),
                "dll_characteristics": _flag_names(
                    int(pe.OPTIONAL_HEADER.DllCharacteristics),
                    pefile.DLL_CHARACTERISTICS,
                    "IMAGE_DLLCHARACTERISTICS_",
                ),
                "number_of_imported_dlls": len(imports),
                "number_of_imported_functions": imported_function_count,
                "number_of_exports": len(exports),
                "average_section_entropy": float(sum(entropies) / len(entropies)),
                "maximum_section_entropy": float(max(entropies)),
                "minimum_section_entropy": float(min(entropies)),
                "string_statistics": string_statistics,
            }
            if formatted_timestamp is None:
                notes.append("The raw PE timestamp is outside the platform datetime range; timestamp_utc is null.")
            return PEFeatureResult(static_features, sections, model_features, schema_name, notes)
        except (AttributeError, KeyError, OverflowError, ValueError) as error:
            if isinstance(error, (PEFeatureExtractionError, FeatureSchemaMismatchError)):
                raise
            raise PEFeatureExtractionError(f"Required PE feature is unavailable: {error}") from error
        finally:
            pe.close()

    def extract_and_validate(self, file_path: Path, metadata_path: Path) -> PEFeatureResult:
        expected = expected_features_from_metadata(metadata_path)
        feature_version = 3 if len(expected) == EMBER_V3_FEATURE_COUNT else 2
        result = self.extract(file_path, feature_version=feature_version)
        validate_feature_schema(expected, result.model_features, raise_on_mismatch=True)
        return result
