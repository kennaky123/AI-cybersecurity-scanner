from pathlib import Path


def is_pe_file(file_path: Path) -> bool:
    """Check only the DOS header signature; full PE parsing belongs to a later phase."""
    try:
        with file_path.open("rb") as file:
            return file.read(2) == b"MZ"
    except OSError:
        return False

