# Safe local scanner fixtures

These files are harmless fixtures for testing upload and validation behavior. They are not malware.

- `benign_python.exe`: a copy of the project virtual environment's Python launcher. Expected: HTTP 200, usually `BENIGN`.
- `benign_notepad.exe`: a copy of Windows Notepad. Expected: HTTP 200, usually `BENIGN`.
- `not_a_pe.exe`: text with an `.exe` suffix and no MZ signature. Expected: HTTP 422, missing MZ signature.
- `fake_mz.exe`: starts with `MZ` but has no valid PE structure. Expected: HTTP 422, invalid PE structure.
- `oversized.exe`: harmless 26 MB zero-filled fixture. Expected: HTTP 413 before PE parsing.

Do not use unknown malware samples for a classroom demo. A `MALWARE` response must come from a real, authorized labeled PE sample; the application deliberately has no fake-positive mode.

