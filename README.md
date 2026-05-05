# PE Parser

A Python library for parsing and extracting machine-learning features from Windows Portable Executable (PE) files. Built from scratch using only the Python standard library — no `pefile` dependency.

## Overview

PE Parser reads raw binary PE files (`.exe`, `.dll`) and extracts structured features from their headers, sections, import tables, and embedded strings. It was built to support static malware analysis and ML-based malware detection research, though it is equally useful for general reverse engineering and security tooling.

## Features

| Category | What is extracted |
|---|---|
| **Headers** | ASLR/NX/DEP flags, subsystem, linker version, timestamp, entry point section, image size, section count |
| **Sections** | Mean/max entropy, high-entropy section count, executable/writable sections, zero-raw-size sections, largest section size ratio |
| **Imports** | DLL count, total import count, ordinal imports, and boolean flags for 10 suspicious API categories |
| **Strings** | String count, total and mean length, presence of URLs, IPs, registry paths, and Base64 blobs |

### Suspicious API Categories

The import extractor classifies imports against a curated API list across 10 behavioural categories: networking, registry, cryptography, process injection, anti-debugging, anti-analysis, keylogging, persistence, file system, and privilege escalation.

## Installation

```bash
git clone <repository-url>
cd pe-parser
```

No external dependencies are required. Python 3.10+ is recommended (uses `match` syntax internally and `dict | dict` merging).

## Usage

### Single File — Human-Readable Output

```bash
python main.py --file path/to/sample.exe --all
```

You can also select individual extractor groups:

```bash
python main.py --file sample.exe --headers --imports
python main.py --file sample.exe --sections --strings
```

### Batch Mode — CSV Feature Extraction

Process an entire directory and write results to a CSV:

```bash
python main.py --dir samples/malware/ --output malware.csv
python main.py --dir samples/benign/ --output benign.csv -r   # -r for recursive
```

Each row in the output CSV corresponds to one successfully parsed PE file. Files that fail to parse (invalid signature, truncated, etc.) are silently skipped.

### Dataset Labelling

After batch extraction, use `labeling.py` to merge and label the two CSVs:

```bash
python labeling.py
```

This reads `output/malware.csv` and `output/benign.csv`, assigns labels (`1` = malicious, `0` = benign), shuffles the dataset, and writes the combined result to `output/features.csv`.

### Using as a Library

```python
from pe_parser.unpacker import Unpacker
from pe_parser.headers_feature_extractor import HeadersFeatureExtractor
from pe_parser.section_feature_extractor import SectionFeatureExtractor
from pe_parser.import_feature_extractor import ImportFeatureExtractor
from pe_parser.string_feature_extractor import StringFeatureExtractor

with Unpacker("sample.exe") as unpacker:
    headers  = HeadersFeatureExtractor(unpacker).extract_features()
    sections = SectionFeatureExtractor(unpacker).extract_analysis_features()
    imports  = ImportFeatureExtractor(unpacker).export_import_features()
    strings  = StringFeatureExtractor(unpacker).extract_string_features()

    all_features = headers | sections | imports | strings
```

The `Unpacker` class is a context manager and handles file opening and closing. All extractor methods return plain `dict[str, float | int | bool]` objects with consistent keys, making them straightforward to feed into pandas or any ML pipeline.

## Project Structure

```
pe-parser/
├── main.py                              # CLI entry point (single file & batch modes)
├── labeling.py                          # Merges malware/benign CSVs and assigns labels
│
└── pe_parser/
    ├── __init__.py                      # Public API surface
    ├── models.py                        # SectionHeader, ImageImportDescriptor dataclasses
    ├── unpacker.py                      # Core binary parser — reads all PE structures
    ├── analyzer.py                      # process_file() wrapper with per-extractor error handling
    ├── orchestrator.py                  # Directory walker for batch mode
    ├── entropy_calculator.py            # Shannon entropy over raw section bytes
    ├── headers_feature_extractor.py     # COFF + optional header features
    ├── section_feature_extractor.py     # Section table features
    ├── import_feature_extractor.py      # Import table + suspicious API classification
    ├── string_feature_extractor.py      # Printable string scan via mmap
    │
    └── constants/
        ├── header_constants.py          # struct format strings and field name lists
        └── suspicious_apis_constants.py # Curated API → behavioural category mapping
```

## Feature Reference

### Header Features

| Feature | Type | Description |
|---|---|---|
| `has_debug_stripped` | bool | COFF `IMAGE_FILE_DEBUG_STRIPPED` flag set |
| `dll_characteristics_nx` | bool | NX/DEP (`IMAGE_DLLCHARACTERISTICS_NX_COMPAT`) enabled |
| `dll_characteristics_aslr` | bool | ASLR (`IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`) enabled |
| `subsystem` | int | Windows subsystem (2=GUI, 3=Console, etc.) |
| `major_linker_version` | int | Linker version from optional header |
| `timestamp_year` | int | Year derived from COFF timestamp (0 if zeroed) |
| `timestamp_is_zero` | bool | Timestamp field is exactly zero |
| `entry_point_in_unusual_section` | bool | Entry point RVA does not fall in `.text` or `.code` |
| `size_of_image` | int | Total virtual size of the loaded image in bytes |
| `number_of_sections` | int | Count of PE section headers |
| `is_dll` | bool | File extension is `.dll` (set by orchestrator) |

### Section Features

| Feature | Type | Description |
|---|---|---|
| `mean_section_entropy` | float | Average Shannon entropy across all non-empty sections |
| `max_section_entropy` | float | Highest entropy of any single section |
| `high_entropy_section_count` | int | Sections with entropy > 7.0 (packed/encrypted indicator) |
| `executable_sections_count` | int | Sections with the `IMAGE_SCN_MEM_EXECUTE` flag |
| `writeable_executable_sections` | int | Sections that are both writable and executable (W^X violation) |
| `sections_with_zero_raw_size` | int | Sections with `SizeOfRawData == 0` (expanded at runtime) |
| `largest_section_size_ratio` | float | Largest section virtual size as a fraction of total |

### Import Features

| Feature | Type | Description |
|---|---|---|
| `import_dll_count` | int | Number of imported DLLs |
| `total_import_count` | int | Total imported functions (named + ordinal) |
| `import_ordinal_count` | int | Functions imported by ordinal only |
| `has_any_ordinal_imports` | bool | Any ordinal imports present |
| `ordinal_import_ratio` | float | Fraction of imports that are ordinal |
| `imports_networking` | bool | Imports Winsock / WinINet / WinHTTP / DNS APIs |
| `imports_registry` | bool | Imports registry read/write APIs |
| `imports_cryptography` | bool | Imports CryptoAPI or BCrypt APIs |
| `imports_process_injection` | bool | Imports remote memory / thread APIs |
| `imports_anti_debugging` | bool | Imports debugger detection APIs |
| `imports_anti_analysis` | bool | Imports VM/sandbox evasion APIs |
| `imports_keylogging` | bool | Imports keyboard hook or clipboard APIs |
| `imports_persistence` | bool | Imports service or DLL hijacking APIs |
| `imports_file_system` | bool | Imports file enumeration/write APIs |
| `imports_privilege_escalation` | bool | Imports token manipulation APIs |

### String Features

| Feature | Type | Description |
|---|---|---|
| `string_count` | int | Number of printable ASCII strings ≥ 4 characters |
| `total_string_length` | int | Sum of all string lengths in bytes |
| `mean_string_length` | float | Average string length |
| `has_url_strings` | bool | Any string contains `http://` or `https://` |
| `has_ip_strings` | bool | Any string matches an IPv4 address pattern |
| `has_registry_strings` | bool | Any string contains registry path prefixes |
| `has_base64_strings` | bool | Any string matches a Base64 pattern (≥ 32 chars) |

## Error Handling

`analyzer.py` wraps each extractor in `safe_extract()`. If any individual extractor raises an exception (e.g. a malformed import table), that extractor's output is replaced with a set of sentinel defaults (typically `-1` for numeric fields, `False` for booleans). This means a single corrupt section or import table will not discard the entire file's features.

Files that fail at the `Unpacker` level (missing PE signature, read errors) return `None` from `process_file()` and are excluded from batch output entirely.

## PE Format Support

- PE32 (32-bit) and PE32+ (64-bit) executables
- Handles both named and ordinal imports
- RVA-to-file-offset conversion handles all standard section layouts
- String extraction uses `mmap` for memory-efficient scanning of large binaries

## References

- [Microsoft PE Format Specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [COFF Header Reference](https://learn.microsoft.com/en-us/windows/win32/api/winnt/)
