# PE Parser

A Python library for parsing and analyzing Portable Executable (PE) files, commonly used in Windows executables and DLLs.

## Overview

PE Parser provides tools to extract and analyze the structure of PE files, including headers, sections, and import tables. This is useful for reverse engineering, malware analysis, security research, and understanding Windows executable formats.

## Features

- **DOS Header Parsing**: Extract MS-DOS stub header information
- **NT Headers Parsing**: Parse PE signature, COFF header, and optional header
- **Section Headers**: Read and analyze section table entries
- **Import Directory Table**: Extract imported DLL names and functions
- **RVA to File Offset Conversion**: Utility to convert Relative Virtual Addresses to file offsets
- **DLL Characteristics Analysis**: Parse and display security and compatibility flags

## Installation

Clone the repository and ensure you have Python 3.x installed:

```bash
git clone <repository-url>
cd pe-parser
```

No external dependencies are required - the parser uses only Python standard library modules.

## Usage

### Basic Usage

Run the main script and provide a path to a PE file:

```bash
python main.py
```

When prompted, enter the path to a PE file (`.exe`, `.dll`, etc.):

```
Enter the path to the file: path/to/file.exe
```

### Example Output

The parser will display:
- Linking/compilation timestamp
- Optional header details (entry point, image base, subsystem, etc.)
- DLL characteristics flags (ASLR, DEP, CFG, etc.)
- Section headers information
- Import table with DLL names and function addresses

### Using as a Library

```python
import pe_parser
from pe_parser.unpackers import DOS_header_unpack, optional_header_unpack
from pe_parser.utils import rva_to_file_offset

# Read and parse DOS header
with open('example.exe', 'rb') as f:
    dos_header = f.read(64)
    dos_data = DOS_header_unpack(dos_header)
    print(f"PE offset: {dos_data['e_lfanew']}")
```

## Project Structure

```
pe-parser/
├── main.py                 # Main entry point and demonstration
├── pe_parser/
│   ├── __init__.py        # Package initialization
│   ├── models.py          # Data structures (section_header, image_import_descriptor)
│   ├── unpackers.py       # Binary unpacking functions
│   └── utils.py           # Utility functions (RVA conversion, flag parsing)
```

## PE File Structure

The parser handles the standard PE file format:

1. **DOS Header** (64 bytes): Legacy MS-DOS compatibility header
2. **PE Signature** (4 bytes): "PE\0\0" magic signature
3. **COFF Header** (20 bytes): Machine type, section count, timestamps
4. **Optional Header** (224/240 bytes): Entry point, base addresses, subsystem info
5. **Section Headers** (40 bytes each): Code and data section information
6. **Import Directory Table**: External DLL and function references

## Supported Features

- ✅ PE32 (32-bit) and PE32+ (64-bit) formats
- ✅ DOS header parsing
- ✅ COFF/Image file header parsing
- ✅ Optional header with data directory
- ✅ Section table parsing
- ✅ Import directory table parsing
- ✅ RVA to file offset conversion
- ✅ DLL characteristics flag interpretation

## Requirements

- Python 3.x
- No external dependencies

## Contributing

Contributions are welcome! Areas for improvement:
- Export table parsing
- Resource directory parsing
- Relocation table handling
- Digital signature verification
- Enhanced error handling and validation

## License

[Add your license here]

## References

- [Microsoft PE Format Documentation](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [PE Format Specification](https://learn.microsoft.com/en-us/windows/win32/api/winnt/)

## Disclaimer

This tool is intended for educational purposes, security research, and legitimate analysis. Users are responsible for ensuring they have proper authorization before analyzing any files.
