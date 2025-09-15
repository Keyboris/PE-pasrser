"""
PE Parser - A Python library for parsing Portable Executable (PE) files.
"""

__version__ = "0.1.0"

from pe_parser.models import section_header, image_import_descriptor
from pe_parser.unpackers import (
    DOS_header_unpack,
    image_file_header_unpack,
    optional_header_unpack,
    section_headers_unpack,
    import_directory_table_unpack
)
from pe_parser.utils import rva_to_file_offset

__all__ = [
    # Models
    'SectionHeader',
    'ImageImportDescriptor',
    
    # Unpacker functions
    'dos_header_unpack',
    'image_file_header_unpack',
    'optional_header_unpack',
    'section_headers_unpack',
    'import_directory_table_unpack',
    
    # Utility functions
    'rva_to_file_offset',
]