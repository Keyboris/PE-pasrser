"""
PE Parser - A Python library for parsing Portable Executable (PE) files.
"""

__version__ = "0.1.0"

from .models import SectionHeader, ImageImportDescriptor
from .unpackers import (
    dos_header_unpack,
    image_file_header_unpack,
    optional_header_unpack,
    section_headers_unpack,
    import_directory_table_unpack
)
from .utils import rva_to_file_offset

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