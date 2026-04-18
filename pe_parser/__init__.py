"""
PE Parser - A Python library for parsing Portable Executable (PE) files.
"""

__version__ = "0.2.0"

from pe_parser.models import SectionHeader, ImageImportDescriptor
from pe_parser.unpacker import Unpacker
from pe_parser.feature_extractor import FeatureExtractor
from pe_parser.utils import rva_to_file_offset, section_name_by_rva

__all__ = [
    # Models
    'SectionHeader',
    'ImageImportDescriptor',
    
    # Core Classes
    'Unpacker',
    'FeatureExtractor',
    
    # Utility functions
    'rva_to_file_offset',
    'section_name_by_rva'
]