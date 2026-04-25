"""
PE Parser - A Python library for parsing Portable Executable (PE) files.
"""

__version__ = "0.2.0"

from pe_parser.models import SectionHeader, ImageImportDescriptor
from pe_parser.unpacker import Unpacker
from pe_parser.headers_feature_extractor import HeadersFeatureExtractor
from pe_parser.section_feature_extractor import SectionFeatureExtractor
from pe_parser.import_feature_extractor import ImportFeatureExtractor
from pe_parser.constants.header_constants import DOS_HEADER_FORMAT, DOS_HEADER_KEYS, COFF_HEADER_FORMAT, COFF_HEADER_KEYS, OPTIONAL_HEADER_64_KEYS, OPTIONAL_HEADER_64_FORMAT, OPTIONAL_HEADER_32_FORMAT, OPTIONAL_HEADER_32_KEYS
from pe_parser.constants.suspicious_apis_constants import SUSPICIOUS_APIS
from pe_parser.entropy_calculator import section_entropy
from pe_parser.utils import rva_to_file_offset, section_name_by_rva

__all__ = [
    # Models
    'SectionHeader',
    'ImageImportDescriptor',
    
    # Core Classes
    'Unpacker',
    'HeadersFeatureExtractor',
    'SectionFeatureExtractor',
    'ImportFeatureExtractor',

    
    # Utility functions
    'rva_to_file_offset',
    'section_name_by_rva',
    'section_entropy',

    # Constants
    'DOS_HEADER_FORMAT',
    'DOS_HEADER_KEYS',
    'COFF_HEADER_FORMAT',
    'COFF_HEADER_KEYS',
    'OPTIONAL_HEADER_64_KEYS',
    'OPTIONAL_HEADER_64_FORMAT',
    'OPTIONAL_HEADER_32_FORMAT',
    'OPTIONAL_HEADER_32_KEYS',
    'SUSPICIOUS_APIS'
]