from pe_parser.unpacker import Unpacker
from pe_parser.headers_feature_extractor import HeadersFeatureExtractor
from pe_parser.import_feature_extractor import ImportFeatureExtractor
from pe_parser.section_feature_extractor import SectionFeatureExtractor
from pe_parser.string_feature_extractor import StringFeatureExtractor
from logging import warning

def safe_extract(extractor_fn, defaults: dict) -> dict:
    try:
        return extractor_fn()
    except Exception as e:
        warning(f"{extractor_fn.__qualname__} failed: {e}")
        return defaults

HEADER_DEFAULTS = {
    "has_debug_stripped": False,
    "dll_characteristics_nx": False,
    "dll_characteristics_aslr": False,
    "subsystem": -1, 
    "major_linker_version": -1,
    "timestamp_year": -1,
    "timestamp_is_zero": False,
    "entry_point_in_unusual_section": False,
    "size_of_image": -1,
    "number_of_sections": -1,
    "is_dll": False
}

SECTION_DEFAULTS = {
    "mean_section_entropy": -1.0,
    "max_section_entropy": -1.0,
    "high_entropy_section_count": -1,
    "executable_sections_count": -1,
    "writeable_executable_sections": -1,
    "sections_with_zero_raw_size": -1,
    "largest_section_size_ratio": -1.0
}

IMPORT_DEFAULTS = {
    "import_dll_count": -1,
    "total_import_count": -1,
    "import_ordinal_count": -1,
    "has_any_ordinal_imports": False,
    "ordinal_import_ratio": -1.0,
    "imports_networking": False,
    "imports_registry": False,
    "imports_cryptography": False,
    "imports_process_injection": False,
    "imports_anti_debugging": False,
    "imports_anti_analysis": False,
    "imports_keylogging": False,
    "imports_persistence": False,
    "imports_file_system": False,
    "imports_privilege_escalation": False
}

STRING_DEFAULTS = {
    "string_count": -1,
    "total_string_length": -1,
    "has_url_strings": False,
    "has_ip_strings": False,
    "has_registry_strings": False,
    "has_base64_strings": False,
    "mean_string_length": -1.0
}

def process_file(filepath: str) -> dict | None:
    try:
        with Unpacker(filepath) as unpacker:
            return (
                safe_extract(HeadersFeatureExtractor(unpacker).extract_features, HEADER_DEFAULTS)
                | safe_extract(SectionFeatureExtractor(unpacker).extract_analysis_features, SECTION_DEFAULTS)
                | safe_extract(ImportFeatureExtractor(unpacker).export_import_features, IMPORT_DEFAULTS)
                | safe_extract(StringFeatureExtractor(unpacker).extract_string_features, STRING_DEFAULTS)
            )
    except Exception:
        return None