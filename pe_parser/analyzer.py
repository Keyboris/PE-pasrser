from unpacker import Unpacker
from headers_feature_extractor import HeadersFeatureExtractor
from import_feature_extractor import ImportFeatureExtractor
from section_feature_extractor import SectionFeatureExtractor
from string_feature_extractor import StringFeatureExtractor

def process_file(filepath: str, headers_flag: bool, section_flag: bool, import_flag: bool, string_flag: bool) -> dict[str, float | int | bool] | None:
    try:
        with Unpacker(filepath) as unpacker:
                header_features = HeadersFeatureExtractor(unpacker).extract_features()
                section_features = SectionFeatureExtractor(unpacker).extract_analysis_features()
                import_features = ImportFeatureExtractor(unpacker).export_import_features()
                string_features = StringFeatureExtractor(unpacker).extract_string_features()
                return header_features | section_features | import_features | string_features
    except Exception:
         return None