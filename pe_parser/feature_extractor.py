import utils
from datetime import datetime

class FeatureExtractor:
    def __init__(self, unpacker):
        self.unpacker = unpacker
        self.COFF_header = unpacker.COFF_header_unpacked
        self.optional_header = unpacker.optional_header_unpacked

    def extract_features(self):
        entry_point_rva = self.optional_header["AddressOfEntryPoint"]
        entry_point_section = utils.section_name_by_rva(entry_point_rva, self.unpacker.section_headers_unpacked)
        
        ts = self.COFF_header["TimeDateStamp"]
        try:
            year = datetime.fromtimestamp(ts).year if ts != 0 else 0
        except (ValueError, OSError):
            year = 0

        features = {
            "has_debug_stripped": (self.COFF_header["Characteristics"] & 0x0200) != 0,
            "dll_characteristics_nx": (self.optional_header["DllCharacteristics"] & 0x0100) != 0,
            "dll_characteristics_aslr": (self.optional_header["DllCharacteristics"] & 0x0040) != 0,
            "subsystem": self.optional_header["Subsystem"],
            "major_linker_version": self.optional_header["MajorLinkerVersion"],
            "timestamp_year": year,
            "timestamp_is_zero": ts == 0,
            "entry_point_in_unusual_section": entry_point_section not in [".text", ".code"], # It's safer to check what it ISN'T
            "size_of_image": self.optional_header["SizeOfImage"],
            "number_of_sections": self.COFF_header["NumberOfSections"]
        }

        return features