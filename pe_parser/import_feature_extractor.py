from utils import rva_to_file_offset
from constants import suspicious_apis_constants
from unpacker import Unpacker

class ImportFeatureExtractor:
    def __init__(self, unpacker: Unpacker):
        self.unpacker = unpacker
        self.import_descriptors = unpacker.import_directory_table_unpacked
        self.file = unpacker.file
        self.has_ordinal_imports = False
        self.section_headers_unpacked = unpacker.section_headers_unpacked
        self.name_extract_from_import_descriptors()
        self.imports_networking = False

    def name_extract_from_import_descriptors(self):
        self.import_names = set()
        self.import_ordinals = set()
        self.dll_names = set()
        ordinal_flag = (1 << 63) if self.unpacker.is_64_bit else (1 << 31)

        for descriptor in self.import_descriptors:
            if descriptor.OriginalFirstThunk == 0:
                continue

            # Seek to dll names and add to the set for import_dll_counter
            dll_name_offset = rva_to_file_offset(descriptor.Name, self.section_headers_unpacked)
            self.file.seek(dll_name_offset)
            dll_name_bytes = bytearray()
            while (byte := self.file.read(1)) not in (b'\x00', b''):
                dll_name_bytes.append(ord(byte))
            self.dll_names.add(dll_name_bytes.decode('ascii', errors='replace').lower())

            # Seek to the ilt for import names and import ordinals
            int_offset = rva_to_file_offset(descriptor.OriginalFirstThunk, self.section_headers_unpacked)
            self.file.seek(int_offset, 0)
            ilt_entries = self.unpacker.import_lookup_table_unpack()

            for entry in ilt_entries:
                if entry & ordinal_flag:
                    self.import_ordinals.add(entry & 0xFFFF)
                    self.has_ordinal_imports = True
                    continue
                mask = 0x7FFFFFFFFFFFFFFF if self.unpacker.is_64_bit else 0x7FFFFFFF
                name_offset = rva_to_file_offset(entry & mask, self.section_headers_unpacked)
                self.file.seek(name_offset)
                _hint = self.file.read(2)
                name_bytes = bytearray()
                while (byte := self.file.read(1)) not in (b'\x00', b''):
                    name_bytes.append(ord(byte))
                try:
                    self.import_names.add(name_bytes.decode('ascii'))
                except UnicodeDecodeError:
                    pass

    def import_dll_counter(self):
        return len(self.dll_names)
                
    def has_networking_imports(self) -> bool:
        return any(
            name in suspicious_apis_constants.SUSPICIOUS_APIS["networking"]
            for name in self.import_names
        )
    
    def has_registry_imports(self) -> bool:
        return any(
            name in suspicious_apis_constants.SUSPICIOUS_APIS["registry"]
            for name in self.import_names
        )


    def has_cryptography_imports(self) -> bool:
        return any(
            name in suspicious_apis_constants.SUSPICIOUS_APIS["cryptography"]
            for name in self.import_names
        )

    def has_process_injection_imports(self) -> bool:
        return any(
            name in suspicious_apis_constants.SUSPICIOUS_APIS["process_injection"]
            for name in self.import_names
        )

    def has_anti_debugging_imports(self) -> bool:
        return any(
            name in suspicious_apis_constants.SUSPICIOUS_APIS["anti_debugging"]
            for name in self.import_names
        )

    def has_anti_analysis_imports(self) -> bool:
        return any(
            name in suspicious_apis_constants.SUSPICIOUS_APIS["anti_analysis"]
            for name in self.import_names
        )

    def has_keylogging_imports(self) -> bool:
        return any(
            name in suspicious_apis_constants.SUSPICIOUS_APIS["keylogging"]
            for name in self.import_names
            )

    def has_persistence_imports(self) -> bool:
        return any(
            name in suspicious_apis_constants.SUSPICIOUS_APIS["persistence"]
            for name in self.import_names
        )

    def has_file_system_imports(self) -> bool:
        return any(
            name in suspicious_apis_constants.SUSPICIOUS_APIS["file_system"]
            for name in self.import_names
        )
    
    def has_privilege_escalation_imports(self) -> bool:
        return any(
            name in suspicious_apis_constants.SUSPICIOUS_APIS["privilege_escalation"]
            for name in self.import_names
        )

    def export_import_features(self) -> dict[str, float | int | bool]:
        total = len(self.import_names) + len(self.import_ordinals)
        features = {
            "import_dll_count": self.import_dll_counter(),
            "total_import_count": total,
            "import_ordinal_count": len(self.import_ordinals),
            "has_any_ordinal_imports": len(self.import_ordinals) > 0,
            "ordinal_import_ratio": len(self.import_ordinals) / total if total > 0 else 0.0,
            "imports_networking": self.has_networking_imports(),
            "imports_registry": self.has_registry_imports(),
            "imports_cryptography": self.has_cryptography_imports(),
            "imports_process_injection": self.has_process_injection_imports(),
            "imports_anti_debugging": self.has_anti_debugging_imports(),
            "imports_anti_analysis": self.has_anti_analysis_imports(),
            "imports_keylogging": self.has_keylogging_imports(),
            "imports_persistence": self.has_persistence_imports(),
            "imports_file_system": self.has_file_system_imports(),
            "imports_privilege_escalation": self.has_privilege_escalation_imports()
        }

        return features