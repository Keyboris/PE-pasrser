from pe_parser.entropy_calculator import section_entropy
from pe_parser.unpacker import Unpacker

class SectionFeatureExtractor:

    def __init__(self, unpacker: Unpacker):
        self.section_headers = unpacker.section_headers_unpacked
        self.file = unpacker.file
        self.entropies = self.section_entropies()
    
    def section_entropies(self) -> list:
        entropies = []
        for section in self.section_headers:
            if section.SizeOfRawData == 0:
                continue
            self.file.seek(section.PointerToRawData)
            data = self.file.read(section.SizeOfRawData)
            entropies.append(section_entropy(data))
        return entropies

    def mean_entropy(self) -> float:
        e = self.entropies
        return sum(e) / len(e) if e else 0.0

    def max_entropy(self) -> float:
        e = self.entropies
        return max(e) if e else 0.0
    
    def high_entropy_section_count(self) -> int:
        e = self.entropies
        return sum(entropy > 7 for entropy in e)

    def executable_sections_count(self) -> int:
        count = 0
        for section_header in self.section_headers:
            if section_header.Characteristics & 0x20000000:
                count += 1
        return count
    
    def writeable_executable_sections_count(self) -> int:
        count = 0
        for section_header in self.section_headers:
            if section_header.Characteristics & 0x20000000 and section_header.Characteristics & 0x80000000:
                count += 1
        return count
    
    def sections_with_zero_raw_size_count(self) -> int:
        return sum(header.SizeOfRawData == 0 for header in self.section_headers)

    def largest_section_size_ratio(self) -> float:
        if not self.section_headers:
            return 0.0
        total = sum(h.VirtualSize for h in self.section_headers)
        if total == 0:
            return 0.0
        largest = max(h.VirtualSize for h in self.section_headers)
        return largest / total
    

    def extract_analysis_features(self) -> dict[str, float | int]:
        analysis_features = {
            "mean_section_entropy": self.mean_entropy(),
            "max_section_entropy": self.max_entropy(),
            "high_entropy_section_count": self.high_entropy_section_count(),
            "executable_sections_count": self.executable_sections_count(),
            "writeable_executable_sections": self.writeable_executable_sections_count(),
            "sections_with_zero_raw_size": self.sections_with_zero_raw_size_count(),
            "largest_section_size_ratio": self.largest_section_size_ratio()
        }

        return analysis_features