import re
import mmap
from pe_parser.unpacker import Unpacker

IP_PATTERN = re.compile(rb'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
BASE64_PATTERN = re.compile(rb'[A-Za-z0-9+/]{32,}={0,2}')

REGISTRY_MARKERS = (b'HKEY_', b'HKLM\\', b'HKCU\\', b'SOFTWARE\\', b'CurrentVersion')
URL_MARKERS = (b'http://', b'https://')

class StringFeatureExtractor:

    def __init__(self, unpacker: Unpacker):
        self.file = unpacker.file

    def extract_string_features(self, min_length=4) -> dict:
        results = {
            "string_count": 0,
            "total_string_length": 0,
            "has_url_strings": False,
            "has_ip_strings": False,
            "has_registry_strings": False,
            "has_base64_strings": False,
            "mean_string_length": 0.0,
        }

        self.file.seek(0)
        try:
            mm = mmap.mmap(self.file.fileno(), length=0, access=mmap.ACCESS_READ)
        except (ValueError, OSError):
            self.file.seek(0)
            mm = self.file.read()

        current = bytearray()

        def check_string(s: bytearray):
            results["string_count"] += 1
            results["total_string_length"] += len(s)
            if not results["has_url_strings"] and any(m in s for m in URL_MARKERS):
                results["has_url_strings"] = True
            if not results["has_ip_strings"] and IP_PATTERN.search(s):
                results["has_ip_strings"] = True
            if not results["has_registry_strings"] and any(m in s for m in REGISTRY_MARKERS):
                results["has_registry_strings"] = True
            if not results["has_base64_strings"] and BASE64_PATTERN.search(s):
                results["has_base64_strings"] = True

        for byte in mm:
            if isinstance(byte, int):  # mmap yields ints
                b = byte
            else:
                b = byte[0]            # fallback bytes yields bytes
            if 0x20 <= b <= 0x7E:
                current.append(b)
            else:
                if len(current) >= min_length:
                    check_string(current)
                current = bytearray()

        if len(current) >= min_length:
            check_string(current)

        if hasattr(mm, 'close'):
            mm.close()

        if results["string_count"] > 0:
            results["mean_string_length"] = results["total_string_length"] / results["string_count"]

        return results