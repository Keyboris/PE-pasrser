from os.path import join
from os import walk
from pe_parser.analyzer import process_file
import os

def process_destination(dirpath: str, recursive: bool) -> list[dict]:
    results = []
    for root, dirs, files in walk(dirpath):
        for name in files:
            full_path = join(root, name)
            result = process_file(full_path)
            if result is not None:
                result["filepath"] = full_path
                result["is_dll"] = True if os.path.splitext(full_path) == ".dll" else False
                print(f"processed: {full_path}")
                results.append(result)
        if not recursive:
            break
    return results