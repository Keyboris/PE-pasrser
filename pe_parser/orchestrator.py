from os.path import join, isfile, isdir
from os import walk
from analyzer import process_file


def process_destination(filepath: str, recursive: bool, headers_flag: bool, section_flag: bool, import_flag: bool, string_flag: bool) -> list[dict[str, float | int | bool]]:

    if isfile(filepath):
        current = process_file(full_path, headers_flag, section_flag, import_flag, string_flag)
        if current is not None:
            return list[current]
        else:
            return []
        
    elif isdir(filepath):
        files_processed = []
        for root, dirs, files in walk(filepath):
            for n in files:
                full_path = join(root, n)
                current = process_file(full_path, headers_flag, section_flag, import_flag, string_flag)
                if current is not None:
                    files_processed.append()
            if not recursive:
                break
        
        return files_processed