DOS_HEADER_FORMAT = '<HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHL'
DOS_HEADER_KEYS = ["e_magic", "e_cblp", "e_cp", "e_crlc", "e_cparhdr", "e_minalloc", "e_maxalloc", "e_ss", "e_sp", "e_csum", "e_ip", "e_cs", "e_lfarlc",\
                    "e_ovno", "e_res", "e_oemid", "e_oeminfo", "e_res2", "e_lfanew"]

COFF_HEADER_FORMAT = '<HHLLLHH'
COFF_HEADER_KEYS = ["Machine", "NumberOfSections", "TimeDateStamp", "PointerToSymbolTable", "NumberOfSymbols", "SizeOfOptionalHeader", "Characteristics"]

OPTIONAL_HEADER_32_FORMAT = '<HBBLLLLLLLLLHHHHHHLLLLHHLLLLLL'
OPTIONAL_HEADER_32_KEYS = ["Magic", "MajorLinkerVersion", "MinorLinkerVersion", "SizeOfCode", "SizeOfInitializedData", "SizeOfUninitializedData",
                          "AddressOfEntryPoint", "BaseOfCode", "BaseOfData", "ImageBase", "SectionAlignment", "FileAlignment", "MajorOperatingSystemVersion",
                          "MinorOperatingSystemVersion", "MajorImageVersion", "MinorImageVersion", "MajorSubsystemVersion", "MinorSubsystemVersion",
                          "Win32VersionValue", "SizeOfImage", "SizeOfHeaders", "CheckSum", "Subsystem", "DllCharacteristics", "SizeOfStackReserve",
                          "SizeOfStackCommit", "SizeOfHeapReserve", "SizeOfHeapCommit", "LoaderFlags", "NumberOfRvaAndSizes", "DataDirectory"]

OPTIONAL_HEADER_64_FORMAT = '<HBBLLLLLQLLHHHHHHLLLLHHQQQQLL'
OPTIONAL_HEADER_64_KEYS = ["Magic", "MajorLinkerVersion", "MinorLinkerVersion", "SizeOfCode", "SizeOfInitializedData", "SizeOfUninitializedData",
                        "AddressOfEntryPoint", "BaseOfCode", "ImageBase", "SectionAlignment", "FileAlignment", "MajorOperatingSystemVersion",
                        "MinorOperatingSystemVersion", "MajorImageVersion", "MinorImageVersion", "MajorSubsystemVersion", "MinorSubsystemVersion",
                        "Win32VersionValue", "SizeOfImage", "SizeOfHeaders", "CheckSum", "Subsystem", "DllCharacteristics", "SizeOfStackReserve", 
                        "SizeOfStackCommit", "SizeOfHeapReserve", "SizeOfHeapCommit", "LoaderFlags", "NumberOfRvaAndSizes","DataDirectory"]
