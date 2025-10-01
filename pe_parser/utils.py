def rva_to_file_offset(RVA, Sections):  
    for section in Sections:
        if section.VirtualAddress <= RVA < (section.VirtualAddress + section.VirtualSize):
            File_Offset = section.PointerToRawData + (RVA - section.VirtualAddress)
            return File_Offset
        
def dll_characteristics_parse(value):
    flags = {
        0x0020: "HIGH_ENTROPY_VA",
        0x0040: "DYNAMIC_BASE", 
        0x0080: "FORCE_INTEGRITY",
        0x0100: "NX_COMPAT",
        0x0200: "NO_ISOLATION",
        0x0400: "NO_SEH",
        0x0800: "NO_BIND",
        0x1000: "APPCONTAINER",
        0x2000: "WDM_DRIVER",
        0x4000: "GUARD_CF",
        0x8000: "TERMINAL_SERVER_AWARE"
    }

    print("DLL Characteristics flags:")
    for flag, name in flags.items():
        if value & flag:
            print(f"  - 0x{flag:04X}: {name}")

def print_data_optional_header(optional_header_unpacked):

    print("\nOPTIONAL HEADER \n======================================= \n")

    print(f"Magic word: {optional_header_unpacked["Magic"]:02X} (0x20B for 64 bits, 0x10b for 32 bits, 0x107 for ROM files)")
    print(f"Major linker version: {optional_header_unpacked["MajorLinkerVersion"]}")
    print(f"Minor linker version: {optional_header_unpacked["MinorLinkerVersion"]}")
    print(f"Size of code: {optional_header_unpacked["SizeOfCode"]}B")
    print(f"Size of initialized data: {optional_header_unpacked["SizeOfInitializedData"]}B")
    print(f"Size of unitialized data: {optional_header_unpacked["SizeOfUninitializedData"]}B")
    print(f"Address of entry point: {optional_header_unpacked["AddressOfEntryPoint"]}")
    print(f"Base of code: {optional_header_unpacked["BaseOfCode"]}")
    if optional_header_unpacked["Magic"] == "0x20B":
        print(f"Base of data: {optional_header_unpacked["BaseOfData"]}")
    print(f"Image base: {optional_header_unpacked["ImageBase"]}")
    print(f"Section alignment: {optional_header_unpacked["SectionAlignment"]}B")
    print(f"Major operating system version: {optional_header_unpacked["MajorOperatingSystemVersion"]}")
    print(f"Minor operating system version: {optional_header_unpacked["MinorOperatingSystemVersion"]}")
    print(f"Major image version: {optional_header_unpacked["MajorImageVersion"]}")
    print(f"Minor image version: {optional_header_unpacked["MinorImageVersion"]}")
    print(f"Major subsystem version: {optional_header_unpacked["MajorSubsystemVersion"]}")
    print(f"Minor subsystem version: {optional_header_unpacked["MinorSubsystemVersion"]}")
    print(f"Win 32 version value (reserved, must be 0): {optional_header_unpacked["Win32VersionValue"]}")
    print(f"Size of headers: {optional_header_unpacked["SizeOfHeaders"]}B")
    print(f"Checksum: {optional_header_unpacked["CheckSum"]}")
    print(f"Subsystem: {optional_header_unpacked["Subsystem"]}")
    print(dll_characteristics_parse(int(optional_header_unpacked["DllCharacteristics"])))
    print(f"Size of stack reserve: {optional_header_unpacked["SizeOfStackReserve"]}B")
    print(f"Size of stack commit: {optional_header_unpacked["SizeOfStackCommit"]}B")
    print(f"Size of heap reserve: {optional_header_unpacked["SizeOfHeapReserve"]}B")
    print(f"Size of heap commit: {optional_header_unpacked["SizeOfHeapCommit"]}B")
    print(f"Loader flags (reserved, should be 0): {optional_header_unpacked["LoaderFlags"]}")
    print(f"Number of data directory (NumberOfRvaAndSizes): {optional_header_unpacked["NumberOfRvaAndSizes"]}")
