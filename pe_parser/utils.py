def rva_to_file_offset(RVA, Sections):   #blya(
    for section in Sections:
        if section.VirtualAddress <= RVA < (section.VirtualAddress + section.VirtualSize):
            File_Offset = section.PointerToRawData + (RVA - section.VirtualAddress)
            return File_Offset