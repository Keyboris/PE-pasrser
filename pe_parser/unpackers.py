import struct
from .models import section_header
from .models import image_import_descriptor

def DOS_header_unpack (header):

    data = struct.unpack('<HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHL', header)

    return {
        "e_magic":data[0],
        "e_cblp":data[1],
        "e_cp":data[2],
        "e_crlc":data[3],
        "e_cparhdr":data[4],
        "e_minalloc":data[5],
        "e_maxalloc":data[6],
        "e_ss":data[7],
        "e_sp":data[8],
        "e_csum":data[9],
        "e_ip":data[10],
        "e_cs":data[11],
        "e_lfarlc":data[12],
        "e_ovno":data[13],
        "e_res":data[14:18],
        "e_oemid":data[18],
        "e_oeminfo":data[19],
        "e_res2":data[20:30],
        "e_lfanew":data[30]
    }

def image_file_header_unpack(header):
    data = struct.unpack('<HHLLLHH', header)

    return {
        "Machine": data[0],
        "NumberOfSections": data[1],
        "TimeDateStamp": data[2],
        "PointerToSymbolTable": data[3],
        "NumberOfSymbols": data[4],
        "SizeOfOptionalHeader": data[5],
        "Characteristics": data[6]
    }

def optional_header_unpack(header_bytes): #error is because we dont handle the data directory

    magic = struct.unpack_from('<H', header_bytes, 0)[0]

    if magic == 0x10B:  # PE32 (32-bit)
        fixed_format = '<HBBLLLLLLLLLHHHHHHLLLLHHLLLLLL'
        fixed_data = struct.unpack(fixed_format, header_bytes[:96])
        return_vals = {
            "Magic": fixed_data[0],
            "MajorLinkerVersion": fixed_data[1],
            "MinorLinkerVersion": fixed_data[2],
            "SizeOfCode": fixed_data[3],
            "SizeOfInitializedData": fixed_data[4],
            "SizeOfUninitializedData": fixed_data[5],
            "AddressOfEntryPoint": fixed_data[6],
            "BaseOfCode": fixed_data[7],
            "BaseOfData": fixed_data[8],
            "ImageBase": fixed_data[9],
            "SectionAlignment": fixed_data[10],
            "FileAlignment": fixed_data[11],
            "MajorOperatingSystemVersion": fixed_data[12],
            "MinorOperatingSystemVersion": fixed_data[13],
            "MajorImageVersion": fixed_data[14],
            "MinorImageVersion": fixed_data[15],
            "MajorSubsystemVersion": fixed_data[16],
            "MinorSubsystemVersion": fixed_data[17],
            "Win32VersionValue": fixed_data[18],
            "SizeOfImage": fixed_data[19],
            "SizeOfHeaders": fixed_data[20],
            "CheckSum": fixed_data[21],
            "Subsystem": fixed_data[22],
            "DllCharacteristics": fixed_data[23],
            "SizeOfStackReserve": fixed_data[24],
            "SizeOfStackCommit": fixed_data[25],
            "SizeOfHeapReserve": fixed_data[26],
            "SizeOfHeapCommit": fixed_data[27],
            "LoaderFlags": fixed_data[28],
            "NumberOfRvaAndSizes": fixed_data[29],
            "DataDirectory": []
        }

    elif magic == 0x20B:  # PE32+ (64-bit)
        fixed_format = '<HBBLLLLLQLLHHHHHHLLLLHHQQQQLL'
        fixed_data = struct.unpack(fixed_format, header_bytes[:112])
        return_vals = {
            "Magic": fixed_data[0],
            "MajorLinkerVersion": fixed_data[1],
            "MinorLinkerVersion": fixed_data[2],
            "SizeOfCode": fixed_data[3],
            "SizeOfInitializedData": fixed_data[4],
            "SizeOfUninitializedData": fixed_data[5],
            "AddressOfEntryPoint": fixed_data[6],
            "BaseOfCode": fixed_data[7],
            # BaseOfData is not present in PE32+
            "ImageBase": fixed_data[8], 
            "SectionAlignment": fixed_data[9],
            "FileAlignment": fixed_data[10],
            "MajorOperatingSystemVersion": fixed_data[11],
            "MinorOperatingSystemVersion": fixed_data[12],
            "MajorImageVersion": fixed_data[13],
            "MinorImageVersion": fixed_data[14],
            "MajorSubsystemVersion": fixed_data[15],
            "MinorSubsystemVersion": fixed_data[16],
            "Win32VersionValue": fixed_data[17],
            "SizeOfImage": fixed_data[18],
            "SizeOfHeaders": fixed_data[19],
            "CheckSum": fixed_data[20],
            "Subsystem": fixed_data[21],
            "DllCharacteristics": fixed_data[22],
            "SizeOfStackReserve": fixed_data[23], 
            "SizeOfStackCommit": fixed_data[24],   
            "SizeOfHeapReserve": fixed_data[25],   
            "SizeOfHeapCommit": fixed_data[26],    
            "LoaderFlags": fixed_data[27],
            "NumberOfRvaAndSizes": fixed_data[28],
            "DataDirectory": []
        }
    else:
        raise ValueError(f"Invalid optional header magic number: {magic:#x}")
    
    data_dir_format = '<32L'
    data_dir_bytes = header_bytes[struct.calcsize(fixed_format):]

    data_dir = []
    for i in range(0,16):
        offset = i* 8
        entry_data = struct.unpack_from('<LL', data_dir_bytes, offset)
        data_dir.append({
            "VirtualAddress": entry_data[0],
            "Size": entry_data[1]
        })
    
    return_vals["DataDirectory"] = data_dir

    return return_vals


def section_headers_unpack(all_headers_bytes, number_of_sections):
    section_headers_list = []
    
    # define the format string for ONE section header (40 bytes)
    section_format = '<8sLLLLLLHHL'
    
    for i in range(number_of_sections):
        offset = i * 40
        data = struct.unpack_from(section_format, all_headers_bytes, offset)
        
        sec_header = section_header(
            Name=data[0],
            PhysicalAddress=data[1],    
            VirtualSize=data[1],      
            VirtualAddress=data[2],
            SizeOfRawData=data[3],
            PointerToRawData=data[4],
            PointerToRelocations=data[5],
            PointerToLinenumbers=data[6],
            NumberOfRelocations=data[7],
            NumberOfLinenumbers=data[8],
            Characteristics=data[9]
        )
        section_headers_list.append(sec_header)
    
    return section_headers_list

def import_directory_table_unpack(file):
    image_import_descriptors_array = []
    image_import_descriptor_zeroed = False
    image_import_descriptor_format = '<5L'
    while not image_import_descriptor_zeroed:
        data = file.read(20)
        data_unpacked = struct.unpack(image_import_descriptor_format, data)

        current_image_import_descriptor = image_import_descriptor(
            Characteristics = data_unpacked[0],
            OriginalFirstThunk = data_unpacked[0],
            TimeDateStamp = data_unpacked[1],
            ForwarderChain = data_unpacked[2],
            Name = data_unpacked[3],
            FirstThunk = data_unpacked[4]
        )

        if current_image_import_descriptor.isZeroed():
            image_import_descriptor_zeroed = True
        else:
            image_import_descriptors_array.append(current_image_import_descriptor)
    return image_import_descriptors_array

