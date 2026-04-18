import struct
from datetime import datetime
from .models import SectionHeader
from .models import ImageImportDescriptor
from pe_parser.utils import *

class Unpacker:
    
    def __init__(self, file_path):
        self.file_path = file_path
        self.file = open(self.file_path, 'rb')

        DOS_header = self.file.read(64)
        DOS_header_unpacked = self.DOS_header_unpack(DOS_header)
        self.file.seek(DOS_header_unpacked["e_lfanew"])
        PE_signature = self.file.read(4)
        pe_signature = ' '.join(f"{b:02X}" for b in PE_signature)

        # Verify PE signature always before working with file
        if pe_signature != "50 45 00 00":  
            self.file.close()
            raise ValueError(f"PE signature does not match! Found {pe_signature}")

        image_file_header = self.file.read(20)
        self.image_file_header_unpacked = self.image_file_header_unpack(image_file_header)

        # Add to some other method later
        # timestamp = self.image_file_header_unpacked["TimeDateStamp"]
        # date_object = datetime.fromtimestamp(timestamp)
        # print(f"Date of the last linking/executing: {date_object}")

        optional_header = self.file.read(self.image_file_header_unpacked["SizeOfOptionalHeader"])
        self.optional_header_unpacked = self.optional_header_unpack(optional_header)
        # 0x20B is PE32+ (64-bit), 0x10B is PE32 (32-bit)
        self.is_64_bit = (self.optional_header_unpacked["Magic"] == 0x20B)        

        section_headers = self.file.read(40 * self.image_file_header_unpacked["NumberOfSections"])
        self.section_headers_unpacked = self.section_headers_unpack(section_headers, self.image_file_header_unpacked["NumberOfSections"])


    def close_file(self):
        self.file.close()


    def DOS_header_unpack (self, header):

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

    def image_file_header_unpack(self, header):
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

    def optional_header_unpack(self, header_bytes): 

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


    def section_headers_unpack(self, all_headers_bytes, number_of_sections):
        section_headers_list = []
        
        # define the format string for ONE section header (40 bytes)
        section_format = '<8sLLLLLLHHL'
        
        for i in range(number_of_sections):
            offset = i * 40
            data = struct.unpack_from(section_format, all_headers_bytes, offset)
            
            sec_header = SectionHeader(
                Name=data[0],    
                VirtualSize=data[1],
                PhysicalAddress=data[2],      
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

    def import_directory_table_unpack(self):
        image_import_descriptors_array = []
        image_import_descriptor_zeroed = False
        image_import_descriptor_format = '<5L'
        while not image_import_descriptor_zeroed:
            data = self.file.read(20)
            data_unpacked = struct.unpack(image_import_descriptor_format, data)

            current_image_import_descriptor = ImageImportDescriptor(
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

    import struct

    def import_lookup_table_unpack(self):
        import_lookup_table_array = []
        if self.is_64_bit:
            entry_format = '<Q'  # Q = 8 bytes (64-bit)
            entry_size = 8
        else:
            entry_format = '<L'  # L = 4 bytes (32-bit)
            entry_size = 4
            
        while True:
            data = self.file.read(entry_size)
            entry_value = struct.unpack(entry_format, data)[0]
            if entry_value == 0:
                break
                
            import_lookup_table_array.append(entry_value)
        return import_lookup_table_array


    def name_lookup_by_image_import_descriptor(self, descriptor):
        int_offset = rva_to_file_offset(descriptor.OriginalFirstThunk, self.section_headers_unpacked)
        self.file.seek(int_offset, 0)
        import_lookup_table_unpacked = self.import_lookup_table_unpack()
        
        import_names = []
        ordinal_flag = (1 << 63) if self.is_64_bit else (1 << 31)
        
        for entry in import_lookup_table_unpacked:
            if entry & ordinal_flag:
                ordinal_number = entry & 0xFFFF
                import_names.append(f"Ordinal_{ordinal_number}")
                continue
                
            name_offset = rva_to_file_offset(entry, self.section_headers_unpacked)
            self.file.seek(name_offset, 0)
            _hint = self.file.read(2)
    
            name_bytes = bytearray()
            while (byte := self.file.read(1)) != b'\x00':
                if not byte: 
                    break
                name_bytes.append(ord(byte))
            
            try:
                name_string = name_bytes.decode('ascii')
                import_names.append(name_string)
            except UnicodeDecodeError:
                import_names.append("<Decode Error>")
                
        return import_names
    


    def print_section_characteristics(self):
        for section_header in self.section_headers_unpackeds:
            #TODO: entropy calculation, string parsing
            print(f"Name of the section: {section_header.Name}")
            print(f'{section_header.Characteristics:#x}')
            if section_header.Characteristics & 0x80000000 and section_header.Characteristics & 0x20000000:
                print("WARNING: section is marked as both writable and executable")
