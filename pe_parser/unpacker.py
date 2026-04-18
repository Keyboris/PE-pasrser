import struct
import constants
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

        COFF_file_header = self.file.read(20)
        self.COFF_header_unpacked = self.COFF_header_unpack(COFF_file_header)

        optional_header = self.file.read(self.COFF_header_unpacked["SizeOfOptionalHeader"])
        self.optional_header_unpacked = self.optional_header_unpack(optional_header)
        # 0x20B is PE32+ (64-bit), 0x10B is PE32 (32-bit)
        self.is_64_bit = (self.optional_header_unpacked["Magic"] == 0x20B)        

        section_headers = self.file.read(40 * self.COFF_header_unpacked["NumberOfSections"])
        self.section_headers_unpacked = self.section_headers_unpack(section_headers, self.COFF_header_unpacked["NumberOfSections"])


    def close_file(self):
        self.file.close()


    def DOS_header_unpack (self, header):
        data = struct.unpack(constants.DOS_HEADER_FORMAT, header)
        return dict(zip(constants.DOS_HEADER_KEYS, data))

    def COFF_header_unpack(self, header):
        data = struct.unpack(constants.COFF_HEADER_FORMAT, header)
        return dict(zip(constants.COFF_HEADER_KEYS, data))

    def optional_header_unpack(self, header_bytes): 

        magic = struct.unpack_from('<H', header_bytes, 0)[0]

        if magic == 0x10B:  # PE32 (32-bit)
            fixed_format = constants.OPTIONAL_HEADER_32_FORMAT
            fixed_data = struct.unpack(fixed_format, header_bytes[:96])
            return_vals = dict(zip(constants.OPTIONAL_HEADER_32_KEYS, fixed_data))

        elif magic == 0x20B:  # PE32+ (64-bit)
            fixed_format = constants.OPTIONAL_HEADER_64_FORMAT
            fixed_data = struct.unpack(fixed_format, header_bytes[:112])
            return_vals = dict(zip(constants.OPTIONAL_HEADER_64_KEYS, fixed_data))
        else:
            raise ValueError(f"Invalid optional header magic number: {magic:#x}")
        
        data_dir_format = '<32L'
        data_dir_bytes = header_bytes[struct.calcsize(fixed_format):]

        return_vals["DataDirectory"] = [{"VirtualAddress": va, "Size": size} for va, size in struct.iter_unpack('<LL', data_dir_bytes)]

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


        #UNPACKER ONLY UNPACKS

    # def name_lookup_by_image_import_descriptor(self, descriptor):
    #     int_offset = rva_to_file_offset(descriptor.OriginalFirstThunk, self.section_headers_unpacked)
    #     self.file.seek(int_offset, 0)
    #     import_lookup_table_unpacked = self.import_lookup_table_unpack()
        
    #     import_names = []
    #     ordinal_flag = (1 << 63) if self.is_64_bit else (1 << 31)
        
    #     for entry in import_lookup_table_unpacked:
    #         if entry & ordinal_flag:
    #             ordinal_number = entry & 0xFFFF
    #             import_names.append(f"Ordinal_{ordinal_number}")
    #             continue
                
    #         name_offset = rva_to_file_offset(entry, self.section_headers_unpacked)
    #         self.file.seek(name_offset, 0)
    #         _hint = self.file.read(2)
    
    #         name_bytes = bytearray()
    #         while (byte := self.file.read(1)) != b'\x00':
    #             if not byte: 
    #                 break
    #             name_bytes.append(ord(byte))
            
    #         try:
    #             name_string = name_bytes.decode('ascii')
    #             import_names.append(name_string)
    #         except UnicodeDecodeError:
    #             import_names.append("<Decode Error>")
                
    #     return import_names
    


    # def print_section_characteristics(self):
    #     for section_header in self.section_headers_unpackeds:
    #         #TODO: entropy calculation, string parsing
    #         print(f"Name of the section: {section_header.Name}")
    #         print(f'{section_header.Characteristics:#x}')
    #         if section_header.Characteristics & 0x80000000 and section_header.Characteristics & 0x20000000:
    #             print("WARNING: section is marked as both writable and executable")
