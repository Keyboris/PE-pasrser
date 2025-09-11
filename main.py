import struct
from datetime import datetime

class section_header:
    def __init__(self, Name, PhysicalAddress, VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData, PointerToRelocations, PointerToLinenumbers, NumberOfRelocations, NumberOfLinenumbers, Characteristics):
        self.Name = Name
        self.PhysicalAddress = PhysicalAddress
        self.VirtualSize = VirtualSize
        self.VirtualAddress = VirtualAddress
        self.SizeOfRawData = SizeOfRawData
        self.PointerToRawData = PointerToRawData
        self.PointerToRelocations = PointerToRelocations
        self.PointerToLinenumbers = PointerToLinenumbers
        self.NumberOfRelocations = NumberOfRelocations
        self.NumberOfLinenumbers = NumberOfLinenumbers
        self.Characteristics = Characteristics

class image_import_descriptor:
    def __init__(self, Characteristics = 0, OriginalFirstThunk = 0, TimeDateStamp = 0, ForwarderChain = 0, Name = 0, FirstThunk = 0):
        self.Characteristics = Characteristics
        self.OriginalFirstThunk = OriginalFirstThunk
        self.TimeDateStamp = TimeDateStamp
        self.ForwarderChain = ForwarderChain
        self.Name = Name
        self.FirstThunk = FirstThunk

    def isZeroed(self):
        return (self.Characteristics == 0 and
                self.OriginalFirstThunk == 0 and
                self.TimeDateStamp == 0 and
                self.ForwarderChain == 0 and
                self.Name == 0 and
                self.FirstThunk == 0)

def main():
        
    path_to_file = input("Enter the path to the file: ")
    #READING THE DOS HEADER
    # try:
    #     with open(path_to_file, "rb") as f:
    #         DOS_header_bytes = f.read(64)
    #         DOS_header_string = ""
    #         for byte in DOS_header_bytes:
    #             DOS_header_string += f"{byte:02X} "
    #         print(DOS_header_string)
    # except FileNotFoundError:
    #     print(f"File {path_to_file} was not found")
    # except Exception as e:
    #     print(e)

    def rva_to_file_offset(RVA, Sections):   #blya(
        for section in Sections:
            if section.VirtualAddress <= RVA < (section.VirtualAddress + section.VirtualSize):
                File_Offset = section.PointerToRawData + (RVA - section.VirtualAddress)
                return File_Offset


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
    


    #READING THE NT HEADERS
    try:
        with open(path_to_file, 'rb') as file:
            DOS_header = file.read(64)

            DOS_header_unpacked = DOS_header_unpack(DOS_header)

            print(f"e_lfanew: {DOS_header_unpacked["e_lfanew"]}")
            
            file.seek(DOS_header_unpacked["e_lfanew"])

            PE_signature = file.read(4)

            print(' '.join(f"{b:02X}" for b in PE_signature))

            image_file_header = file.read(20)
            image_file_header_unpacked = image_file_header_unpack(image_file_header)

            print(f"Machine: {image_file_header_unpacked["Machine"]:02X}")
            print(f"Size of the optinal header: {image_file_header_unpacked["SizeOfOptionalHeader"]}")
            timestamp = image_file_header_unpacked["TimeDateStamp"]
            date_object = datetime.fromtimestamp(timestamp)
            print(f"date of last linking/executing: {date_object}")

            

            # image_file_header_string = ""
            # for byte in image_file_header:
            #     image_file_header_string += f"{byte:02X} "
            # print(image_file_header_string)

            optional_header = file.read(image_file_header_unpacked["SizeOfOptionalHeader"])
            optional_header_unpacked = optional_header_unpack(optional_header)

            print(f"magic word: {optional_header_unpacked["Magic"]:02X} (0x20B for 64 bits, 0x10b for 32 bits)")

            print(f"data directory: {str(optional_header_unpacked["DataDirectory"])}")
            

            #next, get the section haeders data




            section_headers = file.read(40 * image_file_header_unpacked["NumberOfSections"])
            print(f"Size of the seciton headers: {40 * image_file_header_unpacked["NumberOfSections"]}")

            section_headers_unpacked = section_headers_unpack(section_headers, image_file_header_unpacked["NumberOfSections"])

            print(f"name of the fisrt section: {section_headers_unpacked[2].Name}")
            
            data_directory = optional_header_unpacked["DataDirectory"]
            print(optional_header_unpacked["ImageBase"] + data_directory[1].get("VirtualAddress"))
            print(optional_header_unpacked["ImageBase"])
            file.seek(rva_to_file_offset(data_directory[1].get("VirtualAddress"), section_headers_unpacked), 0)  #fuck              wtf does fuck mean? i forgot   no i know, hopefully solved      SOLVED   LESSSSSSGOOOOOOOOOOOOO

            data = file.read(20)
            print(f"confirmation: {len(data)}")


            import_directory_table = import_directory_table_unpack(file)

            print("\nimport table: ")

            for descriptor in import_directory_table:
                name_offset = rva_to_file_offset(descriptor.Name, section_headers_unpacked)
                file.seek(name_offset, 0) # Seek to the DLL name string
                dll_name = bytearray()
                while (byte := file.read(1)) != b'\x00':
                    dll_name.append(ord(byte))
                print(f"DLL: {dll_name.decode('ascii')}")
                print(f"Functions IAT RVA: {descriptor.FirstThunk:#x}")
                print(f"Functions ILT RVA: {descriptor.OriginalFirstThunk:#x}\n")

            
    except Exception as e:
        print(e)

    #C:\Users\iluya\Downloads\smallexe.exe
    #C:\Users\iluya\Downloads\cuda_13.0.0_windows.exe
    #C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global Offensive\game\csgo\bin\win64\client.dll
    #for the ht headers, the structure is the following:
    #4 bytes for the PE signature (50450000)
    #20 bytes for the file header/COFF header
    #optional header which is either 224 bytes 32 bit files or 240 bytews for 64 bit files
    #the first 2 byte field of the optional header is the magic word which is either 10B for 32 bit files or 20B for 64 bit files

if __name__ == '__main__':
    main()