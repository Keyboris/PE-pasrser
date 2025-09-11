import struct
import pe_parser.models
import pe_parser.utils
import pe_parser.unpackers
from datetime import datetime

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


    #READING THE NT HEADERS
    try:
        with open(path_to_file, 'rb') as file:
            DOS_header = file.read(64)

            DOS_header_unpacked = pe_parser.unpackers.DOS_header_unpack(DOS_header)

            print(f"e_lfanew: {DOS_header_unpacked["e_lfanew"]}")
            
            file.seek(DOS_header_unpacked["e_lfanew"])

            PE_signature = file.read(4)

            print(' '.join(f"{b:02X}" for b in PE_signature))

            image_file_header = file.read(20)
            image_file_header_unpacked = pe_parser.unpackers.image_file_header_unpack(image_file_header)

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
            optional_header_unpacked = pe_parser.unpackers.optional_header_unpack(optional_header)

            print(f"magic word: {optional_header_unpacked["Magic"]:02X} (0x20B for 64 bits, 0x10b for 32 bits)")

            print(f"data directory: {str(optional_header_unpacked["DataDirectory"])}")
            

            #next, get the section haeders data




            section_headers = file.read(40 * image_file_header_unpacked["NumberOfSections"])
            print(f"Size of the seciton headers: {40 * image_file_header_unpacked["NumberOfSections"]}")

            section_headers_unpacked = pe_parser.unpackers.section_headers_unpack(section_headers, image_file_header_unpacked["NumberOfSections"])

            print(f"name of the fisrt section: {section_headers_unpacked[2].Name}")
            
            data_directory = optional_header_unpacked["DataDirectory"]
            print(optional_header_unpacked["ImageBase"] + data_directory[1].get("VirtualAddress"))
            print(optional_header_unpacked["ImageBase"])
            file.seek(pe_parser.utils.rva_to_file_offset(data_directory[1].get("VirtualAddress"), section_headers_unpacked), 0)  #fuck              wtf does fuck mean? i forgot   no i know, hopefully solved      SOLVED   LESSSSSSGOOOOOOOOOOOOO

            data = file.read(20)
            print(f"confirmation: {len(data)}")


            import_directory_table = pe_parser.unpackers.import_directory_table_unpack(file)

            print("\nimport table: ")

            for descriptor in import_directory_table:
                name_offset = pe_parser.utils.rva_to_file_offset(descriptor.Name, section_headers_unpacked)
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