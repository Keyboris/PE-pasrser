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
            
            file.seek(DOS_header_unpacked["e_lfanew"])

            PE_signature = file.read(4)

            pe_signature = ' '.join(f"{b:02X}" for b in PE_signature)

            if pe_signature != "50 45 00 00":
                print("PE signature does not match! Please make sure that the file is a PE file.")
                exit(1)

            image_file_header = file.read(20)
            image_file_header_unpacked = pe_parser.unpackers.image_file_header_unpack(image_file_header)

            timestamp = image_file_header_unpacked["TimeDateStamp"]
            date_object = datetime.fromtimestamp(timestamp)
            print(f"Date of the last linking/executing: {date_object}")

            

            optional_header = file.read(image_file_header_unpacked["SizeOfOptionalHeader"])
            optional_header_unpacked = pe_parser.unpackers.optional_header_unpack(optional_header)
            
            pe_parser.utils.print_data_optional_header(optional_header_unpacked)

            #print(f"Data directory: {str(optional_header_unpacked["DataDirectory"])}")

            print("\n SECTION HEADERS \n======================================= \n")            

            section_headers = file.read(40 * image_file_header_unpacked["NumberOfSections"])
            print(f"Size of seciton headers: {40 * image_file_header_unpacked["NumberOfSections"]}")

            section_headers_unpacked = pe_parser.unpackers.section_headers_unpack(section_headers, image_file_header_unpacked["NumberOfSections"])

            print(f"Name of the fisrt section: {section_headers_unpacked[2].Name}")
            
            data_directory = optional_header_unpacked["DataDirectory"]
            print(optional_header_unpacked["ImageBase"] + data_directory[1].get("VirtualAddress"))
            print(optional_header_unpacked["ImageBase"])
            file.seek(pe_parser.utils.rva_to_file_offset(data_directory[1].get("VirtualAddress"), section_headers_unpacked), 0)  

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

    #for the ht headers, the structure is the following:
    #4 bytes for the PE signature (50450000)
    #20 bytes for the file header/COFF header
    #optional header which is either 224 bytes 32 bit files or 240 bytews for 64 bit files
    #the first 2 byte field of the optional header is the magic word which is either 10B for 32 bit files or 20B for 64 bit files

if __name__ == '__main__':
    main()
