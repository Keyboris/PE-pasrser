import struct
import pe_parser.models
import pe_parser.utils
import pe_parser.unpacker


def main():
        pass






                
            # data_directory = optional_header_unpacked["DataDirectory"]
            # file.seek(pe_parser.utils.rva_to_file_offset(data_directory[1].get("VirtualAddress"), section_headers_unpacked), 0)  

            # import_directory_table = pe_parser.unpackers.import_directory_table_unpack(file)

            # print("\nimport table: ")

            # for descriptor in import_directory_table:
            #     name_offset = pe_parser.utils.rva_to_file_offset(descriptor.Name, section_headers_unpacked)
            #     file.seek(name_offset, 0) # Seek to the DLL name string
            #     dll_name = bytearray()
            #     while (byte := file.read(1)) != b'\x00':
            #         dll_name.append(ord(byte))
            #     print(f"DLL: {dll_name.decode('ascii')}")
            #     print(f"Functions IAT RVA: {descriptor.FirstThunk:#x}")
            #     print(f"Functions ILT RVA: {descriptor.OriginalFirstThunk:#x}\n")
            #     file.seek(pe_parser.utils.rva_to_file_offset(descriptor.OriginalFirstThunk, section_headers_unpacked))


    # TODO: separate feature printing from feature extraction. All logic must be taken out of main. Use feature extraction for ml. main() must accept filepath as a parameter.
    # It must then print out relevant information according to the flags.
    

if __name__ == '__main__':
    main()
