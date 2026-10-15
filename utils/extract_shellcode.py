import lief
import sys
from pathlib import Path


def main():
    pe_path = sys.argv[1]
    output_path = sys.argv[2]

    binary = lief.parse(sys.argv[1])
    if binary is None:
        raise RuntimeError(f"无法解析 PE 文件: {pe_path}")

    text_section = binary.get_section(".text")
    if text_section is None:
        raise RuntimeError(f"无法找到 .text 节: {pe_path}")

    with open(output_path, "wb") as f:
        f.write(bytes(text_section.content))

    exports = binary.get_export()
    if exports is None:
        raise RuntimeError(f"无法找到导出表: {pe_path}")

    for entry in exports.entries:
        name = entry.name or "<NONAME>"
        ordinal = entry.ordinal
        rva = entry.address
        bin_offset = ''
        if text_section.virtual_address <= rva and rva < text_section.virtual_address + text_section.sizeof_raw_data:
            bin_offset = f"0x{rva - text_section.virtual_address:x}"

        print(f"{bin_offset} {name}")

def print_export_functions(binary):
    export = binary.get_export()

    if export is None:
        print("该 PE 文件没有导出表")
        return

    for entry in export.entries:
        print(entry.address, entry.name)






if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"用法: python {sys.argv[0]} input.exe output.bin")
        sys.exit(1)
    
    main()

   
