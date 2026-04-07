#!/usr/bin/env python3
"""
Post-process carrier_on.ko to add .gnu.linkonce.this_module section
required by the kernel module loader.

Struct module layout for kernel 4.19.81-perf+ (from qca_cld3_wlan.ko):
  - Total size: 0x340 (832 bytes)
  - Offset 0x18: name[56] (module name string)
  - Offset 0x150: init function pointer (R_AARCH64_ABS64)
  - Offset 0x310: exit function pointer (R_AARCH64_ABS64)
"""
import struct
import sys

INPUT = "/Users/xmxx/pinganhuijia/tmp/carrier_on_raw.ko"
OUTPUT = "/Users/xmxx/pinganhuijia/tmp/carrier_on_fixed.ko"

MODULE_SIZE = 0x340  # 832 bytes
NAME_OFFSET = 0x18
INIT_OFFSET = 0x150
EXIT_OFFSET = 0x310
MODULE_NAME = b"carrier_on"

R_AARCH64_ABS64 = 0x101

def read_elf64_shdr(data, offset):
    fields = struct.unpack_from('<IIQQQQIIQQ', data, offset)
    return {
        'sh_name': fields[0],
        'sh_type': fields[1],
        'sh_flags': fields[2],
        'sh_addr': fields[3],
        'sh_offset': fields[4],
        'sh_size': fields[5],
        'sh_link': fields[6],
        'sh_info': fields[7],
        'sh_addralign': fields[8],
        'sh_entsize': fields[9],
    }

def main():
    with open(INPUT, 'rb') as f:
        data = bytearray(f.read())

    # Parse ELF header
    e_shoff = struct.unpack_from('<Q', data, 40)[0]
    e_shentsize = struct.unpack_from('<H', data, 58)[0]
    e_shnum = struct.unpack_from('<H', data, 60)[0]
    e_shstrndx = struct.unpack_from('<H', data, 62)[0]

    print(f"Original: {len(data)} bytes, {e_shnum} sections")
    print(f"e_shoff=0x{e_shoff:x}, e_shentsize={e_shentsize}, e_shstrndx={e_shstrndx}")

    # Read shstrtab
    shstrtab_shdr = read_elf64_shdr(data, e_shoff + e_shstrndx * e_shentsize)
    shstrtab_off = shstrtab_shdr['sh_offset']
    shstrtab_size = shstrtab_shdr['sh_size']

    # Find symtab section for link field
    symtab_idx = None
    for i in range(e_shnum):
        shdr = read_elf64_shdr(data, e_shoff + i * e_shentsize)
        if shdr['sh_type'] == 2:  # SHT_SYMTAB
            symtab_idx = i
            break

    # Find init_module and cleanup_module symbol indices
    symtab_shdr = read_elf64_shdr(data, e_shoff + symtab_idx * e_shentsize)
    sym_off = symtab_shdr['sh_offset']
    sym_count = symtab_shdr['sh_size'] // 24

    init_sym_idx = None
    cleanup_sym_idx = None

    strtab_shdr = read_elf64_shdr(data, e_shoff + symtab_shdr['sh_link'] * e_shentsize)
    strtab_off = strtab_shdr['sh_offset']

    for i in range(sym_count):
        off = sym_off + i * 24
        st_name = struct.unpack_from('<I', data, off)[0]
        name_end = data.index(b'\x00', strtab_off + st_name)
        name = data[strtab_off + st_name:name_end].decode()
        if name == 'init_module':
            init_sym_idx = i
        elif name == 'cleanup_module':
            cleanup_sym_idx = i

    print(f"init_module: sym {init_sym_idx}")
    print(f"cleanup_module: sym {cleanup_sym_idx}")

    # Step 1: Add section name strings to shstrtab
    new_sec_name = b".gnu.linkonce.this_module\x00"
    new_rela_name = b".rela.gnu.linkonce.this_module\x00"

    # Append to shstrtab
    sec_name_offset = shstrtab_size  # offset within shstrtab
    rela_name_offset = shstrtab_size + len(new_sec_name)

    # Insert the new strings at the end of shstrtab data
    insert_pos = shstrtab_off + shstrtab_size
    new_strings = new_sec_name + new_rela_name
    data[insert_pos:insert_pos] = new_strings

    # Update shstrtab size
    shstrtab_shdr_off = e_shoff + e_shstrndx * e_shentsize
    # But e_shoff might need updating if section headers are after insert_pos
    if e_shoff >= insert_pos:
        e_shoff += len(new_strings)
        struct.pack_into('<Q', data, 40, e_shoff)
        shstrtab_shdr_off = e_shoff + e_shstrndx * e_shentsize

    # Update all section offsets after insert_pos
    for i in range(e_shnum):
        shdr_off = e_shoff + i * e_shentsize
        shdr = read_elf64_shdr(data, shdr_off)
        if i == e_shstrndx:
            shdr['sh_size'] += len(new_strings)
            struct.pack_into('<IIQQQQIIQQ', data, shdr_off,
                shdr['sh_name'], shdr['sh_type'], shdr['sh_flags'],
                shdr['sh_addr'], shdr['sh_offset'], shdr['sh_size'],
                shdr['sh_link'], shdr['sh_info'], shdr['sh_addralign'],
                shdr['sh_entsize'])
        elif shdr['sh_offset'] >= insert_pos and shdr['sh_offset'] > 0:
            shdr['sh_offset'] += len(new_strings)
            struct.pack_into('<IIQQQQIIQQ', data, shdr_off,
                shdr['sh_name'], shdr['sh_type'], shdr['sh_flags'],
                shdr['sh_addr'], shdr['sh_offset'], shdr['sh_size'],
                shdr['sh_link'], shdr['sh_info'], shdr['sh_addralign'],
                shdr['sh_entsize'])

    # Step 1b: Also add PLT section name strings
    plt_name = b".plt\x00"
    init_plt_name = b".init.plt\x00"
    alt_text_name = b".text.ftrace_trampoline\x00"
    plt_name_offset = shstrtab_size + len(new_strings)
    init_plt_name_offset = plt_name_offset + len(plt_name)
    alt_text_name_offset = init_plt_name_offset + len(init_plt_name)

    # Re-insert these additional strings at insert_pos (which is now shifted)
    extra_strings = plt_name + init_plt_name + alt_text_name
    data[insert_pos + len(new_strings):insert_pos + len(new_strings)] = extra_strings

    # Update shstrtab size again
    for i in range(e_shnum):
        shdr_off = e_shoff + i * e_shentsize
        shdr = read_elf64_shdr(data, shdr_off)
        if i == e_shstrndx:
            shdr['sh_size'] += len(extra_strings)
            struct.pack_into('<IIQQQQIIQQ', data, shdr_off,
                shdr['sh_name'], shdr['sh_type'], shdr['sh_flags'],
                shdr['sh_addr'], shdr['sh_offset'], shdr['sh_size'],
                shdr['sh_link'], shdr['sh_info'], shdr['sh_addralign'],
                shdr['sh_entsize'])
        elif shdr['sh_offset'] > insert_pos and shdr['sh_offset'] > 0:
            shdr['sh_offset'] += len(extra_strings)
            struct.pack_into('<IIQQQQIIQQ', data, shdr_off,
                shdr['sh_name'], shdr['sh_type'], shdr['sh_flags'],
                shdr['sh_addr'], shdr['sh_offset'], shdr['sh_size'],
                shdr['sh_link'], shdr['sh_info'], shdr['sh_addralign'],
                shdr['sh_entsize'])

    # Also update e_shoff if needed
    if e_shoff >= insert_pos + len(new_strings):
        e_shoff += len(extra_strings)
        struct.pack_into('<Q', data, 40, e_shoff)

    # Step 2: Add .gnu.linkonce.this_module section data
    # Align to 64 bytes
    align_pad = (64 - (len(data) % 64)) % 64
    data.extend(b'\x00' * align_pad)
    module_data_off = len(data)

    # Create module struct
    module_data = bytearray(MODULE_SIZE)
    # Set name
    module_data[NAME_OFFSET:NAME_OFFSET + len(MODULE_NAME)] = MODULE_NAME
    data.extend(module_data)

    # Step 3: Add .rela.gnu.linkonce.this_module section data
    rela_data_off = len(data)
    # Two rela entries:
    # 1. init at offset 0x150
    rela1 = struct.pack('<QQq', INIT_OFFSET,
                        (init_sym_idx << 32) | R_AARCH64_ABS64, 0)
    # 2. exit at offset 0x310
    rela2 = struct.pack('<QQq', EXIT_OFFSET,
                        (cleanup_sym_idx << 32) | R_AARCH64_ABS64, 0)
    data.extend(rela1 + rela2)

    # Step 4: Add two new section headers
    new_sec_idx = e_shnum  # this_module section index
    new_rela_idx = e_shnum + 1  # rela.this_module section index

    # Re-read symtab_idx (may have changed if reordering happened)
    # Actually, section indices don't change, just offsets
    # But we need to re-find symtab_idx after offset adjustments
    for i in range(e_shnum):
        shdr = read_elf64_shdr(data, e_shoff + i * e_shentsize)
        if shdr['sh_type'] == 2:  # SHT_SYMTAB
            symtab_idx = i
            break

    # .gnu.linkonce.this_module section header
    this_module_shdr = struct.pack('<IIQQQQIIQQ',
        sec_name_offset,  # sh_name (offset in shstrtab)
        1,  # sh_type = SHT_PROGBITS
        3,  # sh_flags = SHF_WRITE | SHF_ALLOC
        0,  # sh_addr
        module_data_off,  # sh_offset
        MODULE_SIZE,  # sh_size
        0,  # sh_link
        0,  # sh_info
        64,  # sh_addralign
        0,  # sh_entsize
    )

    # .rela.gnu.linkonce.this_module section header
    rela_module_shdr = struct.pack('<IIQQQQIIQQ',
        rela_name_offset,  # sh_name
        4,  # sh_type = SHT_RELA
        0x40,  # sh_flags = SHF_INFO_LINK
        0,  # sh_addr
        rela_data_off,  # sh_offset
        48,  # sh_size (2 entries × 24 bytes)
        symtab_idx,  # sh_link (symtab section)
        new_sec_idx,  # sh_info (section being relocated)
        8,  # sh_addralign
        24,  # sh_entsize (sizeof Elf64_Rela)
    )

    # Append section headers
    # Section headers are at e_shoff, we need to append after existing ones
    sec_headers_end = e_shoff + e_shnum * e_shentsize
    # Ensure we have space
    if sec_headers_end > len(data):
        data.extend(b'\x00' * (sec_headers_end - len(data)))

    # Actually, the section header table might not be at the end.
    # We need to append the new section headers at the end of the section header table.
    # If the section header table is at the end of the file, we can just append.
    # Otherwise, we need to relocate it.

    # Check if section headers are at the end
    if e_shoff + e_shnum * e_shentsize <= len(data):
        # Headers might not be at the very end, but we can extend
        # Let's just put them at the end of the current data
        pass

    # Actually, simpler: put new section headers right after existing ones
    # Check if there's data after the section header table
    sh_table_end = e_shoff + e_shnum * e_shentsize
    if sh_table_end < module_data_off:
        # Section headers are before our new data - OK
        # But we can't just append to them because other data is in between
        # Need to move section headers to the end

        # Move section header table to end of file
        old_sh_data = bytes(data[e_shoff:e_shoff + e_shnum * e_shentsize])
        new_e_shoff = len(data)
        # Align
        align = (8 - (new_e_shoff % 8)) % 8
        data.extend(b'\x00' * align)
        new_e_shoff = len(data)
        data.extend(old_sh_data)
        data.extend(this_module_shdr)
        data.extend(rela_module_shdr)

        # Update e_shoff
        struct.pack_into('<Q', data, 40, new_e_shoff)
        e_shoff = new_e_shoff
    else:
        # Section headers are at the end, just append
        data.extend(this_module_shdr)
        data.extend(rela_module_shdr)

    # Update e_shnum
    struct.pack_into('<H', data, 60, e_shnum + 2)

    with open(OUTPUT, 'wb') as f:
        f.write(data)

    print(f"Output: {len(data)} bytes, {e_shnum + 2} sections")
    print(f"Module data at 0x{module_data_off:x}, rela at 0x{rela_data_off:x}")
    print(f"Section headers at 0x{e_shoff:x}")
    print(f"Written: {OUTPUT}")

if __name__ == "__main__":
    main()
