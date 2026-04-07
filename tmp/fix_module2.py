#!/usr/bin/env python3
"""
Post-process carrier_on.ko to make it a valid kernel module.
Adds: .gnu.linkonce.this_module, .plt, .init.plt sections.

Approach: Build new file by appending all new data and section headers at the end.
"""
import struct

INPUT = "/Users/xmxx/pinganhuijia/tmp/carrier_on_v3.o"
OUTPUT = "/Users/xmxx/pinganhuijia/tmp/carrier_on_v3.ko"

MODULE_SIZE = 0x340
NAME_OFFSET = 0x18
INIT_OFFSET = 0x150
EXIT_OFFSET = 0x310
MODULE_NAME = b"carrier_on"
R_AARCH64_ABS64 = 0x101

SHDR_FMT = '<IIQQQQIIQQ'
SHDR_SIZE = 64  # struct.calcsize(SHDR_FMT)


def pack_shdr(name, stype, flags, addr, offset, size, link, info, align, entsize):
    return struct.pack(SHDR_FMT, name, stype, flags, addr, offset, size,
                       link, info, align, entsize)


def main():
    with open(INPUT, 'rb') as f:
        data = bytearray(f.read())

    # ELF header
    e_shoff = struct.unpack_from('<Q', data, 40)[0]
    e_shentsize = struct.unpack_from('<H', data, 58)[0]
    e_shnum = struct.unpack_from('<H', data, 60)[0]
    e_shstrndx = struct.unpack_from('<H', data, 62)[0]

    # Read all section headers
    shdrs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        fields = struct.unpack_from(SHDR_FMT, data, off)
        shdrs.append({
            'sh_name': fields[0], 'sh_type': fields[1], 'sh_flags': fields[2],
            'sh_addr': fields[3], 'sh_offset': fields[4], 'sh_size': fields[5],
            'sh_link': fields[6], 'sh_info': fields[7],
            'sh_addralign': fields[8], 'sh_entsize': fields[9],
        })

    # Get shstrtab
    shstrtab = shdrs[e_shstrndx]
    shstrtab_data = data[shstrtab['sh_offset']:shstrtab['sh_offset'] + shstrtab['sh_size']]

    # Find symtab index
    symtab_idx = None
    for i, s in enumerate(shdrs):
        if s['sh_type'] == 2:  # SHT_SYMTAB
            symtab_idx = i
            break

    # Find init_module and cleanup_module symbol indices
    sym_shdr = shdrs[symtab_idx]
    strtab_shdr = shdrs[sym_shdr['sh_link']]
    sym_count = sym_shdr['sh_size'] // 24

    init_sym = cleanup_sym = None
    for i in range(sym_count):
        off = sym_shdr['sh_offset'] + i * 24
        st_name = struct.unpack_from('<I', data, off)[0]
        name_start = strtab_shdr['sh_offset'] + st_name
        name_end = data.index(b'\x00', name_start)
        name = data[name_start:name_end].decode()
        if name == 'init_module':
            init_sym = i
        elif name == 'cleanup_module':
            cleanup_sym = i

    print(f"init_module: sym {init_sym}, cleanup_module: sym {cleanup_sym}")

    # Add new section name strings to shstrtab
    new_names = {
        'this_module': b'.gnu.linkonce.this_module\x00',
        'rela_this_module': b'.rela.gnu.linkonce.this_module\x00',
        'plt': b'.plt\x00',
        'init_plt': b'.init.plt\x00',
    }

    name_offsets = {}
    pos = len(shstrtab_data)
    extra_strtab = bytearray()
    for key, val in new_names.items():
        name_offsets[key] = pos
        extra_strtab.extend(val)
        pos += len(val)

    # Build new file: original data + new sections
    # Start by copying original data up to end of actual content
    # (exclude old section header table since we'll rebuild it at the end)
    
    # Find max data offset (excluding section headers)
    max_data_end = 0
    for s in shdrs:
        if s['sh_type'] != 0 and s['sh_offset'] > 0:
            end = s['sh_offset'] + s['sh_size']
            if end > max_data_end:
                max_data_end = end

    # New file starts with original data
    out = bytearray(data[:max_data_end])

    # Append extra shstrtab strings
    # Update shstrtab section to include new strings
    # The shstrtab data must be contiguous, so we need to append right after it
    shstrtab_end = shstrtab['sh_offset'] + shstrtab['sh_size']
    if shstrtab_end == max_data_end:
        # shstrtab is at the end of data, just append
        out.extend(extra_strtab)
        shdrs[e_shstrndx]['sh_size'] += len(extra_strtab)
    else:
        # Need to put extra strings somewhere and adjust
        # Easier: copy shstrtab to end and update offset
        new_shstrtab_off = len(out)
        out.extend(shstrtab_data)
        out.extend(extra_strtab)
        shdrs[e_shstrndx]['sh_offset'] = new_shstrtab_off
        shdrs[e_shstrndx]['sh_size'] = len(shstrtab_data) + len(extra_strtab)

    # Align to 64
    while len(out) % 64:
        out.append(0)

    # .gnu.linkonce.this_module data
    module_off = len(out)
    module_data = bytearray(MODULE_SIZE)
    module_data[NAME_OFFSET:NAME_OFFSET + len(MODULE_NAME)] = MODULE_NAME
    out.extend(module_data)

    # .rela.gnu.linkonce.this_module data
    while len(out) % 8:
        out.append(0)
    rela_module_off = len(out)
    rela_entry1 = struct.pack('<QQq', INIT_OFFSET,
                              (init_sym << 32) | R_AARCH64_ABS64, 0)
    rela_entry2 = struct.pack('<QQq', EXIT_OFFSET,
                              (cleanup_sym << 32) | R_AARCH64_ABS64, 0)
    out.extend(rela_entry1 + rela_entry2)

    # .plt data (empty, 8-byte aligned, but kernel needs non-zero size)
    # The kernel's module_emit_plt_entry() allocates entries here
    # We need some space - allocate room for a few PLT entries
    # Each PLT entry on AArch64 is 2 instructions (8 bytes) + 8 bytes data = 16 bytes
    # Allocate space for 8 entries = 128 bytes
    while len(out) % 8:
        out.append(0)
    plt_off = len(out)
    PLT_SIZE = 8 * 24  # 8 entries, each 24 bytes (3 insns)
    out.extend(b'\x00' * PLT_SIZE)

    # .init.plt data (empty, same format)
    while len(out) % 8:
        out.append(0)
    init_plt_off = len(out)
    INIT_PLT_SIZE = 8 * 24
    out.extend(b'\x00' * INIT_PLT_SIZE)

    # Build new section header table at end of file
    while len(out) % 8:
        out.append(0)
    new_shoff = len(out)

    this_module_idx = e_shnum
    rela_module_idx = e_shnum + 1
    plt_idx = e_shnum + 2
    init_plt_idx = e_shnum + 3
    new_shnum = e_shnum + 4

    # Write existing section headers
    for s in shdrs:
        out.extend(pack_shdr(s['sh_name'], s['sh_type'], s['sh_flags'],
                             s['sh_addr'], s['sh_offset'], s['sh_size'],
                             s['sh_link'], s['sh_info'],
                             s['sh_addralign'], s['sh_entsize']))

    # .gnu.linkonce.this_module
    out.extend(pack_shdr(name_offsets['this_module'], 1, 3,  # SHT_PROGBITS, WA
                         0, module_off, MODULE_SIZE,
                         0, 0, 64, 0))

    # .rela.gnu.linkonce.this_module
    out.extend(pack_shdr(name_offsets['rela_this_module'], 4, 0x40,  # SHT_RELA, INFO_LINK
                         0, rela_module_off, 48,
                         symtab_idx, this_module_idx, 8, 24))

    # .plt
    out.extend(pack_shdr(name_offsets['plt'], 1, 6,  # SHT_PROGBITS, AX
                         0, plt_off, PLT_SIZE,
                         0, 0, 16, 0))

    # .init.plt
    out.extend(pack_shdr(name_offsets['init_plt'], 1, 6,  # SHT_PROGBITS, AX
                         0, init_plt_off, INIT_PLT_SIZE,
                         0, 0, 16, 0))

    # Update ELF header
    struct.pack_into('<Q', out, 40, new_shoff)
    struct.pack_into('<H', out, 60, new_shnum)

    with open(OUTPUT, 'wb') as f:
        f.write(out)

    print(f"Original: {len(data)} bytes, {e_shnum} sections")
    print(f"Output: {len(out)} bytes, {new_shnum} sections")
    print(f"  .gnu.linkonce.this_module: off=0x{module_off:x}, size=0x{MODULE_SIZE:x}")
    print(f"  .rela: off=0x{rela_module_off:x}, 2 entries")
    print(f"  .plt: off=0x{plt_off:x}, size={PLT_SIZE}")
    print(f"  .init.plt: off=0x{init_plt_off:x}, size={INIT_PLT_SIZE}")
    print(f"  Section headers at 0x{new_shoff:x}")

if __name__ == "__main__":
    main()
