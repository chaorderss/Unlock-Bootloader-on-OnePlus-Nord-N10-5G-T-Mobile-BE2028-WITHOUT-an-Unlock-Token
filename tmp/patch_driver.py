#!/usr/bin/env python3
"""
Patch qca_cld3_wlan.ko to add ndo_start_xmit (hdd_hard_start_xmit) to
wlan_mon_drv_ops, enabling TX in monitor mode.

Also adds hdd_select_queue at +0x30 for proper multi-queue support.

Strategy:
1. Parse ELF structure
2. Add new RELA entries in .rela.rodata for:
   - wlan_mon_drv_ops[+0x20] -> hdd_hard_start_xmit (R_AARCH64_ABS64)
   - wlan_mon_drv_ops[+0x30] -> hdd_select_queue (R_AARCH64_ABS64)
3. Since we can't easily expand .rela.rodata in-place, we'll:
   a. Find an existing unused/duplicate rela entry to overwrite, OR
   b. Expand the section by appending entries and adjusting section size

Approach (b) is cleaner: append new rela entries after the current .rela.rodata
data and update the section header's sh_size.
"""
import struct
import sys
import shutil
import os

INPUT = "/Users/xmxx/pinganhuijia/tmp/qca_cld3_wlan.ko"
OUTPUT = "/Users/xmxx/pinganhuijia/tmp/qca_cld3_wlan_patched.ko"

# R_AARCH64_ABS64
R_AARCH64_ABS64 = 0x101

# From analysis:
# wlan_mon_drv_ops is at .rodata offset 0x5f10
# ndo_start_xmit slot: +0x20 = rodata offset 0x5f30
# ndo_select_queue slot: +0x30 = rodata offset 0x5f40

# Symbol indices (from readelf -s):
SYM_HDD_HARD_START_XMIT = 8423
SYM_HDD_SELECT_QUEUE = 11863

# New relocations to add:
NEW_RELAS = [
    # (r_offset_in_rodata, sym_idx, r_type, r_addend)
    (0x5f30, SYM_HDD_HARD_START_XMIT, R_AARCH64_ABS64, 0),  # ndo_start_xmit
    (0x5f40, SYM_HDD_SELECT_QUEUE, R_AARCH64_ABS64, 0),       # ndo_select_queue
]


def read_elf64_shdr(data, offset):
    """Read one ELF64 section header"""
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


def write_elf64_shdr(data, offset, shdr):
    """Write one ELF64 section header"""
    struct.pack_into('<IIQQQQIIQQ', data, offset,
                     shdr['sh_name'],
                     shdr['sh_type'],
                     shdr['sh_flags'],
                     shdr['sh_addr'],
                     shdr['sh_offset'],
                     shdr['sh_size'],
                     shdr['sh_link'],
                     shdr['sh_info'],
                     shdr['sh_addralign'],
                     shdr['sh_entsize'])


def get_section_name(data, shstrtab_offset, name_offset):
    end = data.index(b'\x00', shstrtab_offset + name_offset)
    return data[shstrtab_offset + name_offset:end].decode('utf-8', errors='replace')


def main():
    with open(INPUT, 'rb') as f:
        original = f.read()

    data = bytearray(original)

    # Parse ELF header
    e_shoff = struct.unpack_from('<Q', data, 40)[0]
    e_shentsize = struct.unpack_from('<H', data, 58)[0]
    e_shnum = struct.unpack_from('<H', data, 60)[0]
    e_shstrndx = struct.unpack_from('<H', data, 62)[0]

    # Get section string table
    shstrtab = read_elf64_shdr(data, e_shoff + e_shstrndx * e_shentsize)

    # Find sections
    rela_rodata_idx = None
    rela_rodata = None

    for i in range(e_shnum):
        shdr_off = e_shoff + i * e_shentsize
        shdr = read_elf64_shdr(data, shdr_off)
        name = get_section_name(data, shstrtab['sh_offset'], shdr['sh_name'])
        if name == '.rela.rodata':
            rela_rodata_idx = i
            rela_rodata = shdr
            rela_rodata_shdr_off = shdr_off
            break

    if rela_rodata is None:
        print("ERROR: .rela.rodata section not found")
        return 1

    print(f"=== .rela.rodata section ===")
    print(f"  Index: {rela_rodata_idx}")
    print(f"  File offset: 0x{rela_rodata['sh_offset']:08x}")
    print(f"  Size: 0x{rela_rodata['sh_size']:08x} ({rela_rodata['sh_size']} bytes)")
    print(f"  Entries: {rela_rodata['sh_size'] // 24}")
    print(f"  Section header at: 0x{rela_rodata_shdr_off:08x}")

    # Check what's immediately after .rela.rodata
    rela_end = rela_rodata['sh_offset'] + rela_rodata['sh_size']
    print(f"  Data ends at: 0x{rela_end:08x}")

    # Find next section after .rela.rodata by file offset
    next_section_off = len(data)
    next_section_name = "EOF"
    for i in range(e_shnum):
        shdr = read_elf64_shdr(data, e_shoff + i * e_shentsize)
        name = get_section_name(data, shstrtab['sh_offset'], shdr['sh_name'])
        if shdr['sh_offset'] > rela_rodata['sh_offset'] and shdr['sh_offset'] < next_section_off:
            next_section_off = shdr['sh_offset']
            next_section_name = name

    gap = next_section_off - rela_end
    print(f"  Next section: {next_section_name} at 0x{next_section_off:08x}")
    print(f"  Gap after .rela.rodata: {gap} bytes")

    # Each new rela entry is 24 bytes (sizeof(Elf64_Rela))
    needed = len(NEW_RELAS) * 24
    print(f"  Need {needed} bytes for {len(NEW_RELAS)} new entries")

    if gap >= needed:
        # Great! We can simply append entries in the gap
        print(f"  Strategy: Append in existing gap (have {gap}, need {needed})")

        for i, (r_offset, sym_idx, r_type, r_addend) in enumerate(NEW_RELAS):
            r_info = (sym_idx << 32) | r_type
            entry_off = rela_end + i * 24
            struct.pack_into('<QQq', data, entry_off, r_offset, r_info, r_addend)
            print(f"  Writing rela entry at 0x{entry_off:08x}: "
                  f"offset=0x{r_offset:08x} info=0x{r_info:016x} addend=0x{r_addend:x}")

        # Update .rela.rodata section header size
        new_size = rela_rodata['sh_size'] + needed
        rela_rodata['sh_size'] = new_size
        write_elf64_shdr(data, rela_rodata_shdr_off, rela_rodata)
        print(f"  Updated .rela.rodata sh_size: 0x{new_size:08x} ({new_size // 24} entries)")
    else:
        # Need to insert bytes - more complex
        # Alternative: find unused rela entries to overwrite
        print(f"  Not enough gap ({gap} < {needed}). Looking for alternative...")

        # We'll insert the new entries at the end of .rela.rodata and shift everything after it
        # This requires updating all section offsets > rela_end
        insert_point = rela_end
        insert_size = needed
        # Align to 8 bytes
        insert_size = (insert_size + 7) & ~7

        print(f"  Inserting {insert_size} bytes at 0x{insert_point:08x}")

        # Insert bytes
        data[insert_point:insert_point] = b'\x00' * insert_size

        # Write new rela entries
        for i, (r_offset, sym_idx, r_type, r_addend) in enumerate(NEW_RELAS):
            r_info = (sym_idx << 32) | r_type
            entry_off = insert_point + i * 24
            struct.pack_into('<QQq', data, entry_off, r_offset, r_info, r_addend)
            print(f"  Writing rela entry at 0x{entry_off:08x}")

        # Update .rela.rodata size
        rela_rodata['sh_size'] += insert_size
        # Need to re-find the section header offset (it may have moved if it was after insert point)
        if rela_rodata_shdr_off >= insert_point:
            rela_rodata_shdr_off += insert_size
        # Also update e_shoff if section headers are after insert point
        if e_shoff >= insert_point:
            new_e_shoff = e_shoff + insert_size
            struct.pack_into('<Q', data, 40, new_e_shoff)
            e_shoff = new_e_shoff
            print(f"  Updated e_shoff: 0x{e_shoff:08x}")

        # Update all section header offsets that are >= insert_point
        for i in range(e_shnum):
            shdr_off = e_shoff + i * e_shentsize
            shdr = read_elf64_shdr(data, shdr_off)
            name = get_section_name(data, shstrtab['sh_offset'] + (insert_size if shstrtab['sh_offset'] >= insert_point else 0), shdr['sh_name'])

            if i == rela_rodata_idx:
                # Update size only (offset stays)
                shdr['sh_size'] = rela_rodata['sh_size']
                write_elf64_shdr(data, shdr_off, shdr)
            elif shdr['sh_offset'] >= insert_point and shdr['sh_offset'] > 0:
                shdr['sh_offset'] += insert_size
                write_elf64_shdr(data, shdr_off, shdr)

        print(f"  Updated section offsets")

    # Verify the patch
    print(f"\n=== Verification ===")
    # Re-read the section header
    new_shdr = read_elf64_shdr(data, rela_rodata_shdr_off if gap >= needed else e_shoff + rela_rodata_idx * e_shentsize)
    new_count = new_shdr['sh_size'] // 24
    print(f"  .rela.rodata new entry count: {new_count} (was {rela_rodata['sh_size'] // 24 - len(NEW_RELAS)})")

    # Check our new entries are there
    check_off = rela_end  # where we wrote new entries
    for i in range(len(NEW_RELAS)):
        off = check_off + i * 24
        r_offset, r_info, r_addend = struct.unpack_from('<QQq', data, off)
        sym_idx = r_info >> 32
        r_type = r_info & 0xffffffff
        print(f"  New entry {i}: offset=0x{r_offset:08x} sym={sym_idx} "
              f"type=0x{r_type:04x} addend=0x{r_addend:x}")

    # Write output
    with open(OUTPUT, 'wb') as f:
        f.write(data)

    orig_size = len(original)
    new_size = len(data)
    print(f"\n=== Output ===")
    print(f"  Original: {orig_size} bytes")
    print(f"  Patched:  {new_size} bytes")
    print(f"  Diff:     {new_size - orig_size} bytes")
    print(f"  Written:  {OUTPUT}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
