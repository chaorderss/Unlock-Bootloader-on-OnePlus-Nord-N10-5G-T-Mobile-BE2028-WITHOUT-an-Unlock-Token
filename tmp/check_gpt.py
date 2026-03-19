#!/usr/bin/env python3
"""Parse GPT to find devinfo partition sector offset and compare GUID with PE binary."""
import struct

gpt_path = '/Users/xmxx/pinganhuijia/edl_backup/lun4/gpt_main4.bin'
pe_path = '/tmp/ffs_modules/pe32_59d536f5_1.bin'

gpt = open(gpt_path, 'rb').read()
pe = open(pe_path, 'rb').read()

def fmt_guid(b):
    return f'{struct.unpack_from("<I", b, 0)[0]:08X}-{struct.unpack_from("<H", b, 4)[0]:04X}-{struct.unpack_from("<H", b, 6)[0]:04X}-{b[8]:02X}{b[9]:02X}-{b[10]:02X}{b[11]:02X}{b[12]:02X}{b[13]:02X}{b[14]:02X}{b[15]:02X}'

# GPT header at LBA 1 (offset 512)
sig = gpt[512:520]
print(f'GPT signature: {sig}')
entry_lba = struct.unpack_from('<Q', gpt, 512+72)[0]
entry_count = struct.unpack_from('<I', gpt, 512+80)[0]
entry_size = struct.unpack_from('<I', gpt, 512+84)[0]
print(f'Entries start LBA: {entry_lba}, count: {entry_count}, entry size: {entry_size}')

entries_start = entry_lba * 512
for i in range(min(entry_count, 128)):
    off = entries_start + i * entry_size
    if off + entry_size > len(gpt):
        break
    type_guid = gpt[off:off+16]
    if type_guid == b'\x00' * 16:
        continue
    unique_guid = gpt[off+16:off+32]
    first_lba = struct.unpack_from('<Q', gpt, off+32)[0]
    last_lba = struct.unpack_from('<Q', gpt, off+40)[0]
    name_raw = gpt[off+56:off+128]
    name = name_raw.decode('utf-16-le').rstrip('\x00')
    if 'devinfo' in name.lower():
        print(f'\n*** DEVINFO PARTITION ***')
        print(f'  Name: {name}')
        print(f'  First LBA: {first_lba} (byte offset: 0x{first_lba*4096:X})')
        print(f'  Last LBA: {last_lba}')
        print(f'  Size: {(last_lba - first_lba + 1) * 4096} bytes (assuming 4K sectors)')
        print(f'  Type GUID: {fmt_guid(type_guid)}')
        print(f'  Unique GUID: {fmt_guid(unique_guid)}')

# Check GUID in PE binary at 0x69BE0
print('\n=== GUID in PE binary at 0x69BE0 (used by ReadWritePartition) ===')
pe_guid = pe[0x69BE0:0x69BF0]
print(f'  Raw: {pe_guid.hex()}')
print(f'  Formatted: {fmt_guid(pe_guid)}')

# Also check 0x69C10
pe_guid2 = pe[0x69C10:0x69C20]
print(f'\n  GUID at 0x69C10: {pe_guid2.hex()}')
print(f'  Formatted: {fmt_guid(pe_guid2)}')

# Check if ReadWritePartition uses partition name or GUID
# The GUID at 0x69BE0 is used as parameter to BlockIo protocol
# Let's also check if this GUID matches the GPT type or unique GUID
print('\n=== GUID COMPARISON ===')
# Search all GPT entries for matching GUIDs
for i in range(min(entry_count, 128)):
    off = entries_start + i * entry_size
    if off + entry_size > len(gpt):
        break
    type_guid = gpt[off:off+16]
    if type_guid == b'\x00' * 16:
        continue
    unique_guid = gpt[off+16:off+32]
    name_raw = gpt[off+56:off+128]
    name = name_raw.decode('utf-16-le').rstrip('\x00')

    if type_guid == pe_guid or unique_guid == pe_guid:
        print(f'  PE GUID 0x69BE0 matches partition: {name}')
        if type_guid == pe_guid:
            print(f'    Matched: type_guid')
        if unique_guid == pe_guid:
            print(f'    Matched: unique_guid')
    if type_guid == pe_guid2 or unique_guid == pe_guid2:
        print(f'  PE GUID 0x69C10 matches partition: {name}')

# Also search for the GUID bytes in PE binary (in case it's stored elsewhere)
print('\n=== Search PE for devinfo unique GUID ===')
# Get devinfo unique GUID from GPT
for i in range(min(entry_count, 128)):
    off = entries_start + i * entry_size
    if off + entry_size > len(gpt):
        break
    name_raw = gpt[off+56:off+128]
    name = name_raw.decode('utf-16-le').rstrip('\x00')
    if 'devinfo' in name.lower():
        unique_guid = gpt[off+16:off+32]
        type_guid = gpt[off:off+16]
        # Search PE for this GUID
        idx = pe.find(unique_guid)
        if idx >= 0:
            print(f'  Devinfo unique GUID found in PE at offset 0x{idx:X}')
        else:
            print(f'  Devinfo unique GUID NOT found in PE')
        idx = pe.find(type_guid)
        if idx >= 0:
            print(f'  Devinfo type GUID found in PE at offset 0x{idx:X}')
        else:
            print(f'  Devinfo type GUID NOT found in PE')

# Check the actual ReadWritePartition function at 0x18248 more carefully
# What GUID does it use and how?
print('\n=== ReadWritePartition 0x18248 — GUID usage ===')
# Scan for ADRP in ReadWritePartition area
for off in range(0x18248, 0x18400, 4):
    inst = struct.unpack_from('<I', pe, off)[0]
    if (inst & 0x9F000000) == 0x90000000:
        rd = inst & 0x1F
        immhi = (inst >> 5) & 0x7FFFF
        immlo = (inst >> 29) & 0x3
        iv = (immhi << 2) | immlo
        if iv & 0x100000:
            iv |= ~0x1FFFFF
        pg = ((off & ~0xFFF) + (iv << 12)) & 0xFFFFFFFF
        # Check next ADD for full address
        next_inst = struct.unpack_from('<I', pe, off+4)[0]
        if (next_inst & 0xFF800000) == 0x91000000:
            nimm = (next_inst >> 10) & 0xFFF
            sh = (next_inst >> 22) & 1
            if sh:
                nimm <<= 12
            addr = pg + nimm
            print(f'  0x{off:05X}: ADRP+ADD → 0x{addr:X}')
            if 0x69000 <= addr <= 0x6A000:
                raw = pe[addr:addr+16]
                print(f'    Data at 0x{addr:X}: {raw.hex()}')
                if len(raw) >= 16:
                    print(f'    As GUID: {fmt_guid(raw)}')
        else:
            print(f'  0x{off:05X}: ADRP x{rd}, 0x{pg:X}')

print('\nDone.')
