#!/usr/bin/env python3
"""Parse GPT with 4K sector size and check GUID references in PE."""
import struct

gpt_path = '/Users/xmxx/pinganhuijia/edl_backup/lun4/gpt_main4.bin'
pe_path = '/tmp/ffs_modules/pe32_59d536f5_1.bin'

gpt = open(gpt_path, 'rb').read()
pe = open(pe_path, 'rb').read()

def fmt_guid(b):
    if len(b) < 16:
        return "too short"
    return (f'{struct.unpack_from("<I", b, 0)[0]:08X}-'
            f'{struct.unpack_from("<H", b, 4)[0]:04X}-'
            f'{struct.unpack_from("<H", b, 6)[0]:04X}-'
            f'{b[8]:02X}{b[9]:02X}-'
            f'{b[10]:02X}{b[11]:02X}{b[12]:02X}{b[13]:02X}{b[14]:02X}{b[15]:02X}')

# Try different sector sizes
for sector_size in [4096, 512]:
    hdr_off = sector_size  # LBA 1
    if hdr_off + 92 > len(gpt):
        continue
    sig = gpt[hdr_off:hdr_off+8]
    if sig == b'EFI PART':
        print(f'GPT found with sector size {sector_size}')
        entry_lba = struct.unpack_from('<Q', gpt, hdr_off+72)[0]
        entry_count = struct.unpack_from('<I', gpt, hdr_off+80)[0]
        entry_size = struct.unpack_from('<I', gpt, hdr_off+84)[0]
        print(f'Entries start LBA: {entry_lba}, count: {entry_count}, size: {entry_size}')

        entries_start = entry_lba * sector_size
        devinfo_found = False
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
            name = gpt[off+56:off+128].decode('utf-16-le').rstrip('\x00')

            if 'devinfo' in name.lower():
                devinfo_found = True
                print(f'\n*** DEVINFO PARTITION ***')
                print(f'  Name: {name}')
                print(f'  First LBA: {first_lba} (byte offset: 0x{first_lba * sector_size:X})')
                print(f'  Last LBA: {last_lba}')
                size = (last_lba - first_lba + 1) * sector_size
                print(f'  Size: {size} bytes')
                print(f'  Type GUID: {fmt_guid(type_guid)}')
                print(f'  Unique GUID: {fmt_guid(unique_guid)}')

                # Check if these GUIDs match PE binary
                pe_guid1 = pe[0x69BE0:0x69BF0]
                pe_guid2 = pe[0x69C10:0x69C20]
                if type_guid == pe_guid1:
                    print(f'  >> Type GUID matches PE 0x69BE0!')
                if unique_guid == pe_guid1:
                    print(f'  >> Unique GUID matches PE 0x69BE0!')
                if type_guid == pe_guid2:
                    print(f'  >> Type GUID matches PE 0x69C10!')
                if unique_guid == pe_guid2:
                    print(f'  >> Unique GUID matches PE 0x69C10!')

                # Search PE for both GUIDs
                for pe_off in range(0, len(pe) - 16):
                    if pe[pe_off:pe_off+16] == type_guid:
                        print(f'  >> Type GUID found in PE at 0x{pe_off:X}')
                    if pe[pe_off:pe_off+16] == unique_guid:
                        print(f'  >> Unique GUID found in PE at 0x{pe_off:X}')

        if not devinfo_found:
            print('\n  devinfo partition NOT found in GPT!')
            print('  All partitions:')
            for i in range(min(entry_count, 128)):
                off = entries_start + i * entry_size
                if off + entry_size > len(gpt):
                    break
                type_guid = gpt[off:off+16]
                if type_guid == b'\x00' * 16:
                    continue
                name = gpt[off+56:off+128].decode('utf-16-le').rstrip('\x00')
                first_lba = struct.unpack_from('<Q', gpt, off+32)[0]
                print(f'    {name}: LBA {first_lba}')
        break
else:
    print('GPT signature not found at LBA 1 with either 512 or 4096 sector size')
    print(f'File size: {len(gpt)} bytes')
    # Try to find EFI PART signature anywhere
    idx = gpt.find(b'EFI PART')
    if idx >= 0:
        print(f'Found "EFI PART" at offset 0x{idx:X} ({idx})')

# Check PE .data section GUIDs
print('\n=== PE binary GUID locations ===')
print(f'  0x69BE0: {fmt_guid(pe[0x69BE0:0x69BF0])}')
print(f'  0x69C10: {fmt_guid(pe[0x69C10:0x69C20])}')

# Check data section GUIDs referenced by ReadWritePartition
print(f'\n  0x1BEBE0: {pe[0x1BEBE0:0x1BEBF0].hex()}')
print(f'  0x1BEC10: {pe[0x1BEC10:0x1BEC20].hex()}')
# These might be zero (uninitialized) or contain data
if pe[0x1BEBE0:0x1BEBF0] != b'\x00' * 16:
    print(f'  0x1BEBE0 as GUID: {fmt_guid(pe[0x1BEBE0:0x1BEBF0])}')
if pe[0x1BEC10:0x1BEC20] != b'\x00' * 16:
    print(f'  0x1BEC10 as GUID: {fmt_guid(pe[0x1BEC10:0x1BEC20])}')

# Disassemble ReadWritePartition to understand GUID usage
print('\n=== ReadWritePartition 0x18248 detailed ===')
def r32(off):
    return struct.unpack_from('<I', pe, off)[0]

for off in range(0x18248, 0x18420, 4):
    inst = r32(off)
    s = f'  0x{off:05X}: 0x{inst:08X}'
    if (inst & 0x9F000000) == 0x90000000:
        rd = inst & 0x1F
        immhi = (inst >> 5) & 0x7FFFF; immlo = (inst >> 29) & 0x3
        iv = (immhi << 2) | immlo
        if iv & 0x100000: iv |= ~0x1FFFFF
        pg = ((off & ~0xFFF) + (iv << 12)) & 0xFFFFFFFF
        s += f'  ADRP x{rd}, 0x{pg:X}'
    elif (inst & 0xFF800000) == 0x91000000:
        rd = inst & 0x1F; rn = (inst >> 5) & 0x1F
        imm12 = (inst >> 10) & 0xFFF
        sh = (inst >> 22) & 1
        if sh: imm12 <<= 12
        s += f'  ADD x{rd}, x{rn}, #0x{imm12:X}'
    elif (inst >> 26) == 0x25:
        imm = inst & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        t = off + (imm << 2)
        s += f'  BL 0x{t & 0xFFFFFFFF:05X}'
    elif (inst & 0xFFFFFC1F) == 0xD63F0000:
        rn = (inst >> 5) & 0x1F
        s += f'  BLR x{rn}'
    elif (inst & 0xFFC00000) == 0xF9400000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = ((inst >> 10) & 0xFFF) * 8
        s += f'  LDR x{rt}, [x{rn}, #{imm}]'
    elif (inst & 0xFFC00000) == 0xF9000000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = ((inst >> 10) & 0xFFF) * 8
        s += f'  STR x{rt}, [x{rn}, #{imm}]'
    elif inst == 0xD65F03C0:
        s += '  RET'
    print(s)
    if inst == 0xD65F03C0 and off > 0x183A0:
        break

print('\nDone.')
