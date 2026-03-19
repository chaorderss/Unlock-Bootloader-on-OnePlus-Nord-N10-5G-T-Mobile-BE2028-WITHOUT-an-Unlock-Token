#!/usr/bin/env python3
"""Verify binary alignment and address mapping."""
import struct

text = open('/tmp/linuxloader_text.bin','rb').read()
pe = open('/tmp/ffs_modules/pe32_59d536f5_1.bin','rb').read()
print(f'Text size: 0x{len(text):X}')
print(f'PE size: 0x{len(pe):X}')

def u32t(off): return struct.unpack_from('<I', text, off)[0]
def u32p(off): return struct.unpack_from('<I', pe, off)[0]

# Check if text == pe[0:text_size]
if text == pe[:len(text)]:
    print('Text == PE[0:text_size] ← SAME')
else:
    for i in range(min(len(text), len(pe))):
        if text[i] != pe[i]:
            print(f'First diff at 0x{i:X}: text=0x{text[i]:02X} pe=0x{pe[i]:02X}')
            break
    idx = pe.find(text[:256])
    if idx >= 0:
        print(f'Text[0:256] found in PE at offset 0x{idx:X}')
    else:
        print('Text NOT found in PE at start')

# Check known addresses
for addr, name in [(0x23390, "BL init_defaults"), (0x232D8, "ReadDeviceInfo entry"),
                   (0x384D0, "init_defaults entry"), (0x22C18, "IsDeviceUnlocked?"),
                   (0x38538, "STRB devinfo[13]"), (0x189E0, "IsSecureBootEnabled"),
                   (0x362D8, "OemCheckResetDevInfo"), (0x01558, "BL ReadDeviceInfo")]:
    wt = u32t(addr) if addr < len(text) else 0
    wp = u32p(addr) if addr < len(pe) else 0
    print(f'{name:30s} text[0x{addr:05X}]=0x{wt:08X}  pe[0x{addr:05X}]=0x{wp:08X}  {"SAME" if wt==wp else "DIFF!!"}')

# Parse PE headers to find section layout
print('\n--- PE Header Analysis ---')
# DOS header: e_lfanew at offset 0x3C
e_lfanew = struct.unpack_from('<I', pe, 0x3C)[0]
print(f'e_lfanew = 0x{e_lfanew:X}')
# PE signature at e_lfanew
sig = struct.unpack_from('<I', pe, e_lfanew)[0]
print(f'PE signature = 0x{sig:08X} (should be 0x00004550)')
# COFF header at e_lfanew + 4
machine = struct.unpack_from('<H', pe, e_lfanew + 4)[0]
num_sections = struct.unpack_from('<H', pe, e_lfanew + 6)[0]
opt_hdr_size = struct.unpack_from('<H', pe, e_lfanew + 20)[0]
print(f'Machine: 0x{machine:X}')
print(f'Num sections: {num_sections}')
print(f'Optional header size: 0x{opt_hdr_size:X}')
# Optional header magic
opt_magic = struct.unpack_from('<H', pe, e_lfanew + 24)[0]
print(f'Optional header magic: 0x{opt_magic:X} (0x20B=PE32+)')
# Image base
if opt_magic == 0x20B:
    image_base = struct.unpack_from('<Q', pe, e_lfanew + 24 + 24)[0]
    entry_point = struct.unpack_from('<I', pe, e_lfanew + 24 + 16)[0]
    print(f'Image base: 0x{image_base:X}')
    print(f'Entry point RVA: 0x{entry_point:X}')

# Section headers start at e_lfanew + 24 + opt_hdr_size
sec_start = e_lfanew + 24 + opt_hdr_size
print(f'\nSections (at offset 0x{sec_start:X}):')
for i in range(num_sections):
    off = sec_start + i * 40
    name = pe[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
    vsize = struct.unpack_from('<I', pe, off + 8)[0]
    va = struct.unpack_from('<I', pe, off + 12)[0]
    rawsize = struct.unpack_from('<I', pe, off + 16)[0]
    rawptr = struct.unpack_from('<I', pe, off + 20)[0]
    chars = struct.unpack_from('<I', pe, off + 36)[0]
    flags = []
    if chars & 0x20: flags.append('CODE')
    if chars & 0x40: flags.append('IDATA')
    if chars & 0x80: flags.append('UDATA')
    if chars & 0x20000000: flags.append('EXEC')
    if chars & 0x40000000: flags.append('READ')
    if chars & 0x80000000: flags.append('WRITE')
    print(f'  [{i}] {name:8s} VA=0x{va:08X} VSize=0x{vsize:08X} RawPtr=0x{rawptr:08X} RawSize=0x{rawsize:08X} {"|".join(flags)}')

# Now find which section contains address 0x384D0
print('\n--- Address resolution ---')
for addr, name in [(0x384D0, "init_defaults"), (0x22C18, "IsDeviceUnlocked?"),
                   (0x232D8, "ReadDeviceInfo"), (0x46AA0, "FastbootInit")]:
    for i in range(num_sections):
        off = sec_start + i * 40
        sec_name = pe[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
        va = struct.unpack_from('<I', pe, off + 12)[0]
        vsize = struct.unpack_from('<I', pe, off + 8)[0]
        rawptr = struct.unpack_from('<I', pe, off + 20)[0]
        if va <= addr < va + vsize:
            file_off = rawptr + (addr - va)
            w = struct.unpack_from('<I', pe, file_off)[0]
            print(f'{name:25s} 0x{addr:05X} → section [{sec_name}] file_off=0x{file_off:X} → 0x{w:08X}')
            break
