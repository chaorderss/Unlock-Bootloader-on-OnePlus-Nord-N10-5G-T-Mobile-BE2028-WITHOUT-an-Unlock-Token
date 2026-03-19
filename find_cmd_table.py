import struct

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin','rb').read()

# Find all the unlock-related strings and their locations
strings_to_find = [
    b'oem get_unlock_code',
    b'CmdTokenFlash',
    b'CmdCustUnlockFlash',
    b'flash token',
    b'flash unlock_token',
    b'oem unlock',
    b'fastboot',
]

print("=== String locations ===")
string_addrs = {}
for s in strings_to_find:
    pos = data.find(s)
    if pos != -1:
        print(f'  0x{pos:06x}: {repr(s.decode())}')
        string_addrs[s] = pos

# Search for absolute pointers to these string locations in the entire binary
# (PE32+ with base relocs would patch these up at load time)
print("\n=== Pointer references ===")
text_strings = [
    b'oem get_unlock_code',
    b'CmdTokenFlash',
    b'CmdCustUnlockFlash',
    b'oem unroot',
    b'oem reboot-recovery',
    b'flash',
]

for needle in text_strings:
    pos = data.find(needle)
    if pos == -1:
        continue
    vma = pos
    # Search for this value as 4-byte ptr
    target4 = struct.pack('<I', vma)
    target8 = struct.pack('<Q', vma)
    found4 = []
    found8 = []
    for off in range(0, len(data)-8, 4):
        if data[off:off+4] == target4:
            found4.append(off)
        if data[off:off+8] == target8:
            found8.append(off)
    print(f'  "{needle.decode()}" @ 0x{vma:x}: 4B refs={[hex(x) for x in found4]}, 8B refs={[hex(x) for x in found8]}')

# Let's also look at the base relocation table to understand what gets patched
print("\n=== Base relocation table (first entries) ===")
# Find .reloc section
pe_off = struct.unpack_from('<I', data, 0x3c)[0]
num_sections = struct.unpack_from('<H', data, pe_off+6)[0]
opt_hdr_size = struct.unpack_from('<H', data, pe_off+20)[0]
sections_off = pe_off + 24 + opt_hdr_size
reloc_vaddr = None
reloc_foff = None
for i in range(num_sections):
    sec_off = sections_off + i*40
    name = data[sec_off:sec_off+8].rstrip(b'\x00').decode('latin-1')
    if name == '.reloc':
        reloc_vaddr = struct.unpack_from('<I', data, sec_off+12)[0]
        reloc_foff = struct.unpack_from('<I', data, sec_off+20)[0]
        reloc_size = struct.unpack_from('<I', data, sec_off+16)[0]
        print(f"  .reloc section: VAddr=0x{reloc_vaddr:x}, FileOff=0x{reloc_foff:x}, Size=0x{reloc_size:x}")
        break

if reloc_foff:
    off = reloc_foff
    end = reloc_foff + reloc_size
    block_count = 0
    total_entries = 0
    all_reloc_addrs = []
    while off < end - 8:
        page_rva = struct.unpack_from('<I', data, off)[0]
        block_size = struct.unpack_from('<I', data, off+4)[0]
        if block_size == 0 or block_size > 0x10000:
            break
        num_entries = (block_size - 8) // 2
        for i in range(num_entries):
            entry = struct.unpack_from('<H', data, off+8+i*2)[0]
            reloc_type = entry >> 12
            reloc_offset = entry & 0xfff
            if reloc_type == 10:  # IMAGE_REL_BASED_DIR64
                vma = page_rva + reloc_offset
                all_reloc_addrs.append(vma)
                total_entries += 1
        off += block_size
        block_count += 1
    print(f"  Total reloc entries: {total_entries} in {block_count} blocks")

    # Now search for relocation entries that patch pointers near our strings
    target_vmas = [0x61f12, 0x61c95, 0x62055]  # oem get_unlock_code, CmdTokenFlash, CmdCustUnlockFlash
    for v in target_vmas:
        refs = [r for r in all_reloc_addrs if abs(data_at_vma(data, r, 8) - v) < 0x10 if v > 0]

# Helper function for reading VMA
def data_at_vma(d, vma, size=8):
    # For this PE: foff = vma (since VAddr==FileOff for all sections)
    return struct.unpack_from('<Q', d, vma)[0]

# Re-search: for each relocation entry, check if the patched value points near our strings
print("\n=== Relocation entries pointing to string area 0x61000-0x62000 ===")
off = reloc_foff
all_reloc_vmas = []
while off < end - 8:
    page_rva = struct.unpack_from('<I', data, off)[0]
    block_size = struct.unpack_from('<I', data, off+4)[0]
    if block_size == 0:
        break
    num_entries = (block_size - 8) // 2
    for i in range(num_entries):
        entry = struct.unpack_from('<H', data, off+8+i*2)[0]
        reloc_type = entry >> 12
        reloc_offset = entry & 0xfff
        if reloc_type == 10:  # DIR64
            vma = page_rva + reloc_offset
            # Read the 8-byte value at this VMA (which is the pointer content)
            try:
                ptr_val = struct.unpack_from('<Q', data, vma)[0]
                if 0x61000 <= ptr_val <= 0x62fff:
                    print(f"  Reloc at VMA 0x{vma:x}: ptr -> 0x{ptr_val:x}")
                    # Read what string is there
                    s = data[ptr_val:ptr_val+32]
                    printable = ''.join(chr(b) if 32<=b<127 else '.' for b in s)
                    print(f"    -> '{printable[:40]}'")
            except:
                pass
    off += block_size
