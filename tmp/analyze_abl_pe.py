#!/usr/bin/env python3
"""Analyze ABL PE structure and find function references."""
import struct

with open('/tmp/abl_dec.bin', 'rb') as f:
    data = f.read()

# Find MZ header
mz = data.find(b'MZ')
print(f"MZ at offset 0x{mz:X}")

# PE offset from MZ+0x3C
pe_offset_rel = struct.unpack_from('<I', data, mz + 0x3C)[0]
pe_abs = mz + pe_offset_rel
print(f"PE header at 0x{pe_abs:X}")

sig = data[pe_abs:pe_abs+4]
print(f"PE signature: {sig}")

# COFF header
coff = pe_abs + 4
machine = struct.unpack_from('<H', data, coff)[0]
num_sections = struct.unpack_from('<H', data, coff + 2)[0]
opt_hdr_size = struct.unpack_from('<H', data, coff + 16)[0]
print(f"Machine: 0x{machine:X} ({'AARCH64' if machine == 0xAA64 else 'ARM' if machine == 0x1C0 else 'unknown'})")
print(f"Number of sections: {num_sections}")
print(f"Optional header size: 0x{opt_hdr_size:X}")

# Optional header
opt = coff + 20
magic = struct.unpack_from('<H', data, opt)[0]
print(f"Optional magic: 0x{magic:X} ({'PE32+' if magic == 0x20B else 'PE32' if magic == 0x10B else 'unknown'})")

if magic == 0x20B:  # PE32+
    image_base = struct.unpack_from('<Q', data, opt + 24)[0]
    entry_rva = struct.unpack_from('<I', data, opt + 16)[0]
elif magic == 0x10B:  # PE32
    image_base = struct.unpack_from('<I', data, opt + 28)[0]
    entry_rva = struct.unpack_from('<I', data, opt + 16)[0]
print(f"Image base: 0x{image_base:X}")
print(f"Entry RVA: 0x{entry_rva:X}")

# Sections
sections_offset = opt + opt_hdr_size
print(f"\n=== Sections ===")
sections = []
for i in range(num_sections):
    s_off = sections_offset + i * 40
    name = data[s_off:s_off+8].rstrip(b'\x00').decode('ascii', errors='replace')
    virt_size = struct.unpack_from('<I', data, s_off + 8)[0]
    virt_addr = struct.unpack_from('<I', data, s_off + 12)[0]
    raw_size = struct.unpack_from('<I', data, s_off + 16)[0]
    raw_ptr = struct.unpack_from('<I', data, s_off + 20)[0]
    characteristics = struct.unpack_from('<I', data, s_off + 36)[0]
    sections.append({
        'name': name, 'virt_addr': virt_addr, 'virt_size': virt_size,
        'raw_ptr': raw_ptr, 'raw_size': raw_size, 'chars': characteristics
    })
    flags = []
    if characteristics & 0x20: flags.append('CODE')
    if characteristics & 0x40: flags.append('IDATA')
    if characteristics & 0x80: flags.append('UDATA')
    if characteristics & 0x20000000: flags.append('EXEC')
    if characteristics & 0x40000000: flags.append('READ')
    if characteristics & 0x80000000: flags.append('WRITE')
    print(f"  {name:8s} VAddr=0x{virt_addr:08X} VSize=0x{virt_size:08X} "
          f"RawPtr=0x{raw_ptr:08X} RawSize=0x{raw_size:08X} [{', '.join(flags)}]")


# Helper: RVA to file offset
def rva_to_file(rva):
    for s in sections:
        if s['virt_addr'] <= rva < s['virt_addr'] + s['virt_size']:
            return mz + s['raw_ptr'] + (rva - s['virt_addr'])
    return None

# Helper: file offset to RVA
def file_to_rva(foff):
    foff -= mz  # relative to PE start
    for s in sections:
        if s['raw_ptr'] <= foff < s['raw_ptr'] + s['raw_size']:
            return s['virt_addr'] + (foff - s['raw_ptr'])
    return None

# Key string file offsets and their RVAs
key_strings = {
    'init_param_sw_prj_id': 0x061455,
    'sw_proj_id_proc: %u': 0x06149C,
    'Failed to read sw prj id proc flag': 0x061469,
    'Process: start backup': 0x0614B1,
    'Store SPI to RPMB success': 0x0614E3,
    'RPMB enalbed. Clean backup proc flag': 0x06150B,
    'Failed to set sw proj procedure flag': 0x061539,
    'Failed to store SPI to RPMB': 0x06156A,
    'Process: check and restore from RPMB': 0x061593,
    'Not equal. Restore.': 0x0615CC,
    'Software ID equals!': 0x06165C,
    'GetParamSoftwareProjectIDProcState': 0x060807,
    'GetParamSoftwareProjectIDProcState %d': 0x06082A,
    'GetParamSoftwareProjectID': 0x06071E,
    'rpmb_enable=%a': 0x05FA8D,
}

print("\n=== String RVAs ===")
for name, foff in key_strings.items():
    rva = file_to_rva(foff)
    if rva is not None:
        print(f"  {name}: file=0x{foff:06X} RVA=0x{rva:08X} VA=0x{image_base + rva:X}")
    else:
        print(f"  {name}: file=0x{foff:06X} RVA=? (not in any section)")

# Search for ADRP+ADD pairs that reference these strings in code sections
# AARCH64 ADRP: bits [31:24] = 0x90 (for ADRP) or 0xB0/0xD0/0xF0
# But let's search by looking for the bottom 12 bits of the target offset
# ADRP sets PC to (PC & ~0xFFF) + (imm << 12)
# ADD adds the low 12 bits

# Alternative: search for literal pool references (LDR with PC-relative offset)
# In ARM64 UEFI code, string pointers might be in .reloc data

# Let's use a simpler approach: search code for bytes that could encode the RVA values
# Or search for ADR/ADRP patterns

print("\n=== Searching for references to key strings in code ===")
# Look in .text section for references
text_section = None
data_section = None
for s in sections:
    if s['chars'] & 0x20:  # CODE
        text_section = s
    if s['name'] == '.data' or (s['chars'] & 0x40 and not s['chars'] & 0x20):
        data_section = s

if text_section:
    text_start = mz + text_section['raw_ptr']
    text_end = text_start + text_section['raw_size']
    text_rva_start = text_section['virt_addr']
    print(f"Text section: file 0x{text_start:X}-0x{text_end:X}, RVA 0x{text_rva_start:X}")

    # For AARCH64, search for ADRP+ADD pairs
    if machine == 0xAA64:
        for name, foff in key_strings.items():
            target_rva = file_to_rva(foff)
            if target_rva is None:
                continue
            target_page = target_rva & ~0xFFF
            target_offset = target_rva & 0xFFF

            # Search code for ADRP instructions targeting this page
            refs = []
            for off in range(text_start, text_end - 8, 4):
                insn = struct.unpack_from('<I', data, off)[0]
                # ADRP: [31]=1 [30:29]=immlo [28:24]=10000 [23:5]=immhi [4:0]=Rd
                if (insn >> 24) & 0x9F == 0x90:  # ADRP
                    pc_rva = file_to_rva(off)
                    if pc_rva is None:
                        continue
                    pc_page = pc_rva & ~0xFFF
                    immlo = (insn >> 29) & 3
                    immhi = (insn >> 5) & 0x7FFFF
                    imm = (immhi << 2) | immlo
                    if imm >= 0x100000:
                        imm -= 0x200000  # sign extend
                    adrp_target = pc_page + (imm << 12)
                    if adrp_target == target_page:
                        rd = insn & 0x1F
                        # Check next instruction for ADD with same register
                        next_insn = struct.unpack_from('<I', data, off + 4)[0]
                        # ADD immediate: [31]=1 [30:23]=00100010 [21:10]=imm12 [9:5]=Rn [4:0]=Rd
                        if (next_insn >> 22) & 0x3FF == 0x244:  # ADD X
                            add_imm = (next_insn >> 10) & 0xFFF
                            add_rn = (next_insn >> 5) & 0x1F
                            if add_rn == rd and add_imm == target_offset:
                                refs.append(off)

            if refs:
                for ref in refs[:3]:
                    ref_rva = file_to_rva(ref)
                    print(f"  {name}: ADRP+ADD at file 0x{ref:06X} (RVA 0x{ref_rva:08X})")
    elif machine == 0x1C0:  # ARM (32-bit)
        print("  ARM32 architecture - checking for literal pool references")
        # For 32-bit ARM, strings are typically loaded via literal pools
        # LDR Rn, [PC, #offset] -> loads a pointer from nearby literal pool
        # Let's look for the string offsets in the binary data section / literal pools

        # Search for 4-byte values that match our string RVAs
        for name, foff in key_strings.items():
            target_rva = file_to_rva(foff)
            if target_rva is None:
                continue
            target_va = image_base + target_rva
            target_bytes = struct.pack('<I', target_va)

            # Search in text section and surrounding data
            idx = text_start
            refs = []
            while True:
                pos = data.find(target_bytes, idx, text_end + 0x10000)
                if pos == -1:
                    break
                refs.append(pos)
                idx = pos + 4

            if refs:
                for ref in refs[:3]:
                    ref_rva = file_to_rva(ref)
                    rva_str = f"RVA 0x{ref_rva:08X}" if ref_rva else "outside sections"
                    print(f"  {name}: VA literal at file 0x{ref:06X} ({rva_str})")
                    # Also check for relocation entries pointing here
