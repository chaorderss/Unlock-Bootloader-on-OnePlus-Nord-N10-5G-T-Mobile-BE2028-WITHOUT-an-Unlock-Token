#!/usr/bin/env python3
"""Analyze qtmir application plugin to find and patch SessionAuthorizer::connectionIsAllowed.
The function should return true to bypass connection authorization."""
import struct

with open('qtmir_app.so', 'rb') as f:
    data = f.read()

# Find the "REJECTED" string
rejected_str = b"REJECTED"
idx = data.find(rejected_str)
print(f"'REJECTED' string at offset: 0x{idx:x}")

# Find "not launched" string
not_launched = b"not launched"
idx2 = data.find(not_launched)
print(f"'not launched' at offset: 0x{idx2:x}")

# Find "desktop_file_hint" string
dfh = b"desktop_file_hint"
idx3 = data.find(dfh)
print(f"'desktop_file_hint' at offset: 0x{idx3:x}")

# Find the "connection_is_allowed" string reference
cia = b"connection_is_allowed"
offsets = []
pos = 0
while True:
    i = data.find(cia, pos)
    if i == -1: break
    offsets.append(i)
    pos = i + 1
print(f"\n'connection_is_allowed' found at: {['0x%x' % x for x in offsets]}")

# The function that logs "REJECTED" is in the code section.
# Let's find xrefs to the "REJECTED" string.
# In AArch64, string references use ADRP + ADD/LDR patterns.
# The REJECTED string is at offset 0x{idx:x}.

# First, find the ELF load address / text section
import struct
# Read ELF header
e_phoff = struct.unpack_from('<Q', data, 0x20)[0]
e_phentsize = struct.unpack_from('<H', data, 0x36)[0]
e_phnum = struct.unpack_from('<H', data, 0x38)[0]

print(f"\nELF: phoff=0x{e_phoff:x}, phentsize={e_phentsize}, phnum={e_phnum}")

# Read program headers to find load segments
text_vaddr = None
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type = struct.unpack_from('<I', data, off)[0]
    if p_type == 1:  # PT_LOAD
        p_offset = struct.unpack_from('<Q', data, off + 8)[0]
        p_vaddr = struct.unpack_from('<Q', data, off + 16)[0]
        p_filesz = struct.unpack_from('<Q', data, off + 32)[0]
        p_flags = struct.unpack_from('<I', data, off + 4)[0]
        flags_str = ""
        if p_flags & 4: flags_str += "R"
        if p_flags & 2: flags_str += "W"
        if p_flags & 1: flags_str += "X"
        print(f"  LOAD: vaddr=0x{p_vaddr:x} offset=0x{p_offset:x} filesz=0x{p_filesz:x} flags={flags_str}")
        if p_flags & 1:  # executable
            text_vaddr = p_vaddr
            text_offset = p_offset

# The string "REJECTED" is in the .rodata section, which is part of a LOAD segment.
# For position-independent code, we need to find ADRP instructions that reference
# the page containing the "REJECTED" string.

# The string file offset is idx. In the loaded image, this maps to vaddr = idx (for simple cases)
# or we need to calculate based on LOAD segments.

# For simplicity, in PIE/shared libraries, file offset often = vaddr for the first LOAD segment
# Let's find which segment contains the string
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type = struct.unpack_from('<I', data, off)[0]
    if p_type == 1:
        p_offset = struct.unpack_from('<Q', data, off + 8)[0]
        p_vaddr = struct.unpack_from('<Q', data, off + 16)[0]
        p_filesz = struct.unpack_from('<Q', data, off + 32)[0]
        if p_offset <= idx < p_offset + p_filesz:
            string_vaddr = p_vaddr + (idx - p_offset)
            print(f"\n'REJECTED' string vaddr = 0x{string_vaddr:x}")
            break

# Now search for ADRP instructions that reference the page of this string
string_page = string_vaddr & ~0xFFF
print(f"String page: 0x{string_page:x}")

# Search all ADRP instructions in the text section
print(f"\nSearching for ADRP refs to page 0x{string_page:x}...")
adrp_refs = []
# Text region is roughly 0x0 to ~0x90000 (typical for this size library)
for off in range(0, min(len(data), 0x100000), 4):
    insn = struct.unpack_from('<I', data, off)[0]
    # ADRP: 1xx1_0000_xxxx_xxxx_xxxx_xxxx_xxxD_DDDD
    if (insn & 0x9F000000) == 0x90000000:
        rd = insn & 0x1F
        immhi = (insn >> 5) & 0x7FFFF
        immlo = (insn >> 29) & 0x3
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= (1 << 21)
        page = ((off >> 12) + imm) << 12
        if page == string_page:
            adrp_refs.append((off, rd))

print(f"Found {len(adrp_refs)} ADRP instructions referencing the string page:")
for off, rd in adrp_refs:
    # Check next instruction for ADD with the low 12 bits of string_vaddr
    string_lo = string_vaddr & 0xFFF
    if off + 4 < len(data):
        next_insn = struct.unpack_from('<I', data, off + 4)[0]
        # ADD Xd, Xn, #imm12
        if (next_insn & 0xFFC00000) == 0x91000000:
            add_rd = next_insn & 0x1F
            add_rn = (next_insn >> 5) & 0x1F
            add_imm = (next_insn >> 10) & 0xFFF
            if add_rn == rd and add_imm == string_lo:
                print(f"  *** 0x{off:x}: ADRP X{rd}, 0x{string_page:x}; ADD X{add_rd}, X{rd}, #0x{string_lo:x} → REFS 'REJECTED'")
                # Now trace backwards to find the function entry
                # Look for typical function prologue (STP X29, X30, [SP, #-N]!)
                func_start = None
                for back in range(off, max(off - 0x200, 0), -4):
                    prev = struct.unpack_from('<I', data, back)[0]
                    # STP x29, x30, [sp, #-N]!  = 0xa9b... or STP with pre-index
                    # Common prologue: a9b... or a9be...
                    if (prev & 0xFFC003E0) == 0xA98003E0:  # STP with pre-index
                        func_start = back
                        break
                    # SUB SP, SP, #imm (another prologue pattern)
                    if (prev & 0xFFC003FF) == 0xD10003FF:
                        func_start = back
                        break
                if func_start:
                    print(f"      Possible function start at 0x{func_start:x}")
            else:
                pass  # ADRP to same page but different offset
    print(f"  0x{off:x}: ADRP X{rd}, 0x{string_page:x}")
