#!/usr/bin/env python3
"""Find ADRP+ADD references to REJECTED string in qtmir_app.so"""
import struct

data = open('qtmir_app.so', 'rb').read()

# Target string at 0x991f0 (file offset = vaddr since first LOAD at vaddr=0)
target = 0x991f0
target_page = target & ~0xFFF  # 0x99000
target_lo = target & 0xFFF     # 0x1f0

print(f"Target: 0x{target:x} (page 0x{target_page:x}, lo 0x{target_lo:x})")

# Search ADRP + ADD
found = False
for off in range(0, min(len(data) - 8, 0xB0000), 4):
    insn = struct.unpack_from('<I', data, off)[0]
    if (insn & 0x9F000000) != 0x90000000:
        continue
    rd = insn & 0x1F
    immhi = (insn >> 5) & 0x7FFFF
    immlo = (insn >> 29) & 0x3
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    page = ((off >> 12) + imm) << 12
    if page != target_page:
        continue

    # Check ADD with exact offset
    next_insn = struct.unpack_from('<I', data, off + 4)[0]
    if (next_insn & 0xFFC00000) == 0x91000000:
        add_rn = (next_insn >> 5) & 0x1F
        add_imm = (next_insn >> 10) & 0xFFF
        if add_rn == rd and add_imm == target_lo:
            add_rd = next_insn & 0x1F
            print(f"FOUND ADRP+ADD at 0x{off:x}: X{rd}->X{add_rd}")
            found = True

if not found:
    print("No ADRP+ADD refs found. Trying broader search...")
    # Maybe the string is loaded via a function like qWarning()
    # The Qt logging system typically uses: qWarning() << "message"
    # which stores the string as a QStringLiteral or char* literal
    #
    # In Qt compiled code, the pattern might be:
    # ADRP Xn, page_of_string
    # ADD Xn, Xn, #lo_offset
    # But the string might be at a different address than we think.

    # Let's also search using the "not launched" string (0x99302)
    targets = [
        ("REJECTED string", 0x991f0),
        ("not launched", 0x99302),
        ("desktop_file_hint #1", 0x992ca),
    ]

    for name, t in targets:
        tp = t & ~0xFFF
        tl = t & 0xFFF
        for off in range(0, min(len(data) - 8, 0xB0000), 4):
            insn = struct.unpack_from('<I', data, off)[0]
            if (insn & 0x9F000000) != 0x90000000:
                continue
            rd = insn & 0x1F
            immhi = (insn >> 5) & 0x7FFFF
            immlo = (insn >> 29) & 0x3
            imm = (immhi << 2) | immlo
            if imm & (1 << 20):
                imm -= (1 << 21)
            page = ((off >> 12) + imm) << 12
            if page != tp:
                continue
            ni = struct.unpack_from('<I', data, off + 4)[0]
            if (ni & 0xFFC00000) == 0x91000000:
                rn2 = (ni >> 5) & 0x1F
                imm2 = (ni >> 10) & 0xFFF
                if rn2 == rd and imm2 == tl:
                    rd2 = ni & 0x1F
                    print(f"  {name}: ADRP+ADD at 0x{off:x}")

# Alternative: search for the "connection_is_allowed" method name in symbol table
# Read .dynsym section
# Parse ELF section headers
e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
e_shentsize = struct.unpack_from('<H', data, 0x3A)[0]
e_shnum = struct.unpack_from('<H', data, 0x3C)[0]
e_shstrndx = struct.unpack_from('<H', data, 0x3E)[0]

# Get section header string table
shstrtab_off = struct.unpack_from('<Q', data, e_shoff + e_shstrndx * e_shentsize + 0x18)[0]

print("\n=== Relevant ELF sections ===")
symtab_off = symtab_size = symtab_entsize = 0
strtab_off = 0
dynsym_off = dynsym_size = dynsym_entsize = 0
dynstr_off = 0

for i in range(e_shnum):
    sh_off = e_shoff + i * e_shentsize
    sh_name_idx = struct.unpack_from('<I', data, sh_off)[0]
    sh_type = struct.unpack_from('<I', data, sh_off + 4)[0]
    sh_offset = struct.unpack_from('<Q', data, sh_off + 0x18)[0]
    sh_size = struct.unpack_from('<Q', data, sh_off + 0x20)[0]
    sh_entsize = struct.unpack_from('<Q', data, sh_off + 0x38)[0]

    # Read section name
    name_end = data.find(b'\x00', shstrtab_off + sh_name_idx)
    name = data[shstrtab_off + sh_name_idx:name_end].decode('ascii', errors='replace')

    if name in ('.symtab', '.strtab', '.dynsym', '.dynstr'):
        print(f"  {name}: offset=0x{sh_offset:x} size=0x{sh_size:x}")

    if name == '.symtab':
        symtab_off = sh_offset
        symtab_size = sh_size
        symtab_entsize = sh_entsize or 24
    elif name == '.strtab':
        strtab_off = sh_offset
    elif name == '.dynsym':
        dynsym_off = sh_offset
        dynsym_size = sh_size
        dynsym_entsize = sh_entsize or 24
    elif name == '.dynstr':
        dynstr_off = sh_offset

# Search dynsym for connection_is_allowed
print("\n=== Searching dynsym for auth-related symbols ===")
if dynsym_off and dynstr_off:
    for i in range(0, dynsym_size, dynsym_entsize):
        st_name = struct.unpack_from('<I', data, dynsym_off + i)[0]
        st_value = struct.unpack_from('<Q', data, dynsym_off + i + 8)[0]
        name_end = data.find(b'\x00', dynstr_off + st_name)
        sym_name = data[dynstr_off + st_name:name_end].decode('ascii', errors='replace')
        if 'connection' in sym_name.lower() or 'authoriz' in sym_name.lower() or 'allowed' in sym_name.lower():
            print(f"  {sym_name} @ 0x{st_value:x}")

# Search symtab too
print("\n=== Searching symtab for auth-related symbols ===")
if symtab_off and strtab_off:
    for i in range(0, symtab_size, symtab_entsize):
        st_name = struct.unpack_from('<I', data, symtab_off + i)[0]
        st_value = struct.unpack_from('<Q', data, symtab_off + i + 8)[0]
        name_end = data.find(b'\x00', strtab_off + st_name)
        sym_name = data[strtab_off + st_name:name_end].decode('ascii', errors='replace')
        if 'connection' in sym_name.lower() or 'authoriz' in sym_name.lower() or 'allowed' in sym_name.lower():
            print(f"  {sym_name} @ 0x{st_value:x}")
else:
    print("  No symtab found (stripped)")
