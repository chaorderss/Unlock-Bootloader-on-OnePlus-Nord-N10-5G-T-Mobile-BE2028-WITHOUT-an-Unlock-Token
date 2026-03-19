#!/usr/bin/env python3
"""Find all references to key unlock strings and trace the flash cust-unlock handler"""
import struct

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin','rb').read()

def decode_adrp(insn, pc):
    if (insn & 0x9F000000) != 0x90000000:
        return None
    rd = insn & 0x1F
    immlo = (insn >> 29) & 0x3
    immhi = (insn >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    return rd, (pc & ~0xFFF) + (imm << 12)

def decode_add_imm(insn):
    if (insn & 0xFF800000) == 0x91000000:
        rd = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm12 = (insn >> 10) & 0xFFF
        sh = (insn >> 22) & 1
        if sh: imm12 <<= 12
        return rd, rn, imm12
    return None

def get_str(off, maxlen=120):
    if off < 0 or off >= len(data):
        return None
    end = off
    while end < len(data) and end < off + maxlen and data[end] != 0:
        end += 1
    try:
        return data[off:end].decode('ascii')
    except:
        return None

# Find all references to these strings:
targets = {
    0x061f98: "Unable to finding related information (-1)",
    0x062e3b: "Please flash unlock token first.",
}

# Also find where the HMAC key strings are referenced
hmac_strings = [
    b'9sLeM7jAuFKcXoxr',   # from conversation summary
    b'C6PMgHLaVydsUGiMP7vYd',
    b'07ltETGOgDs33FkTQOA',
]
for s in hmac_strings:
    idx = data.find(s)
    if idx >= 0:
        print(f"HMAC string '{s.decode()}' found at pe32+ offset {idx:#x}")
        targets[idx] = s.decode()

print()

# Scan ALL .text for ADRP+ADD pairs referencing any target
text_start = 0x1000
text_end = 0x89000
target_pages = {}
for addr in targets:
    page = addr & ~0xFFF
    if page not in target_pages:
        target_pages[page] = []
    target_pages[page].append(addr)

adrp_log = {}  # reg -> (pc, page)
print("=== All code references to key strings ===")
for pc in range(text_start, text_end, 4):
    if pc + 4 > len(data):
        break
    insn = struct.unpack_from('<I', data, pc)[0]

    a = decode_adrp(insn, pc)
    if a:
        rd, page = a
        if page in target_pages:
            adrp_log[rd] = (pc, page)

    add = decode_add_imm(insn)
    if add:
        rd, rn, imm12 = add
        if rn in adrp_log:
            apc, page = adrp_log[rn]
            if 0 < (pc - apc) <= 64:
                final = page + imm12
                if final in targets:
                    print(f"  {pc:#07x}: x{rd} -> {final:#x} \"{targets[final][:60]}\"")

# Now specifically search for the key table strings from model 20888
print()
print("=== Per-model key table strings ===")
for s in [b'Nahp3lub5ZaRah7Ph', b'zeeleSiwo3okahfooph', b'gi2quaef5pheit3W']:
    idx = data.find(s)
    if idx >= 0:
        print(f"  '{s.decode()}' at {idx:#x}")

# Also look for the j{jqdltqdynsn%xut string that appeared at 0x63018
print()
s = get_str(0x63018)
if s:
    print(f"String at 0x63018: '{s}'")
s = get_str(0x633a8)
if s:
    print(f"String at 0x633a8: '{s}'")

# Search for "flash:" command registration
for needle in [b'flash:', b'cust-unlock', b'cust_unlock']:
    idx = 0
    while True:
        idx = data.find(needle, idx)
        if idx < 0:
            break
        end = data.index(0, idx) if 0 in data[idx:idx+200] else idx+80
        print(f"  Found '{needle.decode()}' at {idx:#x}: '{data[idx:end].decode('ascii',errors='replace')[:60]}'")
        idx += 1
