#!/usr/bin/env python3
"""Analyze decompressed ABL PE32 - find token check code"""
import re
import sys
import struct

fname = '/Users/xmxx/pinganhuijia/global_abl_decompressed.bin'
with open(fname, 'rb') as f:
    data = f.read()

print(f"Decompressed size: {len(data)} bytes")

pe_offset = 0xB8  # MZ header starts here
assert data[pe_offset:pe_offset+2] == b'MZ', f"Expected MZ at {hex(pe_offset)}"

e_lfanew = struct.unpack_from('<I', data, pe_offset + 0x3C)[0]
pe_hdr = pe_offset + e_lfanew
assert data[pe_hdr:pe_hdr+4] == b'PE\x00\x00', f"Bad PE at {hex(pe_hdr)}"

machine = struct.unpack_from('<H', data, pe_hdr+4)[0]
num_sections = struct.unpack_from('<H', data, pe_hdr+6)[0]
opt_hdr_size = struct.unpack_from('<H', data, pe_hdr+20)[0]
magic = struct.unpack_from('<H', data, pe_hdr+24)[0]
entry_rva = struct.unpack_from('<I', data, pe_hdr+24+16)[0]
image_base = struct.unpack_from('<Q', data, pe_hdr+24+24)[0] if magic == 0x20B else struct.unpack_from('<I', data, pe_hdr+24+28)[0]

print(f"PE hdr at {hex(pe_hdr)}, machine={hex(machine)}, sections={num_sections}, magic={hex(magic)}, entry_rva={hex(entry_rva)}, image_base={hex(image_base)}")

sec_table_abs = pe_hdr + 24 + opt_hdr_size
sections = []
print("\nSections:")
for i in range(num_sections):
    s = sec_table_abs + i * 40
    name = data[s:s+8].rstrip(b'\x00').decode('ascii', 'replace')
    vsize = struct.unpack_from('<I', data, s+8)[0]
    vaddr = struct.unpack_from('<I', data, s+12)[0]
    raw_size = struct.unpack_from('<I', data, s+16)[0]
    raw_off = struct.unpack_from('<I', data, s+20)[0]
    chars = struct.unpack_from('<I', data, s+36)[0]
    abs_raw_off = pe_offset + raw_off
    print(f"  [{i}] {name!r:10} VA={hex(vaddr)} Vsz={hex(vsize)} raw_off={hex(abs_raw_off)} raw_sz={hex(raw_size)}")
    sections.append({'name': name, 'vaddr': vaddr, 'vsize': vsize, 'abs_off': abs_raw_off, 'raw_size': raw_size})

TOKEN_STR = b'Please flash unlock token first.'
tok_hits = [m.start() for m in re.finditer(re.escape(TOKEN_STR), data)]
print(f"\nToken string at: {[hex(h) for h in tok_hits]}")
for h in tok_hits:
    for sec in sections:
        if sec['abs_off'] <= h < sec['abs_off'] + sec['raw_size']:
            off_in_sec = h - sec['abs_off']
            rva = sec['vaddr'] + off_in_sec
            print(f"  In section '{sec['name']}', sect_off={hex(off_in_sec)}, RVA={hex(rva)}, VA={hex(image_base+rva)}")

print("\n=== All interesting strings per section ===")
for sec in sections:
    if sec['raw_size'] < 10: continue
    sec_data = data[sec['abs_off']:sec['abs_off']+sec['raw_size']]
    strs = re.findall(b'[\x20-\x7e]{5,}', sec_data)
    kw_strs = [(m.start(), s) for s in strs for m in re.finditer(re.escape(s), sec_data, re.I)
               if any(k in s.lower() for k in [b'unlock', b'token', b'devinfo', b'flash', b'lock', b'cust', b'carrier', b'oem'])]
    if kw_strs:
        print(f"\nSection {sec['name']!r}:")
        seen = set()
        for offset_in_sec, s in kw_strs[:30]:
            if s not in seen:
                rva = sec['vaddr'] + offset_in_sec
                print(f"  RVA={hex(rva)}: {s.decode()}")
                seen.add(s)


fname = '/Users/xmxx/pinganhuijia/global_abl_decompressed.bin'
with open(fname, 'rb') as f:
    data = f.read()

print(f"Decompressed size: {len(data)} bytes")

# Find key structures
mz = [m.start() for m in re.finditer(b'MZ\x90\x00', data)]
mz2 = [m.start() for m in re.finditer(b'MZ\x00\x00', data)]
fvh = [m.start() for m in re.finditer(b'_FVH', data)]
print(f"MZ (PE32): {[hex(x) for x in mz[:3]]}")
print(f"MZ variants: {[hex(x) for x in mz2[:3]]}")
print(f"_FVH: {[hex(x) for x in fvh[:3]]}")

# Token string
tok = [m.start() for m in re.finditer(b'Please flash unlock token first', data)]
print(f"\nToken string at: {[hex(x) for x in tok]}")

# For each token string hit, show hex dump context
for h in tok:
    ctx_start = max(0, h-100)
    ctx_end = min(len(data), h+200)
    ctx = data[ctx_start:ctx_end]
    print(f"\n=== Full context around token string at {hex(h)} ===")
    for i in range(0, len(ctx), 16):
        row = ctx[i:i+16]
        hx = ' '.join(f'{b:02x}' for b in row)
        asc = ''.join(chr(b) if 32<=b<127 else '.' for b in row)
        print(f"  {ctx_start+i:08x}: {hx:<47s}  |{asc}|")

# Find PE32 at offset 0xB8
pe_offset = 0xB8
if data[pe_offset:pe_offset+2] == b'MZ':
    print(f"\n=== PE32 at offset {hex(pe_offset)} ===")
    # PE header
    e_lfanew = struct.unpack_from('<I', data, pe_offset + 0x3C)[0]
    pe_hdr_off = pe_offset + e_lfanew
    pe_sig = data[pe_hdr_off:pe_hdr_off+4]
    print(f"e_lfanew: {hex(e_lfanew)}, PE sig: {pe_sig.hex()}")

    if pe_sig == b'PE\x00\x00':
        machine = struct.unpack_from('<H', data, pe_hdr_off+4)[0]
        num_sections = struct.unpack_from('<H', data, pe_hdr_off+6)[0]
        opt_hdr_size = struct.unpack_from('<H', data, pe_hdr_off+20)[0]

        # Optional header
        magic = struct.unpack_from('<H', data, pe_hdr_off+24)[0]
        image_base = struct.unpack_from('<I', data, pe_hdr_off+24+28)[0] if magic == 0x10B else struct.unpack_from('<Q', data, pe_hdr_off+24+24)[0]

        print(f"Machine: {hex(machine)} (0x1C4=ARM Thumb, 0xAA64=ARM64, 0x14C=x86)")
        print(f"Num sections: {num_sections}")
        print(f"Magic: {hex(magic)} (0x10B=PE32, 0x20B=PE32+)")
        print(f"ImageBase: {hex(image_base)}")

        # Sections
        sec_table_off = pe_hdr_off + 24 + opt_hdr_size
        print(f"\nSections (PE offset={hex(pe_offset)}):")
        for i in range(num_sections):
            s = sec_table_off + i*40
            name = data[pe_offset+s:pe_offset+s+8].rstrip(b'\x00').decode('ascii','replace')
            vsize = struct.unpack_from('<I', data, pe_offset+s+8)[0]
            vaddr = struct.unpack_from('<I', data, pe_offset+s+12)[0]
            raw_size = struct.unpack_from('<I', data, pe_offset+s+16)[0]
            raw_off = struct.unpack_from('<I', data, pe_offset+s+20)[0]
            print(f"  [{i}] {name!r:10s} vaddr={hex(vaddr)} vsize={hex(vsize)} raw_off={hex(raw_off)} raw_size={hex(raw_size)}")

# Also look for multiimgoem references
print("\n=== multiimgoem / token-related references ===")
for pat in [b'multiimgoem', b'multiimg', b'oem_partition', b'unlock_token']:
    hits = [m.start() for m in re.finditer(re.escape(pat), data, re.I)]
    if hits:
        print(f"'{pat.decode()}' at {[hex(h) for h in hits[:5]]}")
        h = hits[0]
        ctx = data[max(0,h-60):h+100]
        pr = bytes(b if 32<=b<127 else ord('.') for b in ctx)
        print(f"  ctx: {pr.decode()}")
