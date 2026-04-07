#!/usr/bin/env python3
"""Find all references to the empty string at 0x201130 and find safe space"""
import struct

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

with open('/Users/xmxx/pinganhuijia/tmp/libmir1server.so', 'rb') as f:
    data = f.read()

target_page = 0x201000
target_lo = 0x130
count = 0
print("=== References to 0x201130 ===")
for off in range(0, len(data) - 8, 4):
    insn = read_u32(data, off)
    if (insn & 0x9f000000) == 0x90000000:
        rd = insn & 0x1f
        immhi = (insn >> 5) & 0x7ffff
        immlo = (insn >> 29) & 0x3
        imm = (immhi << 2) | immlo
        if imm & 0x100000: imm -= 0x200000
        page = (off & ~0xfff) + (imm << 12)
        if page == target_page:
            for j in range(1, 8):
                if off + j*4 >= len(data): break
                ni = read_u32(data, off + j*4)
                if (ni & 0xff800000) == 0x91000000:
                    n_imm12 = (ni >> 10) & 0xfff
                    n_rn = (ni >> 5) & 0x1f
                    if n_rn == rd and n_imm12 == target_lo:
                        print(f"  0x{off:06x} + 0x{off+j*4:06x}")
                        count += 1
                        break
                if (ni & 0x9f000000) == 0x90000000 or ni == 0xd65f03c0 or (ni >> 26) == 0x25:
                    break
print(f"Total: {count}")

print("\n=== Zero gaps >= 16 bytes in .rodata ===")
rs, re = 0x1fbbd0, 0x1fbbd0 + 0x322de
in_z, zs = False, 0
gaps = []
for o in range(rs, re):
    if data[o] == 0:
        if not in_z: zs = o; in_z = True
    else:
        if in_z:
            l = o - zs
            if l >= 16: gaps.append((zs, l))
            in_z = False
if in_z:
    l = re - zs
    if l >= 16: gaps.append((zs, l))

for s, l in gaps[:20]:
    print(f"  0x{s:06x} ({l} bytes) [page 0x{s & ~0xfff:x}]")
print(f"Total gaps: {len(gaps)}")
