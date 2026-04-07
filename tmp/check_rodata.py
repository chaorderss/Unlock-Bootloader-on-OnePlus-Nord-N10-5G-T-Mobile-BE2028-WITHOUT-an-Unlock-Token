#!/usr/bin/env python3
"""Check bytes around 0x201130 and find safe space for "Waydroid" string"""
import struct

with open('/Users/xmxx/pinganhuijia/tmp/libmir1server.so', 'rb') as f:
    data = f.read()

# Check raw bytes around 0x201130
print("=== Raw bytes 0x201120 - 0x201160 ===")
for off in range(0x201120, 0x201160, 16):
    hexb = ' '.join(f'{b:02x}' for b in data[off:off+16])
    ascii_repr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[off:off+16])
    print(f"  0x{off:06x}: {hexb}  {ascii_repr}")

# Count zero bytes after 0x201130
zeros = 0
for i in range(0x201130, min(len(data), 0x201130 + 64)):
    if data[i] == 0:
        zeros += 1
    else:
        break
print(f"\nZero bytes starting at 0x201130: {zeros}")
print(f"First non-zero byte at: 0x{0x201130 + zeros:06x}")
if zeros > 0:
    next_str_start = 0x201130 + zeros
    end = data.find(b'\0', next_str_start)
    if end > next_str_start:
        print(f"Next string: {data[next_str_start:end].decode('ascii', errors='replace')}")

# Check if 0x201130 is referenced from ONLY the create_client_session function
# or from other places too. Search for ADRP+ADD combos that resolve to 0x201130
print("\n=== References to 0x201130 ===")
target_page = 0x201000
target_lo = 0x130
count = 0
for off in range(0, len(data) - 8, 4):
    insn = read_u32(data, off)
    if (insn & 0x9f000000) == 0x90000000:  # ADRP
        rd = insn & 0x1f
        immhi = (insn >> 5) & 0x7ffff
        immlo = (insn >> 29) & 0x3
        imm = (immhi << 2) | immlo
        if imm & 0x100000: imm -= 0x200000
        page = (off & ~0xfff) + (imm << 12)
        if page == target_page:
            # Check next few instructions for ADD with offset 0x130
            for j in range(1, 6):
                if off + j*4 >= len(data): break
                next_insn = read_u32(data, off + j*4)
                # ADD Xd, Xrd, #0x130
                if (next_insn & 0xff800000) == 0x91000000:
                    n_imm12 = (next_insn >> 10) & 0xfff
                    n_rn = (next_insn >> 5) & 0x1f
                    if n_rn == rd and n_imm12 == target_lo:
                        n_rd = next_insn & 0x1f
                        print(f"  ADRP+ADD at 0x{off:06x}+0x{off+j*4:06x} -> X{n_rd}")
                        count += 1
print(f"Total references to 0x201130: {count}")

# Also find other empty strings that might be better targets
# Or find unused .rodata space
# Let's look for a nice chunk of zeros in .rodata where we could write "Waydroid"
print("\n=== Looking for padding/unused space in .rodata (ends around 0x22dead) ===")
rodata_start = 0x1fbbd0
rodata_end = rodata_start + 0x322de

# Find sequences of 16+ zero bytes in .rodata
in_zeros = False
zero_start = 0
for off in range(rodata_start, rodata_end):
    if data[off] == 0:
        if not in_zeros:
            zero_start = off
            in_zeros = True
    else:
        if in_zeros:
            length = off - zero_start
            if length >= 16:
                print(f"  Zero gap: 0x{zero_start:06x} - 0x{off-1:06x} ({length} bytes)")
            in_zeros = False
if in_zeros:
    length = rodata_end - zero_start
    if length >= 16:
        print(f"  Zero gap: 0x{zero_start:06x} - 0x{rodata_end-1:06x} ({length} bytes)")

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]
