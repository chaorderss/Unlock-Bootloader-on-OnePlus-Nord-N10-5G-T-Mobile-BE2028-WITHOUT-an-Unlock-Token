#!/usr/bin/env python3
"""
Patch libmir1server.so to set session name "Waydroid" for Wayland clients.

Changes:
1. Write "Waydroid\0" at offset 0x20dcac (in a zero gap in .rodata)
2. Modify ADRP at 0x14fd3c: ADRP X1, 0x201000 → ADRP X1, 0x20d000
3. Modify ADD at 0x14fd50: ADD X1, X1, #0x130 → ADD X1, X1, #0xcac

This makes Mir's create_client_session pass "Waydroid" instead of ""
as the session name for new Wayland client sessions.
"""
import struct, shutil, sys

INPUT = '/Users/xmxx/pinganhuijia/tmp/libmir1server.so'
OUTPUT = '/Users/xmxx/pinganhuijia/tmp/libmir1server_patched.so'

with open(INPUT, 'rb') as f:
    data = bytearray(f.read())

def read_u32(d, off):
    return struct.unpack_from('<I', d, off)[0]

def write_u32(d, off, val):
    struct.pack_into('<I', d, off, val)

# Verify existing instructions
adrp_orig = read_u32(data, 0x14fd3c)
add_orig = read_u32(data, 0x14fd50)
print(f"Original ADRP at 0x14fd3c: 0x{adrp_orig:08x}")
print(f"Original ADD  at 0x14fd50: 0x{add_orig:08x}")

# Verify the target zero gap
for i in range(9):
    assert data[0x20dcac + i] == 0, f"Non-zero at 0x{0x20dcac+i:06x}: 0x{data[0x20dcac+i]:02x}"
print("Target gap at 0x20dcac verified (9+ zeros)")

# Verify original bytes at 0x201130 = empty string
assert data[0x201130] == 0, "Expected empty string at 0x201130"
print("Empty string at 0x201130 verified")

# Patch 1: Write "Waydroid\0" at 0x20dcac
name = b"Waydroid\x00"
for i, b in enumerate(name):
    data[0x20dcac + i] = b
print(f"Wrote '{name[:-1].decode()}' at 0x20dcac")

# Patch 2: ADRP X1, 0x20d000  (was ADRP X1, 0x201000)
# PC page = 0x14fd3c & ~0xfff = 0x14f000
# new target page = 0x20d000
# new imm = (0x20d000 - 0x14f000) >> 12 = 0xBE
new_imm = 0xBE
immlo = new_imm & 0x3       # = 2
immhi = new_imm >> 2        # = 0x2F

new_adrp = (1 << 31) | (immlo << 29) | (0b10000 << 24) | (immhi << 5) | 1  # rd=1
print(f"New ADRP: 0x{new_adrp:08x}")

# Verify: decode back
v_immhi = (new_adrp >> 5) & 0x7ffff
v_immlo = (new_adrp >> 29) & 0x3
v_imm = (v_immhi << 2) | v_immlo
v_page = 0x14f000 + (v_imm << 12)
print(f"  Verify: ADRP X{new_adrp & 0x1f}, 0x{v_page:x}")
assert v_page == 0x20d000, f"ADRP target wrong: 0x{v_page:x}"

write_u32(data, 0x14fd3c, new_adrp)

# Patch 3: ADD X1, X1, #0xcac  (was ADD X1, X1, #0x130)
# ADD encoding: [31] sf=1 | [30:29] 00 | [28:24] 10001 | [23:22] sh=0 | [21:10] imm12 | [9:5] Rn | [4:0] Rd
new_imm12 = 0xcac
new_add = (1 << 31) | (0b10001 << 24) | (new_imm12 << 10) | (1 << 5) | 1  # Rn=1, Rd=1
print(f"New ADD: 0x{new_add:08x}")

# Verify
v_imm12 = (new_add >> 10) & 0xfff
v_rn = (new_add >> 5) & 0x1f
v_rd = new_add & 0x1f
full_addr = 0x20d000 + v_imm12
print(f"  Verify: ADD X{v_rd}, X{v_rn}, #0x{v_imm12:x} → full addr 0x{full_addr:x}")
assert full_addr == 0x20dcac, f"ADD target wrong: 0x{full_addr:x}"

write_u32(data, 0x14fd50, new_add)

# Save
with open(OUTPUT, 'wb') as f:
    f.write(data)

print(f"\nPatched file saved to: {OUTPUT}")
print(f"Size: {len(data)} bytes")

# Verify the result
with open(OUTPUT, 'rb') as f:
    verify = f.read()
s = verify[0x20dcac:0x20dcac+9]
print(f"String at 0x20dcac: {s}")
print(f"ADRP at 0x14fd3c: 0x{read_u32(verify, 0x14fd3c):08x}")
print(f"ADD  at 0x14fd50: 0x{read_u32(verify, 0x14fd50):08x}")
