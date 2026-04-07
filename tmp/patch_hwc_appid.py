#!/usr/bin/env python3
"""
Patch hwcomposer.waydroid.so to inject xdg_toplevel_set_app_id("Waydroid")
before xdg_toplevel_set_maximized.

This makes Mir assign session name "Waydroid" to the hwcomposer's session,
allowing Lomiri's ApplicationManager to match the window to the Waydroid app.

Patches:
1. ELF: Make first LOAD segment executable (R→RX) and extend it
2. Code cave at 0x036368: Trampoline calling wl_proxy_marshal(toplevel, 3, "Waydroid")
3. String at 0x0363a0: "Waydroid\0"
4. Call site 0x03dd18: Redirect to trampoline
"""
import struct, shutil, sys

INPUT = '/Users/xmxx/pinganhuijia/tmp/hwc.so'
OUTPUT = '/Users/xmxx/pinganhuijia/tmp/hwc_appid.so'

with open(INPUT, 'rb') as f:
    data = bytearray(f.read())

print(f"Input size: {len(data)} bytes")

# Verify original instruction at 0x03dd18 is LDR X0, [X26, #0x18] = 0xF9400F40
orig_insn = struct.unpack_from('<I', data, 0x03dd18)[0]
assert orig_insn == 0xF9400F40, f"Expected 0xF9400F40 at 0x03dd18, got 0x{orig_insn:08X}"
print(f"✓ Original instruction at 0x03dd18: 0x{orig_insn:08X} (LDR X0, [X26, #0x18])")

# Verify cave area is all zeros
for i in range(0x036368, 0x0363b0):
    assert data[i] == 0, f"Non-zero byte at 0x{i:06x}: 0x{data[i]:02x}"
print(f"✓ Code cave 0x036368-0x0363b0 is clean (all zeros)")

# Verify set_maximized call at 0x03dd20-0x03dd24
assert struct.unpack_from('<I', data, 0x03dd20)[0] == 0x52800121, "Expected MOV W1, #9 at 0x03dd20"
assert struct.unpack_from('<I', data, 0x03dd24)[0] == 0x9400A0E7, "Expected BL at 0x03dd24"
print(f"✓ set_maximized call confirmed at 0x03dd20-0x03dd24")

# === Patch 1: ELF LOAD segment modification ===
# Find first LOAD segment (p_type=1) with p_offset=0
e_phoff = struct.unpack_from('<Q', data, 32)[0]
e_phentsize = struct.unpack_from('<H', data, 54)[0]
e_phnum = struct.unpack_from('<H', data, 56)[0]

found_segment = False
for i in range(e_phnum):
    ph_off = e_phoff + i * e_phentsize
    p_type = struct.unpack_from('<I', data, ph_off)[0]
    p_flags = struct.unpack_from('<I', data, ph_off + 4)[0]
    p_offset = struct.unpack_from('<Q', data, ph_off + 8)[0]
    p_filesz = struct.unpack_from('<Q', data, ph_off + 32)[0]
    p_memsz = struct.unpack_from('<Q', data, ph_off + 40)[0]

    if p_type == 1 and p_offset == 0:  # PT_LOAD with offset 0
        print(f"\n=== Patching LOAD segment [index {i}] ===")
        print(f"  Before: flags=0x{p_flags:x} (R), filesz=0x{p_filesz:x}, memsz=0x{p_memsz:x}")

        # Change flags from R (4) to RX (5)
        new_flags = 5  # PF_R | PF_X
        struct.pack_into('<I', data, ph_off + 4, new_flags)

        # Extend filesz and memsz to cover our code + string
        new_size = 0x0363b0  # covers code (0x036368-0x036390) + string (0x0363a0-0x0363a9)
        struct.pack_into('<Q', data, ph_off + 32, new_size)  # p_filesz
        struct.pack_into('<Q', data, ph_off + 40, new_size)  # p_memsz

        # Verify
        print(f"  After:  flags=0x{new_flags:x} (RX), filesz=0x{new_size:x}, memsz=0x{new_size:x}")
        found_segment = True
        break

assert found_segment, "Could not find first LOAD segment!"

# === Patch 2: Code trampoline at 0x036368 ===
print(f"\n=== Writing trampoline code at 0x036368 ===")

trampoline = [
    # 0x036368: STR X30, [SP, #-16]!     ; save link register
    0xF81F0FFE,
    # 0x03636c: LDR X0, [X26, #0x18]     ; load xdg_toplevel pointer
    0xF9400F40,
    # 0x036370: CBZ X0, +5 (→ 0x036384)  ; skip if null
    0xB40000A0,
    # 0x036374: MOV W1, #3               ; opcode = XDG_TOPLEVEL_SET_APP_ID
    0x52800061,
    # 0x036378: ADRP X2, 0x036000        ; page containing "Waydroid" string
    0x90000002,
    # 0x03637c: ADD X2, X2, #0x3a0       ; X2 = 0x0363a0 "Waydroid"
    0x910E8042,
    # 0x036380: BL 0x0660c0              ; wl_proxy_marshal(toplevel, 3, "Waydroid")
    0x9400BF50,
    # 0x036384: LDR X30, [SP], #16       ; restore link register
    0xF84107FE,
    # 0x036388: LDR X0, [X26, #0x18]     ; re-execute replaced instruction
    0xF9400F40,
    # 0x03638c: B 0x03dd1c               ; return to original code (CBZ X0, ...)
    0x14001E64,
]

for j, insn in enumerate(trampoline):
    off = 0x036368 + j * 4
    struct.pack_into('<I', data, off, insn)
    print(f"  0x{off:06x}: {insn:08X}")

# Verify branch targets
# CBZ at 0x036370 should target 0x036384
cbz_imm19 = (trampoline[2] >> 5) & 0x7ffff
assert 0x036370 + cbz_imm19 * 4 == 0x036384, "CBZ target mismatch"

# BL at 0x036380 should target 0x0660c0
bl_imm26 = trampoline[6] & 0x3ffffff
assert 0x036380 + bl_imm26 * 4 == 0x0660c0, f"BL target mismatch: {0x036380 + bl_imm26*4:x}"

# B at 0x03638c should target 0x03dd1c
b_imm26 = trampoline[9] & 0x3ffffff
if b_imm26 & 0x2000000:
    b_imm26 -= 0x4000000
assert 0x03638c + b_imm26 * 4 == 0x03dd1c, f"B target mismatch: {0x03638c + b_imm26*4:x}"
print(f"  ✓ All branch targets verified")

# === Patch 3: String literal at 0x0363a0 ===
print(f"\n=== Writing 'Waydroid' string at 0x0363a0 ===")
string = b'Waydroid\x00'
for j, b in enumerate(string):
    data[0x0363a0 + j] = b
print(f"  0x0363a0: {string!r}")

# === Patch 4: Call site redirect at 0x03dd18 ===
print(f"\n=== Redirecting call site at 0x03dd18 ===")
# B 0x036368 from 0x03dd18
# offset = 0x036368 - 0x03dd18 = -0x79B0
# imm26 = -0x79B0 / 4 = -0x1E6C
# signed 26-bit: 0x4000000 - 0x1E6C = 0x3FFE194
b_offset = (0x036368 - 0x03dd18) // 4  # = -0x1E6C
b_imm26 = b_offset & 0x3FFFFFF  # = 0x3FFE194
b_insn = 0x14000000 | b_imm26  # = 0x17FFE194

# Verify
test_imm = b_imm26
if test_imm & 0x2000000:
    test_imm -= 0x4000000
assert 0x03dd18 + test_imm * 4 == 0x036368, f"B target mismatch: {0x03dd18 + test_imm*4:x}"

struct.pack_into('<I', data, 0x03dd18, b_insn)
print(f"  0x03dd18: {b_insn:08X} (B 0x036368)")
print(f"  (was: 0x{orig_insn:08X} LDR X0, [X26, #0x18])")

# === Write output ===
with open(OUTPUT, 'wb') as f:
    f.write(data)

print(f"\n=== Patch complete ===")
print(f"Output: {OUTPUT}")
print(f"Size: {len(data)} bytes (unchanged)")

# Summary
print(f"""
Summary of changes:
1. ELF: First LOAD segment flags R→RX, filesz/memsz 0x036374→0x0363b0
2. 0x036368-0x036390: Trampoline code (10 instructions)
   - Saves LR, loads toplevel, calls set_app_id("Waydroid"), restores LR
   - Then re-executes original LDR and jumps back
3. 0x0363a0: "Waydroid\\0" string literal
4. 0x03dd18: B 0x036368 (redirect to trampoline before set_maximized)

Flow: Before set_maximized(9), trampoline calls set_app_id(3, "Waydroid")
on the same xdg_toplevel proxy, giving Mir a session name.
""")
