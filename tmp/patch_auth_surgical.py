#!/usr/bin/env python3
"""
Surgical patch for qtmir's authorizeSession function.

The original function at 0x4ea00 (4804 bytes):
  - 0x4ea64: CBNZ W0, 0x4ef94  (flag check → cleanup path → back to 0x4ea68)
  - 0x4ea68: STRB WZR, [X20]   (set authorized = FALSE as default)

All success paths later set authorized=true. Rejection paths leave default false.

This patch changes:
  - 0x4ea64: MOV W0, #1        (set W0 = 1)
  - 0x4ea68: STRB W0, [X20]    (set authorized = TRUE as default)

Also restores the FIRST 12 bytes (0x4ea00-0x4ea0b) from the original,
undoing the previous early-return patch (MOV W8,#1; STRB W8,[X2]; RET).

Effect: The full function runs (app matching, session association, etc.),
but if no match is found, authorized defaults to true instead of false.
This lets unmatched sessions (like Waydroid) be authorized.
"""
import struct, shutil, sys

orig_path = '/Users/xmxx/pinganhuijia/tmp/qtmir_orig.so'
current_path = '/Users/xmxx/pinganhuijia/tmp/qtmir_current.so'
output_path = '/Users/xmxx/pinganhuijia/tmp/qtmir_surgical.so'

with open(orig_path, 'rb') as f:
    orig = f.read()

with open(current_path, 'rb') as f:
    current = f.read()

# Start with the current patched binary
data = bytearray(current)

# 1. Restore original first 12 bytes at 0x4ea00 (undo MOV+STRB+RET patch)
print("Step 1: Restore original prologue at 0x4ea00-0x4ea0b")
orig_bytes_12 = orig[0x4ea00:0x4ea0c]
current_bytes_12 = current[0x4ea00:0x4ea0c]
print(f"  Current:  {current_bytes_12.hex()}")
print(f"  Original: {orig_bytes_12.hex()}")

# Verify the current early-return patch
expected = bytes([0x28, 0x00, 0x80, 0x52,  # MOV W8, #1
                  0x48, 0x00, 0x00, 0x39,  # STRB W8, [X2, #0]
                  0xc0, 0x03, 0x5f, 0xd6]) # RET
print(f"  Expected: {expected.hex()}")
assert current_bytes_12 == expected, \
    f"Unexpected bytes at 0x4ea00: {current_bytes_12.hex()}, expected: {expected.hex()}"

data[0x4ea00:0x4ea0c] = orig_bytes_12
print(f"  → Restored to: {orig_bytes_12.hex()}")

# 2. Patch 0x4ea64: CBNZ W0, 0x4ef94 → MOV W0, #1
print("\nStep 2: Patch 0x4ea64: CBNZ → MOV W0, #1")
old_cbnz = struct.unpack_from('<I', orig, 0x4ea64)[0]
print(f"  Original instruction: 0x{old_cbnz:08x}  (CBNZ W0, 0x4ef94)")

# MOV W0, #1 = MOVZ W0, #1 = 0x52800020
mov_w0_1 = 0x52800020
struct.pack_into('<I', data, 0x4ea64, mov_w0_1)
print(f"  Patched to:           0x{mov_w0_1:08x}  (MOV W0, #1)")

# 3. Patch 0x4ea68: STRB WZR, [X20, #0x0] → STRB W0, [X20, #0x0]
print("\nStep 3: Patch 0x4ea68: STRB WZR → STRB W0")
old_strb = struct.unpack_from('<I', orig, 0x4ea68)[0]
print(f"  Original instruction: 0x{old_strb:08x}  (STRB WZR, [X20, #0x0])")
assert old_strb == 0x3900029f, f"Unexpected: 0x{old_strb:08x}"

# STRB W0, [X20, #0x0] = 0x39000280 (change Rt from 31 to 0)
strb_w0 = 0x39000280
struct.pack_into('<I', data, 0x4ea68, strb_w0)
print(f"  Patched to:           0x{strb_w0:08x}  (STRB W0, [X20, #0x0])")

# Write output
with open(output_path, 'wb') as f:
    f.write(data)

print(f"\n✓ Wrote {output_path} ({len(data)} bytes)")

# Verify
verify = open(output_path, 'rb').read()
assert verify[0x4ea00:0x4ea0c] == orig_bytes_12, "Prologue restore failed"
assert struct.unpack_from('<I', verify, 0x4ea64)[0] == 0x52800020, "MOV W0,#1 failed"
assert struct.unpack_from('<I', verify, 0x4ea68)[0] == 0x39000280, "STRB W0 failed"
print("✓ Verification passed")

# Show the patched region
print(f"\nPatched bytes at 0x4ea00-0x4ea6f:")
for off in range(0x4ea00, 0x4ea70, 4):
    insn = struct.unpack_from('<I', verify, off)[0]
    marker = ""
    if off == 0x4ea64: marker = "  ← MOV W0, #1 (was CBNZ)"
    elif off == 0x4ea68: marker = "  ← STRB W0 (was STRB WZR)"
    print(f"  0x{off:05x}: {insn:08x}{marker}")
