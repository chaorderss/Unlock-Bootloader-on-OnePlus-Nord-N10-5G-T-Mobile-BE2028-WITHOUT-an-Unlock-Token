#!/usr/bin/env python3
"""Find all wl_proxy_marshal calls and their opcodes in hwcomposer.waydroid.so"""
import struct

with open('hwc.so', 'rb') as f:
    data = f.read()

# PLT stub for wl_proxy_marshal is at 0x660c0
WL_PROXY_MARSHAL_PLT = 0x660c0

print("=== Searching for BL to wl_proxy_marshal (0x660c0) and their opcodes ===\n")

results = []
for off in range(0, len(data) - 4, 4):
    insn = struct.unpack_from('<I', data, off)[0]
    # BL instruction: 1001_01xx_xxxx_xxxx_xxxx_xxxx_xxxx_xxxx
    if (insn >> 26) == 0b100101:
        imm26 = insn & 0x3FFFFFF
        if imm26 & (1 << 25):
            imm26 -= (1 << 26)
        target = off + imm26 * 4
        if target == WL_PROXY_MARSHAL_PLT:
            # Look backwards for opcode load into W1
            opcode = None
            opcode_off = None
            for back in range(1, 8):
                prev_off = off - back * 4
                if prev_off < 0:
                    break
                prev = struct.unpack_from('<I', data, prev_off)[0]
                # MOVZ Wd, #imm16, LSL #0: 0101_0010_100x_xxxx_xxxx_xxxx_xxxd_dddd
                if (prev & 0xFFE00000) == 0x52800000:
                    rd = prev & 0x1F
                    imm16 = (prev >> 5) & 0xFFFF
                    if rd == 1:  # W1
                        opcode = imm16
                        opcode_off = prev_off
                        break
                # MOV W1, WZR or ORR W1, WZR, Wn
                if (prev & 0xFFFFFFE0) == 0x2A0003E0:
                    rd = prev & 0x1F
                    if rd == 1:
                        rm = (prev >> 16) & 0x1F
                        opcode = 0 if rm == 31 else f"W{rm}"
                        opcode_off = prev_off
                        break
                # MOV W1, #0 via MOVZ W1, #0
                if prev == 0x52800001:
                    opcode = 0
                    opcode_off = prev_off
                    break

            results.append((off, opcode, opcode_off))

for off, opcode, opcode_off in results:
    op_str = f"opcode={opcode}" if opcode is not None else "opcode=?"
    op_loc = f" (loaded at 0x{opcode_off:x})" if opcode_off else ""
    # Also show the raw instruction at opcode_off
    raw = ""
    if opcode_off is not None:
        raw_insn = struct.unpack_from('<I', data, opcode_off)[0]
        raw = f" [insn: {raw_insn:08x}]"
    print(f"  0x{off:05x}: BL wl_proxy_marshal  {op_str}{op_loc}{raw}")

print(f"\nTotal: {len(results)} calls to wl_proxy_marshal")

# Now specifically search for opcode 7 (set_maximized for wl_shell_surface)
print("\n=== Calls with opcode 7 (wl_shell_surface_set_maximized) ===")
for off, opcode, opcode_off in results:
    if opcode == 7:
        print(f"  0x{off:05x}: BL wl_proxy_marshal, opcode=7 (loaded at 0x{opcode_off:x})")
        # Show context: 8 instructions before and 2 after
        print("  Context:")
        for i in range(-8, 3):
            ctx_off = off + i * 4
            if 0 <= ctx_off < len(data) - 4:
                ctx_insn = struct.unpack_from('<I', data, ctx_off)[0]
                marker = " <<<<" if i == 0 or ctx_off == opcode_off else ""
                print(f"    0x{ctx_off:05x}: {ctx_insn:08x}{marker}")

# Also search for opcode 9 (xdg_toplevel set_maximized)
print("\n=== Calls with opcode 9 (xdg_toplevel_set_maximized) ===")
for off, opcode, opcode_off in results:
    if opcode == 9:
        print(f"  0x{off:05x}: BL wl_proxy_marshal, opcode=9 (loaded at 0x{opcode_off:x})")
