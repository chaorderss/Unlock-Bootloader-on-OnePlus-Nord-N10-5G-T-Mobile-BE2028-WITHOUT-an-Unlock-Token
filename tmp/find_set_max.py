#!/usr/bin/env python3
"""Find set_maximized call in hwcomposer by analyzing BL targets near mov w1, #9"""
import struct

with open("/Users/xmxx/pinganhuijia/tmp/hwc.so", "rb") as f:
    data = f.read()

# Known mov w1, #9 locations
mov_locations = [0x3d6d4, 0x3dd20, 0x3e8fc, 0x3ee50]

# wl_proxy_marshal GOT = 0x6e708
# PLT entries are 16 bytes each, GOT entries are 8 bytes each
# PLT for __android_log_print = 0x66060, GOT = 0x6e6d8
# PLT step = 16, GOT step = 8, so:
# PLT(got_addr) = 0x66060 + (got_addr - 0x6e6d8) / 8 * 16
# PLT(0x6e708) = 0x66060 + (0x6e708 - 0x6e6d8) / 8 * 16 = 0x66060 + 6*16 = 0x660c0

wl_proxy_marshal_plt = 0x660c0

# Also let me verify by reading the GOT entry targeted by PLT at 0x660c0
print(f"Expected wl_proxy_marshal PLT at 0x{wl_proxy_marshal_plt:x}")

# Verify: decode the PLT stub at 0x660c0
adrp_inst = struct.unpack_from("<I", data, wl_proxy_marshal_plt)[0]
ldr_inst = struct.unpack_from("<I", data, wl_proxy_marshal_plt + 4)[0]
print(f"PLT stub: {adrp_inst:08x} {ldr_inst:08x}")

if (adrp_inst >> 24) & 0x9f == 0x90:  # ADRP
    immlo = (adrp_inst >> 29) & 3
    immhi = (adrp_inst >> 5) & 0x7FFFF
    imm = ((immhi << 2) | immlo) << 12
    if imm & 0x100000000:
        imm -= 0x200000000
    page = (wl_proxy_marshal_plt & ~0xFFF) + imm
    if (ldr_inst >> 22) & 0x3FF == 0x3E5:  # LDR X, [Xn, #imm]
        ldr_off = ((ldr_inst >> 10) & 0xFFF) << 3
        got_entry = page + ldr_off
        print(f"  Loads from GOT[0x{got_entry:x}]")

# Now check each mov w1, #9 location
for loc in mov_locations:
    print(f"\n=== mov w1, #9 at 0x{loc:x} ===")
    # Show 20 instructions around it
    for off in range(loc - 32, loc + 48, 4):
        inst = struct.unpack_from("<I", data, off)[0]
        marker = ""
        if off == loc:
            marker = " <<< MOV W1, #9"
        if (inst >> 26) == 0x25:  # BL
            offset_val = inst & 0x03FFFFFF
            if offset_val & 0x02000000:
                offset_val -= 0x04000000
            target = off + (offset_val * 4)
            if target == wl_proxy_marshal_plt:
                marker += f" BL wl_proxy_marshal *** MATCH ***"
            else:
                marker += f" BL 0x{target & 0xFFFFFFFF:x}"
        if inst == 0xd65f03c0:
            marker += " RET"
        # Check for mov w2, #0 (d2800002 or 2a1f03e2)
        if inst == 0x2a1f03e2:
            marker += " MOV W2, WZR (=0)"
        if inst == 0xd2800002:
            marker += " MOV X2, #0"
        # Check for mov immediate patterns
        if (inst >> 23) == 0xa5:  # MOV (wide immediate) w register
            rd = inst & 0x1f
            imm16 = (inst >> 5) & 0xFFFF
            hw = (inst >> 21) & 3
            marker += f" MOV W{rd}, #{imm16 << (hw*16)}"

        print(f"  0x{off:05x}: {inst:08x}{marker}")

# Also find "hwc_wayland_thread" to understand the code flow
idx = data.find(b"hwc_wayland_thread")
if idx >= 0:
    print(f"\n'hwc_wayland_thread' string at 0x{idx:x}")

# Find all BL to wl_proxy_marshal_plt
print(f"\nAll BL to wl_proxy_marshal (0x{wl_proxy_marshal_plt:x}):")
for off in range(0, len(data) - 4, 4):
    inst = struct.unpack_from("<I", data, off)[0]
    if (inst >> 26) == 0x25:  # BL
        offset_val = inst & 0x03FFFFFF
        if offset_val & 0x02000000:
            offset_val -= 0x04000000
        target = off + (offset_val * 4)
        if target == wl_proxy_marshal_plt:
            # Look back for the opcode argument (mov w1, #N)
            for back in range(4, 40, 4):
                prev = struct.unpack_from("<I", data, off - back)[0]
                if (prev >> 21) == 0x294:  # MOV Wd, #imm16 (MOVZ)
                    rd = prev & 0x1f
                    imm16 = (prev >> 5) & 0xFFFF
                    if rd == 1:  # w1 = opcode
                        print(f"  0x{off:x}: BL wl_proxy_marshal, opcode w1=#{imm16} (set at 0x{off-back:x})")
                        break
            else:
                print(f"  0x{off:x}: BL wl_proxy_marshal (opcode not found nearby)")
