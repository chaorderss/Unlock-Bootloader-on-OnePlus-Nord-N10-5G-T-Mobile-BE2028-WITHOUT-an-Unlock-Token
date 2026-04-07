#!/usr/bin/env python3
"""Find wl_shell binding in hwcomposer to verify it's supported"""
import struct

with open("/Users/xmxx/pinganhuijia/tmp/hwc.so", "rb") as f:
    data = f.read()

# wl_shell string
wl_shell_str = 0x1a0eb
wl_shell_page = wl_shell_str & ~0xFFF
wl_shell_pageoff = wl_shell_str & 0xFFF
print(f"wl_shell string at 0x{wl_shell_str:x}, page=0x{wl_shell_page:x}, offset=0x{wl_shell_pageoff:x}")

# Search for references
print(f"\nSearching for ADRP+ADD referencing wl_shell string...")
for off in range(0, min(len(data), 0x65000), 4):
    inst = struct.unpack_from("<I", data, off)[0]
    if (inst >> 24) & 0x9f == 0x90:  # ADRP
        rd = inst & 0x1f
        immlo = (inst >> 29) & 3
        immhi = (inst >> 5) & 0x7FFFF
        imm = ((immhi << 2) | immlo) << 12
        if imm & 0x100000000:
            imm -= 0x200000000
        page = (off & ~0xFFF) + imm

        if page == wl_shell_page:
            if off + 4 < len(data):
                inst2 = struct.unpack_from("<I", data, off + 4)[0]
                if (inst2 >> 22) & 0x3FF == 0x244:  # ADD imm64
                    add_imm = (inst2 >> 10) & 0xFFF
                    if add_imm == wl_shell_pageoff:
                        rd2 = inst2 & 0x1f
                        print(f"  FOUND at 0x{off:x} -> x{rd2} = wl_shell str")
                        for ctx_off in range(max(0, off-24), min(len(data), off+40), 4):
                            ci = struct.unpack_from("<I", data, ctx_off)[0]
                            m = ""
                            if ctx_off == off: m = " <-- ADRP"
                            if ctx_off == off + 4: m = " <-- ADD (wl_shell)"
                            if (ci >> 26) == 0x25:
                                toff = ci & 0x03FFFFFF
                                if toff & 0x02000000: toff -= 0x04000000
                                m += f" BL 0x{(ctx_off + toff*4) & 0xFFFFFFFF:x}"
                            print(f"    0x{ctx_off:05x}: {ci:08x}{m}")

# Also show the wider context around the registry handler
print(f"\nFull registry handler context (0x3fb80 - 0x3fd00):")
for off in range(0x3fb80, 0x3fd20, 4):
    inst = struct.unpack_from("<I", data, off)[0]
    m = ""
    if (inst >> 26) == 0x25:
        toff = inst & 0x03FFFFFF
        if toff & 0x02000000: toff -= 0x04000000
        m = f" BL 0x{(off + toff*4) & 0xFFFFFFFF:x}"
    # CBZ/CBNZ
    if (inst >> 24) == 0x34:  # CBZ 32-bit
        imm19 = (inst >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 -= 0x80000
        target = off + imm19 * 4
        m = f" CBZ W{inst&0x1f}, -> 0x{target:x}"
    if (inst >> 24) == 0x35:  # CBNZ 32-bit
        imm19 = (inst >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 -= 0x80000
        target = off + imm19 * 4
        m = f" CBNZ W{inst&0x1f}, -> 0x{target:x}"
    if inst == 0xd65f03c0: m = " RET"
    if off == 0x3fba0: m += " [ADRP xdg_wm_base]"
    if off == 0x3fbb0: m += " [CBZ: if xdg_wm_base match -> bind it]"
    print(f"  0x{off:05x}: {inst:08x}{m}")
