#!/usr/bin/env python3
"""Find xdg_wm_base binding in hwcomposer to patch it to skip xdg_shell
and force fallback to wl_shell"""
import struct

with open("/Users/xmxx/pinganhuijia/tmp/hwc.so", "rb") as f:
    data = f.read()

# The registry handler compares interface strings to bind globals
# Find where "xdg_wm_base" string is referenced
xdg_str = data.find(b"xdg_wm_base\x00")
print(f"'xdg_wm_base' string at 0x{xdg_str:x}")

# Find "wl_shell\x00" string
wl_shell = data.find(b"wl_shell\x00")
print(f"'wl_shell' string at 0x{wl_shell:x}")

# Find "zxdg_shell_v6" string
zxdg = data.find(b"zxdg_shell_v6\x00")
print(f"'zxdg_shell_v6' string at 0x{zxdg:x}")

# In the text section, the registry_global handler will do strcmp-like
# operations with these strings. We need to find where xdg_wm_base is
# compared, and prevent the binding.
# The string address is used via ADRP+ADD instructions.

# Compute the page for each string
xdg_page = xdg_str & ~0xFFF
xdg_pageoff = xdg_str & 0xFFF
print(f"\nxdg_wm_base: page=0x{xdg_page:x}, offset=0x{xdg_pageoff:x}")

# Search for ADRP instructions that load the page containing xdg_wm_base string
# ADRP: (immhi:immlo)<<12 + PC_page
# We need to find ADRP where the computed page matches xdg_page, from different PC locations
print(f"\nSearching for ADRP+ADD referencing xdg_wm_base string (0x{xdg_str:x})...")

for off in range(0, min(len(data), 0x65000), 4):  # text section only
    inst = struct.unpack_from("<I", data, off)[0]
    # Check ADRP: bit 31=1, bits 28:24=10000
    if (inst >> 24) & 0x9f == 0x90:
        rd = inst & 0x1f
        immlo = (inst >> 29) & 3
        immhi = (inst >> 5) & 0x7FFFF
        imm = ((immhi << 2) | immlo) << 12
        if imm & 0x100000000:
            imm -= 0x200000000
        page = (off & ~0xFFF) + imm

        if page == xdg_page:
            # Check next instruction for ADD with the right offset
            if off + 4 < len(data):
                inst2 = struct.unpack_from("<I", data, off + 4)[0]
                # ADD Xd, Xn, #imm12
                if (inst2 >> 22) & 0x3FF == 0x244:  # ADD (immediate, 64-bit)
                    add_imm = (inst2 >> 10) & 0xFFF
                    if add_imm == xdg_pageoff:
                        rd2 = inst2 & 0x1f
                        print(f"  FOUND: ADRP+ADD at 0x{off:x} -> x{rd2} = 0x{xdg_str:x} (xdg_wm_base)")

                        # Show surrounding context
                        for ctx_off in range(max(0, off-20), min(len(data), off+40), 4):
                            ci = struct.unpack_from("<I", data, ctx_off)[0]
                            m = ""
                            if ctx_off == off:
                                m = " <-- ADRP"
                            if ctx_off == off + 4:
                                m = " <-- ADD (xdg_wm_base str)"
                            if (ci >> 26) == 0x25:
                                toff = ci & 0x03FFFFFF
                                if toff & 0x02000000:
                                    toff -= 0x04000000
                                target = ctx_off + toff * 4
                                m += f" BL -> 0x{target & 0xFFFFFFFF:x}"
                            print(f"    0x{ctx_off:05x}: {ci:08x}{m}")
