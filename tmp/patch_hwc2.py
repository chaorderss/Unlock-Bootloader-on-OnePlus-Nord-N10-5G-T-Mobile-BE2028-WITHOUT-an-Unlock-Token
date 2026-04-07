#!/usr/bin/env python3
"""Patch hwcomposer to skip xdg_wm_base binding, forcing wl_shell fallback"""
import struct, shutil

INPUT = "/Users/xmxx/pinganhuijia/tmp/hwc.so"   # original unpatched
OUTPUT = "/Users/xmxx/pinganhuijia/tmp/hwc_patched2.so"

shutil.copy2(INPUT, OUTPUT)

NOP = struct.pack("<I", 0xD503201F)

with open(OUTPUT, "r+b") as f:
    data = bytearray(f.read())

    # Patch: NOP the CBZ at 0x3fbb0 that branches to xdg_wm_base binding code
    # Original: 34000a60 = CBZ W0, +0x14C -> 0x3fcfc (bind xdg_wm_base)
    off = 0x3fbb0
    orig = struct.unpack_from("<I", data, off)[0]
    assert orig == 0x34000a60, f"Expected CBZ 0x34000a60 at 0x{off:x}, got 0x{orig:08x}"
    data[off:off+4] = NOP
    print(f"Patched 0x{off:x}: {orig:08x} -> {0xD503201F:08x} (NOP xdg_wm_base CBZ)")

    f.seek(0)
    f.write(data)
    f.truncate()

print(f"\nPatched binary: {OUTPUT}")
print("Effect: hwcomposer will skip xdg_wm_base, use wl_shell instead")
