#!/usr/bin/env python3
"""Patch hwcomposer.waydroid.so to NOP out xdg_toplevel_set_maximized calls"""
import struct, shutil

INPUT = "/Users/xmxx/pinganhuijia/tmp/hwc.so"
OUTPUT = "/Users/xmxx/pinganhuijia/tmp/hwc_patched.so"

shutil.copy2(INPUT, OUTPUT)

with open(OUTPUT, "r+b") as f:
    data = f.read()

    NOP = struct.pack("<I", 0xD503201F)  # AArch64 NOP

    patches = []

    # Patch 1: NOP the BL wl_proxy_marshal at 0x3dd24 (set_maximized call)
    # This is the first call site: mov w1, #9 at 0x3dd20 then BL at 0x3dd24
    off = 0x3dd24
    orig = struct.unpack_from("<I", data, off)[0]
    assert (orig >> 26) == 0x25, f"Expected BL at 0x{off:x}, got 0x{orig:08x}"
    patches.append((off, "BL wl_proxy_marshal (set_maximized #1)"))

    # Patch 2: NOP the BL wl_proxy_marshal at 0x3dd38 (set_maximized call)
    off = 0x3dd38
    orig = struct.unpack_from("<I", data, off)[0]
    assert (orig >> 26) == 0x25, f"Expected BL at 0x{off:x}, got 0x{orig:08x}"
    patches.append((off, "BL wl_proxy_marshal (set_maximized #2)"))

    # Also NOP the mov w1, #9 at 0x3dd20 (not strictly necessary but cleaner)
    off = 0x3dd20
    orig = struct.unpack_from("<I", data, off)[0]
    assert orig == 0x52800121, f"Expected MOV W1,#9 at 0x{off:x}, got 0x{orig:08x}"
    patches.append((off, "MOV W1, #9"))

    # Apply patches
    f.seek(0)
    patched = bytearray(data)
    for off, desc in patches:
        orig_bytes = patched[off:off+4]
        patched[off:off+4] = NOP
        print(f"Patched 0x{off:x}: {orig_bytes.hex()} -> {NOP.hex()} ({desc})")

    f.seek(0)
    f.write(patched)
    f.truncate()

print(f"\nPatched binary written to {OUTPUT}")
print(f"Size: {len(data)} bytes (unchanged)")
