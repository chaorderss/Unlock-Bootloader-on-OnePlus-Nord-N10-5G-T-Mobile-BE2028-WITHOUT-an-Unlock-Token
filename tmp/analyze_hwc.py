#!/usr/bin/env python3
"""Analyze hwcomposer binary to find set_maximized for patching"""
import struct, sys

with open("/Users/xmxx/pinganhuijia/tmp/hwc.so", "rb") as f:
    data = f.read()

# Find key strings
for s in [b"set_maximized\x00", b"set_fullscreen\x00", b"xdg_toplevel\x00"]:
    idx = data.find(s)
    print(f"{s!r} at offset: 0x{idx:x}" if idx >= 0 else f"{s!r} NOT FOUND")

# AArch64: mov w1, #9 = 0x52800121
mov_w1_9 = bytes([0x21, 0x01, 0x80, 0x52])
# AArch64: mov w1, #11 = 0x52800161 (set_fullscreen)
mov_w1_11 = bytes([0x61, 0x01, 0x80, 0x52])

print(f"\nmov w1, #9 occurrences:")
idx = 0
while True:
    idx = data.find(mov_w1_9, idx)
    if idx < 0:
        break
    ctx = data[idx-16:idx+20]
    print(f"  0x{idx:x}: {ctx.hex()}")
    idx += 4

print(f"\nmov w1, #11 occurrences:")
idx = 0
while True:
    idx = data.find(mov_w1_11, idx)
    if idx < 0:
        break
    ctx = data[idx-16:idx+20]
    print(f"  0x{idx:x}: {ctx.hex()}")
    idx += 4
