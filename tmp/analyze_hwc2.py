#!/usr/bin/env python3
"""Deeper analysis of hwcomposer binary - find set_maximized in hwc_wayland_thread"""
import struct

with open("/Users/xmxx/pinganhuijia/tmp/hwc.so", "rb") as f:
    data = f.read()

# From crash trace: pc 0x3f188 = hwc_wayland_thread + 88 (0x58)
# So hwc_wayland_thread starts at 0x3f188 - 0x58 = 0x3f130
func_start = 0x3f130
crash_pc = 0x3f188

print(f"hwc_wayland_thread: 0x{func_start:x} - crash at 0x{crash_pc:x}")
print(f"\nDisassembly around hwc_wayland_thread (hex dump):")

# Show the function region
for off in range(func_start - 0x100, func_start + 0x200, 4):
    if off < 0 or off >= len(data):
        continue
    inst = struct.unpack_from("<I", data, off)[0]
    marker = ""
    if off == func_start:
        marker = " <-- func start"
    if off == crash_pc:
        marker = " <-- CRASH PC"
    # Check for mov w1, #9
    if inst == 0x52800121:
        marker += " *** MOV W1, #9 (set_maximized opcode)"
    # Check for BL instruction (opcode 1001 01xx xxxx xxxx xxxx xxxx xxxx xxxx)
    if (inst >> 26) == 0x25:  # BL
        offset_val = inst & 0x03FFFFFF
        if offset_val & 0x02000000:
            offset_val |= 0xFC000000  # sign extend
        target = off + (offset_val << 2)
        marker += f" BL -> 0x{target & 0xFFFFFFFF:x}"
    # Check for RET
    if inst == 0xd65f03c0:
        marker += " RET"
    # check for NOP
    if inst == 0xd503201f:
        marker += " NOP"

    print(f"  0x{off:05x}: {inst:08x}{marker}")

# Also show the strings near set_maximized
print(f"\nStrings near 'set_maximized' (0x18a38):")
print(repr(data[0x18a20:0x18a60]))

# Find "hwc_wayland_thread" string
idx = data.find(b"hwc_wayland_thread")
if idx >= 0:
    print(f"\n'hwc_wayland_thread' string at: 0x{idx:x}")

# Check relocation/PLT entries for wl_proxy_marshal_flags
idx = data.find(b"wl_proxy_marshal_flags")
if idx >= 0:
    print(f"'wl_proxy_marshal_flags' at: 0x{idx:x}")
idx = data.find(b"wl_proxy_marshal")
if idx >= 0:
    print(f"'wl_proxy_marshal' at: 0x{idx:x}")
