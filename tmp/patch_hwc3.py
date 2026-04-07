#!/usr/bin/env python3
"""Patch #3: Two changes to hwcomposer.waydroid.so
1. NOP CBZ at 0x3fbb0 to skip xdg_wm_base binding (force wl_shell)
2. Change ORR W1,WZR,#7 to ORR W1,WZR,#3 at 0x3dd30 (set_toplevel instead of set_maximized)
"""
import struct, shutil

SRC = 'hwc.so'
DST = 'hwc_patched3.so'

shutil.copy2(SRC, DST)

with open(DST, 'r+b') as f:
    # Patch 1: NOP the CBZ at 0x3fbb0 (skip xdg_wm_base binding)
    f.seek(0x3fbb0)
    orig1 = struct.unpack('<I', f.read(4))[0]
    assert orig1 == 0x34000a60, f"Expected CBZ at 0x3fbb0, got 0x{orig1:08x}"
    f.seek(0x3fbb0)
    f.write(struct.pack('<I', 0xd503201f))  # NOP
    print(f"Patch 1: 0x3fbb0: {orig1:08x} -> d503201f (NOP xdg_wm_base CBZ)")

    # Patch 2: Change opcode 7 -> 3 at 0x3dd30
    # ORR W1, WZR, #7 = 0x32000BE1
    # ORR W1, WZR, #3 = 0x320007E1
    f.seek(0x3dd30)
    orig2 = struct.unpack('<I', f.read(4))[0]
    assert orig2 == 0x32000be1, f"Expected ORR W1,WZR,#7 at 0x3dd30, got 0x{orig2:08x}"
    f.seek(0x3dd30)
    f.write(struct.pack('<I', 0x320007e1))  # ORR W1, WZR, #3
    print(f"Patch 2: 0x3dd30: {orig2:08x} -> 320007e1 (opcode 7->3: set_maximized->set_toplevel)")

print(f"\nWritten to {DST}")
