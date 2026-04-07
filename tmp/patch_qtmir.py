#!/usr/bin/env python3
"""Patch qtmir ApplicationManager::authorizeSession to always return true.
This allows Waydroid to connect to Lomiri's Wayland display."""
import struct, shutil

SRC = 'qtmir_app.so'
DST = 'qtmir_app_patched.so'

shutil.copy2(SRC, DST)

with open(DST, 'r+b') as f:
    # authorizeSession is at 0x4ea00
    # Signature: authorizeSession(int pid, bool& authorized)
    #   X0 = this, W1 = pid, X2 = &authorized
    #
    # Original first 3 instructions:
    #   0x4ea00: d503233f  PACIASP
    #   0x4ea04: d10403ff  SUB SP, SP, #0x100
    #   0x4ea08: a90a7bfd  STP X29, X30, [SP, #0xA0]
    #
    # Patch: always set authorized=true and return
    #   MOV W8, #1        (0x52800028)
    #   STRB W8, [X2]     (0x39000048)
    #   RET               (0xd65f03c0)

    f.seek(0x4ea00)
    orig = f.read(12)
    orig_insns = struct.unpack('<III', orig)

    # Verify original instructions
    assert orig_insns[0] == 0xd503233f, f"Expected PACIASP, got 0x{orig_insns[0]:08x}"
    assert orig_insns[1] == 0xd10403ff, f"Expected SUB SP, got 0x{orig_insns[1]:08x}"
    assert orig_insns[2] == 0xa90a7bfd, f"Expected STP, got 0x{orig_insns[2]:08x}"

    # Write patch
    f.seek(0x4ea00)
    f.write(struct.pack('<III',
        0x52800028,  # MOV W8, #1
        0x39000048,  # STRB W8, [X2]
        0xd65f03c0,  # RET
    ))

    print(f"Patched authorizeSession at 0x4ea00:")
    print(f"  0x4ea00: {orig_insns[0]:08x} -> 52800028 (MOV W8, #1)")
    print(f"  0x4ea04: {orig_insns[1]:08x} -> 39000048 (STRB W8, [X2])")
    print(f"  0x4ea08: {orig_insns[2]:08x} -> d65f03c0 (RET)")

print(f"\nWritten to {DST}")
