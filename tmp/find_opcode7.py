#!/usr/bin/env python3
"""Search for wl_shell_surface_set_maximized (opcode 7) in hwcomposer binary.
7 can be loaded as MOVZ W1,#7 (0x528000E1) or ORR W1,WZR,#7 (0x32000BE1)"""
import struct

with open('hwc.so', 'rb') as f:
    data = f.read()

# Decode AArch64 logical immediate
def decode_logical_imm(N, imms, immr, is64):
    """Decode AArch64 logical immediate to integer value"""
    if N == 1:
        if not is64:
            return None
        length = 6
    else:
        # Find highest set bit in ~imms (6 bits)
        nimms = (~imms) & 0x3F
        if nimms == 0:
            return None
        length = nimms.bit_length() - 1
        if length < 1:
            return None

    esize = 1 << (length + 1) if N == 0 else 64
    if N == 0:
        # check imms constraint
        mask_s = (1 << (length + 1)) - 1
        if (imms & mask_s) == mask_s:
            return None  # all ones in element = reserved

    # s and r within element
    s = imms & ((1 << (length + 1)) - 1) if N == 0 else imms
    r = immr & ((1 << (length + 1)) - 1) if N == 0 else immr

    # Create base pattern: s+1 ones
    welem = (1 << (s + 1)) - 1
    # Rotate right by r
    if r > 0:
        welem = ((welem >> r) | (welem << (esize - r))) & ((1 << esize) - 1)

    # Replicate to fill register width
    regsize = 64 if is64 else 32
    result = 0
    for i in range(0, regsize, esize):
        result |= welem << i
    return result & ((1 << regsize) - 1)

WL_PROXY_MARSHAL_PLT = 0x660c0

print("=== Searching for all instructions that load W1 near wl_proxy_marshal calls ===\n")

# Find all BL to wl_proxy_marshal
bl_sites = []
for off in range(0, len(data) - 4, 4):
    insn = struct.unpack_from('<I', data, off)[0]
    if (insn >> 26) == 0b100101:
        imm26 = insn & 0x3FFFFFF
        if imm26 & (1 << 25): imm26 -= (1 << 26)
        target = off + imm26 * 4
        if target == WL_PROXY_MARSHAL_PLT:
            bl_sites.append(off)

# For each BL site, look backwards to find what W1 was loaded with
for bl_off in bl_sites:
    opcode = None
    opcode_off = None
    opcode_insn = None

    for back in range(1, 10):
        prev_off = bl_off - back * 4
        if prev_off < 0:
            break
        prev = struct.unpack_from('<I', data, prev_off)[0]

        # Check if this instruction writes to W1/X1
        rd = prev & 0x1F
        if rd != 1:
            continue

        # MOVZ W1, #imm
        if (prev & 0xFFE00000) == 0x52800000:
            imm16 = (prev >> 5) & 0xFFFF
            opcode = imm16
            opcode_off = prev_off
            opcode_insn = f"MOVZ W1, #{imm16}"
            break

        # ORR W1, WZR, #imm (logical immediate, 32-bit, sf=0, opc=01, N from bit 22)
        if (prev & 0xFFC003E0) == 0x320003E0:  # ORR W1, WZR, #imm check Rn=31(WZR),Rd=1
            N = (prev >> 22) & 1
            immr = (prev >> 16) & 0x3F
            imms = (prev >> 10) & 0x3F
            val = decode_logical_imm(N, imms, immr, False)
            if val is not None:
                opcode = val
                opcode_off = prev_off
                opcode_insn = f"ORR W1, WZR, #{val} (0x{prev:08x})"
                break

        # MOV W1, WZR
        if prev == 0x2A1F03E1:
            opcode = 0
            opcode_off = prev_off
            opcode_insn = "MOV W1, WZR (=0)"
            break

        # MOV W1, Wn (ORR W1, WZR, Wn)
        if (prev & 0xFFE0FFE0) == 0x2A0003E0 and rd == 1:
            rm = (prev >> 16) & 0x1F
            if rm == 31:
                opcode = 0
            else:
                opcode = f"W{rm}"
            opcode_off = prev_off
            opcode_insn = f"MOV W1, {'WZR' if rm==31 else f'W{rm}'}"
            break

    # Only print interesting ones (near wl_shell code area and with opcodes 3-10)
    if opcode is not None and isinstance(opcode, int) and 0x3d000 <= bl_off <= 0x3f600:
        print(f"  0x{bl_off:05x}: BL wl_proxy_marshal, opcode={opcode} (at 0x{opcode_off:x}: {opcode_insn})")

print("\n=== ALL calls with opcode 7 (wl_shell_surface_set_maximized) ===")
for bl_off in bl_sites:
    for back in range(1, 10):
        prev_off = bl_off - back * 4
        if prev_off < 0:
            break
        prev = struct.unpack_from('<I', data, prev_off)[0]
        rd = prev & 0x1F
        if rd != 1:
            continue

        val = None
        # MOVZ
        if (prev & 0xFFE00000) == 0x52800000:
            val = (prev >> 5) & 0xFFFF
        # ORR logical imm
        elif (prev & 0xFFC003E0) == 0x320003E0:
            N = (prev >> 22) & 1
            immr = (prev >> 16) & 0x3F
            imms = (prev >> 10) & 0x3F
            val = decode_logical_imm(N, imms, immr, False)
        # MOV WZR
        elif prev == 0x2A1F03E1:
            val = 0

        if val == 7:
            print(f"\n  *** FOUND: 0x{bl_off:05x}: BL wl_proxy_marshal, opcode=7")
            print(f"      Loaded at 0x{prev_off:x}: insn=0x{prev:08x}")
            # Context
            for i in range(-12, 3):
                ctx_off = bl_off + i * 4
                if 0 <= ctx_off < len(data) - 4:
                    ctx = struct.unpack_from('<I', data, ctx_off)[0]
                    marker = " <<<< BL" if i == 0 else (" <<<< OPCODE" if ctx_off == prev_off else "")
                    print(f"      0x{ctx_off:05x}: {ctx:08x}{marker}")
            break
        elif val is not None:
            break  # Found a W1 write but it's not 7

# Also just raw-search for the byte pattern of ORR W1, WZR, #7
# 7 = 3 consecutive bits: imms=2(=0b000010), immr=0, N=0
# Encoding: 0x32000BE1
print("\n=== Raw search for ORR W1, WZR, #7 (0x32000BE1) ===")
target_bytes = struct.pack('<I', 0x32000BE1)
pos = 0
while True:
    idx = data.find(target_bytes, pos)
    if idx == -1:
        break
    print(f"  Found at offset 0x{idx:x}")
    pos = idx + 1

# And MOVZ W1, #7 (0x528000E1)
print("\n=== Raw search for MOVZ W1, #7 (0x528000E1) ===")
target_bytes = struct.pack('<I', 0x528000E1)
pos = 0
while True:
    idx = data.find(target_bytes, pos)
    if idx == -1:
        break
    print(f"  Found at offset 0x{idx:x}")
    pos = idx + 1
