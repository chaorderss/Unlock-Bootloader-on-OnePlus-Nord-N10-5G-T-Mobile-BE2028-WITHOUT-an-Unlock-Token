#!/usr/bin/env python3
"""Decode instructions before wl_proxy_marshal calls to find opcode loading patterns"""
import struct

def decode_aarch64(insn, off):
    """Basic AArch64 instruction decoder"""
    # NOP
    if insn == 0xd503201f:
        return "NOP"
    # MOVZ Wd, #imm, LSL #shift
    if (insn & 0x7F800000) == 0x52800000:
        rd = insn & 0x1F
        imm16 = (insn >> 5) & 0xFFFF
        hw = (insn >> 21) & 0x3
        sf = (insn >> 31) & 1
        reg = f"X{rd}" if sf else f"W{rd}"
        shift = hw * 16
        if shift:
            return f"MOVZ {reg}, #{imm16}, LSL #{shift}"
        return f"MOVZ {reg}, #{imm16}"
    # MOVK Wd, #imm, LSL #shift
    if (insn & 0x7F800000) == 0x72800000:
        rd = insn & 0x1F
        imm16 = (insn >> 5) & 0xFFFF
        hw = (insn >> 21) & 0x3
        sf = (insn >> 31) & 1
        reg = f"X{rd}" if sf else f"W{rd}"
        shift = hw * 16
        if shift:
            return f"MOVK {reg}, #{imm16}, LSL #{shift}"
        return f"MOVK {reg}, #{imm16}"
    # BL imm26
    if (insn >> 26) == 0b100101:
        imm26 = insn & 0x3FFFFFF
        if imm26 & (1 << 25): imm26 -= (1 << 26)
        target = off + imm26 * 4
        return f"BL 0x{target:x}"
    # B imm26
    if (insn >> 26) == 0b000101:
        imm26 = insn & 0x3FFFFFF
        if imm26 & (1 << 25): imm26 -= (1 << 26)
        target = off + imm26 * 4
        return f"B 0x{target:x}"
    # CBZ/CBNZ
    if (insn & 0x7E000000) == 0x34000000:
        sf = (insn >> 31) & 1
        op = (insn >> 24) & 1
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1<<18): imm19 -= (1<<19)
        rt = insn & 0x1F
        target = off + imm19 * 4
        reg = f"X{rt}" if sf else f"W{rt}"
        name = "CBNZ" if op else "CBZ"
        return f"{name} {reg}, 0x{target:x}"
    # LDR Xt, [Xn, #imm]
    if (insn & 0xFFC00000) == 0xF9400000:
        rt = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm12 = (insn >> 10) & 0xFFF
        return f"LDR X{rt}, [X{rn}, #{imm12*8}]"
    if (insn & 0xFFC00000) == 0xB9400000:
        rt = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm12 = (insn >> 10) & 0xFFF
        return f"LDR W{rt}, [X{rn}, #{imm12*4}]"
    # STR/STP
    if (insn & 0xFFC00000) == 0xF9000000:
        rt = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm12 = (insn >> 10) & 0xFFF
        return f"STR X{rt}, [X{rn}, #{imm12*8}]"
    # MOV (register) = ORR Rd, XZR, Rm
    if (insn & 0xFF200000) in (0x2A000000, 0xAA000000):
        sf = (insn >> 31) & 1
        rm = (insn >> 16) & 0x1F
        rn = (insn >> 5) & 0x1F
        rd = insn & 0x1F
        prefix = "X" if sf else "W"
        if rn == 31:
            return f"MOV {prefix}{rd}, {prefix}{rm}"
        return f"ORR {prefix}{rd}, {prefix}{rn}, {prefix}{rm}"
    # ADD immediate
    if (insn & 0x7F000000) == 0x11000000:
        sf = (insn >> 31) & 1
        sh = (insn >> 22) & 1
        imm12 = (insn >> 10) & 0xFFF
        rn = (insn >> 5) & 0x1F
        rd = insn & 0x1F
        prefix = "X" if sf else "W"
        val = imm12 << (12 if sh else 0)
        return f"ADD {prefix}{rd}, {prefix}{rn}, #{val}"
    # SUB immediate
    if (insn & 0x7F000000) == 0x51000000:
        sf = (insn >> 31) & 1
        imm12 = (insn >> 10) & 0xFFF
        rn = (insn >> 5) & 0x1F
        rd = insn & 0x1F
        prefix = "X" if sf else "W"
        return f"SUB {prefix}{rd}, {prefix}{rn}, #{imm12}"
    # ADRP
    if (insn & 0x9F000000) == 0x90000000:
        rd = insn & 0x1F
        immhi = (insn >> 5) & 0x7FFFF
        immlo = (insn >> 29) & 0x3
        imm = (immhi << 2) | immlo
        if imm & (1 << 20): imm -= (1 << 21)
        page = ((off >> 12) + imm) << 12
        return f"ADRP X{rd}, 0x{page:x}"
    # STP
    if (insn & 0xFFC00000) == 0xA9000000:
        return "STP ..."

    return f"??? (0x{insn:08x})"

with open('hwc.so', 'rb') as f:
    data = f.read()

WL_PROXY_MARSHAL_PLT = 0x660c0

# Focus on wl_shell code area (0x3d000 - 0x3f600)
print("=== wl_proxy_marshal calls in hwc Wayland area with full context ===\n")

for off in range(0x3d000, 0x3f600, 4):
    insn = struct.unpack_from('<I', data, off)[0]
    if (insn >> 26) == 0b100101:
        imm26 = insn & 0x3FFFFFF
        if imm26 & (1 << 25): imm26 -= (1 << 26)
        target = off + imm26 * 4
        if target == WL_PROXY_MARSHAL_PLT:
            print(f"--- BL wl_proxy_marshal at 0x{off:05x} ---")
            for i in range(-10, 3):
                ctx_off = off + i * 4
                if 0 <= ctx_off < len(data) - 4:
                    ctx_insn = struct.unpack_from('<I', data, ctx_off)[0]
                    decoded = decode_aarch64(ctx_insn, ctx_off)
                    marker = " <<<< BL" if i == 0 else ""
                    print(f"  0x{ctx_off:05x}: {ctx_insn:08x}  {decoded}{marker}")
            print()
