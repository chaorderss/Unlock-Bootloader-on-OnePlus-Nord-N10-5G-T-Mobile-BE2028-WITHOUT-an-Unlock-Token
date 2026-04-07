#!/usr/bin/env python3
"""Decode wlan_hdd_mgmt_tx from binary dump"""

# Collected from kfind dumps
# wlan_hdd_mgmt_tx at ffffff9ef984bd98
insns = {
    # First dump (instructions 0-63, offsets 0x000-0x0fc)
    0x000: 0xd10203ff, 0x004: 0xa9026ffc, 0x008: 0xa90367fa, 0x00c: 0xa9045ff8,
    0x010: 0xa90557f6, 0x014: 0xa9064ff4, 0x018: 0xa9077bfd, 0x01c: 0x9101c3fd,
    0x020: 0x900017e0, 0x024: 0x91066000, 0x028: 0xaa0303fa, 0x02c: 0xaa0203f8,
    0x030: 0xaa0103f4, 0x034: 0x9404ff29, 0x038: 0xf940129c, 0x03c: 0x900017e2,
    0x040: 0x900017e3, 0x044: 0xf9400316, 0x048: 0x3940231b, 0x04c: 0x91120842,
    0x050: 0xb9400f17, 0x054: 0x912c8863, 0x058: 0xa9416715, 0x05c: 0x39408313,
    0x060: 0x52800660, 0x064: 0x39408714, 0x068: 0x52801c84, 0x06c: 0xf9444f98,
    0x070: 0x321d03e1, 0x074: 0x9404c20d, 0x078: 0x97ffb544, 0x07c: 0x7100141f,
    0x080: 0x54000161, 0x084: 0x900017e2, 0x088: 0x900017e3, 0x08c: 0x9112b042,
    0x090: 0x912c8863, 0x094: 0x52800660, 0x098: 0x52801ce4, 0x09c: 0x321f03e1,
    0x0a0: 0x9404c202, 0x0a4: 0x128002b9, 0x0a8: 0x14000052, 0x0ac: 0x39787380,
    0x0b0: 0x900017e1, 0x0b4: 0x912c8821, 0x0b8: 0xf9000ff9, 0x0bc: 0x97ffa071,
    0x0c0: 0x128002b9, 0x0c4: 0x35000960, 0x0c8: 0x900017e1, 0x0cc: 0xf9000bfa,
    0x0d0: 0x912c8821, 0x0d4: 0xaa1803e0, 0x0d8: 0x97ff9f98, 0x0dc: 0x340001a0,
    0x0e0: 0x2a0003fa, 0x0e4: 0x900017e2, 0x0e8: 0x900017e3, 0x0ec: 0x912cd442,
    0x0f0: 0x912c8863, 0x0f4: 0x52800660, 0x0f8: 0x321f03e1, 0x0fc: 0x321c0fe4,
    # Second dump (instructions 64-255, offsets 0x100-0x3fc)
    0x100: 0x2a1a03e5, 0x104: 0x9404c1e9, 0x108: 0x2a1a03f9, 0x10c: 0x14000039,
    0x110: 0xf9445388, 0x114: 0xb948cb89, 0x118: 0x3941e103, 0x11c: 0x7100053f,
    0x120: 0x54000268, 0x124: 0x394002a8, 0x128: 0x121e7508, 0x12c: 0x12001d08,
    0x130: 0x7102c11f, 0x134: 0x540001c1, 0x138: 0x52800660, 0x13c: 0x52800681,
    0x140: 0x52800962, 0x144: 0x2a1f03e4, 0x148: 0x9404c42a, 0x14c: 0xf9400b00,
    0x150: 0xaa1503e2, 0x154: 0x39787381, 0x158: 0xf9400fe3, 0x15c: 0x9402a185,
    0x160: 0x7100001f, 0x164: 0x1a9903f9, 0x168: 0x14000022, 0x16c: 0x7100029f,
    0x170: 0x1a9f07f8, 0x174: 0x7100027f, 0x178: 0x1a9f07f9, 0x17c: 0x7100037f,
    0x180: 0x5280067b, 0x184: 0x528008e1, 0x188: 0x52800962, 0x18c: 0x2a1b03e0,
    0x190: 0x2a1f03e4, 0x194: 0x1a9f07fa, 0x198: 0x9404c416, 0x19c: 0xf9445380,
    0x1a0: 0xaa1603e1, 0x1a4: 0xa94117f3, 0x1a8: 0x2a1a03e2, 0x1ac: 0x2a1703e3,
    0x1b0: 0xaa1503e4, 0x1b4: 0x2a1903e6, 0x1b8: 0xf90003f3, 0x1bc: 0x2a1803e7,
    0x1c0: 0x9407cf8a, 0x1c4: 0xf9400266, 0x1c8: 0x900017e2, 0x1cc: 0x900017e3,
    0x1d0: 0x2a0003e5, 0x1d4: 0x912d8442, 0x1d8: 0x912c8863, 0x1dc: 0x52802264,
    0x1e0: 0x321d03e1, 0x1e4: 0x2a1b03e0, 0x1e8: 0x9404c1b0, 0x1ec: 0x2a1f03f9,
    0x1f0: 0x900017e0, 0x1f4: 0x91066000, 0x1f8: 0x9404ff66, 0x1fc: 0x2a1903e0,
    0x200: 0xa9477bfd, 0x204: 0xa9464ff4, 0x208: 0xa94557f6, 0x20c: 0xa9445ff8,
    0x210: 0xa94367fa, 0x214: 0xa9426ffc, 0x218: 0x910203ff, 0x21c: 0xd65f03c0,
}

def sext(val, bits):
    if val & (1 << (bits-1)):
        return val - (1 << bits)
    return val

def decode_insn(addr, val):
    """AArch64 instruction decoder"""

    # NOP
    if val == 0xd503201f:
        return "NOP"

    # RET
    if val == 0xd65f03c0:
        return "RET"

    # SUB SP, SP, #imm
    if (val & 0xffc003ff) == 0xd10003ff:
        imm12 = (val >> 10) & 0xfff
        return f"SUB SP, SP, #{imm12}"

    # ADD SP, SP, #imm
    if (val & 0xffc003ff) == 0x910003ff:
        imm12 = (val >> 10) & 0xfff
        return f"ADD SP, SP, #{imm12}"

    # STP pre-index (64-bit)
    if (val & 0xffc00000) == 0xa9800000 or (val & 0xffc00000) == 0xa9be0000 & 0:
        pass
    if (val >> 22) == (0xa9000000 >> 22):
        # STP signed offset
        rt1 = val & 0x1f
        rn = (val >> 5) & 0x1f
        rt2 = (val >> 10) & 0x1f
        imm7 = (val >> 15) & 0x7f
        imm7s = sext(imm7, 7)
        opc = (val >> 22) & 3
        if opc == 0:
            return f"STP X{rt1}, X{rt2}, [X{rn}, #{imm7s*8}]"

    # STP pre-index (a9be....)
    if (val & 0xffe00000) == 0xa9800000:
        rt1 = val & 0x1f
        rn = (val >> 5) & 0x1f
        rt2 = (val >> 10) & 0x1f
        imm7 = (val >> 15) & 0x7f
        imm7s = sext(imm7, 7)
        return f"STP X{rt1}, X{rt2}, [X{rn}, #{imm7s*8}]!"

    # LDP signed offset
    if (val & 0xffc00000) == 0xa9400000:
        rt1 = val & 0x1f
        rn = (val >> 5) & 0x1f
        rt2 = (val >> 10) & 0x1f
        imm7 = (val >> 15) & 0x7f
        imm7s = sext(imm7, 7)
        return f"LDP X{rt1}, X{rt2}, [X{rn}, #{imm7s*8}]"

    # LDP post-index
    if (val & 0xffc00000) == 0xa8c00000:
        rt1 = val & 0x1f
        rn = (val >> 5) & 0x1f
        rt2 = (val >> 10) & 0x1f
        imm7 = (val >> 15) & 0x7f
        imm7s = sext(imm7, 7)
        return f"LDP X{rt1}, X{rt2}, [X{rn}], #{imm7s*8}"

    # LDP 32-bit signed offset
    if (val & 0xffc00000) == 0x29400000:
        rt1 = val & 0x1f
        rn = (val >> 5) & 0x1f
        rt2 = (val >> 10) & 0x1f
        imm7 = (val >> 15) & 0x7f
        imm7s = sext(imm7, 7)
        return f"LDP W{rt1}, W{rt2}, [X{rn}, #{imm7s*4}]"

    # STP signed offset (64-bit, encoding a900_xxxx)
    if (val & 0xffc00000) == 0xa9000000:
        rt1 = val & 0x1f
        rn = (val >> 5) & 0x1f
        rt2 = (val >> 10) & 0x1f
        imm7 = (val >> 15) & 0x7f
        imm7s = sext(imm7, 7)
        return f"STP X{rt1}, X{rt2}, [X{rn}, #{imm7s*8}]"

    # STP signed offset (32-bit a900_xxxx variant -> 2900_xxxx)
    if (val & 0xffc00000) == 0x29000000:
        rt1 = val & 0x1f
        rn = (val >> 5) & 0x1f
        rt2 = (val >> 10) & 0x1f
        imm7 = (val >> 15) & 0x7f
        imm7s = sext(imm7, 7)
        return f"STP W{rt1}, W{rt2}, [X{rn}, #{imm7s*4}]"

    # MOV Xd, Xm (ORR Xd, XZR, Xm)
    if (val & 0xffe0ffe0) == 0xaa0003e0:
        rd = val & 0x1f
        rm = (val >> 16) & 0x1f
        return f"MOV X{rd}, X{rm}"

    # MOV Wd, Wm
    if (val & 0xffe0ffe0) == 0x2a0003e0:
        rd = val & 0x1f
        rm = (val >> 16) & 0x1f
        return f"MOV W{rd}, W{rm}"

    # ORR Xd, Xn, Xm
    if (val & 0xff200000) == 0xaa000000:
        rd = val & 0x1f
        rn = (val >> 5) & 0x1f
        rm = (val >> 16) & 0x1f
        return f"ORR X{rd}, X{rn}, X{rm}"

    # ORR Wd, Wn, Wm
    if (val & 0xff200000) == 0x2a000000:
        rd = val & 0x1f
        rn = (val >> 5) & 0x1f
        rm = (val >> 16) & 0x1f
        if rn == 31:
            return f"MOV W{rd}, W{rm}"
        return f"ORR W{rd}, W{rn}, W{rm}"

    # MOVZ
    if (val & 0xff800000) == 0x52800000:
        rd = val & 0x1f
        imm16 = (val >> 5) & 0xffff
        hw = (val >> 21) & 3
        s = f"MOVZ W{rd}, #0x{imm16:x}" + (f", LSL #{hw*16}" if hw else "")
        return s + f"  (={imm16})"
    if (val & 0xff800000) == 0xd2800000:
        rd = val & 0x1f
        imm16 = (val >> 5) & 0xffff
        hw = (val >> 21) & 3
        return f"MOVZ X{rd}, #0x{imm16:x}" + (f", LSL #{hw*16}" if hw else "")

    # MOVN
    if (val & 0xff800000) == 0x12800000:
        rd = val & 0x1f
        imm16 = (val >> 5) & 0xffff
        return f"MOVN W{rd}, #0x{imm16:x}  (= -{imm16+1} = -EINVAL)" if imm16 == 0x15 else f"MOVN W{rd}, #0x{imm16:x}  (= {-(imm16+1)})"

    # B unconditional
    if (val >> 26) == 0x05:
        imm26 = val & 0x3ffffff
        if imm26 & 0x2000000: imm26 -= 0x4000000
        target = addr + imm26 * 4
        return f"B 0x{target & 0xffffffff:x}"

    # BL
    if (val >> 26) == 0x25:
        imm26 = val & 0x3ffffff
        if imm26 & 0x2000000: imm26 -= 0x4000000
        target = addr + imm26 * 4
        return f"BL 0x{target & 0xffffffff:x}"

    # B.cond
    if (val & 0xff000010) == 0x54000000:
        imm19 = (val >> 5) & 0x7ffff
        if imm19 & 0x40000: imm19 -= 0x80000
        cond = val & 0xf
        conds = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
        target = addr + imm19 * 4
        return f"B.{conds[cond]} 0x{target & 0xffffffff:x}"

    # CBZ/CBNZ 32-bit
    if (val & 0x7e000000) == 0x34000000:
        is_nz = (val >> 24) & 1
        imm19 = (val >> 5) & 0x7ffff
        if imm19 & 0x40000: imm19 -= 0x80000
        rt = val & 0x1f
        sf = (val >> 31) & 1
        target = addr + imm19 * 4
        reg = f"X{rt}" if sf else f"W{rt}"
        op = "CBNZ" if is_nz else "CBZ"
        return f"{op} {reg}, 0x{target & 0xffffffff:x}"

    # TBZ/TBNZ
    if (val & 0x7e000000) == 0x36000000:
        is_nz = (val >> 24) & 1
        b5 = (val >> 31) & 1
        b40 = (val >> 19) & 0x1f
        bit = (b5 << 5) | b40
        imm14 = (val >> 5) & 0x3fff
        if imm14 & 0x2000: imm14 -= 0x4000
        rt = val & 0x1f
        target = addr + imm14 * 4
        op = "TBNZ" if is_nz else "TBZ"
        reg = f"X{rt}" if b5 else f"W{rt}"
        return f"{op} {reg}, #{bit}, 0x{target & 0xffffffff:x}"

    # LDR X (unsigned offset)
    if (val & 0xffc00000) == 0xf9400000:
        rt = val & 0x1f
        rn = (val >> 5) & 0x1f
        imm12 = (val >> 10) & 0xfff
        return f"LDR X{rt}, [X{rn}, #{imm12*8}]"

    # STR X (unsigned offset)
    if (val & 0xffc00000) == 0xf9000000:
        rt = val & 0x1f
        rn = (val >> 5) & 0x1f
        imm12 = (val >> 10) & 0xfff
        return f"STR X{rt}, [X{rn}, #{imm12*8}]"

    # LDR W (unsigned offset)
    if (val & 0xffc00000) == 0xb9400000:
        rt = val & 0x1f
        rn = (val >> 5) & 0x1f
        imm12 = (val >> 10) & 0xfff
        return f"LDR W{rt}, [X{rn}, #{imm12*4}]"

    # STR W (unsigned offset)
    if (val & 0xffc00000) == 0xb9000000:
        rt = val & 0x1f
        rn = (val >> 5) & 0x1f
        imm12 = (val >> 10) & 0xfff
        return f"STR W{rt}, [X{rn}, #{imm12*4}]"

    # LDRH (unsigned offset)
    if (val & 0xffc00000) == 0x79400000:
        rt = val & 0x1f
        rn = (val >> 5) & 0x1f
        imm12 = (val >> 10) & 0xfff
        return f"LDRH W{rt}, [X{rn}, #{imm12*2}]"

    # LDRB (unsigned offset)
    if (val & 0xffc00000) == 0x39400000:
        rt = val & 0x1f
        rn = (val >> 5) & 0x1f
        imm12 = (val >> 10) & 0xfff
        return f"LDRB W{rt}, [X{rn}, #{imm12}]"

    # STRB (unsigned offset)
    if (val & 0xffc00000) == 0x39000000:
        rt = val & 0x1f
        rn = (val >> 5) & 0x1f
        imm12 = (val >> 10) & 0xfff
        return f"STRB W{rt}, [X{rn}, #{imm12}]"

    # LDRSB (unsigned offset)
    if (val & 0xffc00000) == 0x39800000:
        rt = val & 0x1f
        rn = (val >> 5) & 0x1f
        imm12 = (val >> 10) & 0xfff
        return f"LDRSB W{rt}, [X{rn}, #{imm12}]"

    # CMP (immediate) W
    if (val & 0xff00001f) == 0x7100001f:
        rn = (val >> 5) & 0x1f
        imm12 = (val >> 10) & 0xfff
        return f"CMP W{rn}, #{imm12}"

    # CMP (immediate) X
    if (val & 0xff00001f) == 0xf100001f:
        rn = (val >> 5) & 0x1f
        imm12 = (val >> 10) & 0xfff
        return f"CMP X{rn}, #{imm12}"

    # ADD X (immediate)
    if (val & 0xff000000) == 0x91000000:
        rd = val & 0x1f
        rn = (val >> 5) & 0x1f
        imm12 = (val >> 10) & 0xfff
        sh = (val >> 22) & 1
        if sh:
            return f"ADD X{rd}, X{rn}, #{imm12}, LSL #12  (=#{imm12 << 12})"
        return f"ADD X{rd}, X{rn}, #{imm12}"

    # ADD W (immediate)
    if (val & 0xff000000) == 0x11000000:
        rd = val & 0x1f
        rn = (val >> 5) & 0x1f
        imm12 = (val >> 10) & 0xfff
        return f"ADD W{rd}, W{rn}, #{imm12}"

    # SUB X (immediate)
    if (val & 0xff000000) == 0xd1000000:
        rd = val & 0x1f
        rn = (val >> 5) & 0x1f
        imm12 = (val >> 10) & 0xfff
        return f"SUB X{rd}, X{rn}, #{imm12}"

    # ADRP
    if (val & 0x9f000000) == 0x90000000:
        rd = val & 0x1f
        immhi = (val >> 5) & 0x7ffff
        immlo = (val >> 29) & 3
        imm = (immhi << 2) | immlo
        if imm & 0x100000: imm -= 0x200000
        return f"ADRP X{rd}, #0x{imm << 12 & 0xffffffff:x}"

    # ORR (immediate) W -> also encoding for MOVZ bitmask
    if (val & 0xff800000) == 0x32000000:
        rd = val & 0x1f
        rn = (val >> 5) & 0x1f
        # Decode bitmask immediate
        N = (val >> 22) & 1
        immr = (val >> 16) & 0x3f
        imms = (val >> 10) & 0x3f
        return f"ORR W{rd}, W{rn}, #bitmask(N={N},r={immr},s={imms})"

    # AND (immediate) W
    if (val & 0xff800000) == 0x12000000:
        rd = val & 0x1f
        rn = (val >> 5) & 0x1f
        N = (val >> 22) & 1
        immr = (val >> 16) & 0x3f
        imms = (val >> 10) & 0x3f
        return f"AND W{rd}, W{rn}, #bitmask(N={N},r={immr},s={imms})"

    # CSEL
    if (val & 0xffe00c00) == 0x1a800000:
        rd = val & 0x1f
        rn = (val >> 5) & 0x1f
        rm = (val >> 16) & 0x1f
        cond = (val >> 12) & 0xf
        conds = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
        return f"CSEL W{rd}, W{rn}, W{rm}, {conds[cond]}"

    # CSET (CSINC Xd, XZR, XZR, invcond)
    if (val & 0xffe0fc00) == 0x1a9f0000:
        rd = val & 0x1f
        rn = (val >> 5) & 0x1f
        cond = (val >> 12) & 0xf
        conds = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
        if rn == 31:
            # CSET: invert condition
            inv_cond = cond ^ 1
            return f"CSET W{rd}, {conds[inv_cond]}"
        return f"CSINC W{rd}, W{rn}, WZR, {conds[cond]}"

    # STR X pre-index
    if (val & 0xffe00c00) == 0xf8000c00:
        rt = val & 0x1f
        rn = (val >> 5) & 0x1f
        imm9 = (val >> 12) & 0x1ff
        if imm9 & 0x100: imm9 -= 0x200
        return f"STR X{rt}, [X{rn}, #{imm9}]!"

    # STUR
    if (val & 0xffe00c00) == 0xf8000000:
        rt = val & 0x1f
        rn = (val >> 5) & 0x1f
        imm9 = (val >> 12) & 0x1ff
        if imm9 & 0x100: imm9 -= 0x200
        return f"STUR X{rt}, [X{rn}, #{imm9}]"

    # UBFM/UBFX/LSR/LSL
    if (val & 0xff800000) == 0x53000000:
        rd = val & 0x1f
        rn = (val >> 5) & 0x1f
        imms = (val >> 10) & 0x3f
        immr = (val >> 16) & 0x3f
        return f"UBFM W{rd}, W{rn}, #{immr}, #{imms}"

    # STP X pre-index with writeback
    if (val & 0xffc00000) == 0xa9800000:
        rt1 = val & 0x1f
        rn = (val >> 5) & 0x1f
        rt2 = (val >> 10) & 0x1f
        imm7 = (val >> 15) & 0x7f
        imm7s = sext(imm7, 7)
        return f"STP X{rt1}, X{rt2}, [X{rn}, #{imm7s*8}]!"

    # LDRSB extended reg offset
    if (val & 0xffe00c00) == 0x38e00800 or (val & 0xffe00c00) == 0x38a00800:
        rt = val & 0x1f
        rn = (val >> 5) & 0x1f
        rm = (val >> 16) & 0x1f
        return f"LDRB_ext W{rt}, [X{rn}, X/W{rm}...]"

    # LDRB reg offset (38600800)
    if (val & 0xffe00c00) == 0x38600800:
        rt = val & 0x1f
        rn = (val >> 5) & 0x1f
        rm = (val >> 16) & 0x1f
        return f"LDRB W{rt}, [X{rn}, X{rm}]"

    return f"??? (0x{val:08x})"

# Known QCA driver constants
QDF_MODES = {0: "STA", 1: "SAP", 2: "P2P_CLIENT", 3: "P2P_GO", 4: "FTM",
             5: "IBSS", 6: "MONITOR", 7: "P2P_DEVICE", 8: "OCB",
             9: "EPPING", 10: "QVIT", 11: "NDI", 12: "MAX_NO_OF_MODE"}

print("=" * 80)
print("wlan_hdd_mgmt_tx @ ffffff9ef984bd98 - Full Disassembly")
print("=" * 80)

for off in sorted(insns.keys()):
    val = insns[off]
    dec = decode_insn(off, val)

    # Annotate known patterns
    annotation = ""
    if off == 0x000:
        annotation = "  ; PROLOGUE"
    elif off == 0x034:
        annotation = "  ; BL hdd_get_conparam() - check FTM mode"
    elif off == 0x078:
        annotation = "  ; BL wlan_hdd_validate_context()"
    elif off == 0x07c:
        annotation = "  ; check retval == 5?"
    elif off == 0x080:
        annotation = "  ; if != 5 goto 0x0ac"
    elif off == 0x0a0:
        annotation = "  ; BL wlan_hdd_validate_context() again?"
    elif off == 0x0a4:
        annotation = "  ; *** EINVAL return #1 ***"
    elif off == 0x0a8:
        annotation = "  ; jump to epilogue (return -EINVAL)"
    elif off == 0x0bc:
        annotation = "  ; BL func (validate session?)"
    elif off == 0x0c0:
        annotation = "  ; *** EINVAL preload #2 ***"
    elif off == 0x0c4:
        annotation = "  ; if retval != 0, jump to 0x1f0 (skip to epilogue)"
    elif off == 0x0d8:
        annotation = "  ; BL func (another validation)"
    elif off == 0x0dc:
        annotation = "  ; CBZ W0 -> skip (if 0, continue)"
    elif off == 0x10c:
        annotation = "  ; B 0x1f0 (jump to epilogue!)"
    elif off == 0x11c:
        annotation = "  ; CMP W1, #1 (device_mode?)"
    elif off == 0x120:
        annotation = "  ; B.HI 0x16c - if mode > 1"
    elif off == 0x130:
        annotation = "  ; CMP W0, #0xB0 (#176?)"
    elif off == 0x134:
        annotation = "  ; B.NE 0x170"
    elif off == 0x15c:
        annotation = "  ; BL actual TX func! (sme/offchan?)"
    elif off == 0x160:
        annotation = "  ; check TX retval"
    elif off == 0x164:
        annotation = "  ; CSEL W25 = (retval==0) ? W25 : W25"
    elif off == 0x168:
        annotation = "  ; B 0x1f0 (jump to epilogue)"
    elif off == 0x1c0:
        annotation = "  ; BL actual TX dispatch call"
    elif off == 0x1f0:
        annotation = "  ; EPILOGUE START"
    elif off == 0x1f8:
        annotation = "  ; BL hdd_exit() / cleanup"
    elif off == 0x21c:
        annotation = "  ; RET - END OF FUNCTION"

    # Highlight -EINVAL
    if "EINVAL" in dec:
        annotation = "  ; *** RETURNS -EINVAL ***"

    print(f"  +0x{off:03x}: {val:08x}  {dec}{annotation}")

print()
print("=" * 80)
print("ANALYSIS")
print("=" * 80)
print("""
Function structure:
  0x000-0x01c: Prologue (save registers, set up frame)
  0x020-0x034: Load string arg, BL hdd_get_conparam() - check con_mode
  0x038-0x07c: Setup, load fields, BL validate functions
  0x07c-0x080: CMP W0, #5 / B.NE 0x0ac -- CHECK: if conparam == 5 (FTM MODE!)
               If conparam != 5 (our case: con_mode=4 MONITOR), skip to 0x0ac
               If conparam == 5 (FTM), fall through to another wlan_hdd_validate
               then -EINVAL at 0x0a4
  0x0a4-0x0a8: MOVN W25, #0x15 (-EINVAL) + B to epilogue (FTM mode rejection)
  0x0ac-0x0c4: More validation, BL wlan_hdd_validate_session_id()
               CBNZ at 0x0c4: if session invalid, jump to 0x1f0 (return -EINVAL preloaded)
  0x0dc: CBZ W0 - if validate returns 0, continue
  0x0e0-0x10c: More setup, then B 0x1f0 (another early return path)
  0x110-0x134: Load adapter->device_mode, check mode
               0x11c: CMP W1, #1 (check if mode <= 1, i.e. STA=0 or SAP=1?)
               0x120: B.HI 0x16c (if mode > 1, skip to alternate path)
               0x124-0x134: frame subtype check, CMP W0, #0xB0, B.NE 0x170

  0x138-0x168: STA/SAP TX path - calls sme_send_action or equivalent
               0x148: BL (log?)
               0x15c: BL actual_tx_function
               0x164: CSEL W25 based on result
               0x168: B 0x1f0 (done)

  0x16c-0x198: Mode dispatch for P2P/GO etc
               0x16c: CMP W0, #0  -- check retval? or check mode further
               0x170: CSET W24
               0x174: CMP W0, #0
               0x178: CSET W25
               0x17c: CMP W0, #0

  0x198-0x1c0: More setup, BL alternate TX function (wlansap_send_action?)

  0x1c0: BL <TX function> - this is the actual TX dispatch call

  0x1f0-0x21c: Epilogue (restore regs, return)

KEY FINDING:
  The function at +0x07c checks: CMP W0, #5 (compare con_mode with 5=FTM)
  If con_mode != 5 (our case: 4=MONITOR), it goes to 0x0ac which continues.
  So the FTM check is NOT blocking us (con_mode=4 passes this check).

  The real issue is likely in the device_mode dispatch at +0x11c:
  CMP W1, #1 → B.HI 0x16c (if device_mode > 1)
  For MONITOR mode (device_mode = probably 6 or similar), we go to 0x16c
  Then there may be no valid TX path for monitor mode.

  Need to check what happens at 0x16c for device_mode > 1.
""")

# Let's specifically analyze the mode dispatch
print("MODE DISPATCH ANALYSIS:")
print("-" * 40)
mode_check_insns = [(off, insns[off]) for off in sorted(insns.keys()) if 0x110 <= off <= 0x1c8]
for off, val in mode_check_insns:
    dec = decode_insn(off, val)
    print(f"  +0x{off:03x}: {val:08x}  {dec}")
