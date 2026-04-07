#!/usr/bin/env python3
"""Decode AArch64 instructions from cfg80211_mlme_mgmt_tx dump"""

# Collected from kfind module dumps
insns = {
    # First dump (0x000 - 0x07c)
    0x000: 0xf81b0ff9, 0x004: 0xa9015ff8, 0x008: 0xa90257f6, 0x00c: 0xa9034ff4,
    0x010: 0xa9047bfd, 0x014: 0x910103fd, 0x018: 0xf9400028, 0x01c: 0xf9400d08,
    0x020: 0xb40001e8, 0x024: 0xf9400009, 0x028: 0xaa0003f6, 0x02c: 0xf940f929,
    0x030: 0xb4000169, 0x034: 0xf9400c49, 0x038: 0xaa0203f4, 0x03c: 0xf100653f,
    0x040: 0x540000a3, 0x044: 0xf9400a99, 0x048: 0x79400329, 0x04c: 0x721e053f,
    0x050: 0x54000160, 0x054: 0x128002b7, 0x058: 0x14000002, 0x05c: 0x12800bd7,
    0x060: 0x2a1703e0, 0x064: 0xa9447bfd, 0x068: 0xa9434ff4, 0x06c: 0xa94257f6,
    0x070: 0xa9415ff8, 0x074: 0xf84507f9, 0x078: 0xd65f03c0, 0x07c: 0xb940082a,

    # Second dump (0x080 - 0x17c)
    0x080: 0x320003eb, 0x084: 0xaa0103f5, 0x088: 0xd37ef54a, 0x08c: 0x786a6908,
    0x090: 0xd3441d2a, 0x094: 0x9aca216a, 0x098: 0xea08015f, 0x09c: 0x54fffdc0,
    0x0a0: 0x121e1528, 0x0a4: 0xaa0303f3, 0x0a8: 0x7103411f, 0x0ac: 0x54000081,
    0x0b0: 0x39406328, 0x0b4: 0x7100111f, 0x0b8: 0x540000a1, 0x0bc: 0xf94012a8,
    0x0c0: 0xb40008e8, 0x0c4: 0xf9417508, 0x0c8: 0x14000046, 0x0cc: 0x910122b8,
    0x0d0: 0xaa1803e0, 0x0d4: 0x94012225, 0x0d8: 0xb9400aa8, 0x0dc: 0x12800bd7,
    0x0e0: 0x7100251f, 0x0e4: 0x540005e8, 0x0e8: 0x320003e9, 0x0ec: 0x1ac82129,
    0x0f0: 0x528020ca, 0x0f4: 0x6a0a013f, 0x0f8: 0x54000101, 0x0fc: 0x5280430a,
    0x100: 0x6a0a013f, 0x104: 0x54000240, 0x108: 0xf94012a8, 0x10c: 0xb4000368,
    0x110: 0xf9417508, 0x114: 0x1400001a, 0x118: 0xf9407aaa, 0x11c: 0xb400014a,
    0x120: 0xb940b949, 0x124: 0x7941794a, 0x128: 0x79402b2c, 0x12c: 0xb940132b,
    0x130: 0x4a0a018c, 0x134: 0x4a09016b, 0x138: 0x12003d8c, 0x13c: 0x2a0c016b,
    0x140: 0x3400036b, 0x144: 0x12800d57, 0x148: 0x14000016, 0x14c: 0x71001d1f,
    0x150: 0x54000281, 0x154: 0xb840a328, 0x158: 0xb9401329, 0x15c: 0x79401f2a,
    0x160: 0x79402b2b, 0x164: 0x4a080128, 0x168: 0x4a0a0169, 0x16c: 0x2a090108,
    0x170: 0x35000168, 0x174: 0x14000016, 0x178: 0x9101aaa8, 0x17c: 0xb9401329,

    # Third dump (0x180 - 0x27c)
    0x180: 0xb940010a, 0x184: 0x79402b2b, 0x188: 0x79400908, 0x18c: 0x4a090149,
    0x190: 0x4a0b0108, 0x194: 0x2a080128, 0x198: 0x340001a8, 0x19c: 0x128002b7,
    0x1a0: 0xaa1803e0, 0x1a4: 0x94012205, 0x1a8: 0x17ffffae, 0x1ac: 0x7100051f,
    0x1b0: 0x540000e0, 0x1b4: 0xb9400728, 0x1b8: 0x7940132b, 0x1bc: 0x4a090108,
    0x1c0: 0x4a0a0169, 0x1c4: 0x2a090108, 0x1c8: 0x35fffbe8, 0x1cc: 0xaa1803e0,
    0x1d0: 0x940121fa, 0x1d4: 0xf94012a8, 0x1d8: 0xb5fff768, 0x1dc: 0x9101aaa8,
    0x1e0: 0xb840a329, 0x1e4: 0xb940010a, 0x1e8: 0x79401f2b, 0x1ec: 0x79400908,
    0x1f0: 0x4a090149, 0x1f4: 0x4a0b0108, 0x1f8: 0x2a080128, 0x1fc: 0x340001c8,
    0x200: 0x79400328, 0x204: 0x121e1508, 0x208: 0x7103411f, 0x20c: 0x54fff241,
    0x210: 0x39406328, 0x214: 0x7100111f, 0x218: 0x54fff1e1, 0x21c: 0xf9407aa9,
    0x220: 0x394d06c8, 0x224: 0xb4000069, 0x228: 0x361ff168, 0x22c: 0x14000002,
    0x230: 0x3617f128, 0x234: 0xb0008208, 0x238: 0xb9418908, 0x23c: 0x910c02d8,
    0x240: 0x7100051f, 0x244: 0x5400048b, 0x248: 0xb00057e9, 0x24c: 0xd538d088,
    0x250: 0x91006129, 0x254: 0xb8696908, 0x258: 0xd00070ca, 0x25c: 0x912b014a,
    0x260: 0x1100fd09, 0x264: 0x7100011f, 0x268: 0x1a88b129, 0x26c: 0x13067d29,
    0x270: 0xf869d949, 0x274: 0x320003ea, 0x278: 0x9ac82148, 0x27c: 0xea09011f,

    # Fourth dump (0x280 - 0x37c)
    0x280: 0x540002a0, 0x284: 0xd5384117, 0x288: 0xb9404ae8, 0x28c: 0x11000508,
    0x290: 0xb9004ae8, 0x294: 0xb0008208, 0x298: 0xf940d119, 0x29c: 0xb4000119,
    0x2a0: 0xa9400328, 0x2a4: 0xaa1803e1, 0x2a8: 0xaa1503e2, 0x2ac: 0xaa1403e3,
    0x2b0: 0xd63f0100, 0x2b4: 0xf8418f28, 0x2b8: 0xb5ffff48, 0x2bc: 0xb9404ae8,
    0x2c0: 0x71000508, 0x2c4: 0xb9004ae8, 0x2c8: 0x54000061, 0x2cc: 0xf94002e8,
    0x2d0: 0x37080668, 0x2d4: 0xf94002c8, 0x2d8: 0xaa1803e0, 0x2dc: 0xaa1503e1,
    0x2e0: 0xaa1403e2, 0x2e4: 0xf940f908, 0x2e8: 0xaa1303e3, 0x2ec: 0xd63f0100,
    0x2f0: 0xb0008208, 0x2f4: 0xf9400273, 0x2f8: 0xb9413908, 0x2fc: 0x2a0003f7,
    0x300: 0x7100051f, 0x304: 0x54ffeaeb, 0x308: 0xb00057e9, 0x30c: 0xd538d088,
    0x310: 0x91006129, 0x314: 0xb8696908, 0x318: 0xd00070ca, 0x31c: 0x912b014a,
    0x320: 0x1100fd09, 0x324: 0x7100011f, 0x328: 0x1a88b129, 0x32c: 0x13067d29,
    0x330: 0xf869d949, 0x334: 0x320003ea, 0x338: 0x9ac82148, 0x33c: 0xea09011f,
    0x340: 0x54ffe900, 0x344: 0xd5384114, 0x348: 0xb9404a88, 0x34c: 0x11000508,
    0x350: 0xb9004a88, 0x354: 0xb0008208, 0x358: 0xf940a915, 0x35c: 0xb4000115,
    0x360: 0xa94002a8, 0x364: 0xaa1803e1, 0x368: 0x2a1703e2, 0x36c: 0xaa1303e3,
    0x370: 0xd63f0100, 0x374: 0xf8418ea8, 0x378: 0xb5ffff48, 0x37c: 0xb9404a88,
}

def decode_insn(addr, val):
    """Basic AArch64 instruction decoder"""
    op = val >> 24

    # STP/LDP
    if (val & 0xffc00000) == 0xa9000000:
        return f"STP (pre-index)"
    if (val & 0xffc00000) == 0xa9400000:
        return f"LDP (signed offset)"
    if (val & 0xffc00000) == 0xa8c00000:
        return f"LDP (post-index)"

    # STR pre-index
    if (val >> 21) == 0x7c0 | (val >> 21 & 0x7ff):
        pass

    # MOV/MOVN/MOVZ/MOVK
    if (val & 0xff800000) == 0x52800000:
        rd = val & 0x1f
        imm16 = (val >> 5) & 0xffff
        hw = (val >> 21) & 3
        return f"MOVZ W{rd}, #0x{imm16:x}" + (f", LSL #{hw*16}" if hw else "")
    if (val & 0xff800000) == 0x12800000:
        rd = val & 0x1f
        imm16 = (val >> 5) & 0xffff
        return f"MOVN W{rd}, #0x{imm16:x}  (= {-1 ^ (imm16 << 0) & 0xffffffff:#x} = {-(imm16+1)})"

    # B unconditional
    if (val >> 26) == 0x05:
        imm26 = val & 0x3ffffff
        if imm26 & 0x2000000: imm26 -= 0x4000000
        target = addr + imm26 * 4
        return f"B +0x{target:x}"

    # BL
    if (val >> 26) == 0x25:
        imm26 = val & 0x3ffffff
        if imm26 & 0x2000000: imm26 -= 0x4000000
        target = addr + imm26 * 4
        return f"BL +0x{target:x}"

    # B.cond
    if (val & 0xff000010) == 0x54000000:
        imm19 = (val >> 5) & 0x7ffff
        if imm19 & 0x40000: imm19 -= 0x80000
        cond = val & 0xf
        conds = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
        target = addr + imm19 * 4
        return f"B.{conds[cond]} +0x{target:x}"

    # CBZ/CBNZ
    if (val & 0xfe000000) == 0x34000000:
        is_nz = (val >> 24) & 1
        imm19 = (val >> 5) & 0x7ffff
        if imm19 & 0x40000: imm19 -= 0x80000
        rt = val & 0x1f
        sf = (val >> 31) & 1
        target = addr + imm19 * 4
        reg = f"X{rt}" if sf else f"W{rt}"
        op = "CBNZ" if is_nz else "CBZ"
        return f"{op} {reg}, +0x{target:x}"

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
        return f"{op} W{rt}, #{bit}, +0x{target:x}"

    # LDR (immediate, unsigned offset) 64-bit
    if (val & 0xffc00000) == 0xf9400000:
        rt = val & 0x1f
        rn = (val >> 5) & 0x1f
        imm12 = (val >> 10) & 0xfff
        return f"LDR X{rt}, [X{rn}, #{imm12*8}]"

    # LDR (immediate, unsigned offset) 32-bit
    if (val & 0xffc00000) == 0xb9400000:
        rt = val & 0x1f
        rn = (val >> 5) & 0x1f
        imm12 = (val >> 10) & 0xfff
        return f"LDR W{rt}, [X{rn}, #{imm12*4}]"

    # LDRH (immediate, unsigned offset)
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

    # STR (immediate, unsigned offset) 32-bit
    if (val & 0xffc00000) == 0xb9000000:
        rt = val & 0x1f
        rn = (val >> 5) & 0x1f
        imm12 = (val >> 10) & 0xfff
        return f"STR W{rt}, [X{rn}, #{imm12*4}]"

    # CMP (immediate) = SUBS alias
    if (val & 0xff000000) == 0x71000000:
        rn = (val >> 5) & 0x1f
        imm12 = (val >> 10) & 0xfff
        rd = val & 0x1f
        if rd == 31:
            return f"CMP W{rn}, #{imm12}"
    if (val & 0xff000000) == 0xf1000000:
        rn = (val >> 5) & 0x1f
        imm12 = (val >> 10) & 0xfff
        rd = val & 0x1f
        if rd == 31:
            return f"CMP X{rn}, #{imm12}"

    # TST (immediate) = ANDS with WZR
    if (val & 0xff800000) == 0x72000000:
        rd = val & 0x1f
        if rd == 31:
            rn = (val >> 5) & 0x1f
            return f"TST W{rn}, #imm"
    if (val & 0xff800000) == 0x6a000000:
        rd = val & 0x1f
        if rd == 31:
            rn = (val >> 5) & 0x1f
            rm = (val >> 16) & 0x1f
            return f"TST W{rn}, W{rm}"

    # AND (immediate)
    if (val & 0xff800000) == 0x12000000:
        rd = val & 0x1f
        rn = (val >> 5) & 0x1f
        return f"AND W{rd}, W{rn}, #imm"
    if (val & 0xff800000) == 0x32000000:
        rd = val & 0x1f
        rn = (val >> 5) & 0x1f
        return f"ORR W{rd}, W{rn}, #imm"

    # EOR (register)
    if (val & 0xff200000) == 0x4a000000:
        rd = val & 0x1f
        rn = (val >> 5) & 0x1f
        rm = (val >> 16) & 0x1f
        return f"EOR W{rd}, W{rn}, W{rm}"

    # ORR (register) = MOV alias
    if (val & 0xff200000) == 0x2a000000:
        rd = val & 0x1f
        rn = (val >> 5) & 0x1f
        rm = (val >> 16) & 0x1f
        if rn == 31:
            return f"MOV W{rd}, W{rm}"
        return f"ORR W{rd}, W{rn}, W{rm}"
    if (val & 0xff200000) == 0xaa000000:
        rd = val & 0x1f
        rn = (val >> 5) & 0x1f
        rm = (val >> 16) & 0x1f
        if rn == 31:
            return f"MOV X{rd}, X{rm}"
        return f"ORR X{rd}, X{rn}, X{rm}"

    # ADD (immediate)
    if (val & 0xff000000) == 0x91000000:
        rd = val & 0x1f
        rn = (val >> 5) & 0x1f
        imm12 = (val >> 10) & 0xfff
        sh = (val >> 22) & 1
        if sh:
            return f"ADD X{rd}, X{rn}, #{imm12}, LSL #12"
        return f"ADD X{rd}, X{rn}, #{imm12}"
    if (val & 0xff000000) == 0x11000000:
        rd = val & 0x1f
        rn = (val >> 5) & 0x1f
        imm12 = (val >> 10) & 0xfff
        return f"ADD W{rd}, W{rn}, #{imm12}"

    # BLR
    if (val & 0xfffffc1f) == 0xd63f0000:
        rn = (val >> 5) & 0x1f
        return f"BLR X{rn}"

    # RET
    if val == 0xd65f03c0:
        return "RET"

    # LSR/LSL/UBFM/SBFM
    if (val & 0xff800000) == 0xd3400000:
        return "UBFM (LSR/LSL/UBFX)"
    if (val & 0xff800000) == 0x13000000:
        return "SBFM (ASR/SBFX)"

    # MRS
    if (val >> 20) == 0xd53:
        return "MRS"

    # LDAR/LDXR/LDR register
    if (val & 0xffe00c00) == 0xb8600800:
        rt = val & 0x1f
        rn = (val >> 5) & 0x1f
        rm = (val >> 16) & 0x1f
        return f"LDR W{rt}, [X{rn}, X{rm}]"
    if (val & 0xffe00c00) == 0xf8600800:
        rt = val & 0x1f
        rn = (val >> 5) & 0x1f
        rm = (val >> 16) & 0x1f
        return f"LDR X{rt}, [X{rn}, X{rm}]"

    # ADRP
    if (val & 0x9f000000) == 0x90000000:
        return "ADRP"

    # LDR post-index
    if (val & 0xffe00400) == 0xf8400400:
        rt = val & 0x1f
        rn = (val >> 5) & 0x1f
        imm9 = (val >> 12) & 0x1ff
        if imm9 & 0x100: imm9 -= 0x200
        return f"LDR X{rt}, [X{rn}], #{imm9}"

    # LDR pre-index / LDUR
    if (val & 0xffe00c00) == 0xb8400000:
        rt = val & 0x1f
        rn = (val >> 5) & 0x1f
        return "LDUR/LDR_pre W"

    # LDRH register
    if (val & 0xffe00c00) == 0x78600800:
        rt = val & 0x1f
        rn = (val >> 5) & 0x1f
        rm = (val >> 16) & 0x1f
        return f"LDRH W{rt}, [X{rn}, X{rm}]"

    # CSEL/CSINC
    if (val & 0xff200c00) == 0x1a800000:
        rd = val & 0x1f
        rn = (val >> 5) & 0x1f
        rm = (val >> 16) & 0x1f
        cond = (val >> 12) & 0xf
        conds = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
        return f"CSEL W{rd}, W{rn}, W{rm}, {conds[cond]}"

    # STR pre-index
    if (val & 0xffe00c00) == 0xf8000c00:
        rt = val & 0x1f
        rn = (val >> 5) & 0x1f
        imm9 = (val >> 12) & 0x1ff
        if imm9 & 0x100: imm9 -= 0x200
        return f"STR X{rt}, [X{rn}, #{imm9}]!"

    # LSRV/LSLV - variable shift
    if (val & 0xffe0fc00) == 0x1ac02000:
        rd = val & 0x1f
        rn = (val >> 5) & 0x1f
        rm = (val >> 16) & 0x1f
        return f"LSLV W{rd}, W{rn}, W{rm}"
    if (val & 0xffe0fc00) == 0x9ac02000:
        rd = val & 0x1f
        rn = (val >> 5) & 0x1f
        rm = (val >> 16) & 0x1f
        return f"LSLV X{rd}, X{rn}, X{rm}"

    return "???"

# We're looking for the SA check:
# ether_addr_equal(mgmt->sa, wdev_address(wdev)) - inlined as loads + XOR + OR
# SA = mgmt + 10 bytes (after FC:2 + Duration:2 + DA:6)
# wdev_address returns wdev->netdev->dev_addr (or netdev->dev_addr)
#
# Key: if mismatch → check if it's action/public → if not → return -EINVAL
# In binary: loads from two addresses (6 bytes each), XOR pairs, OR results → CBNZ to -EINVAL

print("cfg80211_mlme_mgmt_tx disassembly:")
print("=" * 70)
for off in sorted(insns.keys()):
    val = insns[off]
    dec = decode_insn(off, val)
    # Mark EINVAL returns
    marker = ""
    if val == 0x128002b7:
        marker = " *** MOVN W23, #0x15 = -EINVAL ***"
    elif val == 0x12800bd7:
        marker = " *** MOVN W23, #0x5e = -EOPNOTSUPP ***"
    elif val == 0x12800d57:
        marker = " *** MOVN W23, #0x6a = -107 ***"
    print(f"  +0x{off:03x}: {val:08x}  {dec}{marker}")
