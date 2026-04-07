import struct

with open('qtmir_app.so', 'rb') as f:
    data = f.read()

# Find all STRB instructions referencing X20 (the authorized pointer)
print("=== STRB to [X20] in authorizeSession (0x4ea00 - 0x4f200) ===")
for off in range(0x4ea00, 0x4f200, 4):
    insn = struct.unpack_from('<I', data, off)[0]
    if (insn & 0xFFC003E0) == 0x39000280:  # STRB ?, [X20, #?]
        rt = insn & 0x1F
        imm = (insn >> 10) & 0xFFF
        if imm == 0:
            val = "WZR (=0, FALSE)" if rt == 31 else f"W{rt}"
            result = 'false' if rt == 31 else 'unknown'
            print(f"  0x{off:05x}: STRB {val}, [X20, #0]   ; authorized = {result}")

print()
print("=== Code at 0x4ef80-0x4f100 (branch targets) ===")

def decode(data, off):
    insn = struct.unpack_from('<I', data, off)[0]
    desc = f"0x{insn:08x}"

    if insn == 0xd65f03c0:
        return desc + " RET"
    if insn == 0xd50323bf:
        return desc + " AUTIASP"
    if insn == 0xd503233f:
        return desc + " PACIASP"

    # BL
    if (insn >> 26) == 0x25:
        ov = insn & 0x3FFFFFF
        if ov & 0x2000000: ov -= 0x4000000
        return desc + f" BL 0x{(off + ov * 4) & 0xFFFFFFFF:x}"

    # B
    if (insn >> 26) == 0x05:
        ov = insn & 0x3FFFFFF
        if ov & 0x2000000: ov -= 0x4000000
        return desc + f" B 0x{(off + ov * 4) & 0xFFFFFFFF:x}"

    # B.cond
    if (insn & 0xFF000010) == 0x54000000:
        cond = insn & 0xF
        ov = (insn >> 5) & 0x7FFFF
        if ov & 0x40000: ov -= 0x80000
        conds = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
        return desc + f" B.{conds[cond]} 0x{(off + ov * 4) & 0xFFFFFFFF:x}"

    # CBZ/CBNZ
    if (insn & 0x7E000000) == 0x34000000:
        op = (insn >> 24) & 1
        sf = (insn >> 31) & 1
        ov = (insn >> 5) & 0x7FFFF
        if ov & 0x40000: ov -= 0x80000
        rt = insn & 0x1F
        w = 'X' if sf else 'W'
        return desc + f" {'CBNZ' if op else 'CBZ'} {w}{rt}, 0x{(off + ov * 4) & 0xFFFFFFFF:x}"

    # TBZ/TBNZ
    if (insn & 0x7E000000) == 0x36000000:
        op = (insn >> 24) & 1
        bit = ((insn >> 31) << 5) | ((insn >> 19) & 0x1F)
        ov = (insn >> 5) & 0x3FFF
        if ov & 0x2000: ov -= 0x4000
        rt = insn & 0x1F
        return desc + f" {'TBNZ' if op else 'TBZ'} X{rt}, #{bit}, 0x{(off + ov * 4) & 0xFFFFFFFF:x}"

    # STRB
    if (insn & 0xFFC00000) == 0x39000000:
        imm = (insn >> 10) & 0xFFF
        rn = (insn >> 5) & 0x1F
        rt = insn & 0x1F
        val = "WZR" if rt == 31 else f"W{rt}"
        return desc + f" STRB {val}, [X{rn}, #{imm}]"

    # MOV wide
    if (insn & 0x7F800000) == 0x52800000:
        sf = (insn >> 31) & 1
        imm16 = (insn >> 5) & 0xFFFF
        rd = insn & 0x1F
        w = 'X' if sf else 'W'
        return desc + f" MOV {w}{rd}, #{imm16}"

    # ADRP
    if (insn & 0x9F000000) == 0x90000000:
        rd = insn & 0x1F
        immlo = (insn >> 29) & 3
        immhi = (insn >> 5) & 0x7FFFF
        imm = ((immhi << 2) | immlo) << 12
        if imm & 0x100000000: imm -= 0x200000000
        page = (off & ~0xFFF) + imm
        return desc + f" ADRP X{rd}, 0x{page & 0xFFFFFFFF:x}"

    # ADD imm
    if (insn & 0x7F800000) == 0x11000000:
        sf = (insn >> 31) & 1
        rd = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm12 = (insn >> 10) & 0xFFF
        sh = (insn >> 22) & 1
        if sh: imm12 <<= 12
        w = 'X' if sf else 'W'
        return desc + f" ADD {w}{rd}, {w}{rn}, #{imm12}"

    # LDP
    if (insn & 0x7FC00000) == 0xa9400000 or (insn & 0x7FC00000) == 0xa9c00000:
        return desc + " LDP"

    # STP
    if (insn & 0x7FC00000) == 0xa9000000 or (insn & 0x7FC00000) == 0xa9800000:
        return desc + " STP"

    return desc

for off in range(0x4ef80, 0x4f100, 4):
    print(f"  0x{off:05x}: {decode(data, off)}")
