#!/usr/bin/env python3
"""
Targeted analysis:
1. Show code around "Device unlocked" string (0x67de7)
2. Show full context around the magic-validation block at 0xf548
3. Find all references to the "Device unlocked" string in code
"""
import struct

DECOMP = '/Users/xmxx/pinganhuijia/global_abl_decompressed.bin'
PE_OFFSET = 0xB8
TEXT_VA = 0x1000
TEXT_RAW = 0x1000
TEXT_SIZE = 0x69000

def va_to_file(va):
    if TEXT_VA <= va < TEXT_VA + TEXT_SIZE:
        return PE_OFFSET + TEXT_RAW + (va - TEXT_VA)
    return None

def file_to_va(off):
    raw = off - PE_OFFSET
    if TEXT_RAW <= raw < TEXT_RAW + TEXT_SIZE:
        return TEXT_VA + (raw - TEXT_RAW)
    return None

def read32le(data, off):
    return struct.unpack_from('<I', data, off)[0]

def decode_insn(data, foff):
    insn = read32le(data, foff)
    va   = file_to_va(foff) or foff
    pc   = va if file_to_va(foff) else foff

    desc = f"0x{insn:08x}"

    # ADRP
    if (insn & 0x9F000000) == 0x90000000:
        rd = insn & 0x1F
        immlo = (insn >> 29) & 0x3
        immhi = (insn >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20): imm -= (1 << 21)
        page = (pc & ~0xFFF) + (imm << 12)
        desc = f"ADRP X{rd}, {page:#x}"
    # ADD immediate
    elif (insn & 0xFF800000) == 0x91000000:
        rd = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm12 = (insn >> 10) & 0xFFF
        sh = (insn >> 22) & 1
        if sh: imm12 <<= 12
        desc = f"ADD  X{rd}, X{rn}, #{imm12:#x}"
    # LDRB Wt, [Xn, #imm12]  (unsigned byte load)
    elif (insn & 0xFFC00000) == 0x39400000:
        rt = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm12 = (insn >> 10) & 0xFFF
        desc = f"LDRB W{rt}, [X{rn}, #{imm12:#x}]"
    # STRB
    elif (insn & 0xFFC00000) == 0x39000000:
        rt = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm12 = (insn >> 10) & 0xFFF
        desc = f"STRB W{rt}, [X{rn}, #{imm12:#x}]"
    # LDR Wt, [Xn, #imm] (32-bit)
    elif (insn & 0xFFC00000) == 0xB9400000:
        rt = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm = ((insn >> 10) & 0xFFF) * 4
        desc = f"LDR  W{rt}, [X{rn}, #{imm:#x}]"
    # LDR Xt (64-bit)
    elif (insn & 0xFFC00000) == 0xF9400000:
        rt = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm = ((insn >> 10) & 0xFFF) * 8
        desc = f"LDR  X{rt}, [X{rn}, #{imm:#x}]"
    # RET
    elif insn == 0xD65F03C0:
        desc = "RET"
    # NOP
    elif insn == 0xD503201F:
        desc = "NOP"
    # BL
    elif (insn & 0xFC000000) == 0x94000000:
        imm26 = insn & 0x3FFFFFF
        if imm26 & (1<<25): imm26 -= (1<<26)
        target = pc + imm26*4
        desc = f"BL   {target:#x}"
    # B
    elif (insn & 0xFC000000) == 0x14000000:
        imm26 = insn & 0x3FFFFFF
        if imm26 & (1<<25): imm26 -= (1<<26)
        target = pc + imm26*4
        desc = f"B    {target:#x}"
    # B.cond
    elif (insn & 0xFF000010) == 0x54000000:
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1<<18): imm19 -= (1<<19)
        cond = insn & 0xF
        names = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
        target = pc + imm19*4
        desc = f"B.{names[cond]:<2}  {target:#x}"
    # CBZ/CBNZ
    elif (insn & 0x7E000000) == 0x34000000:
        op = (insn >> 24) & 1
        sf = (insn >> 31) & 1
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1<<18): imm19 -= (1<<19)
        rt = insn & 0x1F
        dest = pc + imm19*4
        reg = 'X' if sf else 'W'
        desc = f"{'CBNZ' if op else 'CBZ '} {reg}{rt}, {dest:#x}"
    # TBZ/TBNZ
    elif (insn & 0x7E000000) == 0x36000000:
        op = (insn >> 24) & 1
        bit = ((insn >> 31) << 5) | ((insn >> 19) & 0x1F)
        imm14 = (insn >> 5) & 0x3FFF
        if imm14 & (1<<13): imm14 -= (1<<14)
        rt = insn & 0x1F
        dest = pc + imm14*4
        desc = f"{'TBNZ' if op else 'TBZ '} W{rt}, #{bit}, {dest:#x}"
    # CMP (SUBS Wzr, Wn, #imm)
    elif (insn & 0xFFC0001F) == 0x7100001F:
        rn = (insn >> 5) & 0x1F
        imm12 = (insn >> 10) & 0xFFF
        sh = (insn >> 22) & 1
        if sh: imm12 <<= 12
        desc = f"CMP  W{rn}, #{imm12:#x}"
    # MOV Wn, #imm
    elif (insn & 0x7F800000) == 0x52800000:
        rd = insn & 0x1F
        imm16 = (insn >> 5) & 0xFFFF
        desc = f"MOV  W{rd}, #{imm16:#x}"
    # TST (ANDS Wzr, Wn, #imm)
    elif (insn & 0xFFC0001F) == 0x7200001F:
        rn = (insn >> 5) & 0x1F
        # imm12 decodes are complex, skip
        desc = f"TST  W{rn}, ..."
    # STP/LDP simplified
    elif (insn >> 30) == 0b10 and ((insn >> 27) & 0b111) == 0b101:
        op = (insn >> 22) & 0x7
        if op in (1, 3, 5):
            desc = f"LDP  ..."
        else:
            desc = f"STP  ..."
    # MOV (register)
    elif (insn & 0xFFE0FFE0) == 0xAA0003E0:
        rd = insn & 0x1F
        rm = (insn >> 16) & 0x1F
        desc = f"MOV  X{rd}, X{rm}"
    elif (insn & 0xFFE0FFE0) == 0x2A0003E0:
        rd = insn & 0x1F
        rm = (insn >> 16) & 0x1F
        desc = f"MOV  W{rd}, W{rm}"

    return insn, va, desc

def dump_code(data, foff, count=40, mark_foff=None):
    """Dump count instructions starting from foff"""
    for i in range(count):
        off = foff + i*4
        if off + 4 > len(data): break
        insn, va, desc = decode_insn(data, off)
        marker = " >>>" if off == mark_foff else "    "
        vastr = f"VA {va:#010x}" if file_to_va(off) else f"raw {off:#010x}"
        print(f"  {marker} {off:#010x} ({vastr}): {insn:08x}  {desc}")

def find_code_refs_to_string_va(data, str_va, window=40):
    """Find ADRP+ADD sequences that load near str_va (within ±4096)"""
    str_page = str_va & ~0xFFF
    str_off  = str_va & 0xFFF
    refs = []
    for i in range(0, TEXT_SIZE - 4, 4):
        foff = PE_OFFSET + TEXT_RAW + i
        insn = read32le(data, foff)
        va   = TEXT_VA + i
        if (insn & 0x9F000000) != 0x90000000:
            continue
        rd = insn & 0x1F
        immlo = (insn >> 29) & 0x3
        immhi = (insn >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20): imm -= (1 << 21)
        page = (va & ~0xFFF) + (imm << 12)
        if page != str_page:
            continue
        # Check if next instruction is ADD with matching offset
        if foff + 4 < len(data):
            insn2 = read32le(data, foff + 4)
            if (insn2 & 0xFF800000) == 0x91000000:
                rd2 = insn2 & 0x1F
                rn2 = (insn2 >> 5) & 0x1F
                imm12 = (insn2 >> 10) & 0xFFF
                if rd2 == rn2 == rd and imm12 == str_off:
                    refs.append(foff)
    return refs

with open(DECOMP, 'rb') as f:
    data = bytearray(f.read())

print("="*60)
print("1. Code references to 'Device unlocked' string at 0x67de7")
print("="*60)
str_va = 0x67de7
refs = find_code_refs_to_string_va(data, str_va)
if not refs:
    # Try nearby
    for off in range(0x67d00, 0x67e00, 0x10):
        sub_refs = find_code_refs_to_string_va(data, off)
        if sub_refs:
            refs.extend([(r, off) for r in sub_refs])
    print(f"  No direct refs to {str_va:#x}, searching broadly...")
    # Search for string in data
    s = b'Device unlocked'
    p = 0
    while True:
        idx = data.find(s, p)
        if idx < 0: break
        va = idx  # approximation, raw file offset as VA (data section)
        print(f"  String at file offset {idx:#x}")
        code_refs = find_code_refs_to_string_va(data, idx)
        print(f"    Code refs: {[hex(r) for r in code_refs]}")
        for r in code_refs:
            print(f"\n  Context for ref at {r:#x}:")
            dump_code(data, r - 20*4, 60, r)
        p = idx + 1
else:
    for r in refs:
        print(f"\n  Code ref at file {r:#x}:")
        dump_code(data, r - 20*4, 60, r)

print("\n" + "="*60)
print("2. Full context around magic validation at file 0xf528 (80 insns before)")
print("="*60)
dump_code(data, 0xf528 - 80*4, 130, 0xf548)

print("\n" + "="*60)
print("3. What is at branch target 0xf8f8 (from B.NE at 0xf530+)?")
print("="*60)
# 0xf8f8 is a VA, convert to file
foff_f8f8 = va_to_file(0xf8f8) or (PE_OFFSET + TEXT_RAW + (0xf8f8 - TEXT_VA))
print(f"  File offset for VA 0xf8f8: {foff_f8f8:#x}")
dump_code(data, foff_f8f8, 30)
