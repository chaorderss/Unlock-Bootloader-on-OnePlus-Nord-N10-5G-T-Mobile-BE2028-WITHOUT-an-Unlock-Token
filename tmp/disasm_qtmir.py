#!/usr/bin/env python3
"""Disassemble ApplicationManager::onSessionStarting and related functions"""
import struct

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def disasm_one(data, addr, insn):
    # RET
    if insn == 0xd65f03c0:
        return "RET"
    # RETAA/RETAB
    if insn == 0xd65f0bff:
        return "RETAA"
    # NOP
    if insn == 0xd503201f:
        return "NOP"
    # PACIASP
    if insn == 0xd503233f:
        return "PACIASP"
    # AUTIASP
    if insn == 0xd50323bf:
        return "AUTIASP"
    # BL imm
    if (insn >> 26) == 0x25:
        imm26 = insn & 0x3ffffff
        if imm26 & 0x2000000: imm26 -= 0x4000000
        return f"BL 0x{addr + imm26*4:x}"
    # B imm
    if (insn >> 26) == 0x05:
        imm26 = insn & 0x3ffffff
        if imm26 & 0x2000000: imm26 -= 0x4000000
        return f"B 0x{addr + imm26*4:x}"
    # B.cond
    if (insn & 0xff000010) == 0x54000000:
        cond = insn & 0xf
        imm19 = (insn >> 5) & 0x7ffff
        if imm19 & 0x40000: imm19 -= 0x80000
        conds = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
        return f"B.{conds[cond]} 0x{addr + imm19*4:x}"
    # CBZ/CBNZ
    if (insn & 0x7e000000) == 0x34000000:
        sf = (insn >> 31) & 1
        op = (insn >> 24) & 1
        imm19 = (insn >> 5) & 0x7ffff
        if imm19 & 0x40000: imm19 -= 0x80000
        rt = insn & 0x1f
        reg = f"{'X' if sf else 'W'}{rt}"
        return f"{'CBNZ' if op else 'CBZ'} {reg}, 0x{addr + imm19*4:x}"
    # TBZ/TBNZ
    if (insn & 0x7e000000) == 0x36000000:
        op = (insn >> 24) & 1
        b5 = (insn >> 31) & 1
        b40 = (insn >> 19) & 0x1f
        bit = (b5 << 5) | b40
        imm14 = (insn >> 5) & 0x3fff
        if imm14 & 0x2000: imm14 -= 0x4000
        rt = insn & 0x1f
        return f"{'TBNZ' if op else 'TBZ'} X{rt}, #{bit}, 0x{addr + imm14*4:x}"
    # ADRP
    if (insn & 0x9f000000) == 0x90000000:
        rd = insn & 0x1f
        immhi = (insn >> 5) & 0x7ffff
        immlo = (insn >> 29) & 0x3
        imm = (immhi << 2) | immlo
        if imm & 0x100000: imm -= 0x200000
        page = (addr & ~0xfff) + (imm << 12)
        return f"ADRP X{rd}, 0x{page:x}"
    # ADR
    if (insn & 0x9f000000) == 0x10000000:
        rd = insn & 0x1f
        immhi = (insn >> 5) & 0x7ffff
        immlo = (insn >> 29) & 0x3
        imm = (immhi << 2) | immlo
        if imm & 0x100000: imm -= 0x200000
        return f"ADR X{rd}, 0x{addr + imm:x}"
    # ADD imm
    if (insn & 0x7f800000) == 0x11000000:
        sf = (insn >> 31) & 1
        sh = (insn >> 22) & 1
        imm12 = (insn >> 10) & 0xfff
        rn = (insn >> 5) & 0x1f
        rd = insn & 0x1f
        if sh: imm12 <<= 12
        rp = "X" if sf else "W"
        return f"ADD {rp}{rd}, {rp}{rn}, #0x{imm12:x}"
    # SUB imm
    if (insn & 0x7f800000) == 0x51000000:
        sf = (insn >> 31) & 1
        sh = (insn >> 22) & 1
        imm12 = (insn >> 10) & 0xfff
        rn = (insn >> 5) & 0x1f
        rd = insn & 0x1f
        if sh: imm12 <<= 12
        rp = "X" if sf else "W"
        return f"SUB {rp}{rd}, {rp}{rn}, #0x{imm12:x}"
    # MOV reg (ORR Rd, XZR, Rm)
    if (insn & 0x7fe0ffe0) == 0x2a0003e0:
        sf = (insn >> 31) & 1
        rm = (insn >> 16) & 0x1f
        rd = insn & 0x1f
        rp = "X" if sf else "W"
        return f"MOV {rp}{rd}, {rp}{rm}"
    # MOVZ
    if (insn & 0x7f800000) == 0x52800000:
        sf = (insn >> 31) & 1
        hw = (insn >> 21) & 3
        imm16 = (insn >> 5) & 0xffff
        rd = insn & 0x1f
        rp = "X" if sf else "W"
        val = imm16 << (hw * 16)
        return f"MOV {rp}{rd}, #{val} (MOVZ #0x{imm16:x} LSL#{hw*16})"
    # MOVN
    if (insn & 0x7f800000) == 0x12800000:
        sf = (insn >> 31) & 1
        hw = (insn >> 21) & 3
        imm16 = (insn >> 5) & 0xffff
        rd = insn & 0x1f
        rp = "X" if sf else "W"
        return f"MOVN {rp}{rd}, #0x{imm16:x} LSL#{hw*16}"
    # MOVK
    if (insn & 0x7f800000) == 0x72800000:
        sf = (insn >> 31) & 1
        hw = (insn >> 21) & 3
        imm16 = (insn >> 5) & 0xffff
        rd = insn & 0x1f
        rp = "X" if sf else "W"
        return f"MOVK {rp}{rd}, #0x{imm16:x} LSL#{hw*16}"
    # LDR/STR unsigned offset
    if (insn & 0x3b200c00) == 0x39000000:
        size = (insn >> 30) & 3
        opc = (insn >> 22) & 3
        imm12 = (insn >> 10) & 0xfff
        rn = (insn >> 5) & 0x1f
        rt = insn & 0x1f
        offset = imm12 << size
        mnems = {(0,0):"STRB",(0,1):"LDRB",(1,0):"STRH",(1,1):"LDRH",
                 (2,0):"STR",(2,1):"LDR",(3,0):"STR",(3,1):"LDR"}
        mnem = mnems.get((size,opc), f"MEM{size}_{opc}")
        rp = "W" if size <= 2 else "X"
        if size == 0: rp = "W"
        if opc >= 2: rp = "W" if size == 0 else ("W" if size == 1 else "")
        if size == 3 and opc <= 1: rp = "X"
        return f"{mnem} {rp}{rt}, [X{rn}, #0x{offset:x}]"
    # LDR (register)
    if (insn & 0x3b200c00) == 0x38200800:
        size = (insn >> 30) & 3
        opc = (insn >> 22) & 3
        rm = (insn >> 16) & 0x1f
        rn = (insn >> 5) & 0x1f
        rt = insn & 0x1f
        mnem = "LDR" if opc == 1 else "STR"
        rp = "X" if size == 3 else "W"
        return f"{mnem} {rp}{rt}, [X{rn}, X{rm}]"
    # STP/LDP signed offset
    if (insn & 0x3e000000) == 0x28000000:
        opc = (insn >> 30) & 3
        p = (insn >> 24) & 1
        w = (insn >> 23) & 1
        l = (insn >> 22) & 1
        imm7 = (insn >> 15) & 0x7f
        if imm7 & 0x40: imm7 -= 0x80
        rt2 = (insn >> 10) & 0x1f
        rn = (insn >> 5) & 0x1f
        rt = insn & 0x1f
        scale = 2 + (opc >> 1)
        off_val = imm7 << scale
        rp = "X" if opc >= 2 else "W"
        mnem = "LDP" if l else "STP"
        wb = "!" if w and not p else ""
        pre = ", " if p else ""
        return f"{mnem} {rp}{rt}, {rp}{rt2}, [X{rn}, #{off_val}]{wb}"
    # LDR literal (PC-relative)
    if (insn & 0xbf000000) == 0x18000000:
        sf = (insn >> 30) & 1
        imm19 = (insn >> 5) & 0x7ffff
        if imm19 & 0x40000: imm19 -= 0x80000
        rt = insn & 0x1f
        rp = "X" if sf else "W"
        return f"LDR {rp}{rt}, [PC+0x{imm19*4:x}] (=0x{addr+imm19*4:x})"
    # BLR
    if (insn & 0xfffffc1f) == 0xd63f0000:
        rn = (insn >> 5) & 0x1f
        return f"BLR X{rn}"
    # BR
    if (insn & 0xfffffc1f) == 0xd61f0000:
        rn = (insn >> 5) & 0x1f
        return f"BR X{rn}"
    # CMP (SUBS XZR)
    if (insn & 0x7f20001f) == 0x6b00001f:
        sf = (insn >> 31) & 1
        rm = (insn >> 16) & 0x1f
        rn = (insn >> 5) & 0x1f
        rp = "X" if sf else "W"
        return f"CMP {rp}{rn}, {rp}{rm}"
    # CMP imm (SUBS XZR, Xn, #imm)
    if (insn & 0x7f80001f) == 0x7100001f:
        sf = (insn >> 31) & 1
        imm12 = (insn >> 10) & 0xfff
        rn = (insn >> 5) & 0x1f
        rp = "X" if sf else "W"
        return f"CMP {rp}{rn}, #0x{imm12:x}"

    return f"??? 0x{insn:08x}"

def disasm_range(data, start, end):
    results = []
    off = start
    while off < end and off + 4 <= len(data):
        insn = read_u32(data, off)
        asm = disasm_one(data, off, insn)
        results.append((off, insn, asm))
        off += 4
    return results

with open('/Users/xmxx/pinganhuijia/tmp/qtmir_orig.so', 'rb') as f:
    data = f.read()

# Function addresses from ELF symbols
funcs = {
    'ApplicationManager::onSessionStarting': (0x04fcc4, 1040),
    'ApplicationManager::authorizeSession': (0x04ea00, 4804),
    'TaskController::onSessionStarting': (0x087ff0, 840),
    'Session::setApplication': (0x0738e4, 52),
    'ApplicationManager::onProcessStarting': (0x052a20, 1124),
    'ApplicationManager::startApplication': (0x0531f0, 2728),
}

# Find strings referenced by the functions (for annotation)
def find_string_at(data, off):
    """Try to read a C string at offset"""
    end = data.find(b'\0', off)
    if end > off and end - off < 200:
        try:
            return data[off:end].decode('ascii')
        except:
            pass
    return None

def resolve_adrp_add(data, adrp_addr, adrp_insn, add_insn):
    """Resolve ADRP+ADD to get the target address"""
    rd = adrp_insn & 0x1f
    immhi = (adrp_insn >> 5) & 0x7ffff
    immlo = (adrp_insn >> 29) & 0x3
    imm = (immhi << 2) | immlo
    if imm & 0x100000: imm -= 0x200000
    page = (adrp_addr & ~0xfff) + (imm << 12)

    if (add_insn & 0x7f800000) == 0x11000000:
        imm12 = (add_insn >> 10) & 0xfff
        sh = (add_insn >> 22) & 1
        if sh: imm12 <<= 12
        return page + imm12
    return page

# Disassemble each function
for name, (addr, size) in funcs.items():
    # Only the first 3 functions
    if name not in ['ApplicationManager::onSessionStarting', 'TaskController::onSessionStarting', 'Session::setApplication']:
        continue

    print(f"\n{'='*80}")
    print(f"=== {name} @ 0x{addr:06x} (size={size}) ===")
    print(f"{'='*80}")

    instrs = disasm_range(data, addr, addr + size)
    for i, (off, raw, asm) in enumerate(instrs):
        # Annotate ADRP+ADD pairs with string references
        annotation = ""
        if asm.startswith("ADRP") and i + 1 < len(instrs):
            next_off, next_raw, next_asm = instrs[i+1]
            if next_asm.startswith("ADD"):
                target = resolve_adrp_add(data, off, raw, next_raw)
                if target and target < len(data):
                    s = find_string_at(data, target)
                    if s:
                        annotation = f'  // -> "{s[:60]}"'
        if asm.startswith("BL 0x"):
            # Try to identify the call target
            target = int(asm.split("0x")[1], 16)
            for fn, (fa, fs) in funcs.items():
                if target == fa:
                    annotation = f"  // {fn}"
                    break

        print(f"  0x{off:06x}: {raw:08x}  {asm}{annotation}")
