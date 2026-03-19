import struct

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb').read()

def decode_bl(instr, pc):
    imm26 = instr & 0x03FFFFFF
    if imm26 & 0x02000000:
        imm26 -= 0x04000000
    return pc + imm26 * 4

def decode_adrp(instr, pc):
    immhi = (instr >> 5) & 0x7FFFF
    immlo = (instr >> 29) & 0x3
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    return (pc & ~0xFFF) + (imm << 12)

def disasm(start, end, label=""):
    if label:
        print(f'\n=== {label} ===')
    for off in range(start, end, 4):
        instr = struct.unpack_from('<I', data, off)[0]
        desc = f'raw 0x{instr:08X}'

        if (instr & 0xFC000000) == 0x94000000:
            desc = f'BL 0x{decode_bl(instr, off):X}'
        elif (instr & 0xFC000000) == 0x14000000:
            desc = f'B 0x{decode_bl(instr, off):X}'
        elif (instr & 0xFF000010) == 0x54000000:
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 & 0x40000: imm19 -= 0x80000
            cond = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV'][instr & 0xF]
            desc = f'B.{cond} 0x{off + imm19*4:X}'
        elif (instr & 0x7E000000) == 0x34000000:
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 & 0x40000: imm19 -= 0x80000
            op = 'CBNZ' if (instr >> 24) & 1 else 'CBZ'
            reg = instr & 0x1F
            size = 'W' if (instr >> 31) == 0 else 'X'
            desc = f'{op} {size}{reg} -> 0x{off + imm19*4:X}'
        elif (instr & 0x7E000000) == 0x36000000:
            imm14 = (instr >> 5) & 0x3FFF
            if imm14 & 0x2000: imm14 -= 0x4000
            op = 'TBNZ' if (instr >> 24) & 1 else 'TBZ'
            bit = ((instr >> 31) << 5) | ((instr >> 19) & 0x1F)
            reg = instr & 0x1F
            desc = f'{op} X{reg}, #{bit} -> 0x{off + imm14*4:X}'
        elif (instr & 0x9F000000) == 0x90000000:
            desc = f'ADRP X{instr&0x1F}, 0x{decode_adrp(instr, off):X}'
        elif (instr & 0xFF800000) == 0x91000000:
            imm12 = (instr >> 10) & 0xFFF
            rd = instr & 0x1F
            rn = (instr >> 5) & 0x1F
            sh = (instr >> 22) & 1
            if sh: imm12 <<= 12
            desc = f'ADD X{rd}, X{rn}, #0x{imm12:X}'
        elif instr == 0xD65F03C0:
            desc = 'RET'
        elif (instr & 0xFFE00000) == 0xAA000000:
            rm = (instr >> 16) & 0x1F
            rn = (instr >> 5) & 0x1F
            rd = instr & 0x1F
            if rn == 31: desc = f'MOV X{rd}, X{rm}'
            else: desc = f'ORR X{rd}, X{rn}, X{rm}'
        elif (instr & 0xFFE00000) == 0x2A000000:
            rm = (instr >> 16) & 0x1F
            rn = (instr >> 5) & 0x1F
            rd = instr & 0x1F
            if rn == 31: desc = f'MOV W{rd}, W{rm}'
            else: desc = f'ORR W{rd}, W{rn}, W{rm}'
        elif (instr & 0xFFC00000) == 0xF9400000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            rt = instr & 0x1F
            desc = f'LDR X{rt}, [X{rn}, #0x{imm12*8:X}]'
        elif (instr & 0xFFC00000) == 0xF9000000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            rt = instr & 0x1F
            desc = f'STR X{rt}, [X{rn}, #0x{imm12*8:X}]'
        elif (instr & 0xFFC00000) == 0xB9400000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            rt = instr & 0x1F
            desc = f'LDR W{rt}, [X{rn}, #0x{imm12*4:X}]'
        elif (instr & 0xFFC00000) == 0xB9000000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            rt = instr & 0x1F
            desc = f'STR W{rt}, [X{rn}, #0x{imm12*4:X}]'
        elif (instr & 0xFF800000) == 0x52800000:
            hw = (instr >> 21) & 0x3
            imm16 = (instr >> 5) & 0xFFFF
            rd = instr & 0x1F
            desc = f'MOV W{rd}, #0x{imm16 << (hw*16):X}'
        elif (instr & 0xFF800000) == 0xD2800000:
            hw = (instr >> 21) & 0x3
            imm16 = (instr >> 5) & 0xFFFF
            rd = instr & 0x1F
            desc = f'MOV X{rd}, #0x{imm16 << (hw*16):X}'
        elif (instr & 0xFF800000) == 0xD1000000:
            imm12 = (instr >> 10) & 0xFFF
            rd = instr & 0x1F
            rn = (instr >> 5) & 0x1F
            desc = f'SUB X{rd}, X{rn}, #0x{imm12:X}'
        elif (instr & 0xFFC00000) == 0x39400000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            rt = instr & 0x1F
            desc = f'LDRB W{rt}, [X{rn}, #0x{imm12:X}]'
        elif (instr & 0xFFC00000) == 0x39000000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            rt = instr & 0x1F
            desc = f'STRB W{rt}, [X{rn}, #0x{imm12:X}]'
        elif (instr & 0xFFC00000) == 0x79400000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            rt = instr & 0x1F
            desc = f'LDRH W{rt}, [X{rn}, #0x{imm12*2:X}]'
        elif (instr & 0xFFE0FC00) == 0xD63F0000:
            rn = (instr >> 5) & 0x1F
            desc = f'BLR X{rn}'
        elif (instr & 0xFF200C00) == 0xF8200800:
            desc = f'STR pre/post 0x{instr:08X}'
        elif (instr & 0x7F000000) == 0x71000000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            desc = f'CMP W{rn}, #0x{imm12:X}'
        elif (instr & 0xFF000000) == 0x6B000000:
            rm = (instr >> 16) & 0x1F
            rn = (instr >> 5) & 0x1F
            desc = f'CMP/SUBS W{rn}, W{rm}'
        elif (instr & 0xFF000000) == 0xEB000000:
            rm = (instr >> 16) & 0x1F
            rn = (instr >> 5) & 0x1F
            desc = f'CMP/SUBS X{rn}, X{rm}'
        elif (instr & 0x7F000000) == 0x72000000:
            desc = f'TST/ANDS 0x{instr:08X}'
        elif (instr & 0xFFE0001F) == 0xD4000001:
            desc = f'SVC 0x{instr:08X}'

        print(f'  0x{off:05X}: {desc}')

# 1. Disassemble the full init function 0x37D38 from entry to especially
# the area around the string compare and what happens on each branch

# First, let's see what happens between 0x37F84 and 0x37FC0 (when string DOESN'T match)
disasm(0x37F70, 0x37FC4, "String compare and both branches (0x37F70-0x37FC0)")

# 2. Also let's see what's at 0x37F48-0x37F70 — what leads up to the string compare?
disasm(0x37F40, 0x37F78, "Before string compare (0x37F40-0x37F78)")

# 3. Check what's at 0x37F88 — the early return target
disasm(0x37F84, 0x37FA0, "After no-match fallthrough (0x37F84-0x37FA0)")

# 4. Check the "vzw_unlock" string address
print('\n=== UTF-16 strings near carrier unlock modes ===')
for name, addr in [('oproot', 0x61854), ('cust-unlock', 0x61862), ('vzw_unlock', 0x6187A)]:
    chars = []
    p = addr
    while p < addr + 40:
        ch = struct.unpack_from('<H', data, p)[0]
        if ch == 0: break
        chars.append(chr(ch))
        p += 2
    print(f'  0x{addr:X}: "{"".join(chars)}"')

# 5. Is there a "vzw_unlock" comparison somewhere in 0x37D38?
# Search for ADRP + ADD that points to 0x6187A
print('\n=== Searching for refs to "vzw_unlock" (0x6187A) in init function ===')
for off in range(0x37D38, 0x38400, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr & 0x9F000000) == 0x90000000:  # ADRP
        page = decode_adrp(instr, off)
        if page == 0x61000:
            # Check next instruction for ADD
            if off + 4 < len(data):
                next_instr = struct.unpack_from('<I', data, off+4)[0]
                if (next_instr & 0xFF800000) == 0x91000000:
                    imm12 = (next_instr >> 10) & 0xFFF
                    target = page + imm12
                    if target in [0x61854, 0x61862, 0x6187A, 0x61890]:
                        rn = (next_instr >> 5) & 0x1F
                        rd = next_instr & 0x1F
                        print(f'  0x{off:X}: ADRP + ADD -> 0x{target:X}')

# 6. Disassemble entry of init function to see all string comparisons
disasm(0x37D38, 0x37E40, "Init function entry (0x37D38-0x37E40)")

# 7. Full disassembly from 0x37E40 to first string compare
disasm(0x37E40, 0x37F80, "Init function middle (0x37E40-0x37F80)")

# 8. What is the function at 0x4DBC8? It's called right before both 0x36CA8 and 0x37D38
print('\n=== Function 0x4DBC8 (called at 0x49CE0) ===')
disasm(0x4DBC8, 0x4DC20, "0x4DBC8")

# 9. Look at what 0x36CA8 does with X0 (X0=buffer, X1=something, X2=something)
# The key: does 0x36CA8 WRITE to the buffer (X0)?
disasm(0x36CA8, 0x36E00, "Function 0x36CA8 (full)")
