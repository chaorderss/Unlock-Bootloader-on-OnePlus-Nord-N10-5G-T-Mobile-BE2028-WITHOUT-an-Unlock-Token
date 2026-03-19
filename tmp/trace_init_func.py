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

def disasm(start, end):
    for off in range(start, end, 4):
        instr = struct.unpack_from('<I', data, off)[0]
        desc = f'raw 0x{instr:08X}'

        if (instr & 0xFC000000) == 0x94000000:
            desc = f'BL 0x{decode_bl(instr, off):X}'
        elif (instr & 0xFC000000) == 0x14000000:
            target = decode_bl(instr, off)
            desc = f'B 0x{target:X}'
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
            desc = f'{op} X{reg}, #{bit}, 0x{off + imm14*4:X}'
        elif (instr & 0x9F000000) == 0x90000000:
            desc = f'ADRP X{instr&0x1F}, 0x{decode_adrp(instr, off):X}'
        elif (instr & 0xFF800000) == 0x91000000:
            imm12 = (instr >> 10) & 0xFFF
            rd = instr & 0x1F
            rn = (instr >> 5) & 0x1F
            sh = (instr >> 22) & 1
            if sh: imm12 <<= 12
            desc = f'ADD X{rd}, X{rn}, #0x{imm12:X}'
        elif (instr & 0xFF800000) == 0x11000000:
            imm12 = (instr >> 10) & 0xFFF
            rd = instr & 0x1F
            rn = (instr >> 5) & 0x1F
            desc = f'ADD W{rd}, W{rn}, #0x{imm12:X}'
        elif instr == 0xD65F03C0:
            desc = 'RET'
        elif instr == 0x2A1F03E0:
            desc = 'MOV W0, WZR'
        elif instr == 0x320003E0:
            desc = 'MOV W0, #1'
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
        elif (instr & 0xFFC00000) == 0xF9400000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            rt = instr & 0x1F
            desc = f'LDR X{rt}, [X{rn}, #0x{imm12*8:X}]'
        elif (instr & 0xFFC00000) == 0xB9400000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            rt = instr & 0x1F
            desc = f'LDR W{rt}, [X{rn}, #0x{imm12*4:X}]'
        elif (instr & 0xFFC00000) == 0xF9000000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            rt = instr & 0x1F
            desc = f'STR X{rt}, [X{rn}, #0x{imm12*8:X}]'
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
        elif (instr & 0xFFC00000) == 0x72000000:
            N = (instr >> 22) & 1
            immr = (instr >> 16) & 0x3F
            imms = (instr >> 10) & 0x3F
            rn = (instr >> 5) & 0x1F
            desc = f'TST W{rn}, #bitmask(N={N},immr={immr},imms={imms})'
        elif (instr & 0x7F000000) == 0x71000000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            desc = f'CMP W{rn}, #0x{imm12:X}'
        elif (instr & 0x7F000000) == 0xF1000000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            desc = f'CMP X{rn}, #0x{imm12:X}'
        elif (instr & 0xFFE0FC00) == 0xAA0003E0:
            rm = (instr >> 16) & 0x1F
            rd = instr & 0x1F
            desc = f'MOV X{rd}, X{rm}'
        elif (instr & 0xFF000000) == 0xA9000000:
            desc = f'STP 0x{instr:08X}'
        elif (instr & 0xFF000000) == 0xA8000000:
            desc = f'LDP 0x{instr:08X}'
        elif (instr & 0xFFC003E0) == 0xD50003E0:
            desc = f'MSR/SYS 0x{instr:08X}'
        elif (instr & 0xFFC003E0) == 0xEB000000:
            desc = f'SUBS X 0x{instr:08X}'
        elif (instr & 0xFFC003FF) == 0xEB00001F:
            rm = (instr >> 16) & 0x1F
            rn = (instr >> 5) & 0x1F
            desc = f'CMP X{rn}, X{rm}'
        elif (instr & 0xFFC003FF) == 0x6B00001F:
            rm = (instr >> 16) & 0x1F
            rn = (instr >> 5) & 0x1F
            desc = f'CMP W{rn}, W{rm}'
        elif (instr & 0xFF800000) == 0xD1000000:
            imm12 = (instr >> 10) & 0xFFF
            rd = instr & 0x1F
            rn = (instr >> 5) & 0x1F
            desc = f'SUB X{rd}, X{rn}, #0x{imm12:X}'

        print(f'  0x{off:05X}: {desc}')

# Dump the entire function area from 0x37D00 to 0x38420
print('=== FULL function area 0x37D00 - 0x38420 ===')
disasm(0x37D00, 0x38420)

# Also find callers of functions in 0x37D00-0x38420
print('\n=== BL targets into 0x37D00-0x38420 ===')
for off in range(0, len(data)-4, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr & 0xFC000000) == 0x94000000:
        target = decode_bl(instr, off)
        if 0x37D00 <= target <= 0x38420:
            print(f'  0x{off:05X}: BL 0x{target:X}')
