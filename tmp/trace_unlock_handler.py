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

def disasm_range(start, end):
    for off in range(start, end, 4):
        instr = struct.unpack_from('<I', data, off)[0]
        desc = f'0x{instr:08X}'

        if (instr & 0xFC000000) == 0x94000000:
            desc = f'BL 0x{decode_bl(instr, off):X}'
        elif (instr & 0xFC000000) == 0x14000000:
            t = decode_bl(instr, off)
            desc = f'B 0x{t:X}'
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
        elif (instr & 0x9F000000) == 0x90000000:
            page = decode_adrp(instr, off)
            rd = instr & 0x1F
            desc = f'ADRP X{rd}, 0x{page:X}'
        elif (instr & 0xFF800000) == 0x91000000:
            imm12 = (instr >> 10) & 0xFFF
            desc = f'ADD X{instr&0x1F}, X{(instr>>5)&0x1F}, #0x{imm12:X}'
        elif instr == 0xD65F03C0:
            desc = 'RET'
        elif instr == 0x2A1F03E0:
            desc = 'MOV W0, WZR'
        elif instr == 0x320003E0:
            desc = 'MOV W0, #1'
        elif instr == 0xD503201F:
            desc = 'NOP'

        print(f'  0x{off:X}: {desc}')

# Unlock handler: IsAllowUnlock check → fallback → carrier check → security level → boottype
print('=== Unlock handler 0x48810 - 0x48960 ===')
disasm_range(0x48810, 0x48960)

# Check string at 0x6214A (pointed to by 0x383F4)
s_addr = 0x6214A
end = data.index(b'\x00', s_addr)
print(f'\nString @ 0x6214A: {data[s_addr:end]}')

# Check string at 0x560000 + 0x4EB (from 0x38408)
# 0x56000 + 0x4EB = 0x564EB
s_addr2 = 0x564EB
end2 = data.index(b'\x00', s_addr2)
print(f'String @ 0x564EB: {data[s_addr2:end2]}')

# Disasm function that writes [0x1BF518] - find its start
# Code at 0x383A0-0x38414; find function entry
print('\n=== Looking for function start before 0x383A0 ===')
# Search backwards for function prologue (STP X29, X30, [SP, -N]!)
for off in range(0x38300, 0x383A4, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    # STP with pre-decrement: A9Bxxxxx
    if (instr & 0xFFC00000) == 0xA9800000 and (instr & 0x200000):
        imm7 = (instr >> 15) & 0x7F
        if imm7 & 0x40: imm7 -= 0x80
        rt1 = (instr >> 10) & 0x1F
        rt2 = instr & 0x1F
        rn = (instr >> 5) & 0x1F
        if rn == 31:  # SP
            print(f'  Prologue STP at 0x{off:X}: regs {rt1},{rt2}, offset={imm7*8}')

print('\n=== Disasm 0x38320 - 0x38420 (write to [0x1BF518]) ===')
disasm_range(0x38320, 0x38420)
