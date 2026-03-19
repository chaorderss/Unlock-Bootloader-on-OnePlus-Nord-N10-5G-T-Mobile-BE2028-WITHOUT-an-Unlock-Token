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

# Disasm 0x4FD10 - the token check function
print('=== Function 0x4FD10 (token check) ===')
disasm_range(0x4FD10, 0x4FF00)

# Check some strings referenced from this area
print('\n=== Strings near 0x62000 area used in unlock init ===')
for addr in [0x6212A, 0x6214A]:
    end = data.index(b'\x00', addr)
    print(f'  0x{addr:X}: {data[addr:end]}')

# What calls the token init function around 0x383A0?
# Find the function containing 0x383A0 by looking for its prologue
print('\n=== Finding function entry for init code at ~0x38300 ===')
for off in range(0x37C00, 0x383B0, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    # STP X29,X30,[SP,#-N]! prologue
    if (instr & 0xFFE07C1F) == 0xA9800FBF and ((instr >> 5) & 0x1F) == 31:
        print(f'  Prologue at 0x{off:X}: 0x{instr:08X}')

# Disasm 0x48708 - called after setting [0x1BF518]=1
print('\n=== Function 0x48708 ===')
disasm_range(0x48708, 0x487B0)
