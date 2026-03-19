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
        print(f'  0x{off:X}: {desc}')

# Check critical strings
print('=== Strings used in unlock function ===')
for addr in [0x66E08, 0x66E19, 0x66E30, 0x66E87, 0x66EBF]:
    try:
        end = data.index(b'\x00', addr)
        print(f'  0x{addr:X}: {data[addr:end]}')
    except: pass

# Disasm 0x49E04 (jump target when IsCriticalUnlocked returns 0)
print('\n=== 0x49E04-0x49FF0 (path when critical=0) ===')
disasm_range(0x49E04, 0x4A00C)

# Check 0x22C28 - what does it do?
print('\n=== Function 0x22C28 ===')
disasm_range(0x22C28, 0x22C60)

# Test: does 0x49BF8 path call 0x3BB48 anywhere?
# Search for BL 0x3BB48 beyond 0x4882C
print('\n=== All BL 0x3BB48 calls ===')
for i in range(0, 0x69000-4, 4):
    instr = struct.unpack_from('<I', data, i)[0]
    if (instr & 0xFC000000) == 0x94000000:
        t = decode_bl(instr, i)
        if t == 0x3BB48:
            print(f'  BL 0x3BB48 from 0x{i:X}')

# Also check: function 0x487AC - is it called from within 0x49BF8?
print('\n=== BL 0x487AC callers ===')
for i in range(0, 0x69000-4, 4):
    instr = struct.unpack_from('<I', data, i)[0]
    if (instr & 0xFC000000) == 0x94000000:
        t = decode_bl(instr, i)
        if t == 0x487AC:
            print(f'  BL 0x487AC from 0x{i:X}')
        if t == 0x48708:
            print(f'  BL 0x48708 from 0x{i:X}')

# All B 0x487AC branches too (tail calls)
print('\n=== All B 0x487AC tail calls ===')
for i in range(0, 0x69000-4, 4):
    instr = struct.unpack_from('<I', data, i)[0]
    if (instr & 0xFC000000) == 0x14000000:
        t = decode_bl(instr, i)
        if t == 0x487AC:
            print(f'  B 0x487AC from 0x{i:X}')
