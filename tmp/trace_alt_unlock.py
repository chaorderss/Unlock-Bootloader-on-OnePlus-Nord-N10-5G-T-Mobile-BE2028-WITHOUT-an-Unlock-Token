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

# Read all UTF-16 strings from 0x68000 page (partition name table)
print('=== UTF-16 partition names in 0x68000 page ===')
off = 0x68000
while off < 0x69000:
    instr = struct.unpack_from('<I', data, off)[0]
    if instr == 0:
        off += 4
        continue
    # Try to read UTF-16 string
    s = ''
    p = off
    while p < 0x69000:
        w = struct.unpack_from('<H', data, p)[0]
        if w == 0:
            break
        if 0x20 <= w <= 0x7E:
            s += chr(w)
        else:
            s = None
            break
        p += 2
    if s and len(s) >= 2:
        print(f'  0x{off:X}: "{s}" (len={len(s)})')
        off = p + 2
    else:
        off += 2

# Check specific offsets used in code
print('\n=== Specific partition names used in unlock handler ===')
for off in [0x681FA, 0x68218, 0x68292, 0x6829A]:
    s = ''
    p = off
    while p < 0x69000:
        w = struct.unpack_from('<H', data, p)[0]
        if w == 0: break
        if 0x20 <= w <= 0x7E:
            s += chr(w)
        else:
            s = '???'; break
        p += 2
    print(f'  0x{off:X}: "{s}"')

# Find callers of 0x49BAC
print('\n=== Callers of 0x49BAC ===')
for i in range(0, 0x69000-4, 4):
    instr = struct.unpack_from('<I', data, i)[0]
    if (instr & 0xFC000000) == 0x94000000:
        t = decode_bl(instr, i)
        if t == 0x49BAC:
            print(f'  BL 0x49BAC from 0x{i:X}')

# Disasm 0x49BAC-0x49D10 (the full function context)
print('\n=== Function 0x49BAC - 0x49D20 ===')
disasm_range(0x49BAC, 0x49D20)

# What's at 0x4A058 (error jump from ops check)?
print('\n=== 0x4A050-0x4A090 (error path from ops check) ===')
disasm_range(0x4A050, 0x4A090)

# Disasm full continuation 0x49D50-0x4A060 to see boottype check
print('\n=== 0x49D50-0x4A060 (continuation after IsDeviceUnlocked) ===')
disasm_range(0x49D50, 0x4A060)
