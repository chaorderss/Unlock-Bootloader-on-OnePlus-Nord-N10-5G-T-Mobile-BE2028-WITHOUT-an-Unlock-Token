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

# Check strings referenced from init function at 0x37D38
print('=== Strings near 0x62xxx area ===')
for addr in [0x627BA, 0x627A0, 0x627B5, 0x627A5]:
    try:
        end = data.index(b'\x00', addr)
        s = data[addr:min(end, addr+80)]
        print(f'  0x{addr:X}: {s}')
    except:
        # might be UTF-16
        s = data[addr:addr+40]
        print(f'  0x{addr:X} (raw): {s.hex()}')

# Check frp UTF-16 context
frp_off = 0x68292
print(f'\nFRP UTF-16 context at 0x{frp_off:X}:')
print(f'  Bytes: {data[frp_off-4:frp_off+20].hex()}')
# Look for what references 0x68292
print('\nSearching for ADRP → page containing 0x68292 (page 0x68000):')
for i in range(0, 0x69000-4, 4):
    instr = struct.unpack_from('<I', data, i)[0]
    if (instr & 0x9F000000) == 0x90000000:
        page = decode_adrp(instr, i)
        if page == 0x68000:
            ni = struct.unpack_from('<I', data, i+4)[0]
            if (ni & 0xFF800000) == 0x91000000:
                imm12 = (ni >> 10) & 0xFFF
                if imm12 == 0x292:
                    print(f'  0x{i:X}: ADRP+ADD → 0x68292 (frp string)')

# Find callers of 0x37D38
print('\n=== Callers of 0x37D38 ===')
for i in range(0, 0x69000-4, 4):
    instr = struct.unpack_from('<I', data, i)[0]
    if (instr & 0xFC000000) == 0x94000000:
        target = decode_bl(instr, i)
        if target == 0x37D38:
            print(f'  BL 0x37D38 from 0x{i:X}')

# Find callers of function at ~0x37CD8 (starts before 0x37D00)
# First find prologue
print('\n=== Function prologue search 0x37A00-0x37D50 ===')
for off in range(0x37A00, 0x37D50, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr & 0xFFC003E0) == 0xA9800000:  # STP with pre-decrement to SP
        rt1 = instr & 0x1F
        rt2 = (instr >> 10) & 0x1F
        rn = (instr >> 5) & 0x1F
        if rn == 31:
            print(f'  0x{off:X}: STP X{rt1}, X{rt2}, [SP, ...]!')

# Disasm 0x37D38 - 0x37E00 context
print('\n=== 0x37D38-0x37E00 ===')
disasm_range(0x37D38, 0x37E00)

# Read strings that function at 0x37D38 loads
# 0x37DA8: ADD X1, X1, #0x7BA → 0x627BA
# 0x37DC0: ADD X1, X1, #0x7A0 → 0x627A0
for base_off in [0x627A0, 0x627BA, 0x627BF, 0x627A5]:
    raw = data[base_off:base_off+40]
    print(f'\n0x{base_off:X}: {raw}')
