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

# Full carrier check function 0x3BB48 - 0x3BBF0
print('=== Carrier check 0x3BB48 FULL ===')
for off in range(0x3BB48, 0x3BBF0, 4):
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
    elif (instr & 0x9F000000) == 0x90000000:
        desc = f'ADRP X{instr&0x1F}, 0x{decode_adrp(instr, off):X}'
    elif (instr & 0xFF800000) == 0x91000000:
        imm12 = (instr >> 10) & 0xFFF
        rd = instr & 0x1F
        rn = (instr >> 5) & 0x1F
        desc = f'ADD X{rd}, X{rn}, #0x{imm12:X}'
    elif instr == 0xD65F03C0:
        desc = 'RET'
    elif instr == 0x2A1F03E0:
        desc = 'MOV W0, WZR'
    elif instr == 0x320003E0:
        desc = 'MOV W0, #1'
    elif (instr & 0xFFC00000) == 0x72000000:
        # TST Wn, #imm (alias of ANDS WZR, Wn, #imm)
        desc = f'TST/ANDS 0x{instr:08X}'
    elif (instr & 0xFFC00000) == 0xA8C00000:
        # LDP with post-increment
        desc = f'LDP post-inc 0x{instr:08X}'
    elif (instr & 0xFFC00000) == 0x2A000000:
        # ORR / MOV between regs
        rm = (instr >> 16) & 0x1F
        rd = instr & 0x1F
        rn = (instr >> 5) & 0x1F
        desc = f'MOV/ORR W{rd}, W{rn}, W{rm}'

    print(f'  0x{off:X}: {desc}')

# Function 0x38610 (called first in carrier check)
print('\n=== Function 0x38610 (called first) ===')
for off in range(0x38610, 0x38680, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    desc = f'raw 0x{instr:08X}'
    if (instr & 0xFC000000) == 0x94000000:
        desc = f'BL 0x{decode_bl(instr, off):X}'
    elif instr == 0xD65F03C0:
        desc = 'RET'
    elif (instr & 0x9F000000) == 0x90000000:
        desc = f'ADRP X{instr&0x1F}, 0x{decode_adrp(instr, off):X}'
    elif (instr & 0xFF800000) == 0x91000000:
        imm12 = (instr >> 10) & 0xFFF
        desc = f'ADD X{instr&0x1F}, X{(instr>>5)&0x1F}, #0x{imm12:X}'
    elif (instr & 0xFFC00000) == 0x39400000:
        # LDRB
        imm12 = (instr >> 10) & 0xFFF
        rn = (instr >> 5) & 0x1F
        rt = instr & 0x1F
        desc = f'LDRB W{rt}, [X{rn}, #0x{imm12:X}]'
    print(f'  0x{off:X}: {desc}')

# Function 0x39D08 (called as second in carrier check, before model compare)
print('\n=== Function 0x39D08 ===')
for off in range(0x39D08, 0x39D60, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    desc = f'raw 0x{instr:08X}'
    if (instr & 0xFC000000) == 0x94000000:
        desc = f'BL 0x{decode_bl(instr, off):X}'
    elif instr == 0xD65F03C0:
        desc = 'RET'
    elif (instr & 0x9F000000) == 0x90000000:
        desc = f'ADRP X{instr&0x1F}, 0x{decode_adrp(instr, off):X}'
    elif (instr & 0xFF800000) == 0x91000000:
        imm12 = (instr >> 10) & 0xFFF
        desc = f'ADD X{instr&0x1F}, X{(instr>>5)&0x1F}, #0x{imm12:X}'
    print(f'  0x{off:X}: {desc}')

# Function 0x2A1EC (string compare)
print('\n=== Function 0x2A1EC (string compare?) ===')
for off in range(0x2A1EC, 0x2A250, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    desc = f'raw 0x{instr:08X}'
    if (instr & 0xFC000000) == 0x94000000:
        desc = f'BL 0x{decode_bl(instr, off):X}'
    elif instr == 0xD65F03C0:
        desc = 'RET'
    elif (instr & 0x7E000000) == 0x34000000:
        imm19 = (instr >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 -= 0x80000
        op = 'CBNZ' if (instr >> 24) & 1 else 'CBZ'
        reg = instr & 0x1F
        desc = f'{op} W{reg} -> 0x{off + imm19*4:X}'
    print(f'  0x{off:X}: {desc}')

# Function 0x38420 (reads [0x1BF518])
print('\n=== Function 0x38420 full decode ===')
instr_0x38424 = struct.unpack_from('<I', data, 0x38424)[0]
# LDRB Wt, [Xn, #imm12]
if (instr_0x38424 & 0xFFC00000) == 0x39400000:
    imm12 = (instr_0x38424 >> 10) & 0xFFF
    rn = (instr_0x38424 >> 5) & 0x1F
    rt = instr_0x38424 & 0x1F
    print(f'  0x38424: LDRB W{rt}, [X{rn}, #0x{imm12:X}]')
    # For LDRB, offset = imm12 (no scaling)
    print(f'  Effective address: page(0x1BF000) + 0x{imm12:X} = 0x{0x1BF000+imm12:X}')
else:
    print(f'  0x38424: raw 0x{instr_0x38424:08X}')

# Check value at computed address
addr = 0x1BF000 + ((instr_0x38424 >> 10) & 0xFFF)
val = data[addr]
print(f'  PE initial value at 0x{addr:X}: 0x{val:02X}')

# 0x72001C1F = TST W0, #0x80000000? No - decode properly
print('\n=== Decode TST at 0x3BBC0 ===')
tst = struct.unpack_from('<I', data, 0x3BBC0)[0]
# ANDS W31(=WZR), Wn, #imm
# Encoding: 0111 0010 0Nimms Nimmr 0bRn 11111
# sf=0, opc=11, N=0
N = (tst >> 22) & 1
immr = (tst >> 16) & 0x3F
imms = (tst >> 10) & 0x3F
rn = (tst >> 5) & 0x1F
rd = tst & 0x1F
print(f'  ANDS W{rd}, W{rn}, N={N} immr={immr} imms={imms}')
# For 32-bit, N must be 0
# DecodeBitMasks with immN=0, imms, immr, immediate=True
# imms=0b000111 (7), immr=0b000000 (0) → mask = 0xFF (8 ones)
# Actually need proper decoding
size = 32
element = 0xFFFFFFFF >> (31 - imms)
mask = (element >> immr) | (element << (size - immr))
mask &= 0xFFFFFFFF
print(f'  Bitmask: 0x{mask:08X}')
print(f'  → TST W{rn}, #0x{mask:X}  (tests if W{rn} & 0x{mask:X} != 0)')
