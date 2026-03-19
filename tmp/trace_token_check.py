import struct

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb').read()

def decode_bl(instr, pc):
    imm26 = instr & 0x03FFFFFF
    if imm26 & 0x02000000:
        imm26 -= 0x04000000
    return pc + imm26 * 4

def decode_bcond(instr, pc):
    imm19 = (instr >> 5) & 0x7FFFF
    if imm19 & 0x40000:
        imm19 -= 0x80000
    cond = instr & 0xF
    cond_names = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
    return pc + imm19 * 4, cond_names[cond]

def decode_cbz(instr, pc):
    # CBZ/CBNZ
    imm19 = (instr >> 5) & 0x7FFFF
    if imm19 & 0x40000:
        imm19 -= 0x80000
    op = 'CBNZ' if (instr >> 24) & 1 else 'CBZ'
    reg = instr & 0x1F
    size = 'W' if (instr >> 31) == 0 else 'X'
    return pc + imm19 * 4, f'{op} {size}{reg}'

def decode_adrp(instr, pc):
    immhi = (instr >> 5) & 0x7FFFF
    immlo = (instr >> 29) & 0x3
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    return (pc & ~0xFFF) + (imm << 12)

def disasm(start, count=50):
    print(f'\n=== Disasm @ 0x{start:X} ===')
    for i in range(count):
        off = start + i*4
        if off >= len(data):
            break
        instr = struct.unpack_from('<I', data, off)[0]

        desc = f'0x{instr:08X}'

        # BL
        if (instr & 0xFC000000) == 0x94000000:
            target = decode_bl(instr, off)
            desc = f'BL 0x{target:X}'
        # B
        elif (instr & 0xFC000000) == 0x14000000:
            target = decode_bl(instr, off)
            desc = f'B 0x{target:X}'
        # B.cond
        elif (instr & 0xFF000010) == 0x54000000:
            target, cond = decode_bcond(instr, off)
            desc = f'B.{cond} 0x{target:X}'
        # CBZ/CBNZ
        elif (instr & 0x7E000000) == 0x34000000:
            target, op = decode_cbz(instr, off)
            desc = f'{op} -> 0x{target:X}'
        # ADRP
        elif (instr & 0x9F000000) == 0x90000000:
            page = decode_adrp(instr, off)
            rd = instr & 0x1F
            desc = f'ADRP X{rd}, 0x{page:X}'
        # ADD imm
        elif (instr & 0xFF800000) == 0x91000000:
            imm12 = (instr >> 10) & 0xFFF
            rd = instr & 0x1F
            rn = (instr >> 5) & 0x1F
            desc = f'ADD X{rd}, X{rn}, #0x{imm12:X}'
        # LDR/LDRB literals
        elif (instr & 0xFF000000) in (0x58000000, 0x18000000):
            desc = f'LDR literal 0x{instr:08X}'
        # RET
        elif instr == 0xD65F03C0:
            desc = 'RET'
        # NOP
        elif instr == 0xD503201F:
            desc = 'NOP'
        # MOV W0, WZR
        elif instr == 0x2A1F03E0:
            desc = 'MOV W0, WZR'
        # MOV W0, #1
        elif instr == 0x320003E0:
            desc = 'MOV W0, #1 (ORR)'

        print(f'  0x{off:X}: {desc}')

        if instr == 0xD65F03C0 and i > 5:  # RET at end
            break

# The carrier check function containing the token error
# Token error string ref at 0x3BBD4
# Looking at structure - need to find function start
# Let me disasm from 0x3BB48 (carrier check mentioned in summary)
disasm(0x3BB48, 70)

# Also disasm the function 0x38420 that returns [0x1BF518]
print('\n\n=== Function 0x38420 ===')
disasm(0x38420, 20)

# Check what's at 0x1BF518 in the data section
val = struct.unpack_from('<I', data, 0x1BF518)[0]
print(f'\n[0x1BF518] initial value in PE: 0x{val:X}')

# Search for writes to 0x1BF518
# ADRP + STR pattern
print('\nSearching writes to [0x1BF518] (page 0x1BF000 + 0x518)...')
for i in range(0, 0x69000-4, 4):
    instr = struct.unpack_from('<I', data, i)[0]
    if (instr & 0x9F000000) == 0x90000000:
        page = decode_adrp(instr, i)
        if page == 0x1BF000:
            # Check next instructions for STR/STRB with offset 0x518
            for j in range(1, 5):
                ni = struct.unpack_from('<I', data, i + j*4)[0]
                # STR W, [Xn, #imm12]
                if (ni & 0xFFC00000) == 0xB9000000:
                    imm12 = ((ni >> 10) & 0xFFF) * 4
                    if imm12 == 0x518 or imm12 == 0x51C:
                        print(f'  STR at 0x{i+j*4:X} → offset 0x{imm12:X}: context 0x{i:X}-0x{i+j*4:X}')
                # STRB W, [Xn, #imm12]
                elif (ni & 0xFFC00000) == 0x39000000:
                    imm12 = (ni >> 10) & 0xFFF
                    if imm12 == 0x518:
                        print(f'  STRB at 0x{i+j*4:X} → offset 0x{imm12:X}: context 0x{i:X}-0x{i+j*4:X}')
