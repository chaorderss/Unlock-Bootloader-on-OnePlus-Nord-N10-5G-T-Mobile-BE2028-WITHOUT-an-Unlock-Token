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

# Read strings at the 4 model addresses
print('=== Model strings in carrier check ===')
for addr in [0x5F53B, 0x5F524, 0x5FB26, 0x5FB2C]:
    end = data.index(b'\x00', addr)
    s = data[addr:end]
    print(f'  0x{addr:X}: {s}')

# What string is at 0x5F9CC? (from earlier analysis of 0x3BBA4)
for addr in [0x5F9CC, 0x5FB26, 0x5FB2C]:
    try:
        end = data.index(b'\x00', addr)
        s = data[addr:end]
        print(f'  Extra 0x{addr:X}: {s}')
    except:
        pass

# Disasm the full carrier check - need to see 0x3BBBC onwards
print('\n=== Carrier check continuation (0x3BBBC-0x3BBF0) ===')
for off in range(0x3BBBC, 0x3BBF0, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    desc = f'0x{instr:08X}'
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
        desc = f'ADD X{instr&0x1F}, X{(instr>>5)&0x1F}, #0x{imm12:X}'
    elif instr == 0xD65F03C0:
        desc = 'RET'
    elif instr == 0x2A1F03E0:
        desc = 'MOV W0, WZR'
    elif instr == 0x320003E0:
        desc = 'MOV W0, #1'
    print(f'  0x{off:X}: {desc}')

# Disasm around 0x383EC-0x38420 (STRB write to [0x1BF518])
print('\n=== Write to [0x1BF518] context @ 0x383C0-0x38430 ===')
for off in range(0x383A0, 0x38430, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    desc = f'0x{instr:08X}'
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
        desc = f'ADD X{instr&0x1F}, X{(instr>>5)&0x1F}, #0x{imm12:X}'
    elif instr == 0xD65F03C0:
        desc = 'RET'
    elif instr == 0x2A1F03E0:
        desc = 'MOV W0, WZR'
    elif instr == 0x320003E0:
        desc = 'MOV W0, #1'
    marker = ' <<<<' if off == 0x383F8 else ''
    print(f'  0x{off:X}: {desc}{marker}')

# Also find what calls the carrier check function
print('\n=== Callers of 0x3BB48 ===')
for i in range(0, 0x69000-4, 4):
    instr = struct.unpack_from('<I', data, i)[0]
    if (instr & 0xFC000000) == 0x94000000:
        target = decode_bl(instr, i)
        if target == 0x3BB48:
            print(f'  BL 0x3BB48 from 0x{i:X}')
