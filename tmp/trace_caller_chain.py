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

# 0x49D0C calls 0x37D38. What is at 0x49D0C context?
print('=== Context around 0x49D0C (caller of 0x37D38) ===')
disasm_range(0x49C80, 0x49E00)

# Find callers of the function containing 0x49D0C
print('\n=== Find function start near 0x49C00-0x49D0C ===')
for off in range(0x49800, 0x49D10, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr & 0xFFC00000) in (0xA9800000, 0xA98003E0):
        rt1 = instr & 0x1F
        rn = (instr >> 5) & 0x1F
        if rn == 31:
            print(f'  Prologue candidate at 0x{off:X}: rt1=X{rt1}')

# Find callers of function at 0x49C80 area
print('\n=== Callers searching for 0x49xxx functions ===')
for i in range(0, 0x69000-4, 4):
    instr = struct.unpack_from('<I', data, i)[0]
    if (instr & 0xFC000000) == 0x94000000:
        target = decode_bl(instr, i)
        if 0x49C00 <= target <= 0x49E00:
            print(f'  BL 0x{target:X} from 0x{i:X}')

# Also check string references around the frp region
# Look for "frp" referenced as partition name
print('\n=== Searching frp-related strings ===')
# ASCII "frp\0"
frp_ascii = b'frp\x00'
idx = 0
while True:
    idx = data.find(frp_ascii, idx)
    if idx < 0: break
    print(f'  ASCII "frp" at 0x{idx:X}')
    idx += 1

# UTF-16 search for various partition names
for name in ['frp', 'keystore', 'cdt', 'unlock', 'OemInfo']:
    encoded = (name + '\0').encode('utf-16-le')
    idx = 0
    while True:
        idx = data.find(encoded, idx)
        if idx < 0: break
        print(f'  UTF-16 "{name}" at 0x{idx:X}')
        idx += 2

# Function at 0x4DEBC called from 0x37D98 - this is likely ReadPartition
print('\n=== Function 0x4DEBC (partition read?) - first 30 instrs ===')
disasm_range(0x4DEBC, 0x4DF60)
