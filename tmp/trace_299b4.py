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

# Check what string is at 0x61862
print('=== String at 0x61862 ===')
s = data[0x61862:0x618A0]
null = s.find(b'\x00')
if null >= 0: s = s[:null]
print(f'  "{s.decode("ascii", errors="replace")}"')

# Disassemble function 0x299B4
print('\n=== Function 0x299B4 ===')
for off in range(0x299B4, 0x29AF0, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    desc = f'raw 0x{instr:08X}'

    if (instr & 0xFC000000) == 0x94000000:
        target = decode_bl(instr, off)
        desc = f'BL 0x{target:X}'
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
    elif (instr & 0x9F000000) == 0x90000000:
        desc = f'ADRP X{instr&0x1F}, 0x{decode_adrp(instr, off):X}'
    elif (instr & 0xFF800000) == 0x91000000:
        imm12 = (instr >> 10) & 0xFFF
        rd = instr & 0x1F
        rn = (instr >> 5) & 0x1F
        sh = (instr >> 22) & 1
        if sh: imm12 <<= 12
        desc = f'ADD X{rd}, X{rn}, #0x{imm12:X}'
    elif instr == 0xD65F03C0:
        desc = 'RET'
    elif instr == 0x2A1F03E0:
        desc = 'MOV W0, WZR'
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
    elif (instr & 0xFFC00000) == 0x39400000:
        imm12 = (instr >> 10) & 0xFFF
        rn = (instr >> 5) & 0x1F
        rt = instr & 0x1F
        desc = f'LDRB W{rt}, [X{rn}, #0x{imm12:X}]'
    elif (instr & 0xFF800000) == 0x52800000:
        hw = (instr >> 21) & 0x3
        imm16 = (instr >> 5) & 0xFFFF
        rd = instr & 0x1F
        desc = f'MOV W{rd}, #0x{imm16 << (hw*16):X}'
    elif (instr & 0xFFE00000) == 0xAA000000:
        rm = (instr >> 16) & 0x1F
        rn = (instr >> 5) & 0x1F
        rd = instr & 0x1F
        if rn == 31: desc = f'MOV X{rd}, X{rm}'
        else: desc = f'ORR X{rd}, X{rn}, X{rm}'
    elif (instr & 0xFFC00000) == 0x72000000:
        rn = (instr >> 5) & 0x1F
        desc = f'TST W{rn}, #bitmask'
    elif (instr & 0x7F000000) == 0x71000000:
        imm12 = (instr >> 10) & 0xFFF
        rn = (instr >> 5) & 0x1F
        desc = f'CMP W{rn}, #0x{imm12:X}'
    elif (instr & 0xFFC00000) == 0xF9000000:
        imm12 = (instr >> 10) & 0xFFF
        rn = (instr >> 5) & 0x1F
        rt = instr & 0x1F
        desc = f'STR X{rt}, [X{rn}, #0x{imm12*8:X}]'

    print(f'  0x{off:05X}: {desc}')
    if desc == 'RET':
        break

# Also decode the MOV instruction at 0x37F40 for model 20888 index
print('\n=== Decode 0x37F40 (model 20888 branch target) ===')
instr = struct.unpack_from('<I', data, 0x37F40)[0]
print(f'  0x37F40: 0x{instr:08X}')
# This should be some kind of MOV W8, #7
# Check ORR W immediate encoding
# 0x32000BE8
# immr = (instr >> 16) & 0x3F = (0x32000BE8 >> 16) & 0x3F = 0x0000 & 0x3F = 0
# imms = (instr >> 10) & 0x3F = (0x32000BE8 >> 10) & 0x3F = (0xC02F) & 0x3F = 0x2F
# Hmm, let me recalculate
bits_21_16 = (instr >> 16) & 0x3F
bits_15_10 = (instr >> 10) & 0x3F
bits_9_5 = (instr >> 5) & 0x1F
bits_4_0 = instr & 0x1F
print(f'  immr={bits_21_16}, imms={bits_15_10}, Rn={bits_9_5}, Rd={bits_4_0}')
# immr=0, imms=2, Rn=31, Rd=8

# For 32-bit ORR immediate with N=0, immr=0, imms=2:
# This creates a bitmask of (imms+1=3) consecutive ones, rotated right by immr=0
# So bitmask = 0b111 = 7
# ORR W8, WZR, #7 → W8 = 7
print(f'  → MOV W8, #7')

# Now verify carrier_id for index 7
table_base = 0x62488
struct_size = 0x58
addr = 7 * struct_size + table_base
carrier_id = struct.unpack_from('<I', data, addr + 0x40)[0]
print(f'\n=== Carrier ID for 20888 (index 7) ===')
print(f'  Table entry at 0x{addr:X}, carrier_id at 0x{addr+0x40:X} = {carrier_id}')

# Check the string at 0x61862 more carefully
print('\n=== Strings around 0x61862 ===')
for start in range(0x61840, 0x618C0, 1):
    if data[start] >= 0x20 and data[start] < 0x7F:
        end = start
        while end < start + 100 and data[end] >= 0x20 and data[end] < 0x7F:
            end += 1
        if end - start > 3:
            s = data[start:end].decode('ascii', errors='replace')
            print(f'  0x{start:X}: "{s}"')
            break

# The function is called from 0x49D0C. Let's check who calls 0x49D0C
print('\n=== Who calls 0x49D0C or the function at that address? ===')
# First, find the function containing 0x49D0C
# Look backward for function prologue
for off in range(0x49C00, 0x49D10, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    # Check for STP/SUB SP patterns
    if (instr & 0xFF800000) == 0xD1000000:  # SUB Xd, SP, #imm
        print(f'  Possible function entry at 0x{off:X}: SUB SP')
    elif (instr >> 24) in [0xA9]:
        # Might be at a function boundary
        pass

# Search for callers of the function containing 0x49D0C
# Actually, let me check what's at 0x49BF8 area (known alternate unlock path from summary)
print('\n=== Area around 0x49BF8 (alternate unlock path) ===')
for off in range(0x49BF0, 0x49D20, 4):
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

    print(f'  0x{off:05X}: {desc}')
