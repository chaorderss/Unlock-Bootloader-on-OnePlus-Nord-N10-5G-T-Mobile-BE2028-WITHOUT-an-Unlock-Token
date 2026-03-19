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

def disasm(start, end, label=""):
    if label:
        print(f'\n=== {label} ===')
    for off in range(start, end, 4):
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
            sh = (instr >> 22) & 1
            if sh: imm12 <<= 12
            desc = f'ADD X{rd}, X{rn}, #0x{imm12:X}'
        elif (instr & 0xFF800000) == 0xD1000000:
            imm12 = (instr >> 10) & 0xFFF
            rd = instr & 0x1F
            rn = (instr >> 5) & 0x1F
            desc = f'SUB X{rd}, X{rn}, #0x{imm12:X}'
        elif instr == 0xD65F03C0:
            desc = 'RET'
        elif (instr & 0xFFC00000) == 0x39400000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            rt = instr & 0x1F
            desc = f'LDRB W{rt}, [X{rn}, #0x{imm12:X}]'
        elif (instr & 0xFFC00000) == 0x39000000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            rt = instr & 0x1F
            desc = f'STRB W{rt}, [X{rn}, #0x{imm12:X}]'
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
        elif (instr & 0xFFC00000) == 0xF9000000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            rt = instr & 0x1F
            desc = f'STR X{rt}, [X{rn}, #0x{imm12*8:X}]'
        elif (instr & 0xFFC00000) == 0xB9000000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            rt = instr & 0x1F
            desc = f'STR W{rt}, [X{rn}, #0x{imm12*4:X}]'
        elif (instr & 0xFF800000) == 0x52800000:
            hw = (instr >> 21) & 0x3
            imm16 = (instr >> 5) & 0xFFFF
            rd = instr & 0x1F
            desc = f'MOV W{rd}, #0x{imm16 << (hw*16):X}'
        elif (instr & 0xFF800000) == 0xD2800000:
            hw = (instr >> 21) & 0x3
            imm16 = (instr >> 5) & 0xFFFF
            rd = instr & 0x1F
            desc = f'MOV X{rd}, #0x{imm16 << (hw*16):X}'
        elif (instr & 0xFFE00000) == 0xAA000000:
            rm = (instr >> 16) & 0x1F
            rn = (instr >> 5) & 0x1F
            rd = instr & 0x1F
            if rn == 31: desc = f'MOV X{rd}, X{rm}'
            else: desc = f'ORR X{rd}, X{rn}, X{rm}'
        elif (instr & 0xFFE00000) == 0x2A000000:
            rm = (instr >> 16) & 0x1F
            rn = (instr >> 5) & 0x1F
            rd = instr & 0x1F
            if rn == 31: desc = f'MOV W{rd}, W{rm}'
            else: desc = f'ORR W{rd}, W{rn}, W{rm}'
        elif (instr & 0xFFC00000) == 0x72000000:
            rn = (instr >> 5) & 0x1F
            desc = f'TST W{rn}, #bitmask'
        elif (instr & 0x7F000000) == 0x71000000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            desc = f'CMP W{rn}, #0x{imm12:X}'
        elif (instr & 0xFF000000) == 0xD6000000:
            rn = (instr >> 5) & 0x1F
            opc = (instr >> 21) & 3
            ops = ['BR','BLR','RET','?'][opc]
            desc = f'{ops} X{rn}'

        print(f'  0x{off:05X}: {desc}')

# Trace the function containing 0x35CD0 (only caller of SetModelString)
# Find function start by looking backward
disasm(0x35C00, 0x35D40, "Function calling SetModelString at 0x35CD0")

# Also check what the setter does with the raw W0 value
# 0x38620: takes W0 (model number as integer)
# 0x38630: STR W0, [X1, #0x9D8] → stores at [0x1BD978 + 0x9D8] = wait that's wrong
# Let me re-check: X1 = 0x1BD978, STR W0, [X1, #0x9D8]
# That would be 0x1BD978 + 0x9D8 = 0x1C3350?
# Actually WAIT - the getter reads LDR W0, [X8, #0x9D8] where X8 = 0x1BD978
# So the actual address is 0x1BD978 + (0x9D8 * 4) = ... no
# For LDRB it's byte offset, for LDR W it's word-scaled

# Re-decode the getter
print('\n=== Re-decode getter 0x38610 ===')
instr_38618 = struct.unpack_from('<I', data, 0x38618)[0]
print(f'  0x38618: raw 0x{instr_38618:08X}')
# B9400000 class: LDR Wt, [Xn, #imm12*4]
if (instr_38618 & 0xFFC00000) == 0xB9400000:
    imm12 = (instr_38618 >> 10) & 0xFFF
    rn = (instr_38618 >> 5) & 0x1F
    rt = instr_38618 & 0x1F
    actual_offset = imm12 * 4
    print(f'  LDR W{rt}, [X{rn}, #0x{actual_offset:X}]')
    # X8 was set to 0x1BD978, so actual addr = 0x1BD978 + actual_offset
    print(f'  → Actual address: 0x1BD978 + 0x{actual_offset:X} = 0x{0x1BD978+actual_offset:X}')
else:
    # Try as raw instruction
    print(f'  Not LDR W - check encoding')
    # Check if it's LDR Wt, [Xn, #offset] with post-index or pre-index
    # Or maybe it's not scaled?
    # 0xB949D900
    # 1011 1001 0100 1001 1101 1001 0000 0000
    # opc=10 (LDR 32), V=0, imm12=0b010011101100 = 0x276*4 = 0x9D8?
    # Actually let me decode properly
    # Bits[31:30] = 10 = size (32-bit)
    # Bits[29:27] = 111 = LDR literal? No...
    # Actually format: size[31:30]=10, V=0, opc=01, imm12, Rn, Rt
    # 0xB9 = 1011 1001 → size=10, V=0, opc=01 → LDR Wt
    # imm12 = bits[21:10] = (0xB949D900 >> 10) & 0xFFF
    imm12 = (instr_38618 >> 10) & 0xFFF
    rt = instr_38618 & 0x1F
    rn = (instr_38618 >> 5) & 0x1F
    actual_offset = imm12 * 4
    print(f'  Manual decode: LDR W{rt}, [X{rn}, #0x{actual_offset:X}]')
    print(f'  → Actual address: 0x1BD978 + 0x{actual_offset:X} = 0x{0x1BD978+actual_offset:X}')

# Re-decode the setter store
print('\n=== Re-decode setter STR at 0x38630 ===')
instr_38630 = struct.unpack_from('<I', data, 0x38630)[0]
print(f'  0x38630: raw 0x{instr_38630:08X}')
if (instr_38630 & 0xFFC00000) == 0xB9000000:
    imm12 = (instr_38630 >> 10) & 0xFFF
    rn = (instr_38630 >> 5) & 0x1F
    rt = instr_38630 & 0x1F
    actual_offset = imm12 * 4
    print(f'  STR W{rt}, [X{rn}, #0x{actual_offset:X}]')
    # X1 = 0x1BD978
    print(f'  → Store to: 0x1BD978 + 0x{actual_offset:X} = 0x{0x1BD978+actual_offset:X}')

# Now trace the SMEM read that gets the project number
# The string "SMEM_PROJECT_INFO" appears → this is Qualcomm shared memory
# It's populated by XBL/SBL and stored in IMEM, NOT on a partition
# Usually comes from hardware/fuse info

# But let me check if there's a "sw project id" from param partition
print('\n=== Looking for param-based project ID reads ===')
# "param sw project id" was found at 0x60B0C
# Let's find what references it
param_str = b'param sw project id'
idx = data.find(param_str)
if idx >= 0:
    print(f'  Found at 0x{idx:X}')
    # Search for ADRP references to this address
    page = idx & ~0xFFF
    offset = idx & 0xFFF
    print(f'  Page: 0x{page:X}, offset: 0x{offset:X}')

    # Find ADRP instructions pointing to this page
    for off in range(0, len(data)-8, 4):
        instr = struct.unpack_from('<I', data, off)[0]
        if (instr & 0x9F000000) == 0x90000000:
            p = decode_adrp(instr, off)
            if p == page:
                # Check next instruction for ADD with our offset
                next_instr = struct.unpack_from('<I', data, off+4)[0]
                if (next_instr & 0xFF800000) == 0x91000000:
                    add_imm = (next_instr >> 10) & 0xFFF
                    sh = (next_instr >> 22) & 1
                    if sh: add_imm <<= 12
                    if add_imm == offset:
                        print(f'  ADRP+ADD ref at 0x{off:X}')

# Look for "SoftwareProjectID" reads too
sw_proj = b'SoftwareProjectID\x00'
idx2 = data.find(sw_proj)
if idx2 >= 0:
    print(f'\n  "SoftwareProjectID" at 0x{idx2:X}')
    page2 = idx2 & ~0xFFF
    offset2 = idx2 & 0xFFF
    for off in range(0, len(data)-8, 4):
        instr = struct.unpack_from('<I', data, off)[0]
        if (instr & 0x9F000000) == 0x90000000:
            p = decode_adrp(instr, off)
            if p == page2:
                next_instr = struct.unpack_from('<I', data, off+4)[0]
                if (next_instr & 0xFF800000) == 0x91000000:
                    add_imm = (next_instr >> 10) & 0xFFF
                    if add_imm == offset2:
                        print(f'  ADRP+ADD ref at 0x{off:X}')
                        # Show the broader context
                        disasm(off-0x10, off+0x20, f"Context around SoftwareProjectID ref at 0x{off:X}")
