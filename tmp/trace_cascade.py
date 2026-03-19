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

def disasm_range(start, end, label=""):
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
        elif (instr & 0x7E000000) == 0x36000000:
            imm14 = (instr >> 5) & 0x3FFF
            if imm14 & 0x2000: imm14 -= 0x4000
            op = 'TBNZ' if (instr >> 24) & 1 else 'TBZ'
            bit = ((instr >> 31) << 5) | ((instr >> 19) & 0x1F)
            reg = instr & 0x1F
            desc = f'{op} X{reg}, #{bit} -> 0x{off + imm14*4:X}'
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
        elif (instr & 0xFFC00000) == 0xF9400000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            rt = instr & 0x1F
            desc = f'LDR X{rt}, [X{rn}, #0x{imm12*8:X}]'
        elif (instr & 0xFFC00000) == 0xF9000000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            rt = instr & 0x1F
            desc = f'STR X{rt}, [X{rn}, #0x{imm12*8:X}]'
        elif (instr & 0xFFC00000) == 0xB9400000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            rt = instr & 0x1F
            desc = f'LDR W{rt}, [X{rn}, #0x{imm12*4:X}]'
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
        elif (instr & 0xFF800000) == 0xD1000000:
            imm12 = (instr >> 10) & 0xFFF
            rd = instr & 0x1F
            rn = (instr >> 5) & 0x1F
            desc = f'SUB X{rd}, X{rn}, #0x{imm12:X}'
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
        elif (instr & 0xFFC00000) == 0x79400000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            rt = instr & 0x1F
            desc = f'LDRH W{rt}, [X{rn}, #0x{imm12*2:X}]'
        elif (instr & 0xFFE0FC00) == 0xD63F0000:
            rn = (instr >> 5) & 0x1F
            desc = f'BLR X{rn}'
        elif (instr & 0x7F000000) == 0x71000000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            desc = f'CMP W{rn}, #0x{imm12:X}'
        elif (instr & 0xFF000000) == 0xEB000000:
            rm = (instr >> 16) & 0x1F
            rn = (instr >> 5) & 0x1F
            desc = f'CMP/SUBS X{rn}, X{rm}'
        elif (instr & 0x7F000000) == 0x72000000:
            desc = f'TST/ANDS 0x{instr:08X}'

        print(f'  0x{off:05X}: {desc}')

# Full disasm of the CRITICAL carrier unlock init path (0x37FC0 to 0x38420)
disasm_range(0x37FC0, 0x38420, "FULL CARRIER UNLOCK INIT PATH (0x37FC0-0x38420)")

# Check what strings are at 0x62074, 0x62068, 0x61F91, 0x62091, etc.
print('\n\n=== Error strings referenced in init path ===')
for addr_label in [(0x620B5, 'near -2'), (0x6208E, 'near verify'), (0x61F82, 'near -1'),
                    (0x62068, 'failed -1'), (0x62074, 'failed -2'),
                    (0x620C6, 'related -2'), (0x620F8, 'related -3'),
                    (0x61F91, 'related -1')]:
    addr, lbl = addr_label
    s = ''
    p = addr
    while p < addr + 100:
        b = data[p]
        if b == 0: break
        s += chr(b) if 0x20 <= b < 0x7F else '.'
        p += 1
    print(f'  0x{addr:X} ({lbl}): "{s}"')

# Also check what GUID is at 0x69B10 (used in 0xEE50)
print('\n=== GUID at 0x69B10 ===')
g = data[0x69B10:0x69B20]
d1 = struct.unpack_from('<I', g, 0)[0]
d2 = struct.unpack_from('<H', g, 4)[0]
d3 = struct.unpack_from('<H', g, 6)[0]
d4 = g[8:16]
print(f'  {d1:08X}-{d2:04X}-{d3:04X}-{d4[0]:02X}{d4[1]:02X}-{d4[2]:02X}{d4[3]:02X}{d4[4]:02X}{d4[5]:02X}{d4[6]:02X}{d4[7]:02X}')

# And GUID at 0x69B90
print('\n=== GUID at 0x69B90 ===')
g = data[0x69B90:0x69BA0]
d1 = struct.unpack_from('<I', g, 0)[0]
d2 = struct.unpack_from('<H', g, 4)[0]
d3 = struct.unpack_from('<H', g, 6)[0]
d4 = g[8:16]
print(f'  {d1:08X}-{d2:04X}-{d3:04X}-{d4[0]:02X}{d4[1]:02X}-{d4[2]:02X}{d4[3]:02X}{d4[4]:02X}{d4[5]:02X}{d4[6]:02X}{d4[7]:02X}')

# Now trace function 0xEE50 (the last gate before FRP check)
disasm_range(0xEE50, 0xEF50, "Function 0xEE50 (last gate before FRP)")

# And function 0x34A18 (second-to-last gate)
disasm_range(0x34A18, 0x34B00, "Function 0x34A18")

# And function 0x2048 (verify function)
disasm_range(0x2048, 0x2100, "Function 0x2048")

# And function 0x1DB4
disasm_range(0x1DB4, 0x1E60, "Function 0x1DB4")
