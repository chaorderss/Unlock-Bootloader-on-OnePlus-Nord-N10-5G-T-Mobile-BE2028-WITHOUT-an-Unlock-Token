import struct

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb').read()

str_va = 0x62E3B
print(f'String VA: 0x{str_va:X}')

def decode_adrp(instr, pc):
    immhi = (instr >> 5) & 0x7FFFF
    immlo = (instr >> 29) & 0x3
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    return (pc & ~0xFFF) + (imm << 12)

results = []
for i in range(0, 0x69000-4, 4):
    instr = struct.unpack_from('<I', data, i)[0]
    if (instr & 0x9F000000) == 0x90000000:
        page_va = decode_adrp(instr, i)
        if page_va == 0x62000:
            if i + 4 < len(data):
                next_instr = struct.unpack_from('<I', data, i+4)[0]
                if (next_instr & 0xFF800000) == 0x91000000:
                    imm12 = (next_instr >> 10) & 0xFFF
                    if imm12 == 0xE3B:
                        print(f'  ADRP+ADD ref at 0x{i:X}')
                        results.append(i)

print(f'Total refs: {len(results)}')

# Now find function boundaries for each ref and disassemble context
for ref in results:
    print(f'\n=== Context around 0x{ref:X} ===')
    start = max(0, ref - 60)
    for off in range(start, min(len(data), ref + 60), 4):
        instr = struct.unpack_from('<I', data, off)[0]
        marker = ' <<<<' if off == ref else ''
        print(f'  0x{off:X}: {instr:08X}{marker}')
