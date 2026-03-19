#!/usr/bin/env python3
import struct

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin','rb').read()

def find_adrp_add_refs(target):
    """Find all ADRP+ADD instruction pairs that load 'target' address"""
    target_page = target & ~0xfff
    target_off = target & 0xfff
    results = []
    for off in range(0x1000, 0x69000, 4):
        insn = struct.unpack_from('<I', data, off)[0]
        if (insn & 0x9f000000) == 0x90000000:  # ADRP
            rd = insn & 0x1f
            imm_lo = (insn >> 29) & 3
            imm_hi = (insn >> 5) & 0x7ffff
            imm = ((imm_hi << 2) | imm_lo) << 12
            if imm & (1 << 32): imm -= (1 << 33)
            pc_page = off & ~0xfff
            target_page_found = (pc_page + imm) & 0xffffffffffff
            if target_page_found == target_page:
                next_insn = struct.unpack_from('<I', data, off+4)[0] if off+4 < len(data) else 0
                if (next_insn & 0xffc00000) == 0x91000000:  # ADD
                    imm12 = (next_insn >> 10) & 0xfff
                    if imm12 == target_off:
                        results.append(off)
    return results

# Find references to "unknown command"
print('=== Refs to "unknown command" (0x62bce) ===')
refs = find_adrp_add_refs(0x62bce)
for r in refs:
    print(f'  0x{r:x}')

# Find references to the command dispatch table (0x633b8)
print('\n=== Refs to command dispatch table (0x633b8) ===')
refs2 = find_adrp_add_refs(0x633b8)
for r in refs2:
    print(f'  0x{r:x}')

# Also search for load of 0x633b8 using LDR/LDUR variants
# The table starts at 0x633b8 which is .text section since text = 0x1000..0x69FFF
# BUT wait: I established text VAddr=0x1000, VSize=0x69000 → text = 0x1000..0x69FFF
# But 0x633b8 > 0x69FFF? Let me check: 0x1000 + 0x69000 = 0x6a000. So 0x69FFF is end.
# So 0x633b8 IS in .text! Not .data.

print('\n=== Read first 50 bytes raw at 0x633b8 to verify ===')
for j in range(0, 50, 8):
    v = struct.unpack_from('<Q', data, 0x633b8+j)[0]
    print(f'  0x{0x633b8+j:x}: {v:#018x}')

# Now let's look at what loads from the dispatch table
# The table entries are 8-byte pointers
# Search for code that loads from 0x633b8 area
print('\n=== Checking section boundaries ===')
# .text: VAddr=0x1000, VSize=0x69000 → 0x1000 to 0x69FFF
# .data: VAddr=0x6a000
print(f'text_end = 0x{0x1000+0x69000-1:x} = 0x69FFF')
print(f'data_start = 0x6a000')
print(f'0x633b8 in .text: {0x633b8 <= 0x69FFF}')
