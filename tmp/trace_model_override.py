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
        elif instr == 0xD65F03C0:
            desc = 'RET'
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
        elif (instr & 0xFF800000) == 0xD1000000:
            imm12 = (instr >> 10) & 0xFFF
            rd = instr & 0x1F
            rn = (instr >> 5) & 0x1F
            desc = f'SUB X{rd}, X{rn}, #0x{imm12:X}'
        print(f'  0x{off:05X}: {desc}')

# =============================================
# 1. Find "SoftwareProjectID" references
# =============================================
print('=== Finding SoftwareProjectID references ===')
# The string "SoftwareProjectID" is at 0x60673
# Let's find all references - page 0x60000, offset 0x673
for off in range(0, len(data)-8, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr & 0x9F000000) == 0x90000000:
        page = decode_adrp(instr, off)
        if page == 0x60000:
            next_instr = struct.unpack_from('<I', data, off+4)[0]
            if (next_instr & 0xFF800000) == 0x91000000:
                add_imm = (next_instr >> 10) & 0xFFF
                sh = (next_instr >> 22) & 1
                if sh: add_imm <<= 12
                # Multiple potential strings around 0x60673, 0x606DF, 0x6075C
                if add_imm in [0x673, 0x66E, 0x6DF, 0x75C, 0x77F, 0x68D, 0x690]:
                    string_addr = page + add_imm
                    s = data[string_addr:string_addr+40]
                    null = s.find(b'\x00')
                    if null >= 0: s = s[:null]
                    print(f'  0x{off:05X}: ref to 0x{string_addr:X} "{s.decode("ascii", errors="replace")}"')

# =============================================
# 2. Find "param sw project id" references
# =============================================
print('\n=== Finding "param sw project id" references ===')
param_str = b'param sw project id'
idx = data.find(param_str)
print(f'  String at 0x{idx:X}')
page = idx & ~0xFFF
offset = idx & 0xFFF
for off in range(0, len(data)-8, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr & 0x9F000000) == 0x90000000:
        p = decode_adrp(instr, off)
        if p == page:
            next_instr = struct.unpack_from('<I', data, off+4)[0]
            if (next_instr & 0xFF800000) == 0x91000000:
                add_imm = (next_instr >> 10) & 0xFFF
                if add_imm == offset:
                    print(f'  ADRP+ADD ref at 0x{off:X}')
                    # Show wide context
                    disasm(off - 0x40, off + 0x40, f"Context of param sw project id ref at 0x{off:X}")

# =============================================
# 3. Check the init function for SoftwareProjectID override
# =============================================
# The init runs from param partition. Let's look at who reads SoftwareProjectID
# and whether it calls SetModelString (0x38620)
#
# 0x35CD0 is the ONLY caller of SetModelString.
# Let's look at the broader function it's in
print('\n=== Broader function containing SetModelString call ===')
# Search backward from 0x35CD0 for function prologue
for off in range(0x35000, 0x35CD0, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    # SUB SP, SP, #imm (stack frame setup)
    if (instr & 0xFF800000) == 0xD1000000:
        rd = instr & 0x1F
        rn = (instr >> 5) & 0x1F
        if rd == 31 and rn == 31:
            # Check if this is followed by STP (register save)
            next_instr = struct.unpack_from('<I', data, off+4)[0]
            if (next_instr >> 24) == 0xA9:
                imm12 = (instr >> 10) & 0xFFF
                print(f'  Possible function prologue at 0x{off:X} (SUB SP, SP, #0x{imm12:X})')

# The function likely starts around 0x349xx or 0x34Axx
# Let me check what reads SMEM
print('\n=== SMEM_PROJECT_INFO references ===')
smem_str = b'SMEM_PROJECT_INFO'
idx3 = data.find(smem_str)
if idx3 >= 0:
    print(f'  String at 0x{idx3:X}')
    s = data[idx3-20:idx3+50]
    print(f'  Context: {s}')

# Let's specifically look for smem_get_addr or similar SMEM reads
# In Qualcomm ABL, SMEM is read via protocol
# The key: is there a "sw project id from param" that overrides SMEM model?

# =============================================
# 4. Dump the function from 0x35980 (likely start) through the SetModelString call
# =============================================
# Let me look for the SMEM read near the SetModelString call
# The SetModelString call is at 0x35CD0
# Just before: 0x35CCC loads something and passes to SetModelString
# Let me trace further back

# 0x35C80: loads W20 from somewhere
# 0x35C88: MOV W8, #0xF893 + MOVK → 0xDC9EF893 (SMEM magic)
# 0x35C90: CMP W20, W8 → checks if SMEM data has correct magic
# This is clearly reading from SMEM shared memory

# The question is: is the model number ALSO read from param?
# Let's look for "SoftwareProjectIDProcState" which might indicate
# a param-based project ID processing state

print('\n=== SoftwareProjectIDProcState refs ===')
for s_str in [b'SoftwareProjectIDProcState\x00']:
    idx = data.find(s_str)
    if idx >= 0:
        page = idx & ~0xFFF
        offset = idx & 0xFFF
        for off in range(0, len(data)-8, 4):
            instr = struct.unpack_from('<I', data, off)[0]
            if (instr & 0x9F000000) == 0x90000000:
                p = decode_adrp(instr, off)
                if p == page:
                    next_instr = struct.unpack_from('<I', data, off+4)[0]
                    if (next_instr & 0xFF800000) == 0x91000000:
                        add_imm = (next_instr >> 10) & 0xFFF
                        if add_imm == offset:
                            print(f'  Ref at 0x{off:X}')
                            disasm(off - 0x30, off + 0x30, f"SoftwareProjectIDProcState context at 0x{off:X}")

# =============================================
# 5. Check the FULL function containing the "param sw project id" flow
# =============================================
# Let me also look for what function processes param data and if it can modify project ID
# Search for writes to the same global [0x1BE350] that SetModelString uses
print('\n=== Searching for writes to [0x1BE350] ===')
# ADRP page 0x1BE000, for STR W the scaled offset = (0x350)/4 = 0xD4
# For LDR/STR W with base register: need ADRP 0x1BD000 + ADD 0x978 first, then STR [Xn, #0x9D8]

# Check all ADRP 0x1BD000 references
count = 0
for off in range(0, len(data)-8, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr & 0x9F000000) == 0x90000000:
        page = decode_adrp(instr, off)
        if page == 0x1BD000:
            next_instr = struct.unpack_from('<I', data, off+4)[0]
            if (next_instr & 0xFF800000) == 0x91000000:
                add_imm = (next_instr >> 10) & 0xFFF
                if add_imm == 0x978:
                    # Check next few for STR with offset 0x9D8
                    for d in range(2, 10):
                        si = struct.unpack_from('<I', data, off + d*4)[0]
                        if (si & 0xFFC00000) == 0xB9000000:
                            si_imm = (si >> 10) & 0xFFF
                            if si_imm * 4 == 0x9D8:
                                rt = si & 0x1F
                                count += 1
                                print(f'  0x{off:05X}: ADRP+ADD 0x1BD978 → 0x{off+d*4:05X}: STR W{rt} to +0x9D8')
                                if count < 5:
                                    disasm(off - 0x10, off + d*4 + 0x10, f"Write context at 0x{off:X}")

print(f'\n  Total writes to model global: {count}')
