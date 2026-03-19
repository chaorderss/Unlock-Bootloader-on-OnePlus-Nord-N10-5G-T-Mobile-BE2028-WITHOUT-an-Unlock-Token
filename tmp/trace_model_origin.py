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
            desc = f'BR/BLR X{rn}'

        print(f'  0x{off:05X}: {desc}')

# =============================================
# 1. Function 0x38610 - the model string GETTER
# =============================================
disasm_range(0x38610, 0x38620, "0x38610 - GetModelString (getter)")
# 0x38610: ADRP X8, 0x1BD000
# 0x38614: ADD X8, X8, #0x978  → X8 = 0x1BD978
# 0x38618: LDR W0, [X8, ...]  → reads and returns value from [0x1BD978]
# 0x3861C: RET

print("\n  → Model string pointer stored at 0x1BD978 (runtime global)")

# =============================================
# 2. Function 0x38620 - the model string SETTER
# =============================================
disasm_range(0x38620, 0x38680, "0x38620 - SetModelString (setter)")

# =============================================
# 3. Find ALL callers of the setter 0x38620
# =============================================
print('\n=== Callers of 0x38620 (SetModelString setter) ===')
for off in range(0, len(data)-4, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr & 0xFC000000) == 0x94000000:
        target = decode_bl(instr, off)
        if target == 0x38620:
            print(f'  0x{off:05X}: BL 0x38620')

# =============================================
# 4. Find ALL writes to 0x1BD978 (STR to this address)
# =============================================
print('\n=== Looking for STRB/STR writes to 0x1BD978 ===')
# The global is at 0x1BD978. After ADRP+ADD or ADRP+STR
# ADRP page is 0x1BD000, offset is 0x978
# For STR X, the offset encoding is imm12*8, so 0x978/8 = 0x12F
# For STR W, the offset encoding is imm12*4, so 0x978/4 = 0x25E
# For direct STR after ADRP+ADD, also check

# Scan for ADRP 0x1BD000 followed by operations on +0x978
for off in range(0, len(data)-8, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr & 0x9F000000) == 0x90000000:
        page = decode_adrp(instr, off)
        if page == 0x1BD000:
            # Check next few instructions for ADD/STR with offset 0x978
            for delta in range(1, 6):
                next_off = off + delta * 4
                if next_off >= len(data) - 4:
                    break
                next_instr = struct.unpack_from('<I', data, next_off)[0]
                # Check for STR Xt, [Xn, #0x978*scale]
                # Or ADD Xd, Xn, #0x978 followed by STR
                if (next_instr & 0xFF800000) == 0x91000000:  # ADD immediate
                    add_imm = (next_instr >> 10) & 0xFFF
                    sh = (next_instr >> 22) & 1
                    if sh: add_imm <<= 12
                    if add_imm == 0x978:
                        rd = next_instr & 0x1F
                        rn_add = (next_instr >> 5) & 0x1F
                        # Check what follows - is it a store?
                        for delta2 in range(1, 5):
                            store_off = next_off + delta2 * 4
                            if store_off >= len(data) - 4:
                                break
                            si = struct.unpack_from('<I', data, store_off)[0]
                            # STR Xt, [Xn, #0] or STR Wt, [Xn, #0]
                            if (si & 0xBFC003E0) == (0xB9000000 | (rd << 5)):
                                st_imm = (si >> 10) & 0xFFF
                                if st_imm == 0:
                                    st_rt = si & 0x1F
                                    print(f'  0x{off:05X}: ADRP 0x1BD000 → 0x{next_off:05X}: ADD +0x978 → 0x{store_off:05X}: STR W/X{st_rt}')

# Also check for direct STR with scaled offset
# STR Wt, [Xn, #0x25E*4] = STR Wt, [Xn, #0x978]
for off in range(0, len(data)-4, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr & 0xFFC00000) == 0xB9000000:  # STR W
        imm12 = (instr >> 10) & 0xFFF
        if imm12 * 4 == 0x978:
            rn = (instr >> 5) & 0x1F
            print(f'  0x{off:05X}: STR W, [X{rn}, #0x978] (direct scaled)')

# =============================================
# 5. Check where model string originates
# =============================================
# The setter 0x38620 takes X0 as 1st arg (the source buffer)
# and writes to [0x1BD978] via memcpy-like function
# Let's trace the setter's callers

# Also: check what's at 0x5BEEE (the format string used in SetModelString)
print('\n=== String at 0x5BEE5 ===')
s = data[0x5BEE5:0x5BF20]
null = s.find(b'\x00')
if null >= 0: s = s[:null]
print(f'  "{s.decode("ascii", errors="replace")}"')

# =============================================
# 6. Check all strings that look like model numbers
# =============================================
print('\n=== International model numbers in binary ===')
# OnePlus Nord N10 models:
# 20888 = T-Mobile US
# 20882 = ?
# 20880 = EU/Global
# 20885 = ?
# 18831, 19861, 19863, 19855, 20809 = from init table

# Check what models are NOT in the carrier check list
# The carrier check (0x3BB48) only checks: 20888, 20882, 20880, 20885
# The init table also has: 18831, 19861, 19863, 19855, 20809

# If we change model to one NOT in {20888,20882,20880,20885},
# the carrier check skips to return 1 immediately

# BUT: where does the model string come from? Is it from a partition?
# Let's look at the caller of 0x38620

print('\n=== Tracing callers of SetModelString ===')
# From the 0x38620 function:
# X0 = source (the model number being set), X1 = dest buffer (0x1BD978)
# It does: get model string len, then memcpy-like

# Let's also check the string "ro.boot.prjname" or similar
# OEM properties are often stored in op2 or opproduct partitions
for off in range(0, len(data), 1):
    chunk = data[off:off+10]
    if b'prjname' in chunk or b'project' in chunk.lower() or b'rf_version' in chunk.lower():
        ctx = data[max(0,off-5):off+40]
        null = ctx.find(b'\x00', 10)
        if null >= 0: ctx = ctx[:null]
        try:
            print(f'  0x{off:X}: "{ctx.decode("ascii", errors="replace")}"')
        except:
            pass

# Search for "model" string in the binary
print('\n=== "model" strings in binary ===')
off = 0
count = 0
while off < len(data) and count < 20:
    idx = data.find(b'model', off)
    if idx == -1:
        break
    # Get surrounding context
    start = max(0, idx - 5)
    end = min(len(data), idx + 40)
    ctx = data[start:end]
    try:
        s = ctx.decode('ascii', errors='replace')
        if any(c.isprintable() for c in s[:10]):
            print(f'  0x{idx:X}: "{s.rstrip(chr(0))}"')
            count += 1
    except:
        pass
    off = idx + 1
