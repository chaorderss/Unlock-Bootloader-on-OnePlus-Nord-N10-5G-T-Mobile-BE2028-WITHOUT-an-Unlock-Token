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

# =============================================
# 1. Search for the string "SoftwareProjectID" in ALL forms
# =============================================
print('=== All occurrences of "SoftwareProjectID" ===')
idx = 0
locs = []
while True:
    idx = data.find(b'SoftwareProjectID', idx)
    if idx == -1:
        break
    ctx = data[idx:idx+40]
    null = ctx.find(b'\x00')
    if null >= 0: ctx = ctx[:null]
    print(f'  0x{idx:X}: "{ctx.decode("ascii", errors="replace")}"')
    locs.append(idx)
    idx += 1

# =============================================
# 2. Check if they're referenced via a table/struct (not ADRP+ADD)
# =============================================
# Search for pointers to these addresses in the binary
print('\n=== Searching for pointers to SoftwareProjectID strings ===')
for loc in locs:
    # 64-bit pointer
    ptr64 = struct.pack('<Q', loc)
    for off in range(0, len(data)-8, 8):
        if data[off:off+8] == ptr64:
            print(f'  Pointer to 0x{loc:X} found at 0x{off:X}')
    # also check 32-bit
    ptr32 = struct.pack('<I', loc)
    for off in range(0, len(data)-4, 4):
        if data[off:off+4] == ptr32:
            print(f'  32-bit pointer to 0x{loc:X} found at 0x{off:X}')

# =============================================
# 3. Look for "param sw project" more carefully
# =============================================
print('\n=== "param sw project" occurrences ===')
idx = 0
while True:
    idx = data.find(b'param sw', idx)
    if idx == -1: break
    ctx = data[idx:idx+50]
    null = ctx.find(b'\x00')
    if null >= 0: ctx = ctx[:null]
    print(f'  0x{idx:X}: "{ctx.decode("ascii", errors="replace")}"')
    idx += 1

# =============================================
# 4. The carrier check (0x3BB48) calls:
#    - 0x38610: GetModelNum → returns W0 = integer (e.g., 20888)
#    - 0x39D08: converts integer to string
#    - 0x2A1EC: compares string
#
# If we look at 0x39D08, it takes W0=20888 and returns X0 pointing to "20888" string
# But what if it reads from ANOTHER source too?
# =============================================
print('\n=== Function 0x39D08 - model int to string converter ===')
for off in range(0x39D08, 0x39E40, 4):
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
    elif (instr & 0xFF800000) == 0x52800000:
        hw = (instr >> 21) & 0x3
        imm16 = (instr >> 5) & 0xFFFF
        rd = instr & 0x1F
        val = imm16 << (hw*16)
        desc = f'MOV W{rd}, #0x{val:X} ({val})'
    elif (instr & 0xFF800000) == 0x72A00000:
        hw = (instr >> 21) & 0x3
        imm16 = (instr >> 5) & 0xFFFF
        rd = instr & 0x1F
        desc = f'MOVK W{rd}, #0x{imm16:X}, LSL#{hw*16}'
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
    elif (instr & 0x7F000000) == 0x71000000:
        imm12 = (instr >> 10) & 0xFFF
        rn = (instr >> 5) & 0x1F
        desc = f'CMP W{rn}, #0x{imm12:X}'
    elif (instr & 0xFFC003FF) == 0x6B00001F:
        rm = (instr >> 16) & 0x1F
        rn = (instr >> 5) & 0x1F
        desc = f'CMP W{rn}, W{rm}'
    elif (instr & 0xFFE00000) == 0x2A000000:
        rm = (instr >> 16) & 0x1F
        rn = (instr >> 5) & 0x1F
        rd = instr & 0x1F
        if rn == 31: desc = f'MOV W{rd}, W{rm}'
        else: desc = f'ORR W{rd}, W{rn}, W{rm}'
    elif (instr & 0xFFE00000) == 0xAA000000:
        rm = (instr >> 16) & 0x1F
        rn = (instr >> 5) & 0x1F
        rd = instr & 0x1F
        if rn == 31: desc = f'MOV X{rd}, X{rm}'
        else: desc = f'ORR X{rd}, X{rn}, X{rm}'

    print(f'  0x{off:05X}: {desc}')
    if desc == 'RET' and off > 0x39D40:
        break

# =============================================
# 5. Decode what 20888 becomes in 0x39D08
# =============================================
print('\n=== Decoding 0x39D08 comparisons ===')
# Looking at the function, it compares W0 (the model integer) against various values
# If match → returns a string pointer from a table
# The MOV + MOVK sequences build comparison values

# 0x39D08: MOV W9, #imm
# 0x39D0C: MOVK W9, #imm, LSL#16
# Then CMP W8, W9

# Decode each MOV+MOVK pair
comparisons = [
    (0x39D08, 0x39D0C),
]

# Actually let me decode each MOVZ+MOVK combo in the function
off = 0x39D08
last_movz = {}
while off < 0x39E40:
    instr = struct.unpack_from('<I', data, off)[0]

    # MOVZ
    if (instr & 0xFF800000) == 0x52800000:
        hw = (instr >> 21) & 0x3
        imm16 = (instr >> 5) & 0xFFFF
        rd = instr & 0x1F
        last_movz[rd] = imm16 << (hw * 16)
    # MOVK
    elif (instr & 0xFF800000) == 0x72800000:
        hw = (instr >> 21) & 0x3
        imm16 = (instr >> 5) & 0xFFFF
        rd = instr & 0x1F
        if rd in last_movz:
            val = last_movz[rd] | (imm16 << (hw * 16))
            print(f'  0x{off:05X}: W{rd} = 0x{val:08X} ({val})')
    # CMP
    elif (instr & 0x7F000000) == 0x71000000:
        imm12 = (instr >> 10) & 0xFFF
        rn = (instr >> 5) & 0x1F
        print(f'  0x{off:05X}: CMP W{rn}, #{imm12}')

    if instr == 0xD65F03C0:
        break
    off += 4

# =============================================
# 6. Check the carrier table entries for "international" models
# =============================================
print('\n=== Carrier table entries ===')
table_base = 0x62488
struct_size = 0x58

# init function model comparisons and their indices:
# 0: 18831 (OnePlus 7T?)
# 1: 19861
# 2: 19863
# 3: 19855
# 4: 20809
# 5: 20882
# 6: 20880
# 7: 20888 (T-Mobile)
# 8: 20885
# 9+: unknown

model_names = {0:'18831', 1:'19861', 2:'19863', 3:'19855', 4:'20809',
               5:'20882', 6:'20880', 7:'20888', 8:'20885'}

for idx in range(10):
    addr = idx * struct_size + table_base
    if addr + struct_size > len(data):
        break
    cid = struct.unpack_from('<I', data, addr + 0x40)[0]
    name = model_names.get(idx, '?')
    # Also read the model name string pointer from the entry
    name_ptr = struct.unpack_from('<Q', data, addr + 0x50)[0]
    if 0 < name_ptr < len(data):
        ns = data[name_ptr:name_ptr+20]
        null = ns.find(b'\x00')
        if null >= 0: ns = ns[:null]
        name_s = ns.decode('ascii', errors='replace')
    else:
        name_s = '?'
    print(f'  Index {idx}: model={name}, carrier_id={cid}, name_ptr=0x{name_ptr:X} → "{name_s}"')

# =============================================
# 7. The KEY question: in the carrier check, which function provides
# the model comparison strings? They're in the DATA section.
# "20888" is at 0x5F524, "20882" at 0x5F53B, "20880" at 0x5FB26, "20885" at 0x5FB2C
# These are ASCII strings in the image's .data/.rodata section
# We CAN'T change them (ABL is signed)
# =============================================

# BUT: Let's check what the init function at 0x37D38 does DIFFERENTLY
# for non-carrier models (like 18831, 19861, etc.)
# If those have carrier_id == 9, they hit the early return at 0x37F84
# If not, they go through the protocol path and potentially set [0x1BF518]

print('\n=== Carrier IDs for all models ===')
carrier_check_models = {'20888', '20882', '20880', '20885'}
for idx in range(9):
    addr = idx * struct_size + table_base
    cid = struct.unpack_from('<I', data, addr + 0x40)[0]
    name = model_names.get(idx, '?')
    in_check = name in carrier_check_models
    note = ''
    if cid == 9:
        note = ' → EARLY RETURN (carrier_id==9, init skips [0x1BF518] write)'
    elif in_check:
        note = f' → IN CARRIER CHECK LIST (needs [0x1BF518]==1)'
    else:
        note = ' → NOT in carrier check list (carrier check auto-passes!)'
    print(f'  {name}: carrier_id={cid}{note}')
