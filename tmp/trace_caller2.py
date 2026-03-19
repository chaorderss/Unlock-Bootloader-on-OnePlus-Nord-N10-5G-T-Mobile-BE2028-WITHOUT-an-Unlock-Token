import struct

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb').read()

def decode_adrp(instr, pc):
    immhi = (instr >> 5) & 0x7FFFF
    immlo = (instr >> 29) & 0x3
    imm = (immhi << 2) | immlo
    if imm & (1 << 20): imm -= (1 << 21)
    return (pc & ~0xFFF) + (imm << 12)

def decode_bl(instr, pc):
    imm26 = instr & 0x03FFFFFF
    if imm26 & 0x02000000: imm26 -= 0x04000000
    return pc + imm26 * 4

# ============================================================
# 1. Read strings near 0x66E08 and 0x66E19 (printed by caller)
# ============================================================
print("=" * 70)
print("1. Strings printed by caller function")
print("=" * 70)

for addr in [0x66E08, 0x66E19]:
    s = data[addr:addr+80]
    # Try ASCII
    end = s.find(b'\x00')
    if end > 0:
        print(f"  0x{addr:05X}: \"{s[:end].decode('ascii', errors='replace')}\"")
    else:
        print(f"  0x{addr:05X}: {s[:40].hex()}")

# ============================================================
# 2. What is X20 in the caller? Trace back to function entry
# ============================================================
print("\n" + "=" * 70)
print("2. Tracing X20 in caller function")
print("=" * 70)

# Function starts around 0x49B64 (prologue found there)
# Disassemble from 0x49B64 to 0x49CDC to find where X20 is set
for off in range(0x49B64, 0x49CE0, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    desc = ''

    # Check for MOV X20, Xn or any write to X20
    rd = instr & 0x1F
    if rd == 20:  # X20 or W20
        # MOV Xd, Xm: AA xx 03 E0 + rd
        if (instr & 0xFFE0FC00) == 0xAA0003E0:
            rm = (instr >> 16) & 0x1F
            desc = f'MOV X20, X{rm}'
        elif (instr & 0xFFE0FC00) == 0x2A0003E0:
            rm = (instr >> 16) & 0x1F
            desc = f'MOV W20, W{rm}'
        elif (instr & 0xFF800000) == 0x91000000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            sh = (instr >> 22) & 1
            val = imm12 << (12 if sh else 0)
            desc = f'ADD X20, X{rn}, #0x{val:X}'
        elif (instr & 0xFF800000) == 0xD1000000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            desc = f'SUB X20, X{rn}, #0x{imm12:X}'
        elif (instr & 0xFFC00000) == 0xF9400000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            desc = f'LDR X20, [X{rn}, #0x{imm12*8:X}]'
        elif (instr & 0xFFC00000) == 0xB9400000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            desc = f'LDR W20, [X{rn}, #0x{imm12*4:X}]'
        elif (instr & 0x9F000000) == 0x90000000:
            desc = f'ADRP X20, 0x{decode_adrp(instr, off):X}'

    if desc:
        print(f'  0x{off:05X}: {instr:08X}  {desc}')

# ============================================================
# 3. Check function 0x2A758 (fills the buffer via tail call)
# ============================================================
print("\n" + "=" * 70)
print("3. Function 0x2A758 (fills the buffer)")
print("=" * 70)

for off in range(0x2A758, 0x2A850, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    desc = f'raw 0x{instr:08X}'

    if instr == 0xD65F03C0: desc = 'RET'
    elif (instr & 0xFC000000) == 0x94000000:
        desc = f'BL 0x{decode_bl(instr, off):X}'
    elif (instr & 0xFC000000) == 0x14000000:
        imm26 = instr & 0x03FFFFFF
        if imm26 & 0x02000000: imm26 -= 0x04000000
        desc = f'B 0x{off + imm26*4:X}'
    elif (instr & 0x9F000000) == 0x90000000:
        desc = f'ADRP X{instr&0x1F}, 0x{decode_adrp(instr, off):X}'
    elif (instr & 0xFF800000) == 0x91000000:
        imm12 = (instr >> 10) & 0xFFF
        rd = instr & 0x1F; rn = (instr >> 5) & 0x1F
        desc = f'ADD X{rd}, X{rn}, #0x{imm12:X}'
    elif (instr & 0xFFC00000) == 0xF9400000:
        imm12 = (instr >> 10) & 0xFFF
        rn = (instr >> 5) & 0x1F; rt = instr & 0x1F
        desc = f'LDR X{rt}, [X{rn}, #0x{imm12*8:X}]'
    elif (instr & 0xFFC00000) == 0xF9000000:
        imm12 = (instr >> 10) & 0xFFF
        rn = (instr >> 5) & 0x1F; rt = instr & 0x1F
        desc = f'STR X{rt}, [X{rn}, #0x{imm12*8:X}]'
    elif (instr & 0xFFE0FC00) == 0xAA0003E0:
        rm = (instr >> 16) & 0x1F; rd = instr & 0x1F
        desc = f'MOV X{rd}, X{rm}'
    elif (instr & 0x7E000000) == 0x34000000:
        imm19 = (instr >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 -= 0x80000
        op = 'CBNZ' if (instr >> 24) & 1 else 'CBZ'
        reg = instr & 0x1F
        size = 'W' if (instr >> 31) == 0 else 'X'
        desc = f'{op} {size}{reg} -> 0x{off + imm19*4:X}'
    elif (instr & 0xFF000000) == 0x54000000:
        imm19 = (instr >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 -= 0x80000
        cond = instr & 0xF
        conds = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
        desc = f'B.{conds[cond]} 0x{off + imm19*4:X}'

    print(f'  0x{off:05X}: {instr:08X}  {desc}')

# ============================================================
# 4. KEY: Check what happens in 0x37D38 when buffer doesn't match
# Does it still return the success marker 0x8000000000000000?
# ============================================================
print("\n" + "=" * 70)
print("4. Return value of 0x37D38 when 'cust-unlock' doesn't match")
print("=" * 70)

# At 0x37F80: CBZ X0 → 0x37FC0 (match → cascade)
# At 0x37F84: (no match) → what happens?
for off in range(0x37F84, 0x37FC0, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    desc = f'raw 0x{instr:08X}'
    if instr == 0xD65F03C0: desc = 'RET'
    elif (instr & 0xFC000000) == 0x94000000:
        desc = f'BL 0x{decode_bl(instr, off):X}'
    elif (instr & 0xFC000000) == 0x14000000:
        imm26 = instr & 0x03FFFFFF
        if imm26 & 0x02000000: imm26 -= 0x04000000
        desc = f'B 0x{off + imm26*4:X}'
    elif (instr & 0xFFE0FC00) == 0xAA0003E0:
        rm = (instr >> 16) & 0x1F; rd = instr & 0x1F
        desc = f'MOV X{rd}, X{rm}'
    elif (instr & 0xFFC00000) == 0xF9400000:
        imm12 = (instr >> 10) & 0xFFF
        rn = (instr >> 5) & 0x1F; rt = instr & 0x1F
        desc = f'LDR X{rt}, [X{rn}, #0x{imm12*8:X}]'
    print(f'  0x{off:05X}: {instr:08X}  {desc}')

# The return path starting at 0x37F88:
print("\n--- Return path 0x37F88-0x37FC0 ---")
for off in range(0x37F88, 0x37FC0, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    desc = f'raw 0x{instr:08X}'
    if instr == 0xD65F03C0: desc = 'RET'
    elif (instr & 0xFFE0FC00) == 0xAA0003E0:
        rm = (instr >> 16) & 0x1F; rd = instr & 0x1F
        desc = f'MOV X{rd}, X{rm}'
    print(f'  0x{off:05X}: {instr:08X}  {desc}')

# ============================================================
# 5. Trace what 0xD214 returns (used to set X20 in 0x37D38)
# ============================================================
print("\n" + "=" * 70)
print("5. Function 0xD214 (called by both 0x36CA8 and 0x37D38)")
print("=" * 70)

for off in range(0xD214, 0xD2C0, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    desc = f'raw 0x{instr:08X}'
    if instr == 0xD65F03C0: desc = 'RET'
    elif (instr & 0xFC000000) == 0x94000000:
        desc = f'BL 0x{decode_bl(instr, off):X}'
    elif (instr & 0x9F000000) == 0x90000000:
        desc = f'ADRP X{instr&0x1F}, 0x{decode_adrp(instr, off):X}'
    elif (instr & 0xFF800000) == 0x91000000:
        imm12 = (instr >> 10) & 0xFFF
        rd = instr & 0x1F; rn = (instr >> 5) & 0x1F
        desc = f'ADD X{rd}, X{rn}, #0x{imm12:X}'
    elif (instr & 0xFFC00000) == 0xF9400000:
        imm12 = (instr >> 10) & 0xFFF
        rn = (instr >> 5) & 0x1F; rt = instr & 0x1F
        desc = f'LDR X{rt}, [X{rn}, #0x{imm12*8:X}]'
    elif (instr & 0xFFC00000) == 0xF9000000:
        imm12 = (instr >> 10) & 0xFFF
        rn = (instr >> 5) & 0x1F; rt = instr & 0x1F
        desc = f'STR X{rt}, [X{rn}, #0x{imm12*8:X}]'
    elif (instr & 0x7E000000) == 0x34000000:
        imm19 = (instr >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 -= 0x80000
        op = 'CBNZ' if (instr >> 24) & 1 else 'CBZ'
        reg = instr & 0x1F
        size = 'W' if (instr >> 31) == 0 else 'X'
        desc = f'{op} {size}{reg} -> 0x{off + imm19*4:X}'
    elif (instr & 0xFFE0FC00) == 0xAA0003E0:
        rm = (instr >> 16) & 0x1F; rd = instr & 0x1F
        desc = f'MOV X{rd}, X{rm}'
    print(f'  0x{off:05X}: {instr:08X}  {desc}')

# ============================================================
# 6. What string is at 0x61854 and neighbors for full context
# ============================================================
print("\n" + "=" * 70)
print("6. UTF-16 strings in the 0x618xx range (operation modes)")
print("=" * 70)

for addr in range(0x61840, 0x618C0, 2):
    c = struct.unpack_from('<H', data, addr)[0]
    if 0x20 <= c < 0x7F:
        pass  # printable
    elif c == 0:
        pass  # null
    else:
        continue

# Just dump the raw data and interpret
raw = data[0x61840:0x618C0]
off = 0
while off < len(raw):
    # Find start of UTF-16 string
    c = struct.unpack_from('<H', raw, off)[0]
    if c == 0:
        off += 2
        continue
    if 0x20 <= c < 0x7F:
        s = ""
        start = off
        while off < len(raw):
            c = struct.unpack_from('<H', raw, off)[0]
            if c == 0:
                break
            if 0x20 <= c < 0x7F:
                s += chr(c)
            else:
                s += f'\\x{c:04x}'
            off += 2
        print(f"  0x{0x61840+start:05X}: \"{s}\"")
    else:
        off += 2

# ============================================================
# 7. Check if there's a second caller path to 0x37D38
# Maybe 0x37D38 is called from somewhere ELSE too
# ============================================================
print("\n" + "=" * 70)
print("7. ALL callers of 0x37D38")
print("=" * 70)

for off in range(0x1000, 0x6A000, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr & 0xFC000000) == 0x94000000:
        target = decode_bl(instr, off)
        if target == 0x37D38:
            print(f'  0x{off:05X}: BL 0x37D38')

# Also check 0x36CA8
print("\nALL callers of 0x36CA8:")
for off in range(0x1000, 0x6A000, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr & 0xFC000000) == 0x94000000:
        target = decode_bl(instr, off)
        if target == 0x36CA8:
            print(f'  0x{off:05X}: BL 0x36CA8')

# ============================================================
# 8. Check all callers of 0x3BB48 (carrier check function)
# This is what produces "Please flash unlock token first"
# ============================================================
print("\nALL callers of 0x3BB48:")
for off in range(0x1000, 0x6A000, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr & 0xFC000000) == 0x94000000:
        target = decode_bl(instr, off)
        if target == 0x3BB48:
            print(f'  0x{off:05X}: BL 0x3BB48')

# ============================================================
# 9. Full caller of 0x3BB48 — the OEM unlock handler
# ============================================================
print("\n" + "=" * 70)
print("9. OEM unlock handler around 0x48810 (calls 0x3BB48)")
print("=" * 70)

for off in range(0x48810, 0x48900, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    desc = f'raw 0x{instr:08X}'

    if instr == 0xD65F03C0: desc = 'RET'
    elif (instr & 0xFC000000) == 0x94000000:
        desc = f'BL 0x{decode_bl(instr, off):X}'
    elif (instr & 0xFC000000) == 0x14000000:
        imm26 = instr & 0x03FFFFFF
        if imm26 & 0x02000000: imm26 -= 0x04000000
        desc = f'B 0x{off + imm26*4:X}'
    elif (instr & 0x9F000000) == 0x90000000:
        desc = f'ADRP X{instr&0x1F}, 0x{decode_adrp(instr, off):X}'
    elif (instr & 0xFF800000) == 0x91000000:
        imm12 = (instr >> 10) & 0xFFF
        rd = instr & 0x1F; rn = (instr >> 5) & 0x1F
        desc = f'ADD X{rd}, X{rn}, #0x{imm12:X}'
    elif (instr & 0xFFC00000) == 0xF9400000:
        imm12 = (instr >> 10) & 0xFFF
        rn = (instr >> 5) & 0x1F; rt = instr & 0x1F
        desc = f'LDR X{rt}, [X{rn}, #0x{imm12*8:X}]'
    elif (instr & 0x7E000000) == 0x34000000:
        imm19 = (instr >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 -= 0x80000
        op = 'CBNZ' if (instr >> 24) & 1 else 'CBZ'
        reg = instr & 0x1F
        size = 'W' if (instr >> 31) == 0 else 'X'
        desc = f'{op} {size}{reg} -> 0x{off + imm19*4:X}'
    elif (instr & 0xFF000000) == 0x54000000:
        imm19 = (instr >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 -= 0x80000
        cond = instr & 0xF
        conds = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
        desc = f'B.{conds[cond]} 0x{off + imm19*4:X}'
    elif (instr & 0xFFE0FC00) == 0xAA0003E0:
        rm = (instr >> 16) & 0x1F; rd = instr & 0x1F
        desc = f'MOV X{rd}, X{rm}'
    elif (instr & 0xFFC00000) == 0x39400000:
        imm12 = (instr >> 10) & 0xFFF
        rn = (instr >> 5) & 0x1F; rt = instr & 0x1F
        desc = f'LDRB W{rt}, [X{rn}, #0x{imm12:X}]'

    print(f'  0x{off:05X}: {instr:08X}  {desc}')
