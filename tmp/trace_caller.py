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

def disasm(start, end, label=""):
    if label: print(f"\n--- {label} ---")
    for off in range(start, end, 4):
        instr = struct.unpack_from('<I', data, off)[0]
        desc = f'raw 0x{instr:08X}'

        # Decode common instructions
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
            rd = instr & 0x1F
            rn = (instr >> 5) & 0x1F
            sh = (instr >> 22) & 1
            val = imm12 << (12 if sh else 0)
            desc = f'ADD X{rd}, X{rn}, #0x{val:X}'
        elif (instr & 0xFF800000) == 0xD1000000:
            imm12 = (instr >> 10) & 0xFFF
            rd = instr & 0x1F
            rn = (instr >> 5) & 0x1F
            desc = f'SUB X{rd}, X{rn}, #0x{imm12:X}'
        elif (instr & 0xFFC00000) == 0xF9400000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F; rt = instr & 0x1F
            desc = f'LDR X{rt}, [X{rn}, #0x{imm12*8:X}]'
        elif (instr & 0xFFC00000) == 0xF9000000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F; rt = instr & 0x1F
            desc = f'STR X{rt}, [X{rn}, #0x{imm12*8:X}]'
        elif (instr & 0xFFC00000) == 0xB9400000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F; rt = instr & 0x1F
            desc = f'LDR W{rt}, [X{rn}, #0x{imm12*4:X}]'
        elif (instr & 0xFFC00000) == 0xB9000000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F; rt = instr & 0x1F
            desc = f'STR W{rt}, [X{rn}, #0x{imm12*4:X}]'
        elif (instr & 0xFF000000) == 0x54000000:
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 & 0x40000: imm19 -= 0x80000
            cond = instr & 0xF
            conds = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
            desc = f'B.{conds[cond]} 0x{off + imm19*4:X}'
        elif (instr & 0x7E000000) == 0x34000000:
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 & 0x40000: imm19 -= 0x80000
            op = 'CBNZ' if (instr >> 24) & 1 else 'CBZ'
            reg = instr & 0x1F
            size = 'W' if (instr >> 31) == 0 else 'X'
            desc = f'{op} {size}{reg} -> 0x{off + imm19*4:X}'
        elif (instr & 0xFFE0FC00) == 0xAA0003E0:
            rm = (instr >> 16) & 0x1F
            rd = instr & 0x1F
            desc = f'MOV X{rd}, X{rm}'
        elif (instr & 0xFFE0FC00) == 0x2A0003E0:
            rm = (instr >> 16) & 0x1F
            rd = instr & 0x1F
            desc = f'MOV W{rd}, W{rm}'
        elif (instr & 0xFF800000) == 0x71000000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            desc = f'CMP W{rn}, #0x{imm12:X}'
        elif (instr & 0xFF800000) == 0xF1000000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            desc = f'CMP X{rn}, #0x{imm12:X}'
        elif (instr & 0xFFE0001F) == 0xEB00001F:
            rm = (instr >> 16) & 0x1F
            rn = (instr >> 5) & 0x1F
            desc = f'CMP X{rn}, X{rm}'
        elif (instr & 0xD6000000) == 0xD6000000:
            if (instr & 0xFFFFFC1F) == 0xD63F0000:
                rn = (instr >> 5) & 0x1F
                desc = f'BLR X{rn}'
            elif (instr & 0xFFFFFC1F) == 0xD61F0000:
                rn = (instr >> 5) & 0x1F
                desc = f'BR X{rn}'
        elif (instr & 0xFFC00000) == 0x39400000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F; rt = instr & 0x1F
            desc = f'LDRB W{rt}, [X{rn}, #0x{imm12:X}]'
        elif (instr & 0xFFC00000) == 0x39000000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F; rt = instr & 0x1F
            desc = f'STRB W{rt}, [X{rn}, #0x{imm12:X}]'

        print(f'  0x{off:05X}: {instr:08X}  {desc}')

# ============================================================
# CALLER FUNCTION: trace who calls 0x37D38 and what X0 is
# ============================================================
print("=" * 70)
print("CALLER ANALYSIS: Who calls 0x37D38 and what is X0?")
print("=" * 70)

# Earlier analysis found 0x49D0C calls 0x37D38
# Let's look at the broader caller function

disasm(0x49BF8, 0x49D20, "Caller function around 0x49BF8-0x49D20")

# Also look at what 0x4DBC8 does (called at 0x49CE0)
# This might fill the buffer
disasm(0x4DBC8, 0x4DC80, "Function 0x4DBC8 (called before 0x37D38)")

# ============================================================
# Check what X21 points to
# X21 was set at 0x49CDC: SUB X21, X29, #0x98
# This is a stack buffer. Let's see what goes INTO it.
# ============================================================

# Let's trace back further to find the outer caller
# Find all BL 0x49BF8 or the function that contains 0x49BF8
print("\n" + "=" * 70)
print("SEARCHING for callers of the function containing 0x49BF8")
print("=" * 70)

# Find function start: look backwards from 0x49BF8 for STP X29,X30,[SP,#-...]
# (function prologue)
for off in range(0x49BF8, 0x49B00, -4):
    instr = struct.unpack_from('<I', data, off)[0]
    # STP X29, X30, [SP, #-imm]! pattern: A9Bxxxxx or A9Cxxxxx
    if (instr & 0xFFC003E0) == 0xA9800000 or (instr & 0xFF8003E0) == 0xA98003E0:
        pass  # might not match exactly
    # Look for common prologue: A9xx7BFD (STP X29, X30, ...)
    if (instr >> 16) & 0xFFFF == 0xA9BC and (instr & 0xFFFF) == 0x7BFD:
        print(f"  Found potential prologue at 0x{off:05X}: {instr:08X}")
    if instr & 0xFFFF == 0x7BFD:
        print(f"  Potential STP X29,X30 at 0x{off:05X}: {instr:08X}")

# Let's just search all BL instructions targeting the 0x49Bxx-0x49C00 range
print("\nSearching BL targets in range 0x49B00-0x49C00:")
for off in range(0x1000, 0x6A000, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr & 0xFC000000) == 0x94000000:
        target = decode_bl(instr, off)
        if 0x49B00 <= target <= 0x49C00:
            print(f'  0x{off:05X}: BL 0x{target:X}')

# ============================================================
# Look at 0x37D38's first parameter more carefully
# The comparison with "cust-unlock" is on X28 = X0 (first param)
# But what IS this param? Is it a string? A struct?
# Let's check how 0x299B4 (the compare function) works
# ============================================================
print("\n" + "=" * 70)
print("STRING COMPARE FUNCTION 0x299B4")
print("=" * 70)
disasm(0x299B4, 0x29A30, "0x299B4 (StrCmp / string compare)")

# ============================================================
# Now trace what 0x36CA8 does with the same buffer
# If it modifies the buffer or reads a sub-field
# ============================================================
print("\n" + "=" * 70)
print("FUNCTION 0x36CA8 (called before 0x37D38 with same buffer)")
print("=" * 70)
disasm(0x36CA8, 0x36E00, "0x36CA8 first 340 bytes")

# ============================================================
# Check how the X21 buffer gets filled
# Is 0x4DBC8 the one that fills it?
# ============================================================
print("\n" + "=" * 70)
print("What writes to the X21 buffer between calls?")
print("=" * 70)

# X21 = [X29 - 0x98] (stack buffer, 0x98 bytes?)
# Before 0x36CA8: 0x4DBC8 is called with unknown params
# Let's see what 0x4DBC8 does with the buffer

# At the caller:
# 0x49CDC: SUB X21, X29, #0x98  → X21 = stack buffer
# 0x49CE0: BL 0x4DBC8           → called BEFORE 36CA8, unknown params
# Actually wait, what are the params to 0x4DBC8?
# Need more context before 0x49CE0

disasm(0x49C90, 0x49D20, "Caller context before and after BL 0x4DBC8")
