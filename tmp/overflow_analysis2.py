import struct

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb').read()

def decode_adrp(instr, pc):
    immhi = (instr >> 5) & 0x7FFFF
    immlo = (instr >> 29) & 0x3
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    return (pc & ~0xFFF) + (imm << 12)

def decode_bl(instr, pc):
    imm26 = instr & 0x03FFFFFF
    if imm26 & 0x02000000:
        imm26 -= 0x04000000
    return pc + imm26 * 4

# ============================================================
# PART A: Trace WHAT writes to 0x1BF50C and 0x1BF514
# (the globals just 12 and 4 bytes before carrier_flag 0x1BF518)
# ============================================================
print("=" * 70)
print("PART A: Writers to globals near 0x1BF518")
print("=" * 70)

# Find all ADRP 0x1BF000 instructions
for off in range(0, len(data) - 8, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr & 0x9F000000) != 0x90000000:
        continue
    page = decode_adrp(instr, off)
    if page != 0x1BF000:
        continue
    rd = instr & 0x1F

    # Check next few instructions for stores to offsets 0x500-0x530
    for delta in range(4, 24, 4):
        if off + delta >= len(data): break
        ni = struct.unpack_from('<I', data, off + delta)[0]

        # STRB Wt, [Xn, #imm]
        if (ni & 0xFFC00000) == 0x39000000:
            nrn = (ni >> 5) & 0x1F
            if nrn == rd:
                imm12 = (ni >> 10) & 0xFFF
                target = page + imm12
                if 0x1BF500 <= target <= 0x1BF530:
                    wt = ni & 0x1F
                    print(f'  0x{off:05X}: ADRP X{rd},0x1BF000 -> STRB W{wt},[X{nrn},#0x{imm12:X}] = write to 0x{target:X}')

        # STR Wt, [Xn, #imm] (32-bit)
        if (ni & 0xFFC00000) == 0xB9000000:
            nrn = (ni >> 5) & 0x1F
            if nrn == rd:
                imm12 = (ni >> 10) & 0xFFF
                target = page + imm12 * 4
                if 0x1BF500 <= target <= 0x1BF530:
                    wt = ni & 0x1F
                    print(f'  0x{off:05X}: ADRP X{rd},0x1BF000 -> STR W{wt},[X{nrn},#0x{imm12*4:X}] = write to 0x{target:X}')

# ============================================================
# PART B: Trace the array at 0x1BF340 (0x40 spacing)
# What are these? And what populates them?
# ============================================================
print("\n" + "=" * 70)
print("PART B: Array-like structure at 0x1BF340 (0x40 spacing)")
print("=" * 70)

# Each entry at 0x1BF340, 0x1BF380, 0x1BF3C0, 0x1BF400, 0x1BF440, 0x1BF480, 0x1BF4C0
# = 0x1BF340 + n*0x40, n=0..6
# 0x1BF500 = 0x1BF340 + 7*0x40 → 7th entry
# 0x1BF518 = 0x1BF340 + 7*0x40 + 0x18 → 7th entry + offset 0x18!

base = 0x1BF340
print(f"Array base: 0x{base:X}")
print(f"Entry size: 0x40 (64 bytes)")
print(f"carrier_flag 0x1BF518 = base + 7*0x40 + 0x18")
print(f"  = entry[7] + 0x18")
print(f"  = 0x{base + 7*0x40:X} + 0x18 = 0x{base + 7*0x40 + 0x18:X}")
print()

# Wait - our carrier table in code was at 0x62488, with entries of 0x58 bytes
# and carrier_id field. Let me check if this 0x1BF340 array is derived from it.
# The carrier table has 9 entries (indices 0-8), carrier_id 0-8
# (our device = index 7, carrier_id 7)
# With 0x40-byte entries and base 0x1BF340:
# entry[0] = 0x1BF340
# entry[7] = 0x1BF340 + 0x1C0 = 0x1BF500
# entry[8] = 0x1BF340 + 0x200 = 0x1BF540
# So the array might have entries 0-7 (8 entries), NOT matching the 9 carrier entries

# But 0x1BF518 is at entry[7]+0x18 if base=0x1BF340 with 0x40 entries
# Actually let me recalculate: (0x1BF518 - 0x1BF340) = 0x1D8 = 472
# 472 / 64 = 7.375 → NOT aligned to 0x40!
# Let me check the actual deltas between the reference addresses

refs = [0x1BF340, 0x1BF380, 0x1BF3C0, 0x1BF400, 0x1BF440, 0x1BF480, 0x1BF4C0,
        0x1BF500, 0x1BF504, 0x1BF508, 0x1BF50C, 0x1BF510, 0x1BF514, 0x1BF518,
        0x1BF51C, 0x1BF520, 0x1BF528]

for i, r in enumerate(refs):
    delta_from_340 = r - 0x1BF340
    delta_from_518 = r - 0x1BF518
    print(f"  0x{r:X}: delta_from_0x1BF340=0x{delta_from_340:X}({delta_from_340}), delta_from_0x1BF518={delta_from_518:+d}")

# ============================================================
# PART C: Find WHO reads 0x1BF340+0x40*n - trace the reader
# ============================================================
print("\n" + "=" * 70)
print("PART C: Who reads the array entries?")
print("=" * 70)

# Find all ADRP 0x1BF000 + LDR with offsets 0x340, 0x380, etc
for off in range(0, len(data) - 8, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr & 0x9F000000) != 0x90000000:
        continue
    page = decode_adrp(instr, off)
    if page != 0x1BF000:
        continue
    rd = instr & 0x1F

    ni = struct.unpack_from('<I', data, off + 4)[0]
    # LDR X, [Xn, #imm] 64-bit
    if (ni & 0xFFC00000) == 0xF9400000:
        nrn = (ni >> 5) & 0x1F
        if nrn == rd:
            imm12 = (ni >> 10) & 0xFFF
            target = page + imm12 * 8
            if 0x1BF300 <= target < 0x1BF540:
                rt = ni & 0x1F
                print(f'  0x{off:05X}: ADRP+LDR X{rt},[...0x{target:X}]')

# ============================================================
# PART D: Key question - the carrier table at 0x62488 has entries
# with pointers at offset +0x38. What do these pointers reference?
# And does any partition data get read INTO these pointed-to buffers?
# ============================================================
print("\n" + "=" * 70)
print("PART D: Carrier table pointer fields")
print("=" * 70)

# Carrier table entry structure (0x58 bytes each):
# +0x00: model_number (uint32)
# +0x08: string_ptr (pointer to model string)
# +0x10: unknown
# +0x18: unknown
# +0x20: unknown
# +0x28: unknown
# +0x30: unknown
# +0x38: pointer (key field)
# +0x40: carrier_id (uint32)
# +0x48: unknown
# +0x50: unknown

for i in range(9):
    entry_off = 0x62488 + i * 0x58
    model = struct.unpack_from('<I', data, entry_off)[0]
    carrier_id = struct.unpack_from('<I', data, entry_off + 0x40)[0]

    # Read all 64-bit values at key offsets
    vals = {}
    for field_off in [0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x48, 0x50]:
        vals[field_off] = struct.unpack_from('<Q', data, entry_off + field_off)[0]

    marker = " <<<< OUR DEVICE" if model == 20888 else ""
    print(f'\n  [{i}] model={model}, carrier_id={carrier_id}{marker}')
    for field_off, val in vals.items():
        # Is this a plausible pointer (within binary range)?
        ptr_note = ""
        if 0x1000 <= val < 0x1C9000:
            ptr_note = " [VALID PTR]"
            # Read what it points to
            pointed = data[val:val+16]
            ptr_note += f" -> {pointed.hex()}"
            # Try as string
            try:
                s = pointed.split(b'\x00')[0].decode('ascii', errors='replace')
                if len(s) > 2:
                    ptr_note += f' "{s}"'
            except:
                pass
        print(f'    +0x{field_off:02X}: 0x{val:016X}{ptr_note}')

# ============================================================
# PART E: Most important - trace ALL writes into 0x1BD000-0x1C1000 region
# that use indirect addressing (register + offset from partition data)
# ============================================================
print("\n" + "=" * 70)
print("PART E: Indirect writes near critical globals")
print("=" * 70)

# Look for patterns where partition data gets copied/written to our target area
# via computed addresses (buffer base + size from data)
#
# Common vulnerability pattern:
#   LDR X0, [partition_data + size_offset]   ; attacker controls size
#   ADD X1, base_ptr, actual_offset
#   BL memcpy                                ; overflow!

# Check: does the init function at 0x37D38 use any indirect stores?
# Specifically in the 0x382A4+ area where it processes after reaching FRP check
print("\nInit function 0x382A4+ indirect memory operations:")
for off in range(0x382A4, 0x38420, 4):
    instr = struct.unpack_from('<I', data, off)[0]

    # Any store instruction
    if (instr & 0x3F000000) in [0x39000000, 0x3B000000, 0x3D000000, 0x3F000000]:
        # STRB/STRH/STR/etc
        print(f'  0x{off:05X}: store 0x{instr:08X}')
    elif (instr & 0xFFE00000) == 0xF8000000 or (instr & 0xFFE00000) == 0xB8000000:
        # STR (register offset)
        print(f'  0x{off:05X}: STR(reg) 0x{instr:08X}')

# ============================================================
# PART F: Check function 0x29464 used heavily in 0x382xx area
# This might be a string/buffer append function
# ============================================================
print("\n" + "=" * 70)
print("PART F: Function 0x29464 (used in FRP processing at 0x382xx)")
print("=" * 70)

for off in range(0x29464, 0x29550, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    desc = f'raw 0x{instr:08X}'

    if (instr & 0xFC000000) == 0x94000000:
        desc = f'BL 0x{decode_bl(instr, off):X}'
    elif (instr & 0xFC000000) == 0x14000000:
        desc = f'B 0x{decode_bl(instr, off):X}'
    elif instr == 0xD65F03C0:
        desc = 'RET'
    elif (instr & 0xFFE0FC00) == 0xD63F0000:
        rn = (instr >> 5) & 0x1F
        desc = f'BLR X{rn}'
    elif (instr & 0x9F000000) == 0x90000000:
        desc = f'ADRP X{instr&0x1F}, 0x{decode_adrp(instr, off):X}'
    elif (instr & 0xFF800000) == 0x91000000:
        imm12 = (instr >> 10) & 0xFFF
        rd = instr & 0x1F
        rn = (instr >> 5) & 0x1F
        desc = f'ADD X{rd}, X{rn}, #0x{imm12:X}'
    elif (instr & 0xFF800000) == 0xD1000000:
        imm12 = (instr >> 10) & 0xFFF
        rd = instr & 0x1F
        rn = (instr >> 5) & 0x1F
        desc = f'SUB X{rd}, X{rn}, #0x{imm12:X}'
    elif (instr & 0x7E000000) == 0x34000000:
        imm19 = (instr >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 -= 0x80000
        op = 'CBNZ' if (instr >> 24) & 1 else 'CBZ'
        reg = instr & 0x1F
        size = 'W' if (instr >> 31) == 0 else 'X'
        desc = f'{op} {size}{reg} -> 0x{off + imm19*4:X}'
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

    print(f'  0x{off:05X}: {desc}')
    if desc == 'RET':
        break
