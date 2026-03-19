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

def disasm(start, end, label=""):
    if label:
        print(f'\n=== {label} ===')
    for off in range(start, end, 4):
        if off >= len(data) - 3: break
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
        elif (instr & 0xFFC00000) == 0x79400000:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            rt = instr & 0x1F
            desc = f'LDRH W{rt}, [X{rn}, #0x{imm12*2:X}]'

        print(f'  0x{off:05X}: {desc}')

# ============================================================
# 1. Trace 0x36898 - the function writing to 0x1BF514
# (just 4 bytes before our target 0x1BF518!)
# ============================================================
disasm(0x36850, 0x368C0, "Writer to 0x1BF514 (at 0x36898)")

# Let's see more context - what function contains 0x36898?
# Search backwards for function prologue
print("\n--- Function containing 0x36898 ---")
for off in range(0x36898, 0x36600, -4):
    instr = struct.unpack_from('<I', data, off)[0]
    # Look for SUB SP, SP pattern or STP with SP
    if (instr & 0xFF800000) == 0xD1000000:  # SUB X31, X31, #imm
        rd = instr & 0x1F
        if rd == 31:
            print(f"  Function entry likely at 0x{off:05X}")
            disasm(off, 0x368D0, "Function containing 0x1BF514 write")
            break
    # Also STP ... [SP, #imm]!
    if (instr & 0xFFC00000) == 0xA9800000:  # STP pre-index
        pass

# ============================================================
# 2. Trace 0x50030 - the actual partition read function
# (FRP reader 0x4FD10 tails into this at 0x4FE18)
# ============================================================
disasm(0x50030, 0x50180, "Partition Read Function 0x50030")

# ============================================================
# 3. Comprehensive search: find ALL BLR (indirect calls through
# protocol function pointers) in .text that target globals near
# our area. These could be UEFI partition read callbacks.
# ============================================================
print("\n" + "=" * 70)
print("3. Search for memcpy-like BL targets used near .data writes")
print("=" * 70)

# Actually, let me try the opposite approach: find ALL write
# instructions in the entire .text that could write to the
# 0x1BF500-0x1BF520 range using BASE+OFFSET where BASE comes
# from a register previously loaded from a global/ADRP

# A more practical approach: search for ANY instruction that
# could write 4+ bytes starting at or covering 0x1BF518
# by searching for ADRP 0x1BF000 + any ADD/store pattern
# where the effective address COULD overlap 0x1BF518

# We already found that 0x383EC is the only STRB to 0x1BF518
# But what about STR (32-bit) or STR (64-bit) that could
# overlap the byte at 0x1BF518?

# STR W to 0x1BF518 would need offset 0x146 (*4 = 0x518) - check
# STR X to 0x1BF518 would need offset 0xA3 (*8 = 0x518) - check
# STR W to 0x1BF514 would write 4 bytes covering 0x1BF514-0x1BF517
#   (does NOT cover 0x1BF518)
# STR X to 0x1BF510 would write 8 bytes covering 0x1BF510-0x1BF517
#   (does NOT cover 0x1BF518)
# STR X to 0x1BF518 would write 8 bytes covering 0x1BF518-0x1BF51F
#   offset 0xA3 (*8 = 0x518)

print("\nSearching for STR X to addr that covers 0x1BF518:")
for off in range(0, 0x60000, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr & 0x9F000000) != 0x90000000:
        continue
    page = decode_adrp(instr, off)
    if page != 0x1BF000:
        continue
    rd = instr & 0x1F

    # Check next instruction for STR X to offset that covers 0x518
    ni = struct.unpack_from('<I', data, off + 4)[0]
    # STR X, [Xn, #imm*8]
    if (ni & 0xFFC00000) == 0xF9000000:
        nrn = (ni >> 5) & 0x1F
        if nrn == rd:
            imm12 = (ni >> 10) & 0xFFF
            target = page + imm12 * 8
            if 0x1BF511 <= target <= 0x1BF518:
                rt = ni & 0x1F
                print(f'  0x{off:05X}: STR X{rt},[...,#0x{imm12*8:X}] -> 0x{target:X} (covers 8 bytes)')

# ============================================================
# 4. ALTERNATIVE APPROACH: Instead of trying to overflow into
# 0x1BF518, can we overflow into 0x1C0010 (IsAllowUnlock)?
# This would bypass the carrier check entirely by making
# IsAllowUnlock=1 (which jumps past the carrier check)
# ============================================================
print("\n" + "=" * 70)
print("4. IsAllowUnlock (0x1C0010) neighborhood analysis")
print("=" * 70)

# What is at 0x1C0000-0x1C0020?
print(f"\nBinary content 0x1BFFF0-0x1C0020:")
print(f"  0x1BFFF0: {data[0x1BFFF0:0x1C0000].hex()}")
print(f"  0x1C0000: {data[0x1C0000:0x1C0010].hex()}")
print(f"  0x1C0010: {data[0x1C0010:0x1C0020].hex()}")

# Who writes to 0x1BFFF8, 0x1BFFF0 (just before IsAllowUnlock)?
print("\nWriters near IsAllowUnlock:")
for off in range(0, 0x60000, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr & 0x9F000000) != 0x90000000:
        continue
    page = decode_adrp(instr, off)
    if page not in [0x1BF000, 0x1C0000]:
        continue
    rd = instr & 0x1F

    for delta in [4, 8]:
        if off + delta >= len(data): break
        ni = struct.unpack_from('<I', data, off + delta)[0]

        for mask, name, mult in [
            (0xFFC00000, 'STR_X', 8),
            (0xFFC00000, 'STR_W', 4),
            (0xFFC00000, 'STRB', 1),
        ]:
            if name == 'STR_X' and (ni & 0xFFC00000) == 0xF9000000:
                nrn = (ni >> 5) & 0x1F
                if nrn == rd:
                    imm12 = (ni >> 10) & 0xFFF
                    target = page + imm12 * 8
                    if 0x1BFFE0 <= target <= 0x1C0020:
                        rt = ni & 0x1F
                        print(f'  0x{off:05X}: STR X{rt} -> 0x{target:X}')
            elif name == 'STR_W' and (ni & 0xFFC00000) == 0xB9000000:
                nrn = (ni >> 5) & 0x1F
                if nrn == rd:
                    imm12 = (ni >> 10) & 0xFFF
                    target = page + imm12 * 4
                    if 0x1BFFE0 <= target <= 0x1C0020:
                        rt = ni & 0x1F
                        print(f'  0x{off:05X}: STR W{rt} -> 0x{target:X}')
            elif name == 'STRB' and (ni & 0xFFC00000) == 0x39000000:
                nrn = (ni >> 5) & 0x1F
                if nrn == rd:
                    imm12 = (ni >> 10) & 0xFFF
                    target = page + imm12
                    if 0x1BFFE0 <= target <= 0x1C0020:
                        rt = ni & 0x1F
                        print(f'  0x{off:05X}: STRB W{rt} -> 0x{target:X}')

# ============================================================
# 5. Map how IsAllowUnlock (0x1C0010) gets populated
# We know it's at ADRP 0x1C0000 + LDR W, [X, #0x10]
# ============================================================
print("\n--- IsAllowUnlock readers ---")
for off in range(0, 0x60000, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr & 0x9F000000) != 0x90000000:
        continue
    page = decode_adrp(instr, off)
    if page != 0x1C0000:
        continue
    rd = instr & 0x1F
    ni = struct.unpack_from('<I', data, off + 4)[0]
    if (ni & 0xFFC00000) == 0xB9400000:  # LDR W
        nrn = (ni >> 5) & 0x1F
        if nrn == rd:
            imm12 = (ni >> 10) & 0xFFF
            target = page + imm12 * 4
            if target == 0x1C0010:
                rt = ni & 0x1F
                print(f'  0x{off:05X}: LDR W{rt}, [0x1C0010] (IsAllowUnlock reader)')

# ============================================================
# 6. Check what writes to 0x1C0010 - the IsAllowUnlock setter
# ============================================================
print("\n--- IsAllowUnlock writers ---")
for off in range(0, 0x60000, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr & 0x9F000000) != 0x90000000:
        continue
    page = decode_adrp(instr, off)
    if page != 0x1C0000:
        continue
    rd = instr & 0x1F
    for delta in [4, 8, 12]:
        if off + delta >= len(data): break
        ni = struct.unpack_from('<I', data, off + delta)[0]
        if (ni & 0xFFC00000) == 0xB9000000:  # STR W
            nrn = (ni >> 5) & 0x1F
            if nrn == rd:
                imm12 = (ni >> 10) & 0xFFF
                target = page + imm12 * 4
                if target == 0x1C0010:
                    rt = ni & 0x1F
                    print(f'  0x{off:05X}+{delta}: STR W{rt} -> 0x1C0010')
        if (ni & 0xFFC00000) == 0x39000000:  # STRB
            nrn = (ni >> 5) & 0x1F
            if nrn == rd:
                imm12 = (ni >> 10) & 0xFFF
                target = page + imm12
                if 0x1C0010 <= target <= 0x1C0013:
                    rt = ni & 0x1F
                    print(f'  0x{off:05X}+{delta}: STRB W{rt} -> 0x{target:X}')

# ============================================================
# 7. NEW APPROACH: Can we directly patch the .data section in
# the PE binary? The binary is in an FFS module in the ABL
# partition. If we modify the .data section to set [0x1BF518]=1
# or [0x1C0010]=1 directly...
# But wait - ABL has secure boot / hash verification.
# Unless... the hash is only on .text? Or the PE header?
# ============================================================
print("\n" + "=" * 70)
print("7. PE binary structure - are sections individually hashed?")
print("=" * 70)
print(f"Binary size: 0x{len(data):X} ({len(data)} bytes)")
print(f".text: 0x001000-0x{0x001000+0x069000:06X} (code)")
print(f".data: 0x06A000-0x{0x06A000+0x15E000:06X} (data)")
print(f".reloc: 0x1C8000-0x{0x1C8000+0x001000:06X} (relocations)")

# Check PE checksum and security directory
pe_sig_off = struct.unpack_from('<I', data, 0x3C)[0]
opt_off = pe_sig_off + 4 + 20

# Check for security directory (certificate table)
# In PE32+, data directories start at opt_off + 112
dd_off = opt_off + 112
num_dd = struct.unpack_from('<I', data, opt_off + 108)[0]
print(f"\nNumber of data directories: {num_dd}")
for i in range(min(num_dd, 16)):
    va = struct.unpack_from('<I', data, dd_off + i*8)[0]
    size = struct.unpack_from('<I', data, dd_off + i*8 + 4)[0]
    if size > 0:
        names = ['Export','Import','Resource','Exception','Certificate',
                 'BaseReloc','Debug','Architecture','GlobalPtr','TLS',
                 'LoadConfig','BoundImport','IAT','DelayImport','CLR','Reserved']
        nm = names[i] if i < len(names) else f'Dir{i}'
        print(f"  DataDir[{i}] ({nm}): VA=0x{va:X}, Size=0x{size:X}")

# Check PE checksum
pe_checksum = struct.unpack_from('<I', data, opt_off + 64)[0]
print(f"\nPE Checksum: 0x{pe_checksum:08X}")
