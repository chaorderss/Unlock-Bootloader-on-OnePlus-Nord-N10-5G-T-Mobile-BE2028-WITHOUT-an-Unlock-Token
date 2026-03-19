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
# 1. FRP reader function 0x4FD10 - full trace
# This is the function that reads the FRP partition
# If it has a buffer overflow, we could potentially overflow
# into neighboring globals
# ============================================================
disasm(0x4FD10, 0x4FE80, "FRP Reader 0x4FD10 (full)")

# ============================================================
# 2. Check what ReadFromPartition-like function is used
# Look for partition name strings being loaded before BLR calls
# Focus on "frp", "config", "opproduct", "op2"
# ============================================================
print("\n" + "=" * 70)
print("2. Partition read callsites")
print("=" * 70)

# UTF-16 partition names in binary:
# 0x68292: "frp"
# 0x68342: "config"
# 0x68274: "devinfo"
# 0x68374: "op2"
# 0x6837C: "opproduct"

# Find all references to "frp" partition name (0x68292)
print("\nReferences to 'frp' (0x68292):")
for off in range(0, 0x60000, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr & 0x9F000000) != 0x90000000:
        continue
    page = decode_adrp(instr, off)
    if page != 0x68000:
        continue
    rd = instr & 0x1F
    ni = struct.unpack_from('<I', data, off + 4)[0]
    if (ni & 0xFF800000) == 0x91000000:
        nrn = (ni >> 5) & 0x1F
        if nrn == rd:
            imm12 = (ni >> 10) & 0xFFF
            target = page + imm12
            if target == 0x68292:
                print(f'  0x{off:05X}: ADRP+ADD -> "frp" (0x68292)')
            elif target == 0x68342:
                print(f'  0x{off:05X}: ADRP+ADD -> "config" (0x68342)')
            elif target == 0x68274:
                print(f'  0x{off:05X}: ADRP+ADD -> "devinfo" (0x68274)')
            elif target == 0x68374:
                print(f'  0x{off:05X}: ADRP+ADD -> "op2" (0x68374)')
            elif target == 0x6837C:
                print(f'  0x{off:05X}: ADRP+ADD -> "opproduct" (0x6837C)')

# ============================================================
# 3. Check param partition reader flow
# The param reader uses AES decryption. If the decrypted data
# has a length field that's not validated, we might overflow.
# Also check config reader.
# ============================================================

# Let's trace the actual ReadFromPartition wrapper
# First find the UEFI block I/O protocol used for partition reads
# Known pattern: LoadImageFromPartition or ReadWriteDeviceInfo style

# Check function 0x4AA8, 0x4B90, 0x4C2C used in the FRP processing path
disasm(0x4AA8, 0x4B30, "Function 0x4AA8 (crypto init?)")
disasm(0x4B90, 0x4C30, "Function 0x4B90 (crypto update?)")
disasm(0x4C2C, 0x4CC0, "Function 0x4C2C (crypto final?)")

# ============================================================
# 4. Most important: find all AllocatePool / CopyMem patterns
# in context of partition reads
# If a partition reader does:
#   size = read_from_partition()  // attacker controls
#   buf = AllocatePool(size)      // may be small
#   CopyMem(buf, data, size)      // actual copy
# But we need it to write to a STATIC buffer, not heap
# ============================================================

# Check what the init function calls use for their data buffers
# In the cascade (0x37FC0+):
# - X24 (= stack frame derived) is used as protocol output buffer
# - X25, X21 are also stack-derived
# None of these are near our target globals in the .data section...

# BUT: Does 0x4FD10 (FRP reader) write to a global? Let's check
print("\n" + "=" * 70)
print("4. Checking if FRP reader returns data to caller or writes to global")
print("=" * 70)

# At 0x383B8: BL 0x4FD10
# Called with: X0=X22 (stack buffer loaded at 0x3838C), X1=[SP+0x8], X2=X27
# Return value checked: CBZ X0 -> 0x383E8 (null = success for our path)
# The FRP reader likely RETURNS a pointer, not writes to a fixed global

# Lets also check the param/config init function — the function that
# reads param/config/opproduct partitions and populates globals

# ============================================================
# 5. Comprehensive scan: find ALL functions that write to .data
# addresses between 0x1BE000-0x1C0000 using CopyMem or loops
# ============================================================
print("\n" + "=" * 70)
print("5. BL 0x4DE08 (CopyMem) calls with destinations in .data")
print("=" * 70)

# 0x4DE08 is CopyMem(dst, src, size)
# Find all BL 0x4DE08 and check if X0 (dst) was previously set to a .data address
for off in range(0, 0x60000, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr & 0xFC000000) != 0x94000000:
        continue
    target = decode_bl(instr, off)
    if target != 0x4DE08:
        continue

    # Look back up to 20 instructions for X0 setup
    for back in range(4, 80, 4):
        bi = struct.unpack_from('<I', data, off - back)[0]
        # ADRP X0, 0x1Bx000 or 0x1C0000
        if (bi & 0x9F00001F) == 0x90000000:  # ADRP X0
            bp = decode_adrp(bi, off - back)
            if 0x1BD000 <= bp <= 0x1C1000:
                # Check next for ADD X0, X0, #imm
                ni2 = struct.unpack_from('<I', data, off - back + 4)[0]
                if (ni2 & 0xFFE003FF) == 0x91000000:  # ADD X0, X0, #imm
                    imm12 = (ni2 >> 10) & 0xFFF
                    dst = bp + imm12
                    # Check what W2 (size) is
                    size_info = ""
                    for sb in range(4, 20, 4):
                        si = struct.unpack_from('<I', data, off - sb)[0]
                        if (si & 0xFF80001F) == 0x52800002:  # MOV W2, #imm
                            sz = (si >> 5) & 0xFFFF
                            size_info = f', size=0x{sz:X}'
                            break
                    print(f'  0x{off:05X}: CopyMem(dst=0x{dst:X}{size_info}) [ADRP at 0x{off-back:05X}]')
                break
        # MOV X0, Xn where Xn was set to a .data addr
        if bi == 0xAA0003E0:  # MOV X0, X0 — nop, skip
            continue

# ============================================================
# 6. BL 0x4DEBC (SetMem/memset) calls to .data addresses
# ============================================================
print("\n" + "=" * 70)
print("6. BL 0x4DEBC (SetMem) calls to .data addresses")
print("=" * 70)
for off in range(0, 0x60000, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr & 0xFC000000) != 0x94000000:
        continue
    target = decode_bl(instr, off)
    if target != 0x4DEBC:
        continue

    for back in range(4, 80, 4):
        bi = struct.unpack_from('<I', data, off - back)[0]
        if (bi & 0x9F00001F) == 0x90000000:
            bp = decode_adrp(bi, off - back)
            if 0x1BD000 <= bp <= 0x1C1000:
                ni2 = struct.unpack_from('<I', data, off - back + 4)[0]
                if (ni2 & 0xFFE003FF) == 0x91000000:
                    imm12 = (ni2 >> 10) & 0xFFF
                    dst = bp + imm12
                    print(f'  0x{off:05X}: SetMem(dst=0x{dst:X}) [ADRP at 0x{off-back:05X}]')
                break
