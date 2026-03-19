#!/usr/bin/env python3
"""
Final focused checks:
1. GetDevInfoPtr (0x22C58) caller at 0x4839C — what does it do with devinfo pointer?
2. Callers of 0x30A80 (secondary devinfo partition read into 0x1BE428)
3. Boot error path: 0x0155C-0x01620 full disassembly
4. Check for STR/STP instructions that could zero devinfo[13] area (wider stores)
5. OemCheckResetDevInfo 0x362D8 — entry and param check
6. Check 0x30740 (last BL in boot function at 0x3691C)
"""
import struct

PE = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
with open(PE, "rb") as f:
    pe = f.read()

def r32(off):
    return struct.unpack_from('<I', pe, off)[0]

def decode(off, inst):
    s = f"  0x{off:05X}: 0x{inst:08X}"
    if inst == 0xD65F03C0: return s + "  RET"
    if inst == 0x00000000: return s + "  (nop/padding)"
    # BL
    if (inst >> 26) == 0x25:
        imm = inst & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        t = off + (imm << 2)
        return s + f"  BL 0x{t & 0xFFFFFFFF:05X}"
    # B
    if (inst >> 26) == 0x05:
        imm = inst & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        t = off + (imm << 2)
        return s + f"  B 0x{t & 0xFFFFFFFF:05X}"
    # B.cond
    if (inst & 0xFF000010) == 0x54000000:
        imm19 = (inst >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 |= ~0x7FFFF
        t = off + (imm19 << 2)
        cond = inst & 0xF
        conds = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
        return s + f"  B.{conds[cond]} 0x{t & 0xFFFFFFFF:05X}"
    # CBZ/CBNZ
    if (inst & 0x7E000000) == 0x34000000:
        sf = (inst >> 31) & 1
        op = (inst >> 24) & 1
        rt = inst & 0x1F
        imm19 = (inst >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 |= ~0x7FFFF
        t = off + (imm19 << 2)
        rn = f"x{rt}" if sf else f"w{rt}"
        mn = "CBNZ" if op else "CBZ"
        return s + f"  {mn} {rn}, 0x{t & 0xFFFFFFFF:05X}"
    # TBZ/TBNZ
    if (inst & 0x7E000000) == 0x36000000:
        op = (inst >> 24) & 1
        b5 = (inst >> 31) & 1
        b40 = (inst >> 19) & 0x1F
        bit = (b5 << 5) | b40
        rt = inst & 0x1F
        imm14 = (inst >> 5) & 0x3FFF
        if imm14 & 0x2000: imm14 |= ~0x3FFF
        t = off + (imm14 << 2)
        mn = "TBNZ" if op else "TBZ"
        return s + f"  {mn} x{rt}, #{bit}, 0x{t & 0xFFFFFFFF:05X}"
    # ADRP
    if (inst & 0x9F000000) == 0x90000000:
        rd = inst & 0x1F
        immhi = (inst >> 5) & 0x7FFFF; immlo = (inst >> 29) & 0x3
        iv = (immhi << 2) | immlo
        if iv & 0x100000: iv |= ~0x1FFFFF
        pg = ((off & ~0xFFF) + (iv << 12)) & 0xFFFFFFFF
        return s + f"  ADRP x{rd}, 0x{pg:X}"
    # ADD Xd, Xn, #imm
    if (inst & 0xFF800000) == 0x91000000:
        rd = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm12 = (inst >> 10) & 0xFFF
        sh = (inst >> 22) & 1
        if sh: imm12 <<= 12
        return s + f"  ADD x{rd}, x{rn}, #0x{imm12:X}"
    # MOV Xd, Xn (ORR alias)
    if (inst & 0xFF3FFC00) == 0xAA1F0000:
        rd = inst & 0x1F; rm = (inst >> 16) & 0x1F
        return s + f"  MOV x{rd}, x{rm}"
    # MOV Wd, Wn
    if (inst & 0xFF3FFC00) == 0x2A1F0000:
        rd = inst & 0x1F; rm = (inst >> 16) & 0x1F
        return s + f"  MOV w{rd}, w{rm}"
    # MOV WZR (W31)
    if (inst & 0xFFE0001F) == 0x2A0003E0:
        rd = inst & 0x1F
        return s + f"  MOV w{rd}, wzr"
    if (inst & 0xFFE0001F) == 0xAA0003E0:
        rd = inst & 0x1F
        return s + f"  MOV x{rd}, xzr"
    # MOVZ
    if (inst & 0xFF800000) == 0x52800000:
        rd = inst & 0x1F; imm16 = (inst >> 5) & 0xFFFF; hw = (inst >> 21) & 0x3
        return s + f"  MOV w{rd}, #0x{imm16 << (hw*16):X}"
    if (inst & 0xFF800000) == 0xD2800000:
        rd = inst & 0x1F; imm16 = (inst >> 5) & 0xFFFF; hw = (inst >> 21) & 0x3
        return s + f"  MOV x{rd}, #0x{imm16 << (hw*16):X}"
    # STRB
    if (inst & 0xFFC00000) == 0x39000000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = (inst >> 10) & 0xFFF
        return s + f"  STRB w{rt}, [x{rn}, #{imm}]"
    # LDRB
    if (inst & 0xFFC00000) == 0x39400000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = (inst >> 10) & 0xFFF
        return s + f"  LDRB w{rt}, [x{rn}, #{imm}]"
    # LDR Xt (64-bit)
    if (inst & 0xFFC00000) == 0xF9400000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = ((inst >> 10) & 0xFFF) * 8
        return s + f"  LDR x{rt}, [x{rn}, #{imm}]"
    # STR Xt (64-bit)
    if (inst & 0xFFC00000) == 0xF9000000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = ((inst >> 10) & 0xFFF) * 8
        return s + f"  STR x{rt}, [x{rn}, #{imm}]"
    # LDR Wt (32-bit)
    if (inst & 0xFFC00000) == 0xB9400000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = ((inst >> 10) & 0xFFF) * 4
        return s + f"  LDR w{rt}, [x{rn}, #{imm}]"
    # STR Wt (32-bit)
    if (inst & 0xFFC00000) == 0xB9000000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = ((inst >> 10) & 0xFFF) * 4
        return s + f"  STR w{rt}, [x{rn}, #{imm}]"
    # STP (pre/post indexed, various)
    if (inst & 0xFFC00000) == 0xA9000000 or (inst & 0xFFC00000) == 0xA9800000 or (inst & 0xFFC00000) == 0xA9BF0000:
        return s + "  STP ..."
    # LDP
    if (inst & 0xFFC00000) == 0xA9400000 or (inst & 0xFFC00000) == 0xA9C00000:
        return s + "  LDP ..."
    # BLR
    if (inst & 0xFFFFFC1F) == 0xD63F0000:
        rn = (inst >> 5) & 0x1F
        return s + f"  BLR x{rn}"
    # BR
    if (inst & 0xFFFFFC1F) == 0xD61F0000:
        rn = (inst >> 5) & 0x1F
        return s + f"  BR x{rn}"
    # CMP (SUBS XZR)
    if (inst & 0xFF20001F) == 0xEB00001F:
        rn = (inst >> 5) & 0x1F; rm = (inst >> 16) & 0x1F
        return s + f"  CMP x{rn}, x{rm}"
    # CMP imm
    if (inst & 0xFF800000) == 0xF1000000:
        rn = (inst >> 5) & 0x1F; imm12 = (inst >> 10) & 0xFFF
        return s + f"  CMP x{rn}, #0x{imm12:X}"
    if (inst & 0xFF800000) == 0x71000000:
        rn = (inst >> 5) & 0x1F; imm12 = (inst >> 10) & 0xFFF
        return s + f"  CMP w{rn}, #0x{imm12:X}"
    # TST
    if (inst & 0xFF80001F) == 0x7200001F:
        rn = (inst >> 5) & 0x1F
        return s + f"  TST w{rn}, #imm"
    # CSEL
    if (inst & 0xFFE00C00) == 0x9A800000 or (inst & 0xFFE00C00) == 0x1A800000:
        return s + "  CSEL/CSINC ..."
    return s

def disasm_range(start, end, label=""):
    if label:
        print(f"\n=== {label} ===")
    for off in range(start, end, 4):
        inst = r32(off)
        print(decode(off, inst))

def find_bl_callers(target, start=0x1000, end=0x6A000):
    callers = []
    for off in range(start, end, 4):
        inst = r32(off)
        if (inst >> 26) == 0x25:
            imm = inst & 0x3FFFFFF
            if imm & 0x2000000: imm |= ~0x3FFFFFF
            t = off + (imm << 2)
            if (t & 0xFFFFFFFF) == target:
                callers.append(off)
    return callers

# ============================================================
# 1. GetDevInfoPtr caller at 0x4839C
# ============================================================
print("=" * 70)
print("1. GetDevInfoPtr (0x22C58) caller at 0x4839C — full function context")
print("=" * 70)

# Find function start (look backwards for prologue)
for off in range(0x4839C, 0x48000, -4):
    inst = r32(off)
    # STP x29, x30, [sp, ...] prologue pattern
    if (inst & 0xFFC003E0) == 0xA9800000 or (inst & 0xFFC003E0) == 0xA9BC0000 or \
       (inst & 0xFFE003E0) == 0xA9BE0000 or (inst & 0xFE000000) == 0x6C000000 or \
       (inst == r32(off) and off < 0x4839C - 80):
        pass
    # Look for RET or padding before the function
    if inst == 0xD65F03C0 or inst == 0x00000000:
        func_start = off + 4
        break
else:
    func_start = 0x48300

print(f"  Probable function starts around 0x{func_start:05X}")
disasm_range(max(0x48300, func_start - 0x20), min(0x484A0, 0x4839C + 0x100), "Context around 0x4839C")

# ============================================================
# 2. Who calls 0x30A80? (secondary devinfo read into 0x1BE428)
# ============================================================
print("\n" + "=" * 70)
print("2. Callers of 0x30A80 (secondary devinfo read into 0x1BE428)")
print("=" * 70)
callers_30a80 = find_bl_callers(0x30A80)
print(f"  BL callers: {len(callers_30a80)} → {['0x{:05X}'.format(c) for c in callers_30a80]}")
for c in callers_30a80:
    disasm_range(c - 16, c + 20, f"Context of caller 0x{c:05X}")

# Also check for B (branch) callers
b_callers_30a80 = []
for off in range(0x1000, 0x6A000, 4):
    inst = r32(off)
    if (inst >> 26) == 0x05:
        imm = inst & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        t = off + (imm << 2)
        if (t & 0xFFFFFFFF) == 0x30A80:
            b_callers_30a80.append(off)
if b_callers_30a80:
    print(f"\n  B (branch) callers: {len(b_callers_30a80)} → {['0x{:05X}'.format(c) for c in b_callers_30a80]}")

# ============================================================
# 3. Boot sequence: 0x01500-0x01700 full disassembly
# ============================================================
print("\n" + "=" * 70)
print("3. Boot sequence 0x01500-0x01700 (full)")
print("=" * 70)
disasm_range(0x01500, 0x01700, "Boot init sequence")

# ============================================================
# 4. Find ANY STP/STR that could write to devinfo[8..16] area
# Devinfo at 0x1BD978, byte 13 = devinfo+13 = 0x1BD985
# Look for STR with base pointing to devinfo buffer
# ============================================================
print("\n" + "=" * 70)
print("4. Search for STP x_,x_,[x_] patterns that could zero devinfo area")
print("   (devinfo buffer at 0x1BD978, byte 13 at 0x1BD985)")
print("=" * 70)
# Look for sequences: ADRP to 0x1BD000, ADD +0x978, then STP/STR (w/x) within ~20 instructions
for off in range(0x1000, 0x6A000, 4):
    inst = r32(off)
    if (inst & 0x9F000000) == 0x90000000:  # ADRP
        rd = inst & 0x1F
        immhi = (inst >> 5) & 0x7FFFF; immlo = (inst >> 29) & 0x3
        iv = (immhi << 2) | immlo
        if iv & 0x100000: iv |= ~0x1FFFFF
        pg = ((off & ~0xFFF) + (iv << 12)) & 0xFFFFFFFF
        if pg == 0x1BD000:
            # Check next instruction for ADD +0x978
            next_inst = r32(off + 4)
            if (next_inst & 0xFF800000) == 0x91000000:
                nrd = next_inst & 0x1F
                nrn = (next_inst >> 5) & 0x1F
                nimm = (next_inst >> 10) & 0xFFF
                if nrn == rd and nimm == 0x978:
                    # Found ADRP+ADD to devinfo buffer. Now search forward for STORE instructions
                    target_reg = nrd
                    for off2 in range(off + 8, min(off + 80, 0x6A000), 4):
                        inst2 = r32(off2)
                        # STP (any variant storing to target_reg base)
                        if (inst2 & 0x7C000000) == 0x28000000 or (inst2 & 0x7C000000) == 0x2C000000:
                            rn = (inst2 >> 5) & 0x1F
                            if rn == target_reg:
                                print(f"  STP to devinfo base at 0x{off2:05X} (ADRP at 0x{off:05X})")
                        # STR (32/64/8-bit) to target_reg
                        if (inst2 & 0xBFC00000) == 0xB9000000 or \
                           (inst2 & 0xFFC00000) == 0xF9000000 or \
                           (inst2 & 0xFFC00000) == 0x39000000:
                            rn = (inst2 >> 5) & 0x1F
                            if rn == target_reg:
                                # Decode offset
                                if (inst2 & 0xFFC00000) == 0x39000000:
                                    imm = (inst2 >> 10) & 0xFFF  # byte offset
                                elif (inst2 & 0xFFC00000) == 0xB9000000:
                                    imm = ((inst2 >> 10) & 0xFFF) * 4  # word offset
                                elif (inst2 & 0xFFC00000) == 0xF9000000:
                                    imm = ((inst2 >> 10) & 0xFFF) * 8  # dword offset
                                else:
                                    imm = -1
                                rt = inst2 & 0x1F
                                print(f"  STORE at 0x{off2:05X}: w/x{rt} → [devinfo+{imm}] (ADRP at 0x{off:05X})")

# ============================================================
# 5. Check 0x362D8 OemCheckResetDevInfo entry — what is param?
# ============================================================
print("\n" + "=" * 70)
print("5. OemCheckResetDevInfo (0x362D8) — first 20 instructions")
print("=" * 70)
disasm_range(0x362D8, 0x36340, "OemCheckResetDevInfo entry")

# Who calls OemCheckResetDevInfo?
oem_callers = find_bl_callers(0x362D8)
print(f"\n  Callers: {['0x{:05X}'.format(c) for c in oem_callers]}")
for c in oem_callers:
    disasm_range(c - 12, c + 8, f"Caller 0x{c:05X} context")

# ============================================================
# 6. Function 0x30740 (called at 0x3691C in boot function)
# ============================================================
print("\n" + "=" * 70)
print("6. Function 0x30740 (called from boot function at 0x3691C)")
print("=" * 70)
disasm_range(0x30740, 0x30830, "0x30740 function")
# Check if it has any ADRP to 0x1BD000
has_devinfo_adrp = False
for off in range(0x30740, 0x30830, 4):
    inst = r32(off)
    if (inst & 0x9F000000) == 0x90000000:
        rd = inst & 0x1F
        immhi = (inst >> 5) & 0x7FFFF; immlo = (inst >> 29) & 0x3
        iv = (immhi << 2) | immlo
        if iv & 0x100000: iv |= ~0x1FFFFF
        pg = ((off & ~0xFFF) + (iv << 12)) & 0xFFFFFFFF
        if pg == 0x1BD000:
            has_devinfo_adrp = True
            print(f"  ** ADRP to devinfo page at 0x{off:05X}!")
if not has_devinfo_adrp:
    print("  No ADRP to devinfo page (0x1BD000) in this range")

# ============================================================
# 7. Check ALL callers of IsDeviceUnlocked that also WRITE back
# Any caller that reads IsDeviceUnlocked and then modifies devinfo?
# ============================================================
print("\n" + "=" * 70)
print("7. IsDeviceUnlocked callers — check for subsequent STRB to devinfo")
print("=" * 70)
idu_callers = find_bl_callers(0x22C18)
print(f"  13 callers: {['0x{:05X}'.format(c) for c in idu_callers]}")

# For each caller, search forward 40 instructions for ADRP 0x1BD000 + store
for c in idu_callers:
    for off in range(c + 4, min(c + 160, 0x6A000), 4):
        inst = r32(off)
        if (inst & 0x9F000000) == 0x90000000:
            rd = inst & 0x1F
            immhi = (inst >> 5) & 0x7FFFF; immlo = (inst >> 29) & 0x3
            iv = (immhi << 2) | immlo
            if iv & 0x100000: iv |= ~0x1FFFFF
            pg = ((off & ~0xFFF) + (iv << 12)) & 0xFFFFFFFF
            if pg == 0x1BD000:
                # Check next few instructions for STRB
                for off2 in range(off, min(off + 20, 0x6A000), 4):
                    inst2 = r32(off2)
                    if (inst2 & 0xFFC00000) == 0x39000000:  # STRB
                        rn = (inst2 >> 5) & 0x1F
                        imm = (inst2 >> 10) & 0xFFF
                        if imm == 13 or imm == 14:
                            print(f"  *** WRITE to devinfo[{imm}] at 0x{off2:05X} after IsDeviceUnlocked call at 0x{c:05X}")

# ============================================================
# 8. Check 0x367F0 boot function — ALL BL targets listed with ADRP info
# ============================================================
print("\n" + "=" * 70)
print("8. Boot function 0x367F0 — ALL BL/BLR targets")
print("=" * 70)
for off in range(0x367F0, 0x36A00, 4):
    inst = r32(off)
    if (inst >> 26) == 0x25:  # BL
        imm = inst & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        t = off + (imm << 2)
        t = t & 0xFFFFFFFF
        # Check if target has ADRP to 0x1BD000 in first 50 instructions
        has_it = False
        for check in range(t, min(t + 200, 0x6A000), 4):
            ci = r32(check)
            if (ci & 0x9F000000) == 0x90000000:
                rd = ci & 0x1F
                immhi = (ci >> 5) & 0x7FFFF; immlo = (ci >> 29) & 0x3
                iv = (immhi << 2) | immlo
                if iv & 0x100000: iv |= ~0x1FFFFF
                pg = ((check & ~0xFFF) + (iv << 12)) & 0xFFFFFFFF
                if pg == 0x1BD000:
                    has_it = True
                    break
            # Stop at RET
            if ci == 0xD65F03C0:
                break
        marker = " ← ACCESSES DEVINFO" if has_it else ""
        print(f"  0x{off:05X}: BL 0x{t:05X}{marker}")
    if (inst & 0xFFFFFC1F) == 0xD63F0000:  # BLR
        rn = (inst >> 5) & 0x1F
        print(f"  0x{off:05X}: BLR x{rn} (indirect call)")

# ============================================================
# 9. ReadDeviceInfo (0x232D8) full — check exact flow
# ============================================================
print("\n" + "=" * 70)
print("9. ReadDeviceInfo 0x232D8 - FULL disassembly")
print("=" * 70)
disasm_range(0x232D8, 0x233C0, "ReadDeviceInfo full")

# ============================================================
# 10. Check if 0x1BE388 ("already read" flag) is written anywhere
# besides ReadDeviceInfo
# ============================================================
print("\n" + "=" * 70)
print("10. Search for ALL writes to 'already read' flag at 0x1BE388")
print("    (ADRP 0x1BE000 + offset 0x388)")
print("=" * 70)
for off in range(0x1000, 0x6A000, 4):
    inst = r32(off)
    if (inst & 0x9F000000) == 0x90000000:  # ADRP
        rd = inst & 0x1F
        immhi = (inst >> 5) & 0x7FFFF; immlo = (inst >> 29) & 0x3
        iv = (immhi << 2) | immlo
        if iv & 0x100000: iv |= ~0x1FFFFF
        pg = ((off & ~0xFFF) + (iv << 12)) & 0xFFFFFFFF
        if pg == 0x1BE000:
            # Check next instructions for STRB with offset that could be 0x388
            for off2 in range(off + 4, min(off + 20, 0x6A000), 4):
                inst2 = r32(off2)
                # STRB wt, [xn, #0x388]
                if (inst2 & 0xFFC00000) == 0x39000000:
                    rn2 = (inst2 >> 5) & 0x1F
                    imm2 = (inst2 >> 10) & 0xFFF
                    if imm2 == 0x388:
                        print(f"  STRB to already_read flag at 0x{off2:05X} (ADRP at 0x{off:05X})")
                # Also check for combined ADD + STR patterns
                if (inst2 & 0xFF800000) == 0x91000000:
                    nimm = (inst2 >> 10) & 0xFFF
                    if nimm == 0x388:
                        # This ADD points directly to the flag address
                        print(f"  ADD to flag address at 0x{off2:05X} (ADRP at 0x{off:05X})")

print("\nDone.")
