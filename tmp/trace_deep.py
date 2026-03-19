#!/usr/bin/env python3
"""Deep investigation of remaining suspects for devinfo[13] reset."""
import struct

PE = '/tmp/ffs_modules/pe32_59d536f5_1.bin'
with open(PE, 'rb') as f:
    data = f.read()

def decode_bl(data, off):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr & 0xFC000000) == 0x94000000:
        imm26 = instr & 0x03FFFFFF
        if imm26 & 0x02000000:
            imm26 -= 0x04000000
        return off + imm26 * 4
    return None

def find_bl_callers(data, target, start=0x1000, end=0x6A000):
    callers = []
    for off in range(start, end, 4):
        d = decode_bl(data, off)
        if d == target:
            callers.append(off)
    return callers

def disasm_range(data, start, end):
    """Simple disassembler for context."""
    for off in range(start, end, 4):
        instr = struct.unpack_from('<I', data, off)[0]
        s = ''
        # BL
        if (instr & 0xFC000000) == 0x94000000:
            imm26 = instr & 0x03FFFFFF
            if imm26 & 0x02000000: imm26 -= 0x04000000
            s = f'BL {hex(off + imm26*4)}'
        # B
        elif (instr & 0xFC000000) == 0x14000000:
            imm26 = instr & 0x03FFFFFF
            if imm26 & 0x02000000: imm26 -= 0x04000000
            s = f'B {hex(off + imm26*4)}'
        # RET
        elif (instr & 0xFFFFFC1F) == 0xD65F03C0:
            s = 'RET'
        # ADRP
        elif (instr & 0x9F000000) == 0x90000000:
            rd = instr & 0x1F
            immhi = (instr >> 5) & 0x7FFFF
            immlo = (instr >> 29) & 0x3
            imm = (immhi << 2) | immlo
            if imm & 0x100000: imm -= 0x200000
            page = (off & ~0xFFF) + (imm << 12)
            s = f'ADRP x{rd}, {hex(page)}'
        # ADD imm
        elif (instr & 0xFFC00000) == 0x91000000:
            rd = instr & 0x1F
            rn = (instr >> 5) & 0x1F
            imm12 = (instr >> 10) & 0xFFF
            sh = (instr >> 22) & 1
            if sh: imm12 <<= 12
            s = f'ADD x{rd}, x{rn}, #{hex(imm12)}'
        # LDRB/STRB unsigned
        elif (instr & 0xFFC00000) in (0x39400000, 0x39000000):
            rt = instr & 0x1F
            rn = (instr >> 5) & 0x1F
            imm = (instr >> 10) & 0xFFF
            is_load = (instr >> 22) & 1
            op = 'LDRB' if is_load else 'STRB'
            s = f'{op} w{rt}, [x{rn}, #{imm}]'
        # LDR (unsigned, 32-bit)
        elif (instr & 0xFFC00000) == 0xB9400000:
            rt = instr & 0x1F
            rn = (instr >> 5) & 0x1F
            imm = ((instr >> 10) & 0xFFF) * 4
            s = f'LDR w{rt}, [x{rn}, #{imm}]'
        # LDR (unsigned, 64-bit)
        elif (instr & 0xFFC00000) == 0xF9400000:
            rt = instr & 0x1F
            rn = (instr >> 5) & 0x1F
            imm = ((instr >> 10) & 0xFFF) * 8
            s = f'LDR x{rt}, [x{rn}, #{imm}]'
        # STR (unsigned, 64-bit)
        elif (instr & 0xFFC00000) == 0xF9000000:
            rt = instr & 0x1F
            rn = (instr >> 5) & 0x1F
            imm = ((instr >> 10) & 0xFFF) * 8
            s = f'STR x{rt}, [x{rn}, #{imm}]'
        # CBZ
        elif (instr & 0xFF000000) == 0xB4000000:
            rt = instr & 0x1F
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 & 0x40000: imm19 -= 0x80000
            s = f'CBZ x{rt}, {hex(off + imm19*4)}'
        # CBNZ
        elif (instr & 0xFF000000) == 0xB5000000:
            rt = instr & 0x1F
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 & 0x40000: imm19 -= 0x80000
            s = f'CBNZ x{rt}, {hex(off + imm19*4)}'
        # TBZ
        elif (instr & 0x7F000000) == 0x36000000:
            bit = ((instr >> 31) << 5) | ((instr >> 19) & 0x1F)
            rt = instr & 0x1F
            imm14 = (instr >> 5) & 0x3FFF
            if imm14 & 0x2000: imm14 -= 0x4000
            s = f'TBZ w{rt}, #{bit}, {hex(off + imm14*4)}'
        elif (instr & 0x7F000000) == 0x37000000:
            bit = ((instr >> 31) << 5) | ((instr >> 19) & 0x1F)
            rt = instr & 0x1F
            imm14 = (instr >> 5) & 0x3FFF
            if imm14 & 0x2000: imm14 -= 0x4000
            s = f'TBNZ w{rt}, #{bit}, {hex(off + imm14*4)}'
        # STP
        elif (instr & 0xFFC00000) == 0xA9000000 or (instr & 0xFE000000) == 0xA9000000:
            s = 'STP ...'
        # MOV (ORR)
        elif (instr & 0xFFE0FFE0) == 0xAA0003E0:
            rd = instr & 0x1F
            rm = (instr >> 16) & 0x1F
            s = f'MOV x{rd}, x{rm}'
        # MOV w (ORR 32)
        elif (instr & 0xFFE0FFE0) == 0x2A0003E0:
            rd = instr & 0x1F
            rm = (instr >> 16) & 0x1F
            s = f'MOV w{rd}, w{rm}'
        # MOV WZR
        elif instr & 0xFFE0FFFF == 0x2A1F03E0:
            rd = instr & 0x1F
            s = f'MOV w{rd}, wzr'
        # BLR
        elif (instr & 0xFFFFFC1F) == 0xD63F0000:
            rn = (instr >> 5) & 0x1F
            s = f'BLR x{rn}'
        # BR
        elif (instr & 0xFFFFFC1F) == 0xD61F0000:
            rn = (instr >> 5) & 0x1F
            s = f'BR x{rn}'
        # NOP
        elif instr == 0xD503201F:
            s = 'NOP'

        print(f'  {hex(off)}: 0x{instr:08X}  {s}')


print("=== 1. Callers of 0x30A80 (secondary ReadWritePartition READ) ===")
callers_30a80 = find_bl_callers(data, 0x30A80)
print(f"  {len(callers_30a80)} callers: {[hex(c) for c in callers_30a80]}")
for c in callers_30a80:
    print(f"\n  Context around caller {hex(c)}:")
    disasm_range(data, max(c-32, 0x1000), min(c+32, 0x6A000))

print("\n=== 2. GetDevInfoPtr caller at 0x4839C ===")
print("  Context (0x48370-0x483D0):")
disasm_range(data, 0x48370, 0x483D0)

print("\n=== 3. Function containing 0x4839C ===")
# Scan backwards for function prologue
for off in range(0x48398, 0x48000, -4):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr & 0xFFFFFC1F) == 0xD65F03C0:  # RET
        print(f"  Previous RET at {hex(off)}, function starts at {hex(off+4)}")
        break
    if instr == 0x00000000:
        print(f"  Padding at {hex(off)}, function starts at {hex(off+4)}")
        break

print("\n=== 4. Boot sequence (0x01540-0x01640) ===")
disasm_range(data, 0x01540, 0x01640)

print("\n=== 5. What does ReadDeviceInfo do on error? ===")
# ReadDeviceInfo at 0x232D8 - show the full function
print("  ReadDeviceInfo (0x232D8-0x23400):")
disasm_range(data, 0x232D8, 0x23400)

print("\n=== 6. Check 0x30740 (called from boot function 0x367F0) ===")
print("  Callers of 0x30740:")
callers_30740 = find_bl_callers(data, 0x30740)
print(f"  {len(callers_30740)} callers: {[hex(c) for c in callers_30740]}")
print("\n  Function 0x30740 first 40 instrs:")
disasm_range(data, 0x30740, 0x30840)

print("\n=== 7. Check OemCheckResetDevInfo param calculation ===")
# boot function calls OemCheckResetDevInfo(0x362D8) at 0x368A4
# What value does it pass as parameter (w0)?
print("  Boot function before OemCheckResetDevInfo call (0x36890-0x368B0):")
disasm_range(data, 0x36890, 0x368B0)

print("\n=== 8. Check 0x34E50 (ProcessParams, first call in boot func) ===")
print("  First 30 instrs:")
disasm_range(data, 0x34E50, 0x34F10)

print("\n=== 9. CRITICAL: Search for ALL STRB that could write offset 13 ===")
# devinfo buffer at 0x1BD978. offset 13 is at 0x1BD985.
# Any register-relative STRB with #13 offset where base points to devinfo
# But also: STRB w?, [x?, #0] where x? = 0x1BD985 via ADRP+ADD
# We already found 4 STRB sites. Let's also search for STR (word) that
# could overwrite byte 13 as part of a wider store
# STR w (32-bit) at devinfo+12 would overwrite bytes 12-15 including byte 13
# STP could also overwrite

# Search for any STORE to offset 12 with 32-bit width (STR w?, [x?, #12])
print("  Searching for STR w?, [x?, #12] in code range (could overwrite byte 13):")
for off in range(0x1000, 0x6A000, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    # STR w unsigned offset: 1011 1001 00xx xxxx xxxx xxxx xxxx xxxx
    if (instr & 0xFFC00000) == 0xB9000000:
        imm = ((instr >> 10) & 0xFFF) * 4
        if imm == 12:
            rt = instr & 0x1F
            rn = (instr >> 5) & 0x1F
            # Check if previous instructions set rn to devinfo buffer
            # Look back for ADRP to 0x1BD000
            for back in range(off-4, max(off-20, 0x1000), -4):
                bi = struct.unpack_from('<I', data, back)[0]
                if (bi & 0x9F000000) == 0x90000000:
                    brd = bi & 0x1F
                    if brd == rn:
                        immhi = (bi >> 5) & 0x7FFFF
                        immlo = (bi >> 29) & 0x3
                        bimm = (immhi << 2) | immlo
                        if bimm & 0x100000: bimm -= 0x200000
                        page = (back & ~0xFFF) + (bimm << 12)
                        if page == 0x1BD000:
                            print(f"  *** FOUND: {hex(off)}: STR w{rt}, [x{rn}, #12] (ADRP to devinfo at {hex(back)})")
                            disasm_range(data, max(off-16, 0x1000), min(off+16, 0x6A000))

# Also check STP that covers byte 13
# STP stores pairs. STP w, w at offset 12 writes bytes 12-19
print("\n  Searching for STP covering devinfo+12 area:")
for off in range(0x1000, 0x6A000, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    # STP 32-bit: 0010 1001 0iii iiii irrr rrnn nnnt tttt  (pre/offset)
    # offset in range 8-16 could overlap byte 13
    if (instr & 0xFFC00000) == 0x29000000 or (instr & 0xFFC00000) == 0x29800000:
        imm7 = (instr >> 15) & 0x7F
        if imm7 & 0x40: imm7 -= 0x80
        byte_off = imm7 * 4  # scaled by 4 for 32-bit STP
        if 8 <= byte_off <= 13:  # any STP that could cover byte 13
            rn = (instr >> 5) & 0x1F
            for back in range(off-4, max(off-20, 0x1000), -4):
                bi = struct.unpack_from('<I', data, back)[0]
                if (bi & 0x9F000000) == 0x90000000:
                    brd = bi & 0x1F
                    if brd == rn:
                        immhi = (bi >> 5) & 0x7FFFF
                        immlo = (bi >> 29) & 0x3
                        bimm = (immhi << 2) | immlo
                        if bimm & 0x100000: bimm -= 0x200000
                        page = (back & ~0xFFF) + (bimm << 12)
                        if page == 0x1BD000:
                            rt = instr & 0x1F
                            rt2 = (instr >> 10) & 0x1F
                            print(f"  *** FOUND STP at {hex(off)}: w{rt},w{rt2} offset={byte_off}")
                            disasm_range(data, max(off-16, 0x1000), min(off+16, 0x6A000))

print("\n=== 10. Check CompareMem at 0x4FD10 ===")
print("  CompareMem function:")
disasm_range(data, 0x4FD10, 0x4FD60)

print("\n=== 11. IMPORTANT: Check if 0x232D8 ReadDeviceInfo reads into CORRECT buffer ===")
# ReadDeviceInfo should call ReadWritePartition(0, devinfo_buf=0x1BD978, 2576)
# But what if it reads into the WRONG buffer?
print("  ReadDeviceInfo args to ReadWritePartition:")
# Look for the call at around 0x23370
disasm_range(data, 0x23340, 0x233A0)

print("\n=== 12. init_defaults(0x384D0) full function to find exact SecureBoot gate ===")
disasm_range(data, 0x384D0, 0x38620)

print("\nDone.")
