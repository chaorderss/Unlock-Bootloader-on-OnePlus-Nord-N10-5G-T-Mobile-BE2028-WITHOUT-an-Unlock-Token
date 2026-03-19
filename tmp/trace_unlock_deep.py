#!/usr/bin/env python3
"""
Deep trace of key unlock-related functions from code references.
Focus on:
1. OemCheckResetDevInfo (0x365b0 area) - param SID/offset for unlock
2. SetUnlockValue (0x22e7c area) - how unlock is written to devinfo
3. UpdateUnlockStatus (0x1d3b4 area) - unlock status update
4. After "Oneplus unlock: succeed" (0x370c0+) - what happens on success
"""

import struct

PE32 = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
with open(PE32, 'rb') as f:
    data = f.read()

def get_string_at(addr):
    if addr < 0 or addr >= len(data):
        return None
    end = data.find(b'\x00', addr)
    if end < 0 or end - addr > 200:
        return None
    try:
        s = data[addr:end].decode('ascii')
        return s if len(s) >= 2 else None
    except:
        return None

def decode_adrp_add(pc, insn1, insn2):
    if (insn1 & 0x9F000000) != 0x90000000:
        return None
    if (insn2 & 0xFFC00000) != 0x91000000:
        return None

    immlo = (insn1 >> 29) & 0x3
    immhi = (insn1 >> 5) & 0x7FFFF
    imm = ((immhi << 2) | immlo) << 12
    if imm & (1 << 32):
        imm -= (1 << 33)

    adrp_result = (pc & ~0xFFF) + imm
    rd = insn1 & 0x1F

    add_rn = (insn2 >> 5) & 0x1F
    if add_rn != rd:
        return None

    add_imm = (insn2 >> 10) & 0xFFF
    add_rd = insn2 & 0x1F
    return adrp_result + add_imm, add_rd

def disasm_range(start, end, label):
    """Full disassembly of a range with all interesting operations."""
    print(f"\n{'='*70}")
    print(f"  {label}: 0x{start:05x} - 0x{end:05x}")
    print(f"{'='*70}")

    for pc in range(start, end, 4):
        if pc + 4 > len(data):
            break
        insn = struct.unpack_from('<I', data, pc)[0]

        line = f"  0x{pc:05x}: {insn:08x}  "
        decoded = False

        # ADRP+ADD (string ref)
        if pc + 8 <= len(data):
            insn2 = struct.unpack_from('<I', data, pc + 4)[0]
            result = decode_adrp_add(pc, insn, insn2)
            if result:
                addr, rd = result
                s = get_string_at(addr)
                if s:
                    print(f"{line}ADRP+ADD x{rd} -> 0x{addr:06x} \"{s[:80]}\"")
                else:
                    print(f"{line}ADRP+ADD x{rd} -> 0x{addr:06x}")
                decoded = True

        # BL
        if (insn & 0xFC000000) == 0x94000000:
            offset = insn & 0x3FFFFFF
            if offset & (1 << 25):
                offset -= (1 << 26)
            target = pc + offset * 4
            print(f"{line}bl 0x{target:05x}")
            decoded = True

        # B (unconditional)
        elif (insn & 0xFC000000) == 0x14000000:
            offset = insn & 0x3FFFFFF
            if offset & (1 << 25):
                offset -= (1 << 26)
            target = pc + offset * 4
            print(f"{line}b 0x{target:05x}")
            decoded = True

        # B.cond
        elif (insn & 0xFF000010) == 0x54000000:
            offset = ((insn >> 5) & 0x7FFFF)
            if offset & (1 << 18):
                offset -= (1 << 19)
            target = pc + offset * 4
            cond = insn & 0xF
            cond_names = {0:'eq',1:'ne',2:'cs',3:'cc',4:'mi',5:'pl',
                         6:'vs',7:'vc',8:'hi',9:'ls',10:'ge',11:'lt',12:'gt',13:'le',14:'al'}
            cn = cond_names.get(cond, f'?{cond}')
            print(f"{line}b.{cn} 0x{target:05x}")
            decoded = True

        # CBZ/CBNZ
        elif (insn & 0x7E000000) == 0x34000000:
            rt = insn & 0x1F
            offset = ((insn >> 5) & 0x7FFFF)
            if offset & (1 << 18):
                offset -= (1 << 19)
            target = pc + offset * 4
            op = 'cbnz' if (insn & 0x01000000) else 'cbz'
            sf = 'x' if (insn & 0x80000000) else 'w'
            print(f"{line}{op} {sf}{rt}, 0x{target:05x}")
            decoded = True

        # MOV immediate (MOVZ/MOVK)
        elif (insn & 0x1F800000) == 0x12800000:  # MOV inverted
            rd = insn & 0x1F
            imm16 = (insn >> 5) & 0xFFFF
            hw = (insn >> 21) & 0x3
            sf = 'x' if (insn & 0x80000000) else 'w'
            val = ~(imm16 << (hw * 16)) & (0xFFFFFFFFFFFFFFFF if sf == 'x' else 0xFFFFFFFF)
            print(f"{line}movn {sf}{rd}, #{val} (0x{val:x})")
            decoded = True
        elif (insn & 0x7F800000) == 0x52800000:  # MOVZ
            rd = insn & 0x1F
            imm16 = (insn >> 5) & 0xFFFF
            hw = (insn >> 21) & 0x3
            val = imm16 << (hw * 16)
            sf = 'x' if (insn & 0x80000000) else 'w'
            print(f"{line}movz {sf}{rd}, #{val} (0x{val:x})")
            decoded = True
        elif (insn & 0x7F800000) == 0x72800000:  # MOVK
            rd = insn & 0x1F
            imm16 = (insn >> 5) & 0xFFFF
            hw = (insn >> 21) & 0x3
            val = imm16 << (hw * 16)
            sf = 'x' if (insn & 0x80000000) else 'w'
            print(f"{line}movk {sf}{rd}, #{val} (0x{val:x})")
            decoded = True

        # ORR immediate (often used for small constants)
        elif (insn & 0x7F800000) == 0x32000000:
            rd = insn & 0x1F
            rn = (insn >> 5) & 0x1F
            sf = 'x' if (insn & 0x80000000) else 'w'
            # Simplified: decode common patterns
            imms = (insn >> 10) & 0x3F
            immr = (insn >> 16) & 0x3F
            N = (insn >> 22) & 1
            # For simple cases, approximate the value
            if rn == 31:  # wzr/xzr
                # Decode bitmask
                size = 32 if sf == 'w' else 64
                try:
                    if sf == 'w':
                        element_size = 32
                        ones = (imms & 0x1F) + 1
                        rotate = immr & 0x1F
                        val = ((1 << ones) - 1)
                        val = ((val >> rotate) | (val << (element_size - rotate))) & 0xFFFFFFFF
                    else:
                        element_size = 64
                        ones = imms + 1
                        rotate = immr
                        val = ((1 << ones) - 1)
                        val = ((val >> rotate) | (val << (element_size - rotate))) & 0xFFFFFFFFFFFFFFFF
                    print(f"{line}orr {sf}{rd}, {sf}zr, #{val} (0x{val:x})")
                except:
                    print(f"{line}orr {sf}{rd}, {sf}zr, #<bitmask>")
                decoded = True

        # STR/LDR with immediate offset
        elif (insn & 0xBFC00000) == 0xB9000000:  # STR/LDR Wt
            is_ldr = (insn >> 22) & 1
            rt = insn & 0x1F
            rn = (insn >> 5) & 0x1F
            imm12 = ((insn >> 10) & 0xFFF) * 4
            op = 'ldr' if is_ldr else 'str'
            print(f"{line}{op} w{rt}, [x{rn}, #{imm12}]")
            decoded = True
        elif (insn & 0xBFC00000) == 0xF9000000:  # STR/LDR Xt
            is_ldr = (insn >> 22) & 1
            rt = insn & 0x1F
            rn = (insn >> 5) & 0x1F
            imm12 = ((insn >> 10) & 0xFFF) * 8
            op = 'ldr' if is_ldr else 'str'
            print(f"{line}{op} x{rt}, [x{rn}, #{imm12}]")
            decoded = True

        # STRB/LDRB
        elif (insn & 0xBFC00000) == 0x39000000:
            is_ldr = (insn >> 22) & 1
            rt = insn & 0x1F
            rn = (insn >> 5) & 0x1F
            imm12 = (insn >> 10) & 0xFFF
            op = 'ldrb' if is_ldr else 'strb'
            print(f"{line}{op} w{rt}, [x{rn}, #{imm12}]")
            decoded = True

        # MOV register
        elif (insn & 0x7FE0FFE0) == 0x2A0003E0:  # MOV Wd, Wm
            rd = insn & 0x1F
            rm = (insn >> 16) & 0x1F
            sf = 'x' if (insn & 0x80000000) else 'w'
            print(f"{line}mov {sf}{rd}, {sf}{rm}")
            decoded = True
        elif (insn & 0xFFE0FFE0) == 0xAA0003E0:  # MOV Xd, Xm
            rd = insn & 0x1F
            rm = (insn >> 16) & 0x1F
            print(f"{line}mov x{rd}, x{rm}")
            decoded = True

        # STP/LDP
        elif (insn & 0x7EC00000) == 0x28800000 or (insn & 0x7EC00000) == 0x29000000:
            pass  # Skip for brevity

        # RET
        elif insn == 0xD65F03C0:
            print(f"{line}ret")
            decoded = True

        # BLR
        elif (insn & 0xFFFFFC1F) == 0xD63F0000:
            rn = (insn >> 5) & 0x1F
            print(f"{line}blr x{rn}")
            decoded = True

        if not decoded:
            # Just show raw hex
            pass  # skip non-decoded for brevity

# 1. OemCheckResetDevInfo - find the function start before 0x365b0
# Look for the nearest STP (function prologue) before 0x365b0
print("\n\nSearching for OemCheckResetDevInfo function prologue...")
for pc in range(0x36500, 0x36000, -4):
    insn = struct.unpack_from('<I', data, pc)[0]
    # STP with pre-index (function prologue): A9Bxxxxx or A98xxxxx
    if (insn & 0xFFC00000) in [0xA9800000, 0xA9BC0000, 0xA9B00000, 0xA9BE0000]:
        print(f"  Possible prologue at 0x{pc:05x}: {insn:08x}")
    # Try broader: any STP with negative offset
    if (insn >> 22) == 0x2A6 or (insn >> 22) == 0x2A7:  # STP pre-index
        print(f"  STP pre-index at 0x{pc:05x}: {insn:08x}")

# Disasm around the OemCheckResetDevInfo reference
disasm_range(0x36500, 0x36700, "OemCheckResetDevInfo area")

# 2. SetUnlockValue area
disasm_range(0x22e00, 0x23100, "SetUnlockValue / devinfo write area")

# 3. UpdateUnlockStatus area
disasm_range(0x1d350, 0x1d600, "UpdateUnlockStatus area")

# 4. IsAllowUnlock area
disasm_range(0x48500, 0x48700, "IsAllowUnlock area")

# 5. "Unable to Update DevInfo" area
disasm_range(0x4ad00, 0x4ae00, "UpdateDevInfo area")

print("\n[done]")
