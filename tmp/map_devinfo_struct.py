#!/usr/bin/env python3
"""
Final analysis: Map the exact devinfo structure and understand the unlock flow.
Key discoveries:
- SetUnlockValue at 0x22e4c: strb w23, [x1, #13] = is_unlocked at offset 0x0D
- SetUnlockCritical at 0x22ea0: strb w23, [x1, #14] = is_unlock_critical at 0x0E
- Both write via bl 0x18248 (devinfo partition read/write)
- OemCheckResetDevInfo at 0x36500: writes to param SID via bl 0x32620

Now let's:
1. Decode the MOV values to understand what gets written
2. Find the devinfo init defaults function to map all fields
3. Check if param → devinfo override exists
4. Map the complete devinfo structure
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

def decode_insn(pc):
    """Decode a single ARM64 instruction at given offset, return description."""
    insn = struct.unpack_from('<I', data, pc)[0]

    # MOVZ
    if (insn & 0x7F800000) == 0x52800000:
        rd = insn & 0x1F
        imm16 = (insn >> 5) & 0xFFFF
        hw = (insn >> 21) & 0x3
        val = imm16 << (hw * 16)
        sf = 'x' if (insn & 0x80000000) else 'w'
        return f"movz {sf}{rd}, #{val} (0x{val:x})"

    # MOVN
    if (insn & 0x7F800000) == 0x12800000:
        rd = insn & 0x1F
        imm16 = (insn >> 5) & 0xFFFF
        hw = (insn >> 21) & 0x3
        sf = 'x' if (insn & 0x80000000) else 'w'
        if sf == 'w':
            val = ~(imm16 << (hw * 16)) & 0xFFFFFFFF
        else:
            val = ~(imm16 << (hw * 16)) & 0xFFFFFFFFFFFFFFFF
        return f"movn {sf}{rd}, #{val} (0x{val:x})"

    # MOVK
    if (insn & 0x7F800000) == 0x72800000:
        rd = insn & 0x1F
        imm16 = (insn >> 5) & 0xFFFF
        hw = (insn >> 21) & 0x3
        val = imm16 << (hw * 16)
        sf = 'x' if (insn & 0x80000000) else 'w'
        return f"movk {sf}{rd}, #0x{val:x}, lsl #{hw*16}"

    # STRB
    if (insn & 0xFFC00000) == 0x39000000:
        rt = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm12 = (insn >> 10) & 0xFFF
        return f"strb w{rt}, [x{rn}, #{imm12}]"

    # LDRB
    if (insn & 0xFFC00000) == 0x39400000:
        rt = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm12 = (insn >> 10) & 0xFFF
        return f"ldrb w{rt}, [x{rn}, #{imm12}]"

    # STR W
    if (insn & 0xFFC00000) == 0xB9000000:
        rt = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm12 = ((insn >> 10) & 0xFFF) * 4
        return f"str w{rt}, [x{rn}, #{imm12}]"

    # LDR W
    if (insn & 0xFFC00000) == 0xB9400000:
        rt = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm12 = ((insn >> 10) & 0xFFF) * 4
        return f"ldr w{rt}, [x{rn}, #{imm12}]"

    # STR X
    if (insn & 0xFFC00000) == 0xF9000000:
        rt = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm12 = ((insn >> 10) & 0xFFF) * 8
        return f"str x{rt}, [x{rn}, #{imm12}]"

    # LDR X
    if (insn & 0xFFC00000) == 0xF9400000:
        rt = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm12 = ((insn >> 10) & 0xFFF) * 8
        return f"ldr x{rt}, [x{rn}, #{imm12}]"

    # ORR imm (wzr)
    if (insn & 0x7F800000) == 0x32000000:
        rd = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        sf = 'x' if (insn & 0x80000000) else 'w'
        if rn == 31:
            imms = (insn >> 10) & 0x3F
            immr = (insn >> 16) & 0x3F
            N = (insn >> 22) & 1
            try:
                if sf == 'w':
                    ones = (imms & 0x1F) + 1
                    rotate = immr & 0x1F
                    val = ((1 << ones) - 1)
                    val = ((val >> rotate) | (val << (32 - rotate))) & 0xFFFFFFFF
                else:
                    ones = imms + 1
                    rotate = immr
                    val = ((1 << ones) - 1)
                    val = ((val >> rotate) | (val << (64 - rotate))) & 0xFFFFFFFFFFFFFFFF
                return f"orr {sf}{rd}, {sf}zr, #{val} (0x{val:x})"
            except:
                return f"orr {sf}{rd}, {sf}zr, #?"

    # BL
    if (insn & 0xFC000000) == 0x94000000:
        offset = insn & 0x3FFFFFF
        if offset & (1 << 25):
            offset -= (1 << 26)
        target = pc + offset * 4
        return f"bl 0x{target:05x}"

    # B
    if (insn & 0xFC000000) == 0x14000000:
        offset = insn & 0x3FFFFFF
        if offset & (1 << 25):
            offset -= (1 << 26)
        target = pc + offset * 4
        return f"b 0x{target:05x}"

    # MOV reg
    if (insn & 0x7FE0FFE0) == 0x2A0003E0:
        rd = insn & 0x1F
        rm = (insn >> 16) & 0x1F
        sf = 'x' if (insn & 0x80000000) else 'w'
        return f"mov {sf}{rd}, {sf}{rm}"
    if (insn & 0xFFE0FFE0) == 0xAA0003E0:
        rd = insn & 0x1F
        rm = (insn >> 16) & 0x1F
        return f"mov x{rd}, x{rm}"

    # RET
    if insn == 0xD65F03C0:
        return "ret"

    # STP pre-index
    if (insn & 0x7FC00000) == 0x29800000:
        return f"stp (prologue)"

    # CBZ/CBNZ
    if (insn & 0x7E000000) == 0x34000000:
        rt = insn & 0x1F
        offset = ((insn >> 5) & 0x7FFFF)
        if offset & (1 << 18):
            offset -= (1 << 19)
        target = pc + offset * 4
        op = 'cbnz' if (insn & 0x01000000) else 'cbz'
        sf = 'x' if (insn & 0x80000000) else 'w'
        return f"{op} {sf}{rt}, 0x{target:05x}"

    return f"raw: {insn:08x}"

# 1. Detailed decode of the SetUnlockValue function body
print("=" * 70)
print("SetUnlockValue function detail (0x22db8 - 0x22f00)")
print("Focus: what offset in devinfo gets written")
print("=" * 70)

for pc in range(0x22db8, 0x22f00, 4):
    d = decode_insn(pc)
    # Also check ADRP+ADD
    insn1 = struct.unpack_from('<I', data, pc)[0]
    if pc + 4 < len(data):
        insn2 = struct.unpack_from('<I', data, pc + 4)[0]
        if (insn1 & 0x9F000000) == 0x90000000 and (insn2 & 0xFFC00000) == 0x91000000:
            immlo = (insn1 >> 29) & 0x3
            immhi = (insn1 >> 5) & 0x7FFFF
            imm = ((immhi << 2) | immlo) << 12
            if imm & (1 << 32):
                imm -= (1 << 33)
            adrp_result = (pc & ~0xFFF) + imm
            rd = insn1 & 0x1F
            add_rn = (insn2 >> 5) & 0x1F
            if add_rn == rd:
                add_imm = (insn2 >> 10) & 0xFFF
                target = adrp_result + add_imm
                s = get_string_at(target)
                if s:
                    d = f"ADRP+ADD x{insn2 & 0x1F} -> 0x{target:06x} \"{s[:70]}\""
                else:
                    d = f"ADRP+ADD x{insn2 & 0x1F} -> 0x{target:06x}"

    print(f"  0x{pc:05x}: {d}")

# 2. Find the devinfo init defaults function (0x384d0)
print("\n\n" + "=" * 70)
print("DevInfo init defaults (0x384d0 - what default values are set)")
print("=" * 70)

# This is WriteDeviceInfo area, the init function is called from ReadDeviceInfo
# when magic doesn't match. Look at 0x38430 and 0x384b0 as well.
for pc in range(0x38400, 0x38600, 4):
    d = decode_insn(pc)
    insn1 = struct.unpack_from('<I', data, pc)[0]
    if pc + 4 < len(data):
        insn2 = struct.unpack_from('<I', data, pc + 4)[0]
        if (insn1 & 0x9F000000) == 0x90000000 and (insn2 & 0xFFC00000) == 0x91000000:
            immlo = (insn1 >> 29) & 0x3
            immhi = (insn1 >> 5) & 0x7FFFF
            imm = ((immhi << 2) | immlo) << 12
            if imm & (1 << 32):
                imm -= (1 << 33)
            adrp_result = (pc & ~0xFFF) + imm
            rd = insn1 & 0x1F
            add_rn = (insn2 >> 5) & 0x1F
            if add_rn == rd:
                add_imm = (insn2 >> 10) & 0xFFF
                target = adrp_result + add_imm
                s = get_string_at(target)
                if s:
                    d = f"ADRP+ADD x{insn2 & 0x1F} -> 0x{target:06x} \"{s[:70]}\""
                else:
                    d = f"ADRP+ADD x{insn2 & 0x1F} -> 0x{target:06x}"

    print(f"  0x{pc:05x}: {d}")

# 3. Check what's at 0x1bd978 (devinfo global buffer pointer)
print(f"\n\nDevInfo global buffer at PE32+ 0x1bd978:")
chunk = data[0x1bd900:0x1bda00]
for i in range(0, len(chunk), 16):
    row = chunk[i:i+16]
    hex_part = ' '.join(f'{b:02x}' for b in row)
    asc_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row)
    print(f"  0x{0x1bd900+i:06x}: {hex_part:<48}  {asc_part}")

# 4. Verify original devinfo.bin structure
print("\n\nOriginal devinfo.bin structure:")
with open("edl_backup/devinfo.bin.original", "rb") as f:
    devinfo = f.read()

# Show all non-zero regions
print(f"Size: {len(devinfo)} bytes")
for i in range(len(devinfo)):
    if devinfo[i] != 0:
        # Get surrounding context
        start = max(0, i - 2)
        end = min(len(devinfo), i + 16)
        while end < len(devinfo) and devinfo[end] != 0:
            end += 1
        end = min(end + 2, len(devinfo))
        row = devinfo[start:end]
        hex_part = ' '.join(f'{b:02x}' for b in row)
        asc_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row)
        print(f"  offset 0x{i:04x} (dec {i:4d}): byte=0x{devinfo[i]:02x} ctx: {hex_part}")
        # Skip to end of this non-zero region
        i = end

# 5. Based on STRB/STR offsets found in code, map the devinfo structure
print("\n\nDevInfo structure mapping (from ABL code analysis):")
print("  Offset 0x00-0x0C (0-12): 'ANDROID-BOOT!' magic (13 bytes)")
print("  Offset 0x0D (13): is_unlocked (STRB at 0x22e4c)")
print("  Offset 0x0E (14): is_unlock_critical (STRB at 0x22ea0)")
print("  Offset 0x0F (15): ? (value 0x01 in original)")

# Search for all STRB/LDRB to the devinfo buffer base register in the code
# The base is loaded via ADRP+ADD to 0x1bd978
# After a function loads the base into some register, STRB/LDRB offsets reveal structure
print("\n\nSearching for all STRB/LDRB with offsets 13-16 in the SetUnlockValue area:")
for pc in range(0x22d00, 0x23200, 4):
    insn = struct.unpack_from('<I', data, pc)[0]
    # STRB
    if (insn & 0xFFC00000) == 0x39000000:
        rt = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm12 = (insn >> 10) & 0xFFF
        print(f"  0x{pc:05x}: strb w{rt}, [x{rn}, #{imm12}]")
    # LDRB
    if (insn & 0xFFC00000) == 0x39400000:
        rt = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm12 = (insn >> 10) & 0xFFF
        print(f"  0x{pc:05x}: ldrb w{rt}, [x{rn}, #{imm12}]")

# Also check the ReadDeviceInfo function for LDRB patterns
print("\nSearching for LDRB in ReadDeviceInfo area (0x23200-0x23500):")
for pc in range(0x23200, 0x23500, 4):
    insn = struct.unpack_from('<I', data, pc)[0]
    if (insn & 0xFFC00000) == 0x39400000:
        rt = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm12 = (insn >> 10) & 0xFFF
        print(f"  0x{pc:05x}: ldrb w{rt}, [x{rn}, #{imm12}]")
    if (insn & 0xFFC00000) == 0x39000000:
        rt = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm12 = (insn >> 10) & 0xFFF
        print(f"  0x{pc:05x}: strb w{rt}, [x{rn}, #{imm12}]")

print("\n[done]")
