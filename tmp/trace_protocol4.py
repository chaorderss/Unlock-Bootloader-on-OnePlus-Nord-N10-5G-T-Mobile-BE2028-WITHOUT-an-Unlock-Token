#!/usr/bin/env python3
"""Find actual devinfo storage: check pointer table, function 0x01370, and all partitions."""
import struct, os, glob

PE = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
pe = open(PE, "rb").read()

TEXT_START = 0x1000
TEXT_SIZE = 0x69000

def decode_insn(insn, addr):
    desc = ""
    if (insn & 0x9F000000) == 0x90000000:
        rd = insn & 0x1F
        immlo = (insn >> 29) & 3
        immhi = (insn >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20): imm -= (1 << 21)
        target = (addr & ~0xFFF) + (imm << 12)
        desc = f"  ADRP x{rd}, 0x{target:X}"
    elif (insn & 0xFFC00000) == 0x91000000:
        rd = insn & 0x1F; rn = (insn >> 5) & 0x1F; imm12 = (insn >> 10) & 0xFFF
        sh = (insn >> 22) & 1
        if sh: imm12 <<= 12
        desc = f"  ADD x{rd}, x{rn}, #0x{imm12:X}"
    elif (insn & 0xFC000000) == 0x94000000:
        imm26 = insn & 0x3FFFFFF
        if imm26 & (1 << 25): imm26 -= (1 << 26)
        desc = f"  BL 0x{addr + imm26*4:05X}"
    elif (insn & 0xFFFFFC1F) == 0xD63F0000:
        rn = (insn >> 5) & 0x1F; desc = f"  BLR x{rn}"
    elif insn == 0xD65F03C0: desc = "  RET"
    elif (insn & 0xFFC00000) == 0xF9400000:
        rt = insn & 0x1F; rn = (insn >> 5) & 0x1F; imm12 = (insn >> 10) & 0xFFF
        desc = f"  LDR x{rt}, [x{rn}, #{imm12*8}]"
    elif (insn & 0xFFC00000) == 0xF9000000:
        rt = insn & 0x1F; rn = (insn >> 5) & 0x1F; imm12 = (insn >> 10) & 0xFFF
        desc = f"  STR x{rt}, [x{rn}, #{imm12*8}]"
    elif (insn & 0xFFE0FFE0) == 0xAA0003E0:
        rd = insn & 0x1F; rm = (insn >> 16) & 0x1F; desc = f"  MOV x{rd}, x{rm}"
    elif (insn & 0xFF000000) == 0xB4000000:
        rt = insn & 0x1F; imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1 << 18): imm19 -= (1 << 19)
        desc = f"  CBZ x{rt}, 0x{addr + imm19*4:05X}"
    elif (insn & 0xFF000000) == 0xB5000000:
        rt = insn & 0x1F; imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1 << 18): imm19 -= (1 << 19)
        desc = f"  CBNZ x{rt}, 0x{addr + imm19*4:05X}"
    elif (insn & 0xFF000010) == 0x54000000:
        cond = insn & 0xF; imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1 << 18): imm19 -= (1 << 19)
        conds = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
        desc = f"  B.{conds[cond]} 0x{addr + imm19*4:05X}"
    elif (insn & 0xFC000000) == 0x14000000:
        imm26 = insn & 0x3FFFFFF
        if imm26 & (1 << 25): imm26 -= (1 << 26)
        desc = f"  B 0x{addr + imm26*4:05X}"
    elif (insn & 0xFFE00000) == 0x52800000:
        rd = insn & 0x1F; imm16 = (insn >> 5) & 0xFFFF
        desc = f"  MOV w{rd}, #{imm16}"
    elif (insn & 0xFF80001F) == 0x7100001F:
        rn = (insn >> 5) & 0x1F; imm12 = (insn >> 10) & 0xFFF
        desc = f"  CMP w{rn}, #{imm12}"
    elif (insn & 0xFFE00C00) == 0xF8400000:
        rt = insn & 0x1F; rn = (insn >> 5) & 0x1F
        imm9 = (insn >> 12) & 0x1FF
        if imm9 & (1 << 8): imm9 -= (1 << 9)
        desc = f"  LDUR x{rt}, [x{rn}, #{imm9}]"
    elif (insn & 0xFFC00000) == 0xB9400000:
        rt = insn & 0x1F; rn = (insn >> 5) & 0x1F; imm12 = (insn >> 10) & 0xFFF
        desc = f"  LDR w{rt}, [x{rn}, #{imm12*4}]"
    elif (insn & 0xFFC00000) == 0xB9000000:
        rt = insn & 0x1F; rn = (insn >> 5) & 0x1F; imm12 = (insn >> 10) & 0xFFF
        desc = f"  STR w{rt}, [x{rn}, #{imm12*4}]"
    elif (insn & 0xFFE0001F) == 0xEB00001F:
        rn = (insn >> 5) & 0x1F; rm = (insn >> 16) & 0x1F
        desc = f"  CMP x{rn}, x{rm}"
    elif (insn & 0xFFE00C00) == 0xF8000000:
        rt = insn & 0x1F; rn = (insn >> 5) & 0x1F
        imm9 = (insn >> 12) & 0x1FF
        if imm9 & (1 << 8): imm9 -= (1 << 9)
        desc = f"  STUR x{rt}, [x{rn}, #{imm9}]"
    elif (insn & 0xFFC00000) == 0x39400000:
        rt = insn & 0x1F; rn = (insn >> 5) & 0x1F; imm12 = (insn >> 10) & 0xFFF
        desc = f"  LDRB w{rt}, [x{rn}, #{imm12}]"
    elif (insn & 0xFFC00000) == 0x39000000:
        rt = insn & 0x1F; rn = (insn >> 5) & 0x1F; imm12 = (insn >> 10) & 0xFFF
        desc = f"  STRB w{rt}, [x{rn}, #{imm12}]"
    return desc

def disasm_range(start, count):
    for i in range(count):
        addr = start + i * 4
        if addr >= len(pe) - 4: break
        insn = struct.unpack_from("<I", pe, addr)[0]
        desc = decode_insn(insn, addr)
        print(f"  0x{addr:05X}: 0x{insn:08X}{desc}")

print("=" * 70)
print("1. Pointer table at 0x0685E0 and surroundings")
print("=" * 70)
# Read data around 0x0685E0 - this should be a table of partition structures
# containing pointers to partition name strings
print("  Raw data 0x0685B0-0x068640:")
for off in range(0x0685B0, 0x068640, 8):
    val = struct.unpack_from("<Q", pe, off)[0]
    # Check if it looks like a pointer to a UCS-2 string in the 0x068xxx area
    comment = ""
    if 0x068000 <= val <= 0x069000:
        # Try to read UCS-2 string
        try:
            s = pe[val:val+40].decode('utf-16-le').split('\x00')[0]
            if s.isascii() and len(s) > 0:
                comment = f"  → '{s}'"
        except:
            pass
    elif 0x069000 <= val <= 0x06A000:
        comment = f"  (in GUID area)"
    elif val < 16:
        comment = f"  (small: {val})"
    print(f"    0x{off:06X}: 0x{val:016X}{comment}")

print()
print("=" * 70)
print("2. Function 0x01370 (context setup, called before LocateProtocol)")
print("=" * 70)
disasm_range(0x01370, 60)

print()
print("=" * 70)
print("3. Search ALL partitions for ANDROID-BOOT! magic")
print("=" * 70)
magic = b"ANDROID-BOOT!"
for root, dirs, files in os.walk("/Users/xmxx/pinganhuijia/edl_backup"):
    for f in sorted(files):
        fp = os.path.join(root, f)
        sz = os.path.getsize(fp)
        if sz > 200 * 1024 * 1024 or sz < 13: continue
        if not f.endswith(('.bin', '.img')): continue
        # Skip GPT files
        if f.startswith('gpt_'): continue
        try:
            data = open(fp, "rb").read()
        except:
            continue
        pos = 0
        found_here = []
        while True:
            idx = data.find(magic, pos)
            if idx < 0: break
            found_here.append(idx)
            pos = idx + 13
        if found_here:
            print(f"  ★ {fp} ({sz} bytes): ANDROID-BOOT! at offsets {[f'0x{p:X}' for p in found_here]}")
            # Show surrounding data for each occurrence
            for idx in found_here[:3]:
                chunk = data[idx:idx+32]
                unlock_byte = chunk[13] if len(chunk) > 13 else None
                charger_byte = chunk[15] if len(chunk) > 15 else None
                verity_byte = chunk[144-idx] if idx == 0 and len(data) > 144 else None
                print(f"      offset 0x{idx:X}: unlock={unlock_byte} charger={charger_byte}")

print()
print("=" * 70)
print("4. What's the structure at 0x0685E0?")
print("=" * 70)
# Map the entire pointer table - look for a pattern of structs
# Each struct might contain: {partition_name_ptr, lun_number, partition_guid, ...}

# Scan backwards from 0x0685E0 to find the start of the table
# by looking for the first pointer that points to a UCS-2 partition name
table_start = None
for off in range(0x068500, 0x068240, -8):
    val = struct.unpack_from("<Q", pe, off)[0]
    if 0x068230 <= val <= 0x068440:  # In the partition name string area
        try:
            s = pe[val:val+20].decode('utf-16-le').split('\x00')[0]
            if s.isascii() and len(s) > 0 and all(c.isalnum() or c in '_-' for c in s):
                table_start = off
        except:
            pass

if table_start:
    # Now scan forward to find the table pattern
    print(f"  First partition name pointer found at 0x{table_start:06X}")
    # Actually, let me scan the whole area systematically
    # Try to find table entries by finding all 8-byte values that point to partition names
    entries = []
    for off in range(0x068400, 0x068700, 8):
        val = struct.unpack_from("<Q", pe, off)[0]
        if 0x068230 <= val <= 0x068440:
            try:
                s = pe[val:val+40].decode('utf-16-le').split('\x00')[0]
                if s.isascii() and len(s) > 0 and all(c.isalnum() or c in '_-' for c in s):
                    entries.append((off, val, s))
            except:
                pass

    print(f"  Found {len(entries)} partition name pointers:")
    for off, val, name in entries:
        marker = " ★ DEVINFO" if name == "devinfo" else ""
        print(f"    0x{off:06X}: → 0x{val:06X} = '{name}'{marker}")
        # Check what's near this pointer (the struct fields around it)
        before = struct.unpack_from("<Q", pe, off - 8)[0] if off >= 8 else 0
        after = struct.unpack_from("<Q", pe, off + 8)[0]
        after2 = struct.unpack_from("<Q", pe, off + 16)[0]
        print(f"              -8: 0x{before:016X}  +8: 0x{after:016X}  +16: 0x{after2:016X}")

print()
print("=" * 70)
print("5. Detailed struct around devinfo pointer at 0x0685E0")
print("=" * 70)
# Show 64 bytes before and after
for off in range(0x068580, 0x068640, 8):
    val = struct.unpack_from("<Q", pe, off)[0]
    comment = ""
    if 0x068000 <= val <= 0x069000:
        try:
            s = pe[val:val+40].decode('utf-16-le').split('\x00')[0]
            if s.isascii() and len(s) > 0:
                comment = f"  → '{s}'"
        except:
            pass
    elif val < 0x100:
        comment = f"  (={val})"
    elif 0x069000 <= val <= 0x06A000:
        # Try GUID
        if off + 16 <= len(pe):
            g = pe[off:off+16]
            d1, d2, d3 = struct.unpack_from("<IHH", g, 0)
            d4 = g[8:16]
            guid_s = f"{d1:08X}-{d2:04X}-{d3:04X}-{d4[0]:02X}{d4[1]:02X}-{d4[2]:02X}{d4[3]:02X}{d4[4]:02X}{d4[5]:02X}{d4[6]:02X}{d4[7]:02X}"
            comment = f"  (GUID? {guid_s})"
    print(f"    0x{off:06X}: 0x{val:016X}{comment}")

# Also dump raw bytes
print("\n  Raw hex dump 0x0685A0-0x068630:")
for off in range(0x0685A0, 0x068630, 16):
    hexs = pe[off:off+16].hex()
    ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in pe[off:off+16])
    print(f"    0x{off:06X}: {hexs}  {ascii_str}")

print()
print("=" * 70)
print("6. Where does function 0x01370 look to find partition context?")
print("=" * 70)
# Also check if 0x01370 uses the LR (return address) to index into a table
# This is a common UEFI pattern for "protocol thunks"
disasm_range(0x01370, 30)

# Also disasm the callers' context more carefully
print("\n  Context around ReadWritePartition BL 0x01370 call (at 0x18268):")
disasm_range(0x18248, 12)

print("\n  Context around function 0x18AF8 BL 0x01370 call (at 0x18B14):")
disasm_range(0x18AF8, 12)

print("\n  Context around 0x027CC BL 0x01370 equivalent:")
# Check if the code at 0x027CC area also calls 0x01370
# Look at 0x02700 area for BL 0x01370
for off in range(0x02700, 0x02740, 4):
    insn = struct.unpack_from("<I", pe, off)[0]
    if (insn & 0xFC000000) == 0x94000000:
        imm26 = insn & 0x3FFFFFF
        if imm26 & (1 << 25): imm26 -= (1 << 26)
        target = off + imm26 * 4
        if target == 0x01370:
            print(f"  ★ BL 0x01370 found at 0x{off:05X}")

# Actually search ALL callers of 0x01370
print("\n  All callers of function 0x01370:")
text_data = pe[TEXT_START:TEXT_START+TEXT_SIZE]
for i in range(0, len(text_data) - 4, 4):
    insn = struct.unpack_from("<I", text_data, i)[0]
    if (insn & 0xFC000000) == 0x94000000:
        imm26 = insn & 0x3FFFFFF
        if imm26 & (1 << 25): imm26 -= (1 << 26)
        addr = TEXT_START + i
        target = addr + imm26 * 4
        if target == 0x01370:
            print(f"    0x{addr:05X}: BL 0x01370")

print("\nDone.")
