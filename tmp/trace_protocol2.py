#!/usr/bin/env python3
"""Deep protocol analysis: find where ReadWritePartition reads devinfo from."""
import struct, os, glob

PE = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
pe = open(PE, "rb").read()

print("=" * 70)
print("1. Data at 0x069C80 and nearby (GUIDs, strings, structures)")
print("=" * 70)
# Read a chunk of data around the GUID area
for offset in [0x069BE0, 0x069C80, 0x069C90, 0x069CA0, 0x069CB0]:
    chunk = pe[offset:offset+16]
    # Try to interpret as GUID
    if len(chunk) >= 16:
        d1, d2, d3 = struct.unpack_from("<IHH", chunk, 0)
        d4 = chunk[8:16]
        guid = f"{d1:08X}-{d2:04X}-{d3:04X}-{d4[0]:02X}{d4[1]:02X}-{d4[2]:02X}{d4[3]:02X}{d4[4]:02X}{d4[5]:02X}{d4[6]:02X}{d4[7]:02X}"
        print(f"  0x{offset:06X}: GUID={guid}")
        print(f"           hex={chunk.hex()}")

# Also check what's right after devinfo UCS-2 string
devinfo_ucs2_off = 0x068274
s = pe[devinfo_ucs2_off:devinfo_ucs2_off+32]
print(f"\n  UCS-2 'devinfo' at 0x{devinfo_ucs2_off:06X}: {s.hex()}")
# Decode UCS-2
try:
    txt = s.decode('utf-16-le').split('\x00')[0]
    print(f"  Decoded: '{txt}'")
except:
    pass

print()
print("=" * 70)
print("2. Find ALL ADRP references to page 0x68000 (devinfo UCS-2 string)")
print("=" * 70)
# ADRP x?, 0x68000 from various PC locations
# ADRP encoding: [31] op=1(64bit), [30:29] immlo, [28:24]=10000, [23:5]=immhi, [4:0]=Rd
# Page offset = SignExt(immhi:immlo) << 12
# Target = (PC & ~0xFFF) + page_offset
TEXT_START = 0x1000
TEXT_SIZE = 0x69000
text = pe[TEXT_START:TEXT_START + TEXT_SIZE]
refs_68000 = []
for i in range(0, len(text) - 4, 4):
    insn = struct.unpack_from("<I", text, i)[0]
    if (insn & 0x9F000000) != 0x90000000:
        continue
    rd = insn & 0x1F
    immlo = (insn >> 29) & 3
    immhi = (insn >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    page_off = imm << 12
    pc = TEXT_START + i
    target = (pc & ~0xFFF) + page_off
    if target == 0x68000:
        refs_68000.append((pc, rd))

print(f"  Found {len(refs_68000)} ADRP references to page 0x68000:")
for pc, rd in refs_68000:
    # Check next instruction for ADD
    off = pc - TEXT_START + 4
    if off < len(text) - 4:
        next_insn = struct.unpack_from("<I", text, off)[0]
        # ADD Xd, Xn, #imm12
        if (next_insn & 0xFFC00000) == 0x91000000:
            add_rd = next_insn & 0x1F
            add_rn = (next_insn >> 5) & 0x1F
            add_imm = (next_insn >> 10) & 0xFFF
            sh = (next_insn >> 22) & 1
            if sh:
                add_imm <<= 12
            if add_rn == rd:
                target_addr = 0x68000 + add_imm
                print(f"    0x{pc:05X}: ADRP x{rd}, 0x68000 + ADD x{add_rd}, x{add_rn}, #0x{add_imm:X} → 0x{target_addr:06X}")
                # Check what's at that address
                if target_addr < len(pe):
                    data = pe[target_addr:target_addr+20]
                    try:
                        s = data.decode('utf-16-le').split('\x00')[0]
                        if s.isprintable() and len(s) > 0:
                            print(f"           → UCS-2 string: '{s}'")
                    except:
                        pass
            else:
                print(f"    0x{pc:05X}: ADRP x{rd}, 0x68000 (next ADD uses different reg)")
        else:
            print(f"    0x{pc:05X}: ADRP x{rd}, 0x68000 (no ADD follows)")
    else:
        print(f"    0x{pc:05X}: ADRP x{rd}, 0x68000")

print()
print("=" * 70)
print("3. 'devinfo' UCS-2 references (page 0x68000 + offset 0x274)")
print("=" * 70)
devinfo_refs = [(pc, rd) for pc, rd in refs_68000]
# Filter for those that ADD to 0x274
for pc, rd in refs_68000:
    off = pc - TEXT_START + 4
    if off < len(text) - 4:
        next_insn = struct.unpack_from("<I", text, off)[0]
        if (next_insn & 0xFFC00000) == 0x91000000:
            add_imm = (next_insn >> 10) & 0xFFF
            add_rn = (next_insn >> 5) & 0x1F
            if add_rn == rd and add_imm == 0x274:
                print(f"  ★ 0x{pc:05X}: references 'devinfo' UCS-2 string (0x068274)")
                # Show surrounding context
                ctx_start = pc - TEXT_START - 16
                ctx_end = pc - TEXT_START + 24
                for j in range(max(0, ctx_start), min(len(text)-4, ctx_end), 4):
                    addr = TEXT_START + j
                    insn = struct.unpack_from("<I", text, j)[0]
                    marker = " ★" if addr == pc else ""
                    print(f"    0x{addr:05X}: 0x{insn:08X}{marker}")

print()
print("=" * 70)
print("4. Search GPTs for devinfo partition on ALL LUNs")
print("=" * 70)
backup_dirs = [
    "/Users/xmxx/pinganhuijia/edl_backup/",
    "/Users/xmxx/pinganhuijia/edl_backup/lun0/",
    "/Users/xmxx/pinganhuijia/edl_backup/lun4/",
]
for d in backup_dirs:
    for gpt_file in sorted(glob.glob(os.path.join(d, "gpt_*.bin"))):
        fname = os.path.basename(gpt_file)
        data = open(gpt_file, "rb").read()
        # Search for "devinfo" in UCS-2
        devinfo_ucs2 = "devinfo".encode('utf-16-le')
        pos = 0
        while True:
            idx = data.find(devinfo_ucs2, pos)
            if idx < 0:
                break
            print(f"  {gpt_file}: 'devinfo' UCS-2 at offset 0x{idx:X}")
            # GPT entry is 128 bytes, find the entry start
            # GPT entries start at LBA 2 (offset 0x2000 for 4K sectors)
            # Each entry is 128 bytes
            # Partition name starts at offset 56 in GPT entry
            entry_name_offset = idx % 128
            entry_start = idx - entry_name_offset
            if entry_name_offset == 56:
                entry = data[entry_start:entry_start+128]
                type_guid = entry[0:16]
                unique_guid = entry[16:32]
                first_lba = struct.unpack_from("<Q", entry, 32)[0]
                last_lba = struct.unpack_from("<Q", entry, 40)[0]
                attrs = struct.unpack_from("<Q", entry, 48)[0]
                name = entry[56:128].decode('utf-16-le').rstrip('\x00')
                tg = struct.unpack_from("<IHH", type_guid, 0)
                tg_str = f"{tg[0]:08X}-{tg[1]:04X}-{tg[2]:04X}-{type_guid[8]:02X}{type_guid[9]:02X}-{type_guid[10]:02X}{type_guid[11]:02X}{type_guid[12]:02X}{type_guid[13]:02X}{type_guid[14]:02X}{type_guid[15]:02X}"
                print(f"    GPT Entry: name='{name}' firstLBA={first_lba} lastLBA={last_lba} typeGUID={tg_str}")
            pos = idx + len(devinfo_ucs2)

# Also check rawprogram XML files
for xml_file in glob.glob("/Users/xmxx/pinganhuijia/edl_backup/**/rawprogram*.xml", recursive=True):
    data = open(xml_file, "r").read()
    if "devinfo" in data.lower():
        print(f"\n  {xml_file}: contains 'devinfo'")
        for line in data.split('\n'):
            if 'devinfo' in line.lower():
                print(f"    {line.strip()}")

print()
print("=" * 70)
print("5. Function at 0x18AF8 - partition handling function")
print("=" * 70)
# Disassemble the function more carefully
import subprocess
func_start = 0x18AF8
func_data = pe[func_start:func_start + 0x200]
with open("/tmp/func_18af8.bin", "wb") as f:
    f.write(func_data)
r = subprocess.run(
    ["llvm-objcopy", "--rename-section=.data=.text", "-I", "binary", "-O", "binary", "/tmp/func_18af8.bin", "/tmp/func_18af8.bin"],
    capture_output=True
)
# Use our disasm approach
for i in range(0, min(len(func_data), 0x200), 4):
    insn = struct.unpack_from("<I", func_data, i)[0]
    addr = func_start + i
    # Decode common instructions
    desc = ""
    # ADRP
    if (insn & 0x9F000000) == 0x90000000:
        rd = insn & 0x1F
        immlo = (insn >> 29) & 3
        immhi = (insn >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= (1 << 21)
        target = (addr & ~0xFFF) + (imm << 12)
        desc = f"  ADRP x{rd}, 0x{target:X}"
    # ADD immediate
    elif (insn & 0xFFC00000) == 0x91000000:
        rd = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm12 = (insn >> 10) & 0xFFF
        sh = (insn >> 22) & 1
        if sh:
            imm12 <<= 12
        desc = f"  ADD x{rd}, x{rn}, #0x{imm12:X}"
    # BL
    elif (insn & 0xFC000000) == 0x94000000:
        imm26 = insn & 0x3FFFFFF
        if imm26 & (1 << 25):
            imm26 -= (1 << 26)
        target = addr + imm26 * 4
        desc = f"  BL 0x{target:05X}"
    # BLR
    elif (insn & 0xFFFFFC1F) == 0xD63F0000:
        rn = (insn >> 5) & 0x1F
        desc = f"  BLR x{rn}"
    # RET
    elif insn == 0xD65F03C0:
        desc = "  RET"
    # LDR Xt, [Xn, #imm]
    elif (insn & 0xFFC00000) == 0xF9400000:
        rt = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm12 = (insn >> 10) & 0xFFF
        desc = f"  LDR x{rt}, [x{rn}, #{imm12*8}]"
    # STP
    elif (insn & 0xFFC00000) == 0xA9000000 or (insn & 0xFFC00000) == 0xA9800000:
        desc = "  STP ..."
    # STR
    elif (insn & 0xFFC00000) == 0xF9000000:
        rt = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm12 = (insn >> 10) & 0xFFF
        desc = f"  STR x{rt}, [x{rn}, #{imm12*8}]"
    # MOV (ORR)
    elif (insn & 0xFFE0FFE0) == 0xAA0003E0:
        rd = insn & 0x1F
        rm = (insn >> 16) & 0x1F
        desc = f"  MOV x{rd}, x{rm}"
    # CBZ
    elif (insn & 0xFF000000) == 0xB4000000:
        rt = insn & 0x1F
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1 << 18):
            imm19 -= (1 << 19)
        target = addr + imm19 * 4
        desc = f"  CBZ x{rt}, 0x{target:05X}"
    # B
    elif (insn & 0xFC000000) == 0x14000000:
        imm26 = insn & 0x3FFFFFF
        if imm26 & (1 << 25):
            imm26 -= (1 << 26)
        target = addr + imm26 * 4
        desc = f"  B 0x{target:05X}"
    # B.cond
    elif (insn & 0xFF000010) == 0x54000000:
        cond = insn & 0xF
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1 << 18):
            imm19 -= (1 << 19)
        target = addr + imm19 * 4
        conds = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
        desc = f"  B.{conds[cond]} 0x{target:05X}"
    # MOV Wd, #imm
    elif (insn & 0xFFE00000) == 0x52800000:
        rd = insn & 0x1F
        imm16 = (insn >> 5) & 0xFFFF
        desc = f"  MOV w{rd}, #{imm16}"
    # CMP
    elif (insn & 0xFFE0001F) == 0x6B00001F:
        rn = (insn >> 5) & 0x1F
        rm = (insn >> 16) & 0x1F
        desc = f"  CMP w{rn}, w{rm}"

    print(f"  0x{addr:05X}: 0x{insn:08X}{desc}")
    if insn == 0xD65F03C0 and i > 0x20:
        break

print()
print("=" * 70)
print("6. Search XBL/FFS modules for protocol GUID")
print("=" * 70)
guid_bytes = bytes([0x91, 0xFF, 0x5E, 0x8E, 0xB6, 0x21, 0xD3, 0x47,
                    0xAF, 0x2B, 0xC1, 0x5A, 0x01, 0xE0, 0x20, 0xEC])
# Search in all files in /tmp/ffs_modules/
ffs_dir = "/tmp/ffs_modules/"
if os.path.isdir(ffs_dir):
    for f in sorted(os.listdir(ffs_dir)):
        fp = os.path.join(ffs_dir, f)
        if not os.path.isfile(fp):
            continue
        data = open(fp, "rb").read()
        positions = []
        pos = 0
        while True:
            idx = data.find(guid_bytes, pos)
            if idx < 0:
                break
            positions.append(idx)
            pos = idx + 16
        if positions:
            print(f"  {f} ({len(data)} bytes): GUID found at {[f'0x{p:X}' for p in positions]}")

# Also search in xbl_a.bin if available
xbl_paths = [
    "/Users/xmxx/pinganhuijia/edl_backup/lun1/xbl_a.bin",
    "/Users/xmxx/pinganhuijia/edl_backup/xbl_a.bin",
]
for xp in xbl_paths:
    if os.path.isfile(xp):
        data = open(xp, "rb").read()
        positions = []
        pos = 0
        while True:
            idx = data.find(guid_bytes, pos)
            if idx < 0:
                break
            positions.append(idx)
            pos = idx + 16
        if positions:
            print(f"  {xp} ({len(data)} bytes): GUID at {[f'0x{p:X}' for p in positions]}")
        else:
            print(f"  {xp} ({len(data)} bytes): GUID NOT FOUND")

# Search in edl_backup for any .elf or other firmware files
for root, dirs, files in os.walk("/Users/xmxx/pinganhuijia/edl_backup"):
    for f in files:
        fp = os.path.join(root, f)
        if os.path.getsize(fp) > 100 * 1024 * 1024:  # skip > 100MB
            continue
        if f.endswith(('.bin', '.elf', '.img', '.mbn')):
            data = open(fp, "rb").read()
            positions = []
            pos = 0
            while True:
                idx = data.find(guid_bytes, pos)
                if idx < 0:
                    break
                positions.append(idx)
                pos = idx + 16
            if positions:
                print(f"  {fp} ({len(data)} bytes): GUID at {[f'0x{p:X}' for p in positions]}")

print()
print("=" * 70)
print("7. Data around 'devinfo' UCS-2 string - what's nearby?")
print("=" * 70)
# Show what's around the devinfo UCS-2 string to see if it's part of a table
for off in range(0x068240, 0x0682C0, 2):
    word = pe[off:off+2]
    if word == b'\x00\x00':
        ch = '\\0'
    else:
        try:
            ch = word.decode('utf-16-le')
            if not ch.isprintable():
                ch = f'0x{word.hex()}'
        except:
            ch = f'0x{word.hex()}'
    if off % 32 == 0:
        print()
        print(f"  0x{off:06X}: ", end="")
    print(f"{ch}", end="")
print()

# Now look for other partition name strings near devinfo
print("\n  UCS-2 partition names in 0x68000-0x69000:")
i = 0x68000
while i < 0x69000:
    # Look for UCS-2 strings (printable ASCII chars with 0x00 high byte)
    if i + 1 < len(pe) and pe[i+1] == 0 and 0x20 <= pe[i] <= 0x7E:
        s = ""
        j = i
        while j + 1 < len(pe) and pe[j+1] == 0 and 0x20 <= pe[j] <= 0x7E:
            s += chr(pe[j])
            j += 2
        if len(s) >= 3:
            print(f"    0x{i:06X}: '{s}'")
            i = j + 2
            continue
    i += 2

print()
print("=" * 70)
print("8. ReadWritePartition function - full disassembly")
print("=" * 70)
# The function at 0x18248 - disassemble completely
func_start = 0x18248
for i in range(0, 0x120, 4):
    addr = func_start + i
    insn = struct.unpack_from("<I", pe, addr)[0]
    desc = ""
    # ADRP
    if (insn & 0x9F000000) == 0x90000000:
        rd = insn & 0x1F
        immlo = (insn >> 29) & 3
        immhi = (insn >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= (1 << 21)
        target = (addr & ~0xFFF) + (imm << 12)
        desc = f"  ADRP x{rd}, 0x{target:X}"
    elif (insn & 0xFFC00000) == 0x91000000:
        rd = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm12 = (insn >> 10) & 0xFFF
        sh = (insn >> 22) & 1
        if sh: imm12 <<= 12
        desc = f"  ADD x{rd}, x{rn}, #0x{imm12:X}"
    elif (insn & 0xFC000000) == 0x94000000:
        imm26 = insn & 0x3FFFFFF
        if imm26 & (1 << 25): imm26 -= (1 << 26)
        target = addr + imm26 * 4
        desc = f"  BL 0x{target:05X}"
    elif (insn & 0xFFFFFC1F) == 0xD63F0000:
        rn = (insn >> 5) & 0x1F
        desc = f"  BLR x{rn}"
    elif insn == 0xD65F03C0:
        desc = "  RET"
    elif (insn & 0xFFC00000) == 0xF9400000:
        rt = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm12 = (insn >> 10) & 0xFFF
        desc = f"  LDR x{rt}, [x{rn}, #{imm12*8}]"
    elif (insn & 0xFFC00000) == 0xF9000000:
        rt = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm12 = (insn >> 10) & 0xFFF
        desc = f"  STR x{rt}, [x{rn}, #{imm12*8}]"
    elif (insn & 0xFFE0FFE0) == 0xAA0003E0:
        rd = insn & 0x1F
        rm = (insn >> 16) & 0x1F
        desc = f"  MOV x{rd}, x{rm}"
    elif (insn & 0xFF000000) == 0xB4000000:
        rt = insn & 0x1F
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1 << 18): imm19 -= (1 << 19)
        target = addr + imm19 * 4
        desc = f"  CBZ x{rt}, 0x{target:05X}"
    elif (insn & 0xFF000000) == 0xB5000000:
        rt = insn & 0x1F
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1 << 18): imm19 -= (1 << 19)
        target = addr + imm19 * 4
        desc = f"  CBNZ x{rt}, 0x{target:05X}"
    elif (insn & 0xFC000000) == 0x14000000:
        imm26 = insn & 0x3FFFFFF
        if imm26 & (1 << 25): imm26 -= (1 << 26)
        target = addr + imm26 * 4
        desc = f"  B 0x{target:05X}"
    elif (insn & 0xFF000010) == 0x54000000:
        cond = insn & 0xF
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1 << 18): imm19 -= (1 << 19)
        target = addr + imm19 * 4
        conds = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
        desc = f"  B.{conds[cond]} 0x{target:05X}"
    elif (insn & 0xFFE00000) == 0x52800000:
        rd = insn & 0x1F
        imm16 = (insn >> 5) & 0xFFFF
        desc = f"  MOV w{rd}, #{imm16}"
    elif (insn & 0xFFE0001F) == 0x6B00001F or (insn & 0xFFE0001F) == 0xEB00001F:
        rn = (insn >> 5) & 0x1F
        rm = (insn >> 16) & 0x1F
        w = "w" if (insn >> 31) == 0 else "x"
        desc = f"  CMP {w}{rn}, {w}{rm}"
    elif (insn & 0xFF80001F) == 0x7100001F:
        rn = (insn >> 5) & 0x1F
        imm12 = (insn >> 10) & 0xFFF
        desc = f"  CMP w{rn}, #{imm12}"
    # LDUR
    elif (insn & 0xFFE00C00) == 0xF8400000:
        rt = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm9 = (insn >> 12) & 0x1FF
        if imm9 & (1 << 8): imm9 -= (1 << 9)
        desc = f"  LDUR x{rt}, [x{rn}, #{imm9}]"
    # STUR
    elif (insn & 0xFFE00C00) == 0xF8000000:
        rt = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm9 = (insn >> 12) & 0x1FF
        if imm9 & (1 << 8): imm9 -= (1 << 9)
        desc = f"  STUR x{rt}, [x{rn}, #{imm9}]"

    print(f"  0x{addr:05X}: 0x{insn:08X}{desc}")
    if insn == 0xD65F03C0 and i > 0x20:
        break

print("\nDone.")
