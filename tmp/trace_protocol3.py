#!/usr/bin/env python3
"""Deep protocol analysis part 3: find how devinfo partition is located."""
import struct, os

PE = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
pe = open(PE, "rb").read()

TEXT_START = 0x1000
TEXT_SIZE = 0x69000
text = pe[TEXT_START:TEXT_START + TEXT_SIZE]

def find_adrp_refs(page_target):
    """Find all ADRP instructions targeting a specific page."""
    refs = []
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
        pc = TEXT_START + i
        target = (pc & ~0xFFF) + (imm << 12)
        if target == page_target:
            refs.append((pc, rd))
    return refs

def disasm_range(start, count):
    """Disassemble a range of instructions."""
    for i in range(count):
        addr = start + i * 4
        if addr >= len(pe) - 4:
            break
        insn = struct.unpack_from("<I", pe, addr)[0]
        desc = decode_insn(insn, addr)
        print(f"  0x{addr:05X}: 0x{insn:08X}{desc}")

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
    elif (insn & 0xFC000000) == 0x97000000 or (insn & 0xFC000000) == 0x96000000:
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
    elif (insn & 0xFF000000) == 0x36000000 or (insn & 0xFF000000) == 0x37000000:
        rt = insn & 0x1F; bit = ((insn >> 31) << 5) | ((insn >> 19) & 0x1F)
        imm14 = (insn >> 5) & 0x3FFF
        if imm14 & (1 << 13): imm14 -= (1 << 14)
        op = "TBNZ" if (insn >> 24) & 1 else "TBZ"
        desc = f"  {op} x{rt}, #{bit}, 0x{addr + imm14*4:05X}"
    return desc

print("=" * 70)
print("1. Search for devinfo GPT type GUID in PE binary")
print("=" * 70)
# devinfo type GUID: 65ADDCF4-0C5C-4D9A-AC2D-D90B5CBFCD03
devinfo_type_guid = bytes([0xF4, 0xDC, 0xAD, 0x65, 0x5C, 0x0C, 0x9A, 0x4D,
                           0xAC, 0x2D, 0xD9, 0x0B, 0x5C, 0xBF, 0xCD, 0x03])
pos = 0
found = False
while True:
    idx = pe.find(devinfo_type_guid, pos)
    if idx < 0:
        break
    found = True
    print(f"  Found devinfo type GUID at PE offset 0x{idx:06X}")
    # Show context
    print(f"    Data around it: {pe[idx-16:idx].hex()} | {pe[idx:idx+16].hex()} | {pe[idx+16:idx+32].hex()}")
    pos = idx + 16
if not found:
    print("  NOT FOUND in PE binary")

print()
print("=" * 70)
print("2. Search for GUID 95A9A93E (used at 0x18B24)")
print("=" * 70)
guid_95 = bytes([0x3E, 0xA9, 0xA9, 0x95, 0x6E, 0xA8, 0x26, 0x49,
                 0xAA, 0xEF, 0x99, 0x18, 0xE7, 0x72, 0xD9, 0x87])
pos = 0
while True:
    idx = pe.find(guid_95, pos)
    if idx < 0:
        break
    print(f"  Found at PE offset 0x{idx:06X}")
    pos = idx + 16

# Find ADRP references to page 0x69000 with ADD offset that reaches 0x069C80
print("\n  References to 0x069C80:")
refs_69 = find_adrp_refs(0x69000)
for pc, rd in refs_69:
    off = pc - TEXT_START + 4
    if off < len(text) - 4:
        next_insn = struct.unpack_from("<I", text, off)[0]
        if (next_insn & 0xFFC00000) == 0x91000000:
            add_rn = (next_insn >> 5) & 0x1F
            add_imm = (next_insn >> 10) & 0xFFF
            sh = (next_insn >> 22) & 1
            if sh: add_imm <<= 12
            if add_rn == rd:
                target = 0x69000 + add_imm
                if target == 0x069C80:
                    add_rd = next_insn & 0x1F
                    print(f"    0x{pc:05X}: ADRP x{rd} + ADD x{add_rd}, → 0x069C80")

print()
print("=" * 70)
print("3. 'devinfo' UCS-2 - how is it referenced?")
print("=" * 70)
# Maybe it's in a pointer table. Search for 0x068274 as a 64-bit pointer
# In the data section, there might be pointers to this string
target_bytes_le = struct.pack("<Q", 0x068274)  # absolute VA (for PE relocations)
# Also search for offset relative patterns
# Actually, in UEFI PE, the image base is 0. So 0x068274 would be the RVA.
# Search for the 4-byte or 8-byte value 0x068274 in the data section
DATA_START = 0x6A000
data_section = pe[DATA_START:]
val32 = struct.pack("<I", 0x068274)
pos = 0
print(f"  Searching for pointer 0x068274 in .data section...")
while True:
    idx = data_section.find(val32, pos)
    if idx < 0:
        break
    abs_off = DATA_START + idx
    print(f"    Found 4-byte ref at 0x{abs_off:06X}: {data_section[idx:idx+8].hex()}")
    pos = idx + 4

# Also search in .text section
pos = 0
print(f"  Searching for pointer 0x068274 in .text section...")
text_data = pe[TEXT_START:TEXT_START+TEXT_SIZE]
while True:
    idx = text_data.find(val32, pos)
    if idx < 0:
        break
    abs_off = TEXT_START + idx
    print(f"    Found 4-byte ref at 0x{abs_off:06X}")
    pos = idx + 4

# Maybe it's referenced with ADR instead of ADRP+ADD?
# ADR: [31]=0, [30:29]=immlo, [28:24]=10000, [23:5]=immhi, [4:0]=Rd
# Target = PC + SignExt(immhi:immlo)
print(f"\n  Searching for ADR instructions to 0x068274...")
for i in range(0, len(text) - 4, 4):
    insn = struct.unpack_from("<I", text, i)[0]
    # ADR: bit 31=0, bits 28:24=10000
    if (insn & 0x9F000000) == 0x10000000:
        rd = insn & 0x1F
        immlo = (insn >> 29) & 3
        immhi = (insn >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= (1 << 21)
        pc = TEXT_START + i
        target = pc + imm
        if target == 0x068274:
            print(f"    ADR x{rd}, 0x068274 at 0x{pc:05X}")

print()
print("=" * 70)
print("4. All UCS-2 partition name strings and their cross-references")
print("=" * 70)
# Scan the read-only data area (end of .text) for UCS-2 strings
# that look like partition names
i = 0x68000
pnames = []
while i < 0x69000:
    if i + 1 < len(pe) and pe[i+1] == 0 and 0x20 <= pe[i] <= 0x7E:
        s = ""
        j = i
        while j + 1 < len(pe) and pe[j+1] == 0 and 0x20 <= pe[j] <= 0x7E:
            s += chr(pe[j])
            j += 2
        if len(s) >= 3 and s.isascii() and all(c.isalnum() or c in '_-:' for c in s):
            pnames.append((i, s))
            i = j + 2
            continue
    i += 2

print(f"  Found {len(pnames)} UCS-2 strings:")
for off, name in pnames:
    # Check if this string has ADRP references
    page = off & ~0xFFF
    page_off = off & 0xFFF
    refs = find_adrp_refs(page)
    ref_count = 0
    ref_addrs = []
    for pc, rd in refs:
        idx = pc - TEXT_START + 4
        if idx < len(text) - 4:
            next_insn = struct.unpack_from("<I", text, idx)[0]
            if (next_insn & 0xFFC00000) == 0x91000000:
                add_rn = (next_insn >> 5) & 0x1F
                add_imm = (next_insn >> 10) & 0xFFF
                sh = (next_insn >> 22) & 1
                if sh: add_imm <<= 12
                if add_rn == rd and add_imm == page_off:
                    ref_count += 1
                    ref_addrs.append(pc)
    status = f"refs={ref_count} @ {[f'0x{a:05X}' for a in ref_addrs[:5]]}" if ref_count > 0 else "NO REFS"
    marker = " ★" if name == "devinfo" else ""
    print(f"    0x{off:06X}: '{name}' ({status}){marker}")

print()
print("=" * 70)
print("5. ReadWritePartition complete disassembly (0x18248)")
print("=" * 70)
disasm_range(0x18248, 80)

print()
print("=" * 70)
print("6. Function 0x18AF8 complete disassembly")
print("=" * 70)
disasm_range(0x18AF8, 60)

print()
print("=" * 70)
print("7. Code at 0x027CC - more context (protocol consumer)")
print("=" * 70)
# After the LocateProtocol call, what does the code do with the result?
disasm_range(0x027E0, 40)

print()
print("=" * 70)
print("8. Search XBL modules for ReadWritePartition GUID")
print("=" * 70)
guid_bytes = bytes([0x91, 0xFF, 0x5E, 0x8E, 0xB6, 0x21, 0xD3, 0x47,
                    0xAF, 0x2B, 0xC1, 0x5A, 0x01, 0xE0, 0x20, 0xEC])
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
            if idx < 0: break
            positions.append(idx)
            pos = idx + 16
        if positions:
            print(f"  {f} ({len(data)} bytes): GUID at {[f'0x{p:X}' for p in positions]}")

# Search all firmware files in edl_backup
for root, dirs, files in os.walk("/Users/xmxx/pinganhuijia/edl_backup"):
    for f in files:
        fp = os.path.join(root, f)
        sz = os.path.getsize(fp)
        if sz > 200 * 1024 * 1024 or sz < 100:  # skip > 200MB and tiny files
            continue
        if f.endswith(('.bin', '.elf', '.img', '.mbn')):
            data = open(fp, "rb").read()
            positions = []
            pos = 0
            while True:
                idx = data.find(guid_bytes, pos)
                if idx < 0: break
                positions.append(idx)
                pos = idx + 16
            if positions:
                print(f"  {fp} ({sz} bytes): GUID at {[f'0x{p:X}' for p in positions]}")

print()
print("=" * 70)
print("9. Search nearby partition name strings for 'devinfo' context")
print("=" * 70)
# Check what string comes right after "devinfo" at 0x068274
# devinfo = 7 chars * 2 bytes + 2 null = 16 bytes, ends at 0x068284
next_str_start = 0x068284
print(f"  After 'devinfo' at 0x068284:")
chunk = pe[next_str_start:next_str_start+64]
try:
    decoded = chunk.decode('utf-16-le').split('\x00')[0]
    print(f"    Next string: '{decoded}'")
except:
    print(f"    Raw: {chunk.hex()}")

# Check before devinfo
prev = pe[0x068254:0x068274]
try:
    decoded = prev.decode('utf-16-le').rstrip('\x00')
    decoded2 = decoded.split('\x00')[-1] if '\x00' in decoded else decoded
    print(f"  Before 'devinfo': '{decoded2}'")
except:
    print(f"  Before: {prev.hex()}")

# Show the entire block around devinfo
print(f"\n  Block 0x068250-0x0682C0 as UCS-2:")
i = 0x068250
while i < 0x0682C0:
    if pe[i] == 0 and pe[i+1] == 0:
        i += 2
        continue
    s = ""
    j = i
    while j + 1 < len(pe) and not (pe[j] == 0 and pe[j+1] == 0):
        try:
            ch = pe[j:j+2].decode('utf-16-le')
            if ch.isprintable():
                s += ch
            else:
                s += f'[{pe[j]:02X}{pe[j+1]:02X}]'
        except:
            s += f'[{pe[j]:02X}{pe[j+1]:02X}]'
        j += 2
    if s:
        print(f"    0x{i:06X}: '{s}'")
    i = j + 2

print("\nDone.")
