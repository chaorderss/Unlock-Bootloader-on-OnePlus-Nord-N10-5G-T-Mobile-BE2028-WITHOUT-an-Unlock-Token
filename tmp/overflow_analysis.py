import struct

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb').read()

def decode_adrp(instr, pc):
    immhi = (instr >> 5) & 0x7FFFF
    immlo = (instr >> 29) & 0x3
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    return (pc & ~0xFFF) + (imm << 12)

# ============================================================
# PART 1: Map all global variable accesses near our targets
# Target globals:
#   0x1BE350 - model number (integer)
#   0x1BF518 - carrier unlock permission flag
#   0x1C0010 - IsAllowUnlock flag
# ============================================================

print("=" * 70)
print("PART 1: Memory layout around critical globals")
print("=" * 70)

# Scan entire binary for ADRP instructions that reference pages near our targets
# Focus on pages 0x1BD000 - 0x1C1000
target_pages = set()
for page in range(0x1BD000, 0x1C2000, 0x1000):
    target_pages.add(page)

# Collect all ADRP+next instruction pairs that target our pages
# This gives us a map of ALL globals in the area
globals_accessed = {}  # address -> list of (access_pc, access_type, register)

for off in range(0, len(data) - 8, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr & 0x9F000000) != 0x90000000:  # Not ADRP
        continue
    page = decode_adrp(instr, off)
    if page not in target_pages:
        continue

    rd = instr & 0x1F
    # Check next instruction
    next_instr = struct.unpack_from('<I', data, off + 4)[0]

    # ADD Xd, Xn, #imm  (0x91000000)
    if (next_instr & 0xFF800000) == 0x91000000:
        nrn = (next_instr >> 5) & 0x1F
        nrd = next_instr & 0x1F
        if nrn == rd:
            imm12 = (next_instr >> 10) & 0xFFF
            sh = (next_instr >> 22) & 1
            if sh: imm12 <<= 12
            addr = page + imm12
            if addr not in globals_accessed:
                globals_accessed[addr] = []
            globals_accessed[addr].append((off, 'ADD', nrd))

    # LDR Xt, [Xn, #imm]  (64-bit load: 0xF9400000)
    elif (next_instr & 0xFFC00000) == 0xF9400000:
        nrn = (next_instr >> 5) & 0x1F
        if nrn == rd:
            imm12 = (next_instr >> 10) & 0xFFF
            addr = page + imm12 * 8
            if addr not in globals_accessed:
                globals_accessed[addr] = []
            globals_accessed[addr].append((off, 'LDR_X', (next_instr & 0x1F)))

    # LDR Wt, [Xn, #imm]  (32-bit load: 0xB9400000)
    elif (next_instr & 0xFFC00000) == 0xB9400000:
        nrn = (next_instr >> 5) & 0x1F
        if nrn == rd:
            imm12 = (next_instr >> 10) & 0xFFF
            addr = page + imm12 * 4
            if addr not in globals_accessed:
                globals_accessed[addr] = []
            globals_accessed[addr].append((off, 'LDR_W', (next_instr & 0x1F)))

    # STR Xt, [Xn, #imm]  (64-bit store: 0xF9000000)
    elif (next_instr & 0xFFC00000) == 0xF9000000:
        nrn = (next_instr >> 5) & 0x1F
        if nrn == rd:
            imm12 = (next_instr >> 10) & 0xFFF
            addr = page + imm12 * 8
            if addr not in globals_accessed:
                globals_accessed[addr] = []
            globals_accessed[addr].append((off, 'STR_X', (next_instr & 0x1F)))

    # STR Wt, [Xn, #imm]  (32-bit store: 0xB9000000)
    elif (next_instr & 0xFFC00000) == 0xB9000000:
        nrn = (next_instr >> 5) & 0x1F
        if nrn == rd:
            imm12 = (next_instr >> 10) & 0xFFF
            addr = page + imm12 * 4
            if addr not in globals_accessed:
                globals_accessed[addr] = []
            globals_accessed[addr].append((off, 'STR_W', (next_instr & 0x1F)))

    # STRB Wt, [Xn, #imm]  (byte store: 0x39000000)
    elif (next_instr & 0xFFC00000) == 0x39000000:
        nrn = (next_instr >> 5) & 0x1F
        if nrn == rd:
            imm12 = (next_instr >> 10) & 0xFFF
            addr = page + imm12
            if addr not in globals_accessed:
                globals_accessed[addr] = []
            globals_accessed[addr].append((off, 'STRB', (next_instr & 0x1F)))

    # LDRB Wt, [Xn, #imm]  (byte load: 0x39400000)
    elif (next_instr & 0xFFC00000) == 0x39400000:
        nrn = (next_instr >> 5) & 0x1F
        if nrn == rd:
            imm12 = (next_instr >> 10) & 0xFFF
            addr = page + imm12
            if addr not in globals_accessed:
                globals_accessed[addr] = []
            globals_accessed[addr].append((off, 'LDRB', (next_instr & 0x1F)))

# Sort and display
sorted_addrs = sorted(globals_accessed.keys())

# Focus on regions near our targets
for target_name, target_addr, radius in [
    ("model_number", 0x1BE350, 0x200),
    ("carrier_unlock_flag", 0x1BF518, 0x200),
    ("IsAllowUnlock", 0x1C0010, 0x100),
]:
    print(f'\n--- Globals near {target_name} (0x{target_addr:X}) ±0x{radius:X} ---')
    for addr in sorted_addrs:
        if abs(addr - target_addr) <= radius:
            refs = globals_accessed[addr]
            writes = [r for r in refs if 'STR' in r[1]]
            reads = [r for r in refs if 'LDR' in r[1] or r[1] == 'ADD']
            marker = " <<<< TARGET" if addr == target_addr else ""
            # Check if overlap potential
            dist = addr - target_addr
            print(f'  0x{addr:05X} (dist={dist:+d}): {len(refs)} refs ({len(writes)}W/{len(reads)}R){marker}')

# ============================================================
# PART 2: Find all partition read operations that copy data to globals
# Look for CopyMem/memcpy-like patterns near partition reads
# ============================================================
print("\n" + "=" * 70)
print("PART 2: Globals that receive partition data (potential overflow targets)")
print("=" * 70)

# Key insight: If a partition reader copies data into a fixed global buffer
# WITHOUT size checks, and we control the partition content, we might overflow
# into an adjacent global.

# Known partition-reading functions:
# 0x4FD10 - FRP reader
# Look for ReadFromPartition or similar patterns

# First, let's understand the actual data segment layout
# Check what's in the binary at addresses around our targets
# (These addresses are virtual addresses = file offsets in this PE)
print('\n--- Binary content at critical global addresses ---')
for name, addr in [
    ("0x1BD978 (model struct base)", 0x1BD978),
    ("0x1BE350 (model number)", 0x1BE350),
    ("0x1BE3D0 (model+0x80)", 0x1BE3D0),
    ("0x1BF000 area", 0x1BF000),
    ("0x1BF500 area", 0x1BF500),
    ("0x1BF518 (carrier flag)", 0x1BF518),
    ("0x1BF520 area", 0x1BF520),
    ("0x1C0000 area", 0x1C0000),
    ("0x1C0010 (IsAllowUnlock)", 0x1C0010),
]:
    if addr < len(data):
        raw = data[addr:addr+32]
        print(f'  {name}: {raw.hex()}')
    else:
        print(f'  {name}: BEYOND FILE (binary size=0x{len(data):X})')

# ============================================================
# PART 3: Check if binary has BSS section (uninitialized globals)
# PE sections tell us which ranges are file-backed vs zero-filled
# ============================================================
print("\n" + "=" * 70)
print("PART 3: PE Section layout (BSS identification)")
print("=" * 70)

# Parse PE headers
pe_sig_off = struct.unpack_from('<I', data, 0x3C)[0]
print(f'PE signature at: 0x{pe_sig_off:X}')
sig = data[pe_sig_off:pe_sig_off+4]
print(f'Signature: {sig}')

# COFF header
coff_off = pe_sig_off + 4
num_sections = struct.unpack_from('<H', data, coff_off + 2)[0]
opt_header_size = struct.unpack_from('<H', data, coff_off + 16)[0]
print(f'Number of sections: {num_sections}')
print(f'Optional header size: {opt_header_size}')

# Optional header
opt_off = coff_off + 20
magic = struct.unpack_from('<H', data, opt_off)[0]
print(f'Optional header magic: 0x{magic:04X} ({"PE32+" if magic == 0x20B else "PE32"})')

if magic == 0x20B:  # PE32+
    image_base = struct.unpack_from('<Q', data, opt_off + 24)[0]
    section_align = struct.unpack_from('<I', data, opt_off + 32)[0]
    file_align = struct.unpack_from('<I', data, opt_off + 36)[0]
    size_of_image = struct.unpack_from('<I', data, opt_off + 56)[0]
    print(f'Image base: 0x{image_base:X}')
    print(f'Section alignment: 0x{section_align:X}')
    print(f'File alignment: 0x{file_align:X}')
    print(f'Size of image: 0x{size_of_image:X}')

# Section headers
sect_off = opt_off + opt_header_size
print(f'\nSections:')
for i in range(num_sections):
    s = sect_off + i * 40
    name = data[s:s+8].rstrip(b'\x00').decode('ascii', errors='replace')
    vsize = struct.unpack_from('<I', data, s + 8)[0]
    va = struct.unpack_from('<I', data, s + 12)[0]
    raw_size = struct.unpack_from('<I', data, s + 16)[0]
    raw_ptr = struct.unpack_from('<I', data, s + 20)[0]
    chars = struct.unpack_from('<I', data, s + 36)[0]

    bss = " [BSS!]" if vsize > raw_size else ""
    writable = " [WRITABLE]" if chars & 0x80000000 else ""
    readable = " [READABLE]" if chars & 0x40000000 else ""
    executable = " [EXEC]" if chars & 0x20000000 else ""
    uninit = " [UNINIT]" if chars & 0x00000080 else ""

    print(f'  [{i}] {name:8s}: VA=0x{va:06X} VSize=0x{vsize:06X} '
          f'RawPtr=0x{raw_ptr:06X} RawSize=0x{raw_size:06X} '
          f'Chars=0x{chars:08X}{bss}{writable}{readable}{executable}{uninit}')

    # Check if our targets fall in this section
    for tname, taddr in [("model", 0x1BE350), ("carrier_flag", 0x1BF518), ("IsAllowUnlock", 0x1C0010)]:
        if va <= taddr < va + vsize:
            offset_in_sect = taddr - va
            in_file = offset_in_sect < raw_size
            print(f'       ^^^ Contains {tname} (0x{taddr:X}) - offset +0x{offset_in_sect:X} in section, '
                  f'{"IN FILE" if in_file else "BSS (zero-init, not in file)"}')

# ============================================================
# PART 4: Find large buffer copies that land near our targets
# Pattern: ADRP to target page + BL to memcpy/CopyMem
# ============================================================
print("\n" + "=" * 70)
print("PART 4: Large data copies landing near target globals")
print("=" * 70)

# Find all calls to potential memcpy functions that use addresses near our targets
# Look for ADRP 0x1BD/1BE/1BF/1C0 followed within ~20 instructions by BL
for off in range(0, min(len(data), 0x60000) - 80, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr & 0x9F000000) != 0x90000000:
        continue
    page = decode_adrp(instr, off)
    if page not in target_pages:
        continue
    rd = instr & 0x1F

    # Check for ADD within next 3 instructions
    for delta in [4, 8, 12]:
        ni = struct.unpack_from('<I', data, off + delta)[0]
        if (ni & 0xFF800000) == 0x91000000:
            nrn = (ni >> 5) & 0x1F
            nrd = ni & 0x1F
            if nrn == rd:
                imm12 = (ni >> 10) & 0xFFF
                sh = (ni >> 22) & 1
                if sh: imm12 <<= 12
                target = page + imm12

                # Now look for a BL within next 20 instructions with this as X0
                if nrd == 0:  # X0 = destination for memcpy
                    for d2 in range(delta + 4, delta + 80, 4):
                        if off + d2 >= len(data): break
                        bi = struct.unpack_from('<I', data, off + d2)[0]
                        if (bi & 0xFC000000) == 0x94000000:
                            bl_target = off + d2 + ((bi & 0x03FFFFFF) * 4)
                            if (bi & 0x02000000): bl_target -= 0x10000000
                            # Check if this is a known copy function
                            # Common: 0x4DEBC (SetMem), 0x4DE08 (CopyMem-like)
                            if bl_target in [0x4DEBC, 0x4DE08, 0x4DFC0, 0x2A758, 0x4B90]:
                                print(f'  0x{off:05X}: ADRP+ADD -> 0x{target:05X} (X0=dest), '
                                      f'BL 0x{bl_target:X} at 0x{off+d2:05X}')
                            break
