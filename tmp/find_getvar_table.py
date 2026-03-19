#!/usr/bin/env python3
"""
找 fastboot getvar dispatch 表和 unlocked 变量的实际读取逻辑。
策略：
1. 搜索 "unlocked" 字符串地址作为 pointer 存在表中
2. 找 "Unlocked"/"Locked" 字符串的引用
3. 找 getvar 变量名表
"""
import struct

PE32 = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
DISASM = "/tmp/linuxloader_disasm.txt"

with open(PE32, "rb") as f:
    pe = f.read()

# Load disasm as dict
line_dict = {}
with open(DISASM, "r") as f:
    for line in f:
        parts = line.strip().split()
        if len(parts) >= 1 and parts[0].startswith("0x"):
            try:
                addr = int(parts[0], 16)
                line_dict[addr] = line.strip()
            except ValueError:
                pass

TEXT_SIZE = 0x6A000

# 1. Search for pointer to "unlocked" string (0x05361C) in PE32+ data
print("=== 搜索 'unlocked' 字符串指针 (LE 0x05361C) ===")
needle = struct.pack('<Q', 0x05361C)  # 64-bit pointer
for off in range(0, len(pe) - 8, 8):
    if pe[off:off+8] == needle:
        print(f"  Found 64-bit ptr at 0x{off:06X}")

needle32 = struct.pack('<I', 0x05361C)  # 32-bit pointer
for off in range(0, len(pe) - 4, 4):
    if pe[off:off+4] == needle32:
        print(f"  Found 32-bit ptr at 0x{off:06X}")

# Also search for "Unlocked" at 0x051DB0
print("\n=== 搜索 'Unlocked' 字符串指针 (0x051DB0) ===")
for width, fmt in [(8, '<Q'), (4, '<I')]:
    needle = struct.pack(fmt, 0x051DB0)
    for off in range(0, len(pe) - width, 4):
        if pe[off:off+width] == needle:
            print(f"  Found {width*8}-bit ptr at 0x{off:06X}")

# 2. Search for ADRP+ADD to "Unlocked" at 0x051DB0 and "Locked" nearby
print("\n=== ADRP+ADD 搜索 Unlocked/Locked ===")
# "Unlocked" at 0x051DB0, "Locked" should be at 0x051DB9
targets = {
    0x051DB0: "Unlocked",
    0x051DB9: "Locked",
    0x0536BE: "yes",
    0x066CE8: "no",
}

code = pe[:TEXT_SIZE]
for target_addr, name in targets.items():
    target_page = target_addr & ~0xFFF
    target_off = target_addr & 0xFFF

    for i in range(0, TEXT_SIZE - 8, 4):
        insn = struct.unpack_from('<I', code, i)[0]
        if (insn & 0x9F000000) == 0x90000000:
            rd = insn & 0x1f
            immlo = (insn >> 29) & 3
            immhi = (insn >> 5) & 0x7ffff
            imm = (immhi << 2) | immlo
            if imm & (1 << 20):
                imm -= (1 << 21)
            page_base = (i & ~0xFFF) + (imm << 12)

            if page_base == target_page and i + 4 < TEXT_SIZE:
                next_insn = struct.unpack_from('<I', code, i + 4)[0]
                if (next_insn & 0xFFC00000) == 0x91000000:
                    add_imm = (next_insn >> 10) & 0xFFF
                    add_rn = (next_insn >> 5) & 0x1f
                    if add_rn == rd and add_imm == target_off:
                        add_rd = next_insn & 0x1f
                        print(f"  '{name}' ref at 0x{i:05X} → x{add_rd}")

# 3. Search for a dispatch table with "unlocked" nearby - look for array of struct {char* name, func_ptr}
print("\n=== 搜索 getvar dispatch 表 ===")
# Look for regions in rodata/data that have consecutive string pointers
# The "unlocked" string is at 0x05361C
# Let's look for a table entry that contains a pointer to a string in the range 0x050000-0x070000
# followed by a function pointer in the range 0x000000-0x06A000

# Better approach: search around known getvar strings for table patterns
# "getvar:partition-type" at 0x066B3A
# "max-download-" near 0x066CA0

# Let's scan the data section for repeating pattern of (string_ptr, func_ptr) pairs
# where string_ptr points to 0x050000-0x070000 range (rodata strings)
# and func_ptr points to 0x000000-0x06A000 range (code)
print("  Scanning for (string_ptr, func_ptr) table entries...")
table_hits = []
for off in range(0x6A000, len(pe) - 16, 8):
    ptr1 = struct.unpack_from('<Q', pe, off)[0]
    ptr2 = struct.unpack_from('<Q', pe, off + 8)[0]

    if 0x050000 <= ptr1 <= 0x070000 and 0x000400 <= ptr2 <= 0x06A000:
        # Check if ptr1 points to a printable ASCII string
        if ptr1 < len(pe):
            try:
                end = pe.index(0, ptr1, ptr1 + 40)
                s = pe[ptr1:end].decode('ascii')
                if s.isprintable() and len(s) > 2:
                    table_hits.append((off, ptr1, ptr2, s))
            except (ValueError, UnicodeDecodeError):
                pass

if table_hits:
    print(f"  Found {len(table_hits)} potential table entries:")
    for off, sptr, fptr, s in table_hits[:50]:
        marker = " <<<" if "unlock" in s.lower() else ""
        print(f"    0x{off:06X}: str=0x{sptr:06X} '{s}', func=0x{fptr:06X}{marker}")
else:
    print("  No (str_ptr, func_ptr) table found in data section")

# 4. Also try 16-byte stride (might have more fields per entry)
print("\n  Trying 16-byte stride table entries...")
table_hits2 = []
for off in range(0x6A000, len(pe) - 16, 16):
    ptr1 = struct.unpack_from('<Q', pe, off)[0]
    if 0x050000 <= ptr1 <= 0x070000 and ptr1 < len(pe):
        try:
            end = pe.index(0, ptr1, ptr1 + 40)
            s = pe[ptr1:end].decode('ascii')
            if s.isprintable() and len(s) > 2:
                ptr2 = struct.unpack_from('<Q', pe, off + 8)[0]
                table_hits2.append((off, ptr1, ptr2, s))
        except (ValueError, UnicodeDecodeError):
            pass

# Group consecutive entries
if table_hits2:
    # Find runs of consecutive entries
    runs = []
    current_run = [table_hits2[0]]
    for i in range(1, len(table_hits2)):
        if table_hits2[i][0] == table_hits2[i-1][0] + 16:
            current_run.append(table_hits2[i])
        else:
            if len(current_run) >= 3:
                runs.append(current_run)
            current_run = [table_hits2[i]]
    if len(current_run) >= 3:
        runs.append(current_run)

    for run in runs:
        print(f"\n  Table at 0x{run[0][0]:06X} ({len(run)} entries, 16-byte stride):")
        for off, sptr, fptr, s in run:
            marker = " <<<" if "unlock" in s.lower() else ""
            print(f"    0x{off:06X}: str=0x{sptr:06X} '{s}', field2=0x{fptr:06X}{marker}")

# 5. Search with 24-byte stride
print("\n  Trying 24-byte stride table entries...")
table_hits3 = []
for off in range(0x6A000, len(pe) - 24, 8):
    ptr1 = struct.unpack_from('<Q', pe, off)[0]
    if 0x050000 <= ptr1 <= 0x070000 and ptr1 < len(pe):
        try:
            end = pe.index(0, ptr1, ptr1 + 60)
            s = pe[ptr1:end].decode('ascii')
            if s.isprintable() and len(s) > 2 and any(kw in s.lower() for kw in ['unlock', 'lock', 'secure', 'serial', 'product', 'variant', 'partition', 'max-download', 'battery', 'slot']):
                ptr2 = struct.unpack_from('<Q', pe, off + 8)[0]
                table_hits3.append((off, ptr1, ptr2, s))
        except (ValueError, UnicodeDecodeError):
            pass

if table_hits3:
    print(f"  Found {len(table_hits3)} fastboot-related table entries:")
    for off, sptr, fptr, s in table_hits3:
        print(f"    0x{off:06X}: str=0x{sptr:06X} '{s}', field2=0x{fptr:06X}")
