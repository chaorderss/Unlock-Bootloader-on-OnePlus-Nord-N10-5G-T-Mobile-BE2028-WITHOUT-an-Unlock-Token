#!/usr/bin/env python3
"""
分析 "unlocked" 字符串周围的数据结构。
字符串上下文: "e_state\x00unlocked\x00android"
这可能是一个 UEFI 变量表或 fastboot 变量注册表。
"""
import struct

PE32 = "/tmp/ffs_modules/pe32_59d536f5_1.bin"

with open(PE32, "rb") as f:
    pe = f.read()

# "unlocked" at 0x05361C
# Let's dump a wide range around it to see the structure
print("=== 0x05361C 周围的字符串/数据区域 ===")
start = 0x053580
end = 0x053700
print(f"  Hex dump 0x{start:06X} - 0x{end:06X}:")
for off in range(start, end, 16):
    hex_part = ' '.join(f'{pe[off+i]:02x}' for i in range(min(16, end - off)))
    ascii_part = ''.join(chr(pe[off+i]) if 32 <= pe[off+i] < 127 else '.' for i in range(min(16, end - off)))
    print(f"  0x{off:06X}: {hex_part:<48s}  {ascii_part}")

# Look for all null-terminated strings in this area
print(f"\n=== 0x053580-0x053700 中的所有字符串 ===")
i = start
while i < end:
    if pe[i] >= 32 and pe[i] < 127:
        j = i
        while j < end and pe[j] != 0:
            j += 1
        s = pe[i:j].decode('ascii', errors='replace')
        if len(s) >= 2:
            print(f"  0x{i:06X}: '{s}'")
        i = j + 1
    else:
        i += 1

# Now look at the broader context: what's before "e_state"?
# Find the full string ending with "e_state"
print(f"\n=== 'e_state' 前面是什么？ ===")
off = pe.rfind(b'\x00', 0, 0x053614) + 1  # find start of "xxx_state" string
if off:
    end_str = pe.index(0, off)
    full = pe[off:end_str].decode('ascii', errors='replace')
    print(f"  0x{off:06X}: '{full}'")

# Let's search for larger context - maybe there's a registration table
# Look for all occurrences of fastboot variable names near this area
print(f"\n=== 0x053500-0x053800 字符串表 ===")
i = 0x053500
while i < 0x053800:
    if pe[i] >= 32 and pe[i] < 127:
        j = i
        while j < 0x053800 and pe[j] != 0:
            j += 1
        s = pe[i:j].decode('ascii', errors='replace')
        if len(s) >= 2:
            print(f"  0x{i:06X}: '{s}'")
        i = j + 1
    else:
        i += 1

# Now check: is there a table of (name, value) pairs nearby?
# The pattern might be: "variable_name\0" followed by "value_string\0"
# "e_state" → "unlocked"? or register_name → value?

# Search for the function at 0x22C18 (which reads devinfo[13])
# and trace its callers
print(f"\n=== IsDeviceUnlocked 函数 (0x22C18) 完整代码 ===")
DISASM = "/tmp/linuxloader_disasm.txt"
with open(DISASM, "r") as f:
    lines = f.readlines()

addr_lines = {}
for idx, line in enumerate(lines):
    s = line.strip()
    if s and s.startswith('0x'):
        try:
            addr = int(s.split()[0], 16)
            addr_lines[addr] = s
        except:
            pass

# Find function boundary around 0x22C18
# Look back for STP (function prologue) or just show from 0x22C00
print("  Code at 0x22C00-0x22C40:")
for addr in range(0x22C00, 0x22C40, 4):
    if addr in addr_lines:
        print(f"    {addr_lines[addr]}")

# Find all BL calls TO the function containing 0x22C18
# First, find the function's entry point
# The ldrb is at 0x22C20, ADRP at 0x22C18
# Look for the function start
func_entry = None
for addr in range(0x22C18, 0x22B00, -4):
    if addr in addr_lines:
        s = addr_lines[addr]
        if 'ret' in s.lower():
            func_entry = addr + 4
            break
        if 'stp' in s.lower() and ('x29' in s or 'x30' in s):
            func_entry = addr
            break

if not func_entry:
    func_entry = 0x22C18
print(f"\n  Function likely starts at: 0x{func_entry:05X}")

# Show full function
print(f"  Full function:")
for addr in range(func_entry, func_entry + 60, 4):
    if addr in addr_lines:
        print(f"    {addr_lines[addr]}")

# Find all BL to this function
print(f"\n=== 调用 IsDeviceUnlocked (BL 0x{func_entry:05X}) 的位置 ===")
TEXT = pe[:TEXT_SIZE]
callers = []
for i in range(0, TEXT_SIZE, 4):
    insn = struct.unpack_from('<I', TEXT, i)[0]
    if (insn & 0xFC000000) == 0x94000000:  # BL
        off26 = insn & 0x03FFFFFF
        if off26 & (1 << 25):
            off26 -= (1 << 26)
        target = i + off26 * 4
        if target == func_entry:
            callers.append(i)
            # Get some context
            if i in addr_lines:
                print(f"  0x{i:05X}: {addr_lines[i]}")

print(f"\n  Total callers: {len(callers)}")

# For each caller, show surrounding code (especially what they do with the return value)
for caller in callers[:10]:
    print(f"\n  --- Caller at 0x{caller:05X} context ---")
    for addr in range(max(caller - 24, 0), min(caller + 40, TEXT_SIZE), 4):
        if addr in addr_lines:
            m = " <<<" if addr == caller else ""
            print(f"    {addr_lines[addr]}{m}")

# Also look for the Qualcomm/UEFI VB state - maybe it's stored in VB metadata
# Search for "vbmeta" or "avb" related
print(f"\n=== Verified Boot 相关字符串 ===")
for needle in [b"device_locked", b"lock_state", b"device_state", b"verified_boot_state", b"ro.boot.verifiedbootstate"]:
    off = pe.find(needle)
    if off != -1:
        end2 = pe.index(0, off)
        s = pe[off:end2].decode('ascii', errors='replace')
        print(f"  0x{off:06X}: '{s}'")
