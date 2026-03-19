#!/usr/bin/env python3
"""
追踪 fastboot getvar "unlocked" 的实际代码路径。
找到 "unlocked" 字符串在 ABL 中的引用，然后分析其读取逻辑。
"""
import struct

PE32 = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
DISASM = "/tmp/linuxloader_disasm.txt"

with open(PE32, "rb") as f:
    pe = f.read()

# 1. Find all "unlocked" string locations
targets = [b"unlocked", b"locked", b"unlock_ability"]
print("=== 字符串位置 ===")
for t in targets:
    off = 0
    while True:
        off = pe.find(t, off)
        if off == -1:
            break
        # Show context
        ctx = pe[max(0,off-4):off+len(t)+4]
        print(f"  0x{off:06X}: {ctx}")
        off += 1

# 2. Find ADRP+ADD references to "unlocked" string at 0x05361c
# and "locked" nearby
# Known: "unlocked" at 0x05361c from conversation
# Let's find exact locations
for needle in [b"unlocked\x00", b"locked\x00", b"unlock_ability\x00"]:
    off = pe.find(needle)
    if off != -1:
        print(f"\n  '{needle[:-1].decode()}' at 0x{off:06X}")

# 3. Scan disasm for refs to these strings
print("\n=== 反汇编中对 unlock 相关字符串的引用 ===")
with open(DISASM, "r") as f:
    lines = f.readlines()

# Build index of all lines for quick lookup
line_dict = {}
for i, line in enumerate(lines):
    parts = line.strip().split()
    if len(parts) >= 1 and parts[0].startswith("0x"):
        try:
            addr = int(parts[0], 16)
            line_dict[addr] = (i, line.strip())
        except ValueError:
            pass

# Search for patterns involving "unlocked" string reference
# In AARCH64, ADRP loads page, ADD adds offset
# unlocked at 0x05361c → page 0x053000, offset 0x61c
target_addrs = {
    0x05361c: "unlocked",
    0x053614: "locked",
    0x066ba3: "unlock_ability",
}

print("\n=== 搜索 ADRP+ADD 对 unlocked/locked 字符串的引用 ===")
TEXT_SIZE = 0x6A000
code = pe[:TEXT_SIZE]

for target_addr, name in target_addrs.items():
    target_page = target_addr & ~0xFFF
    target_off = target_addr & 0xFFF
    print(f"\n--- '{name}' at 0x{target_addr:06X} (page=0x{target_page:06X}, off=0x{target_off:03X}) ---")

    refs = []
    for i in range(0, TEXT_SIZE - 4, 4):
        insn = struct.unpack_from('<I', code, i)[0]

        # ADRP: [31] op=1, [28:24]=10000, immhi[23:5], immlo[30:29]
        if (insn & 0x9F000000) == 0x90000000:
            rd = insn & 0x1f
            immlo = (insn >> 29) & 3
            immhi = (insn >> 5) & 0x7ffff
            imm = (immhi << 2) | immlo
            if imm & (1 << 20):
                imm -= (1 << 21)
            page_base = (i & ~0xFFF) + (imm << 12)

            if page_base == target_page:
                # Check next instruction for ADD
                if i + 4 < TEXT_SIZE:
                    next_insn = struct.unpack_from('<I', code, i + 4)[0]
                    # ADD Xd, Xn, #imm12 : 1001000100 imm12[21:10] Rn[9:5] Rd[4:0]
                    if (next_insn & 0xFFC00000) == 0x91000000:
                        add_imm = (next_insn >> 10) & 0xFFF
                        add_rn = (next_insn >> 5) & 0x1f
                        add_rd = next_insn & 0x1f
                        if add_rn == rd and add_imm == target_off:
                            final_addr = page_base + add_imm
                            refs.append((i, rd, add_rd, final_addr))
                            print(f"  REF at 0x{i:05X}: ADRP x{rd},0x{page_base:X} + ADD x{add_rd},x{rd},#0x{add_imm:X} → 0x{final_addr:06X}")

    if not refs:
        print(f"  (无直接 ADRP+ADD 引用)")

    # For each ref, show surrounding disasm context
    for ref_addr, _, _, _ in refs:
        print(f"\n  函数上下文 (0x{ref_addr:05X} 附近):")
        # Find function boundary (look backwards for STP x29,x30)
        func_start = ref_addr
        for back in range(ref_addr - 4, max(ref_addr - 200, 0), -4):
            if back in line_dict:
                if 'stp' in line_dict[back][1].lower() and ('x29' in line_dict[back][1] or 'x30' in line_dict[back][1]):
                    func_start = back
                    break

        # Show from func_start to ref+40
        for addr in range(func_start, min(ref_addr + 80, TEXT_SIZE), 4):
            if addr in line_dict:
                marker = " <<<" if addr == ref_addr else ""
                print(f"    {line_dict[addr][1]}{marker}")

# 4. Also search for "getvar" dispatch table
print("\n=== 搜索 getvar 相关字符串 ===")
for needle in [b"getvar", b"Getvar", b"GetVar"]:
    off = 0
    while True:
        off = pe.find(needle, off)
        if off == -1:
            break
        ctx_start = max(0, off-2)
        ctx_end = min(len(pe), off+40)
        ctx = pe[ctx_start:ctx_end]
        try:
            s = ctx.decode('ascii', errors='replace')
        except:
            s = ctx.hex()
        print(f"  0x{off:06X}: {s}")
        off += 1

# 5. Search for the specific pattern: code that reads "unlocked" and returns yes/no
print("\n=== 搜索 'yes' 和 'no' 字符串位置 (getvar 返回值) ===")
for needle in [b"yes\x00", b"no\x00"]:
    off = 0
    count = 0
    while count < 5:
        off = pe.find(needle, off)
        if off == -1:
            break
        print(f"  '{needle[:-1].decode()}' at 0x{off:06X}")
        off += 1
        count += 1
