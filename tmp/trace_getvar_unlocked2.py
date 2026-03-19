#!/usr/bin/env python3
"""
1. 找所有从 devinfo 读 is_unlocked (offset 13) 的代码
2. 找 getvar "unlocked" 的处理流程
3. 分析 IsDeviceUnlocked 函数
"""
import struct

PE32 = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
DISASM = "/tmp/linuxloader_disasm.txt"

with open(PE32, "rb") as f:
    pe = f.read()

with open(DISASM, "r") as f:
    disasm_lines = f.readlines()

# Build addr→line mapping
addr_lines = {}
for i, line in enumerate(disasm_lines):
    s = line.strip()
    if s and s[0:2] == '0x':
        try:
            addr = int(s.split()[0], 16)
            addr_lines[addr] = (i, s)
        except:
            pass

TEXT_SIZE = 0x6A000
code = pe[:TEXT_SIZE]

# 1. Find all LDRB Wx, [Xy, #13] instructions — reading is_unlocked
# LDRB (unsigned offset): 0011 1001 01 imm12 Rn Rt
# imm12 = 13 (0x0D)
print("=== 所有 LDRB Wx, [Xy, #13] (读取 is_unlocked) ===")
ldrb_refs = []
for i in range(0, TEXT_SIZE, 4):
    insn = struct.unpack_from('<I', code, i)[0]
    # LDRB (unsigned offset): 0x39400000 | (imm12 << 10) | (Rn << 5) | Rt
    if (insn & 0xFFC00000) == 0x39400000:  # LDRB with unsigned offset
        imm12 = (insn >> 10) & 0xFFF
        rn = (insn >> 5) & 0x1f
        rt = insn & 0x1f
        if imm12 == 13:
            ldrb_refs.append((i, rn, rt))
            print(f"  0x{i:05X}: ldrb w{rt}, [x{rn}, #13]")

# 2. For each ldrb #13, check if the base register was loaded from devinfo buffer (0x1BD978)
print(f"\n=== 追踪 ldrb #13 的来源 (是否来自 devinfo buffer 0x1BD978) ===")
for ldrb_addr, rn, rt in ldrb_refs:
    # Look back up to 20 instructions for ADRP+ADD loading rn
    for back in range(ldrb_addr - 4, max(ldrb_addr - 80, 0), -4):
        insn = struct.unpack_from('<I', code, back)[0]
        if (insn & 0x9F000000) == 0x90000000:  # ADRP
            rd = insn & 0x1f
            if rd == rn:
                immlo = (insn >> 29) & 3
                immhi = (insn >> 5) & 0x7ffff
                imm = (immhi << 2) | immlo
                if imm & (1 << 20):
                    imm -= (1 << 21)
                page_base = (back & ~0xFFF) + (imm << 12)

                # Check next instruction for ADD or LDR
                if back + 4 < TEXT_SIZE:
                    next_insn = struct.unpack_from('<I', code, back + 4)[0]
                    if (next_insn & 0xFFC00000) == 0x91000000:  # ADD
                        add_imm = (next_insn >> 10) & 0xFFF
                        target = page_base + add_imm
                        if target == 0x1BD978:
                            print(f"  ✅ 0x{ldrb_addr:05X}: ldrb w{rt},[x{rn},#13] ← devinfo buf (ADRP at 0x{back:05X} → 0x{target:06X})")
                            # Show surrounding context
                            for ctx_addr in range(max(back - 16, 0), min(ldrb_addr + 20, TEXT_SIZE), 4):
                                if ctx_addr in addr_lines:
                                    m = " <<<" if ctx_addr == ldrb_addr else ""
                                    print(f"      {addr_lines[ctx_addr][1]}{m}")
                            break
                    elif (next_insn & 0xFFC00000) == 0xF9400000:  # LDR (unsigned offset)
                        ldr_imm = (next_insn >> 10) & 0xFFF
                        ldr_rd = next_insn & 0x1f
                        target = page_base + ldr_imm * 8
                        if ldr_rd == rn:
                            # Indirect: load pointer from memory
                            if target < len(pe):
                                ptr = struct.unpack_from('<Q', pe, target)[0] if target + 8 <= len(pe) else 0
                                print(f"  ? 0x{ldrb_addr:05X}: ldrb w{rt},[x{rn},#13] ← ADRP 0x{back:05X}→0x{page_base:X} + LDR [#0x{ldr_imm*8:X}] = deref 0x{target:06X} (ptr=0x{ptr:X})")
                break

# 3. Specifically trace the string "unlocked" usage in the code
# The string is at 0x053620. But let me verify the exact position
print(f"\n=== 精确定位 'unlocked' 字符串 ===")
off = pe.find(b"unlocked\x00")
print(f"  'unlocked\\0' first occurrence at 0x{off:06X}")
print(f"  Context: {pe[off-8:off+16]}")
# Also find if "unlocked" appears elsewhere preceded by a null
for search_off in range(off + 1, len(pe)):
    search_off = pe.find(b"\x00unlocked\x00", search_off)
    if search_off == -1:
        break
    actual = search_off + 1
    print(f"  Another 'unlocked' at 0x{actual:06X}: {pe[actual-4:actual+16]}")

# 4. Search for "device_unlocked" at 0x052900 area
print(f"\n=== 'device_unlocked' 相关字符串 ===")
for needle in [b"device_unlocked", b"DeviceInfo_unlocked", b"is_unlocked"]:
    off = pe.find(needle)
    if off != -1:
        end = pe.index(0, off)
        full = pe[off:end]
        print(f"  0x{off:06X}: '{full.decode()}'")

# 5. Find IsDeviceUnlocked function
# Look for the code pattern that reads devinfo[13] and returns it
# "device_unlocked != " at 0x052900
print(f"\n=== IsDeviceUnlocked 函数追踪 ===")
off = pe.find(b"device_unlocked != ")
if off != -1:
    print(f"  String 'device_unlocked != ' at 0x{off:06X}")
    # Find ADRP+ADD reference to this string
    tgt_page = off & ~0xFFF
    tgt_off = off & 0xFFF
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
            if page_base == tgt_page and i + 4 < TEXT_SIZE:
                next_insn = struct.unpack_from('<I', code, i + 4)[0]
                if (next_insn & 0xFFC00000) == 0x91000000:
                    add_imm = (next_insn >> 10) & 0xFFF
                    if add_imm == tgt_off:
                        print(f"  Referenced at 0x{i:05X}")
                        # Show a wide range around this code
                        func_start = max(i - 100, 0) & ~3
                        func_end = min(i + 100, TEXT_SIZE)
                        print(f"  Function context:")
                        for addr in range(func_start, func_end, 4):
                            if addr in addr_lines:
                                m = " <<<" if addr == i else ""
                                print(f"    {addr_lines[addr][1]}{m}")

# 6. Find what calls the function that reads is_unlocked
# From conversation: 0x03328 references "Device is unlocked, Skipping boot verification"
# Let's look at that area
print(f"\n=== 0x03328 区域: 'Device is unlocked' 引用 ===")
for addr in range(0x032E0, 0x03400, 4):
    if addr in addr_lines:
        print(f"  {addr_lines[addr][1]}")

# 7. Final: look for ADR (short-range) instruction loading 0x05361C
# ADR: 0 immlo[30:29] 10000 immhi[23:5] Rd[4:0]
print(f"\n=== ADR (短距) 搜索 'unlocked' ===")
for i in range(0, TEXT_SIZE, 4):
    insn = struct.unpack_from('<I', code, i)[0]
    if (insn & 0x9F000000) == 0x10000000:  # ADR
        rd = insn & 0x1f
        immlo = (insn >> 29) & 3
        immhi = (insn >> 5) & 0x7ffff
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= (1 << 21)
        target = i + imm
        if target == 0x05361C:
            print(f"  0x{i:05X}: adr x{rd}, 0x{target:06X} ('unlocked')")
            for ctx in range(max(i-20,0), min(i+20,TEXT_SIZE), 4):
                if ctx in addr_lines:
                    m = " <<<" if ctx == i else ""
                    print(f"    {addr_lines[ctx][1]}{m}")
