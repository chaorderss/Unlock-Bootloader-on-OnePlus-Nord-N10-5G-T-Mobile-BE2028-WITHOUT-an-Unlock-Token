#!/usr/bin/env python3
"""
追踪 fastboot getvar "unlocked" 的真实处理器。
已知: "unlocked" at 0x05361C 是 AVB cmdline，不是 getvar。
需要找: fastboot pubish var "unlocked" 的注册代码。
关键线索:
  - "Unlocked" at 0x051DB0, "Locked" 应该紧跟其后
  - IsDeviceUnlocked 读 devinfo[13] 在 0x22C18 area
"""
import struct

PE32 = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
DISASM = "/tmp/linuxloader_disasm.txt"
TEXT_SIZE = 0x6A000

with open(PE32, "rb") as f:
    pe = f.read()

with open(DISASM, "r") as f:
    disasm_lines = f.readlines()

addr_lines = {}
for idx, line in enumerate(disasm_lines):
    s = line.strip()
    if s and s.startswith('0x'):
        try:
            addr = int(s.split()[0], 16)
            addr_lines[addr] = s
        except:
            pass

code = pe[:TEXT_SIZE]

# 1. Dump the exact instructions around 0x22C18-0x22C30
print("=== 手动解码 0x22C10-0x22C40 ===")
for i in range(0x22C10, 0x22C40, 4):
    insn = struct.unpack_from('<I', code, i)[0]
    print(f"  0x{i:05X}: {insn:08X}", end="")

    # Decode common instructions
    if (insn & 0x9F000000) == 0x90000000:  # ADRP
        rd = insn & 0x1f
        immlo = (insn >> 29) & 3
        immhi = (insn >> 5) & 0x7ffff
        imm = (immhi << 2) | immlo
        if imm & (1 << 20): imm -= (1 << 21)
        page = (i & ~0xFFF) + (imm << 12)
        print(f"  adrp x{rd}, 0x{page:X}")
    elif (insn & 0xFFC00000) == 0xF9400000:  # LDR (unsigned offset)
        rt = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm12 = (insn >> 10) & 0xFFF
        print(f"  ldr x{rt}, [x{rn}, #0x{imm12*8:X}]")
    elif (insn & 0xFFC00000) == 0x91000000:  # ADD imm
        rd = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm12 = (insn >> 10) & 0xFFF
        sh = (insn >> 22) & 1
        print(f"  add x{rd}, x{rn}, #0x{imm12 << (12 if sh else 0):X}")
    elif (insn & 0xFFC00000) == 0x39400000:  # LDRB
        rt = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm12 = (insn >> 10) & 0xFFF
        print(f"  ldrb w{rt}, [x{rn}, #0x{imm12:X}]")
    elif insn == 0xD65F03C0:
        print(f"  ret")
    elif (insn & 0xFC000000) == 0x94000000:  # BL
        off26 = insn & 0x03FFFFFF
        if off26 & (1 << 25): off26 -= (1 << 26)
        target = i + off26 * 4
        print(f"  bl 0x{target:05X}")
    elif (insn & 0xFF000000) == 0x35000000:  # CBNZ
        rt = insn & 0x1f
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1 << 18): imm19 -= (1 << 19)
        target = i + imm19 * 4
        print(f"  cbnz w{rt}, 0x{target:05X}")
    elif (insn & 0xFF000000) == 0x34000000:  # CBZ
        rt = insn & 0x1f
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1 << 18): imm19 -= (1 << 19)
        target = i + imm19 * 4
        print(f"  cbz w{rt}, 0x{target:05X}")
    else:
        print(f"  ?")

# Find the function entry containing 0x22C18
# Look backward for RET (previous function end)
func_entry = 0x22C18
for addr in range(0x22C14, 0x22B00, -4):
    insn = struct.unpack_from('<I', code, addr)[0]
    if insn == 0xD65F03C0:  # RET
        func_entry = addr + 4
        break

# Find function end (next RET after 0x22C20)
func_end = 0x22C40
for addr in range(0x22C24, 0x22D00, 4):
    insn = struct.unpack_from('<I', code, addr)[0]
    if insn == 0xD65F03C0:  # RET
        func_end = addr + 4
        break

print(f"\n=== IsDeviceUnlocked: 0x{func_entry:05X} - 0x{func_end:05X} ===")
for i in range(func_entry, func_end, 4):
    insn = struct.unpack_from('<I', code, i)[0]
    if i in addr_lines:
        print(f"  {addr_lines[i]}")
    else:
        print(f"  0x{i:05X}: {insn:08X}")

# 2. Find all callers of this function
print(f"\n=== 所有 BL 0x{func_entry:05X} 调用者 ===")
callers = []
for i in range(0, TEXT_SIZE, 4):
    insn = struct.unpack_from('<I', code, i)[0]
    if (insn & 0xFC000000) == 0x94000000:  # BL
        off26 = insn & 0x03FFFFFF
        if off26 & (1 << 25): off26 -= (1 << 26)
        target = i + off26 * 4
        if target == func_entry:
            callers.append(i)

print(f"  共 {len(callers)} 个调用者:")
for c in callers:
    print(f"  0x{c:05X}")

# 3. Show context for each caller
for c in callers:
    print(f"\n  --- 0x{c:05X} 调用上下文 ---")
    for addr in range(max(c - 32, 0), min(c + 48, TEXT_SIZE), 4):
        insn = struct.unpack_from('<I', code, addr)[0]
        decoded = ""
        if (insn & 0x9F000000) == 0x90000000:  # ADRP
            rd = insn & 0x1f
            immlo = (insn >> 29) & 3
            immhi = (insn >> 5) & 0x7ffff
            imm = (immhi << 2) | immlo
            if imm & (1 << 20): imm -= (1 << 21)
            page = (addr & ~0xFFF) + (imm << 12)
            decoded = f"adrp x{rd}, 0x{page:X}"
        elif (insn & 0xFFC00000) == 0x91000000:  # ADD
            rd = insn & 0x1f; rn = (insn >> 5) & 0x1f; imm12 = (insn >> 10) & 0xFFF
            decoded = f"add x{rd}, x{rn}, #0x{imm12:X}"
            # Check if this points to a known string
            if addr - 4 >= 0:
                prev = struct.unpack_from('<I', code, addr - 4)[0]
                if (prev & 0x9F000000) == 0x90000000:
                    prev_rd = prev & 0x1f
                    if prev_rd == rn:
                        immlo2 = (prev >> 29) & 3; immhi2 = (prev >> 5) & 0x7ffff
                        imm2 = (immhi2 << 2) | immlo2
                        if imm2 & (1 << 20): imm2 -= (1 << 21)
                        pg = ((addr - 4) & ~0xFFF) + (imm2 << 12)
                        target = pg + imm12
                        if target < len(pe):
                            try:
                                end = pe.index(0, target, target + 80)
                                s = pe[target:end].decode('ascii', errors='replace')
                                decoded += f"  → '{s}'"
                            except:
                                decoded += f"  → 0x{target:06X}"
        elif (insn & 0xFC000000) == 0x94000000:  # BL
            off26 = insn & 0x03FFFFFF
            if off26 & (1 << 25): off26 -= (1 << 26)
            tgt = addr + off26 * 4
            decoded = f"bl 0x{tgt:05X}"
        elif insn == 0xD65F03C0:
            decoded = "ret"
        elif (insn & 0xFFC00000) == 0x39400000:  # LDRB
            rt = insn & 0x1f; rn2 = (insn >> 5) & 0x1f; imm12 = (insn >> 10) & 0xFFF
            decoded = f"ldrb w{rt}, [x{rn2}, #{imm12}]"
        if addr in addr_lines:
            m = " <<<" if addr == c else ""
            print(f"    {addr_lines[addr]}{m}")
        else:
            m = " <<<" if addr == c else ""
            print(f"    0x{addr:05X}: {insn:08X}  {decoded}{m}")

# 4. Also try: look for "Unlocked"/"Locked" at 0x051DB0
print(f"\n=== 字符串 Unlocked/Locked 区域 ===")
for off in range(0x051DA0, 0x051DD0, 16):
    hex_part = ' '.join(f'{pe[off+i]:02x}' for i in range(16))
    ascii_part = ''.join(chr(pe[off+i]) if 32 <= pe[off+i] < 127 else '.' for i in range(16))
    print(f"  0x{off:06X}: {hex_part}  {ascii_part}")

# Find refs to "Unlocked" at 0x051DB0
print(f"\n=== ADRP+ADD 引用 'Unlocked' (0x051DB0) 和 'Locked' ===")
for target_addr, name in [(0x051DB0, "Unlocked"), (0x051DB9, "Locked")]:
    target_page = target_addr & ~0xFFF
    target_off = target_addr & 0xFFF
    for i in range(0, TEXT_SIZE - 8, 4):
        insn = struct.unpack_from('<I', code, i)[0]
        if (insn & 0x9F000000) == 0x90000000:
            rd = insn & 0x1f
            immlo = (insn >> 29) & 3
            immhi = (insn >> 5) & 0x7ffff
            imm = (immhi << 2) | immlo
            if imm & (1 << 20): imm -= (1 << 21)
            page_base = (i & ~0xFFF) + (imm << 12)
            if page_base == target_page and i + 4 < TEXT_SIZE:
                next_insn = struct.unpack_from('<I', code, i + 4)[0]
                if (next_insn & 0xFFC00000) == 0x91000000:
                    add_imm = (next_insn >> 10) & 0xFFF
                    add_rn = (next_insn >> 5) & 0x1f
                    if add_rn == rd and add_imm == target_off:
                        add_rd = next_insn & 0x1f
                        print(f"  '{name}' ref at 0x{i:05X} → x{add_rd}")
                        for ctx_addr in range(max(i-16, 0), min(i+32, TEXT_SIZE), 4):
                            if ctx_addr in addr_lines:
                                m2 = " <<<" if ctx_addr == i else ""
                                print(f"    {addr_lines[ctx_addr]}{m2}")
