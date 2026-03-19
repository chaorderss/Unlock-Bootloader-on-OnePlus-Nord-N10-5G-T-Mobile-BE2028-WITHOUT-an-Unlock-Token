#!/usr/bin/env python3
"""
追踪 fastboot 变量注册。
核心目标: 找到 "unlocked" getvar 的注册代码和值来源。
已知:
  - bl 0x4D9DC 可能是 FastbootPublishVar() (在 0x4C108, 0x4C124 被调用)
  - bl 0x4D818 也可能是 publish func (在 0x48484 被调用, "off-mode-charge")
  - bl 0x4D954 是注册相关辅助函数
  - 0x4C0F0: x24 ← ...+0xDC8, 0x4C0F4: x25 ← ...+0xB65
"""
import struct

PE32 = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
TEXT_SIZE = 0x6A000

with open(PE32, "rb") as f:
    pe = f.read()

code = pe[:TEXT_SIZE]

def decode_adrp_add_at(code, addr, pe):
    """Try to decode ADRP+ADD at addr, return resolved address or None"""
    if addr + 8 > len(code):
        return None
    insn1 = struct.unpack_from('<I', code, addr)[0]
    insn2 = struct.unpack_from('<I', code, addr + 4)[0]
    if (insn1 & 0x9F000000) != 0x90000000:
        return None
    rd1 = insn1 & 0x1f
    immlo = (insn1 >> 29) & 3
    immhi = (insn1 >> 5) & 0x7ffff
    imm = (immhi << 2) | immlo
    if imm & (1 << 20): imm -= (1 << 21)
    page = (addr & ~0xFFF) + (imm << 12)

    if (insn2 & 0xFFC00000) == 0x91000000:
        add_rn = (insn2 >> 5) & 0x1f
        if add_rn == rd1:
            add_imm = (insn2 >> 10) & 0xFFF
            target = page + add_imm
            return target
    return None

def get_string_at(pe, addr):
    if addr >= len(pe) or addr < 0:
        return None
    try:
        end = pe.index(0, addr, min(addr + 100, len(pe)))
        s = pe[addr:end].decode('ascii', errors='replace')
        if s.isprintable() and len(s) > 0:
            return s
    except (ValueError, UnicodeDecodeError):
        pass
    return None

# 1. Find ALL callers of 0x4D9DC (likely FastbootPublishVar)
print("=== 所有 BL 0x4D9DC (FastbootPublishVar?) 调用者 ===")
callers_4d9dc = []
for i in range(0, TEXT_SIZE, 4):
    insn = struct.unpack_from('<I', code, i)[0]
    if (insn & 0xFC000000) == 0x94000000:
        off26 = insn & 0x03FFFFFF
        if off26 & (1 << 25): off26 -= (1 << 26)
        target = i + off26 * 4
        if target == 0x4D9DC:
            callers_4d9dc.append(i)

print(f"  共 {len(callers_4d9dc)} 个调用")

# For each caller, try to resolve string arguments
# Arguments are in x0, x1, x2, x3 - look back for ADRP+ADD loading these
for caller in callers_4d9dc:
    strings_found = {}
    # Look back up to 40 instructions for ADRP+ADD pairs
    for back in range(caller - 4, max(caller - 160, 0), -4):
        target = decode_adrp_add_at(code, back, pe)
        if target is not None:
            s = get_string_at(pe, target)
            if s:
                # Which register?
                insn2 = struct.unpack_from('<I', code, back + 4)[0]
                rd = insn2 & 0x1f
                strings_found[back] = (rd, target, s)

    if strings_found:
        parts = []
        for off, (rd, tgt, s) in sorted(strings_found.items()):
            parts.append(f"x{rd}='{s}'")
        info = ", ".join(parts[-3:])  # last 3 string args
        marker = " <<<" if "unlock" in info.lower() or "lock" in info.lower() else ""
        print(f"  0x{caller:05X}: {info}{marker}")

# 2. Also check 0x4D818 callers
print(f"\n=== 所有 BL 0x4D818 调用者 ===")
callers_4d818 = []
for i in range(0, TEXT_SIZE, 4):
    insn = struct.unpack_from('<I', code, i)[0]
    if (insn & 0xFC000000) == 0x94000000:
        off26 = insn & 0x03FFFFFF
        if off26 & (1 << 25): off26 -= (1 << 26)
        target = i + off26 * 4
        if target == 0x4D818:
            callers_4d818.append(i)

print(f"  共 {len(callers_4d818)} 个调用")
for caller in callers_4d818:
    strings_found = {}
    for back in range(caller - 4, max(caller - 160, 0), -4):
        target = decode_adrp_add_at(code, back, pe)
        if target is not None:
            s = get_string_at(pe, target)
            if s:
                insn2 = struct.unpack_from('<I', code, back + 4)[0]
                rd = insn2 & 0x1f
                strings_found[back] = (rd, target, s)

    if strings_found:
        parts = []
        for off, (rd, tgt, s) in sorted(strings_found.items()):
            parts.append(f"x{rd}='{s}'")
        info = ", ".join(parts[-3:])
        marker = " <<<" if "unlock" in info.lower() or "lock" in info.lower() else ""
        print(f"  0x{caller:05X}: {info}{marker}")

# 3. Dump the full function at 0x4C000+ area (fastboot var registration)
# Look for strings being passed in x0-x3 to publish functions
print(f"\n=== 0x4C000-0x4C200 区域完整字符串引用 ===")
for addr in range(0x4BF00, 0x4C300, 4):
    if addr + 8 <= TEXT_SIZE:
        target = decode_adrp_add_at(code, addr, pe)
        if target is not None:
            s = get_string_at(pe, target)
            if s:
                insn2 = struct.unpack_from('<I', code, addr + 4)[0]
                rd = insn2 & 0x1f
                print(f"  0x{addr:05X}: x{rd} ← 0x{target:06X} = '{s}'")

# 4. Search for 0x4D954 callers too
print(f"\n=== 所有 BL 0x4D954 调用者 ===")
callers_4d954 = []
for i in range(0, TEXT_SIZE, 4):
    insn = struct.unpack_from('<I', code, i)[0]
    if (insn & 0xFC000000) == 0x94000000:
        off26 = insn & 0x03FFFFFF
        if off26 & (1 << 25): off26 -= (1 << 26)
        target = i + off26 * 4
        if target == 0x4D954:
            callers_4d954.append(i)

print(f"  共 {len(callers_4d954)} 个调用")
for caller in callers_4d954:
    # Check what string was loaded nearby (last ADRP+ADD before this call)
    for back in range(caller - 4, max(caller - 60, 0), -4):
        target = decode_adrp_add_at(code, back, pe)
        if target:
            s = get_string_at(pe, target)
            if s:
                insn2 = struct.unpack_from('<I', code, back + 4)[0]
                rd = insn2 & 0x1f
                marker = " <<<" if "unlock" in s.lower() or "lock" in s.lower() else ""
                print(f"  0x{caller:05X}: x{rd}='{s}'{marker}")
                break
