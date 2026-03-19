#!/usr/bin/env python3
"""
提取 OemCheckResetDevInfo 和相关函数中引用的调试字符串
这些字符串能直接告诉我们代码在做什么
"""
import struct

PE = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
with open(PE, "rb") as f:
    pe = f.read()

def read_str(offset, maxlen=200):
    """Read null-terminated ASCII or UCS-2 string"""
    # Try ASCII first
    s = b""
    for i in range(maxlen):
        if offset + i >= len(pe):
            break
        b = pe[offset + i]
        if b == 0:
            break
        s += bytes([b])
    if len(s) > 2:
        try:
            return s.decode('ascii')
        except:
            pass
    # Try UCS-2 (UEFI uses UCS-2)
    s = ""
    for i in range(0, maxlen*2, 2):
        if offset + i + 1 >= len(pe):
            break
        c = struct.unpack_from('<H', pe, offset + i)[0]
        if c == 0:
            break
        if 0x20 <= c < 0x7F:
            s += chr(c)
        else:
            s += f"\\u{c:04X}"
    return s

def r32(off):
    return struct.unpack_from('<I', pe, off)[0]

# ============================================================
# 1. OemCheckResetDevInfo 中引用的所有字符串
# ============================================================
print("=" * 70)
print("1. OemCheckResetDevInfo 中引用的调试字符串")
print("=" * 70)

# Collect all ADRP+ADD pairs in the function
string_refs = []
for off in range(0x362D8, 0x36690, 4):
    inst = r32(off)
    if (inst & 0x9F000000) == 0x90000000:  # ADRP
        rd = inst & 0x1F
        immhi = (inst >> 5) & 0x7FFFF; immlo = (inst >> 29) & 0x3
        iv = (immhi << 2) | immlo
        if iv & 0x100000: iv |= ~0x1FFFFF
        pg = ((off & ~0xFFF) + (iv << 12)) & 0xFFFFFFFF
        # Check next few instructions for ADD
        for off2 in range(off+4, min(off+16, 0x36690), 4):
            inst2 = r32(off2)
            if (inst2 & 0xFF800000) == 0x91000000:
                rd2 = inst2 & 0x1F
                rn2 = (inst2 >> 5) & 0x1F
                if rn2 == rd:
                    imm12 = (inst2 >> 10) & 0xFFF
                    sh = (inst2 >> 22) & 1
                    if sh: imm12 <<= 12
                    addr = pg + imm12
                    if 0x50000 <= addr < 0x6A000:  # .text section strings
                        s = read_str(addr)
                        if s and len(s) > 2:
                            string_refs.append((off, addr, s))

for off, addr, s in sorted(set(string_refs)):
    print(f"  0x{off:05X} -> 0x{addr:05X}: \"{s}\"")

# ============================================================
# 2. ReadDeviceInfo 中引用的字符串
# ============================================================
print("\n" + "=" * 70)
print("2. ReadDeviceInfo 中引用的调试字符串")
print("=" * 70)
for off in range(0x232D8, 0x233B0, 4):
    inst = r32(off)
    if (inst & 0x9F000000) == 0x90000000:
        rd = inst & 0x1F
        immhi = (inst >> 5) & 0x7FFFF; immlo = (inst >> 29) & 0x3
        iv = (immhi << 2) | immlo
        if iv & 0x100000: iv |= ~0x1FFFFF
        pg = ((off & ~0xFFF) + (iv << 12)) & 0xFFFFFFFF
        for off2 in range(off+4, min(off+16, 0x233B0), 4):
            inst2 = r32(off2)
            if (inst2 & 0xFF800000) == 0x91000000:
                rd2 = inst2 & 0x1F
                rn2 = (inst2 >> 5) & 0x1F
                if rn2 == rd:
                    imm12 = (inst2 >> 10) & 0xFFF
                    sh = (inst2 >> 22) & 1
                    if sh: imm12 <<= 12
                    addr = pg + imm12
                    s = read_str(addr)
                    if s and len(s) > 2:
                        print(f"  0x{off:05X} -> 0x{addr:05X}: \"{s}\"")

# ============================================================
# 3. init_defaults 中引用的字符串
# ============================================================
print("\n" + "=" * 70)
print("3. init_defaults 中引用的调试字符串")
print("=" * 70)
for off in range(0x384D0, 0x38620, 4):
    inst = r32(off)
    if (inst & 0x9F000000) == 0x90000000:
        rd = inst & 0x1F
        immhi = (inst >> 5) & 0x7FFFF; immlo = (inst >> 29) & 0x3
        iv = (immhi << 2) | immlo
        if iv & 0x100000: iv |= ~0x1FFFFF
        pg = ((off & ~0xFFF) + (iv << 12)) & 0xFFFFFFFF
        for off2 in range(off+4, min(off+16, 0x38620), 4):
            inst2 = r32(off2)
            if (inst2 & 0xFF800000) == 0x91000000:
                rd2 = inst2 & 0x1F
                rn2 = (inst2 >> 5) & 0x1F
                if rn2 == rd:
                    imm12 = (inst2 >> 10) & 0xFFF
                    sh = (inst2 >> 22) & 1
                    if sh: imm12 <<= 12
                    addr = pg + imm12
                    s = read_str(addr)
                    if s and len(s) > 2:
                        print(f"  0x{off:05X} -> 0x{addr:05X}: \"{s}\"")

# ============================================================
# 4. 函数 0x29FE8 中引用的字符串
# ============================================================
print("\n" + "=" * 70)
print("4. 函数 0x29FE8 中引用的调试字符串")
print("=" * 70)
for off in range(0x29FE8, 0x2A110, 4):
    inst = r32(off)
    if (inst & 0x9F000000) == 0x90000000:
        rd = inst & 0x1F
        immhi = (inst >> 5) & 0x7FFFF; immlo = (inst >> 29) & 0x3
        iv = (immhi << 2) | immlo
        if iv & 0x100000: iv |= ~0x1FFFFF
        pg = ((off & ~0xFFF) + (iv << 12)) & 0xFFFFFFFF
        for off2 in range(off+4, min(off+16, 0x2A110), 4):
            inst2 = r32(off2)
            if (inst2 & 0xFF800000) == 0x91000000:
                rd2 = inst2 & 0x1F
                rn2 = (inst2 >> 5) & 0x1F
                if rn2 == rd:
                    imm12 = (inst2 >> 10) & 0xFFF
                    sh = (inst2 >> 22) & 1
                    if sh: imm12 <<= 12
                    addr = pg + imm12
                    s = read_str(addr)
                    if s and len(s) > 2:
                        print(f"  0x{off:05X} -> 0x{addr:05X}: \"{s}\"")

# ============================================================
# 5. 子函数 0x2AA2C 和 0x2AAC8 的字符串（0x29FE8 调用）
# ============================================================
print("\n" + "=" * 70)
print("5. 函数 0x2AA2C 和 0x2AAC8 中的字符串")
print("=" * 70)
for func_start, func_end, name in [(0x2AA2C, 0x2AAD0, "0x2AA2C"), (0x2AAC8, 0x2AB50, "0x2AAC8")]:
    print(f"\n  --- {name} ---")
    for off in range(func_start, func_end, 4):
        inst = r32(off)
        if (inst & 0x9F000000) == 0x90000000:
            rd = inst & 0x1F
            immhi = (inst >> 5) & 0x7FFFF; immlo = (inst >> 29) & 0x3
            iv = (immhi << 2) | immlo
            if iv & 0x100000: iv |= ~0x1FFFFF
            pg = ((off & ~0xFFF) + (iv << 12)) & 0xFFFFFFFF
            for off2 in range(off+4, min(off+16, func_end), 4):
                inst2 = r32(off2)
                if (inst2 & 0xFF800000) == 0x91000000:
                    rd2 = inst2 & 0x1F
                    rn2 = (inst2 >> 5) & 0x1F
                    if rn2 == rd:
                        imm12 = (inst2 >> 10) & 0xFFF
                        addr = pg + imm12
                        s = read_str(addr)
                        if s and len(s) > 2:
                            print(f"    0x{off:05X} -> 0x{addr:05X}: \"{s}\"")

# ============================================================
# 6. SetDeviceUnlocked 中的字符串
# ============================================================
print("\n" + "=" * 70)
print("6. SetDeviceUnlocked 中的字符串")
print("=" * 70)
for off in range(0x22DB8, 0x23100, 4):
    inst = r32(off)
    if (inst & 0x9F000000) == 0x90000000:
        rd = inst & 0x1F
        immhi = (inst >> 5) & 0x7FFFF; immlo = (inst >> 29) & 0x3
        iv = (immhi << 2) | immlo
        if iv & 0x100000: iv |= ~0x1FFFFF
        pg = ((off & ~0xFFF) + (iv << 12)) & 0xFFFFFFFF
        for off2 in range(off+4, min(off+16, 0x23100), 4):
            inst2 = r32(off2)
            if (inst2 & 0xFF800000) == 0x91000000:
                rd2 = inst2 & 0x1F
                rn2 = (inst2 >> 5) & 0x1F
                if rn2 == rd:
                    imm12 = (inst2 >> 10) & 0xFFF
                    addr = pg + imm12
                    s = read_str(addr)
                    if s and len(s) > 2:
                        print(f"  0x{off:05X} -> 0x{addr:05X}: \"{s}\"")

# ============================================================
# 7. 搜索所有包含 "devinfo"、"reset"、"unlock" 的字符串
# ============================================================
print("\n" + "=" * 70)
print("7. 搜索关键字符串")
print("=" * 70)
keywords = [b"devinfo", b"DevInfo", b"DEVINFO", b"reset", b"Reset", b"RESET",
            b"unlock", b"Unlock", b"UNLOCK", b"OemCheck", b"InitDefaults",
            b"init_default", b"ResetDev", b"oem_", b"OEM"]
for kw in keywords:
    pos = 0
    while True:
        idx = pe.find(kw, pos)
        if idx == -1:
            break
        # Read surrounding string
        start = idx
        while start > 0 and pe[start-1] >= 0x20 and pe[start-1] < 0x7F:
            start -= 1
        end = idx + len(kw)
        while end < len(pe) and pe[end] >= 0x20 and pe[end] < 0x7F:
            end += 1
        s = pe[start:end].decode('ascii', errors='replace')
        if len(s) > 3:
            sec = ".text" if idx < 0x6A000 else ".data"
            print(f"  0x{idx:06X} [{sec}]: \"{s}\"")
        pos = idx + len(kw)

# ============================================================
# 8. ReadWritePartition GUID 详细检查
# ============================================================
print("\n" + "=" * 70)
print("8. ReadWritePartition 使用的协议 GUID (0x69BE0)")
print("=" * 70)
guid_off = 0x69BE0
if guid_off + 16 <= len(pe):
    d1 = struct.unpack_from('<I', pe, guid_off)[0]
    d2 = struct.unpack_from('<H', pe, guid_off+4)[0]
    d3 = struct.unpack_from('<H', pe, guid_off+6)[0]
    d4 = pe[guid_off+8:guid_off+16]
    guid = f"{d1:08X}-{d2:04X}-{d3:04X}-{d4[0]:02X}{d4[1]:02X}-{d4[2]:02X}{d4[3]:02X}{d4[4]:02X}{d4[5]:02X}{d4[6]:02X}{d4[7]:02X}"
    print(f"  GUID: {guid}")

# Check other GUIDs near 0x69AF0 (used in boot function)
print("\n  Boot function 使用的 GUID (0x69AF0):")
guid_off = 0x69AF0
if guid_off + 16 <= len(pe):
    d1 = struct.unpack_from('<I', pe, guid_off)[0]
    d2 = struct.unpack_from('<H', pe, guid_off+4)[0]
    d3 = struct.unpack_from('<H', pe, guid_off+6)[0]
    d4 = pe[guid_off+8:guid_off+16]
    guid = f"{d1:08X}-{d2:04X}-{d3:04X}-{d4[0]:02X}{d4[1]:02X}-{d4[2]:02X}{d4[3]:02X}{d4[4]:02X}{d4[5]:02X}{d4[6]:02X}{d4[7]:02X}"
    print(f"  GUID: {guid}")

# ============================================================
# 9. 检查 0x29FE8 入口参数中 x8=[0x6A000+offset] 的值
# ============================================================
print("\n" + "=" * 70)
print("9. 函数 0x29FE8 使用的 .data 区域")
print("=" * 70)
# At 0x29FF8: ADRP x8, 0x6A000
# Check what data follows
off = 0x29FF8
inst = r32(off)
if (inst & 0x9F000000) == 0x90000000:
    rd = inst & 0x1F
    immhi = (inst >> 5) & 0x7FFFF; immlo = (inst >> 29) & 0x3
    iv = (immhi << 2) | immlo
    if iv & 0x100000: iv |= ~0x1FFFFF
    pg = ((off & ~0xFFF) + (iv << 12)) & 0xFFFFFFFF
    print(f"  0x29FF8: ADRP x{rd}, 0x{pg:X}")
    # Check next instruction for LDR/ADD
    inst2 = r32(0x29FFC)
    # 0x29FFC is BL 0x2AA2C, not a LDR. Let me check what x8 is used for
    # Actually x8 from 0x29FF8 might be used later
    # Let me scan forward for uses of x8 after this ADRP
    print(f"  (x8 可能在子函数中使用)")

# Check LDR from 0x6A000 area
for off in range(0x29FE8, 0x2A110, 4):
    inst = r32(off)
    # LDR x from 0x6A page
    if (inst & 0xFFC00000) == 0xF9400000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = ((inst >> 10) & 0xFFF) * 8
        if rn == 8:  # x8 from ADRP
            print(f"  0x{off:05X}: LDR x{rt}, [x8, #{imm}]  → .data[0x6A000+{imm}] = 0x{pg+imm:X}")

# ============================================================
# 10. 0x32620 函数 — OemCheckResetDevInfo 中大量调用
# ============================================================
print("\n" + "=" * 70)
print("10. 函数 0x32620 — OemCheckResetDevInfo 中大量调用")
print("=" * 70)
for off in range(0x32620, 0x326A0, 4):
    inst = r32(off)
    if (inst & 0x9F000000) == 0x90000000:
        rd = inst & 0x1F
        immhi = (inst >> 5) & 0x7FFFF; immlo = (inst >> 29) & 0x3
        iv = (immhi << 2) | immlo
        if iv & 0x100000: iv |= ~0x1FFFFF
        pg = ((off & ~0xFFF) + (iv << 12)) & 0xFFFFFFFF
        for off2 in range(off+4, min(off+16, 0x326A0), 4):
            inst2 = r32(off2)
            if (inst2 & 0xFF800000) == 0x91000000:
                rd2 = inst2 & 0x1F
                rn2 = (inst2 >> 5) & 0x1F
                if rn2 == rd:
                    imm12 = (inst2 >> 10) & 0xFFF
                    addr = pg + imm12
                    s = read_str(addr)
                    if s and len(s) > 2:
                        print(f"  0x{off:05X} -> 0x{addr:05X}: \"{s}\"")

# Also check what callers pass:
# 0x36414: SUB x2=x23-0x18, w0=0xD, w1=0x24, w3=??
# 0x36424: BL 0x32620
print("\n  0x32620 调用参数:")
print("  call 1: w0=0xD, w1=0x24  → 可能是变量 ID 13, flags 0x24")
print("  call 2: w0=0xD, w1=0x28")
print("  call 3: w0=0xD, w1=0x2C")
print("  call 4: w0=0xD, w1=variable-flags")
print("  call 5(second 29FE8): w0=0xD, w1=reboot-related")

# ============================================================
# 11. 检查 ProcessParams (0x34E50) 的字符串 — 可能设置关键标志
# ============================================================
print("\n" + "=" * 70)
print("11. ProcessParams (0x34E50) 中的字符串引用")
print("=" * 70)
for off in range(0x34E50, 0x362D8, 4):
    inst = r32(off)
    if (inst & 0x9F000000) == 0x90000000:
        rd = inst & 0x1F
        immhi = (inst >> 5) & 0x7FFFF; immlo = (inst >> 29) & 0x3
        iv = (immhi << 2) | immlo
        if iv & 0x100000: iv |= ~0x1FFFFF
        pg = ((off & ~0xFFF) + (iv << 12)) & 0xFFFFFFFF
        for off2 in range(off+4, min(off+16, 0x362D8), 4):
            inst2 = r32(off2)
            if (inst2 & 0xFF800000) == 0x91000000:
                rd2 = inst2 & 0x1F
                rn2 = (inst2 >> 5) & 0x1F
                if rn2 == rd:
                    imm12 = (inst2 >> 10) & 0xFFF
                    addr = pg + imm12
                    if 0x50000 <= addr < 0x6A000:
                        s = read_str(addr)
                        if s and len(s) > 2:
                            print(f"  0x{off:05X} -> 0x{addr:05X}: \"{s}\"")

print("\nDone.")
