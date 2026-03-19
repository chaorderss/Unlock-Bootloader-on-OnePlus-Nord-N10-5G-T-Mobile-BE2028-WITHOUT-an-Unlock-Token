#!/usr/bin/env python3
"""
全面追踪 ReadDeviceInfo 函数：
1. 找到函数入口点（包含 0x23344-0x23394 的函数）
2. 反汇编完整函数
3. 找到所有调用者
4. 追踪 devinfo partition 读取机制
5. 搜索所有对 devinfo buffer (0x1BD978) 的写入
"""
import struct, re

PE = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
DISASM = "/tmp/linuxloader_disasm.txt"

with open(PE, "rb") as f:
    pe = f.read()

# ============================================================
# 1. 找到包含 0x23344 的函数入口
# ============================================================
print("=" * 70)
print("=== 1. 找到 ReadDeviceInfo 函数入口 ===")
print("=" * 70)

# 向前搜索函数序言 (STP x29, x30, [sp, #...] 或 SUB sp, sp, #...)
# 从 0x23344 向前搜索
addr = 0x23344
while addr > 0x22000:
    addr -= 4
    inst = struct.unpack_from("<I", pe, addr)[0]
    # STP x29, x30 pattern: 1x101001xx xxxxxxxx x11111 11101 11101
    # More general: look for common prologue patterns
    # SUB SP, SP, #imm: 0xD10003FF pattern
    if (inst & 0xFFE0001F) == 0xA9000000 | 0x7BFD:  # approximate STP
        pass
    # Look for STP with x29,x30
    if (inst & 0xFFC003FF) == 0xA90003FD:  # STP x29, x30, [sp, ...]
        print(f"  Found STP x29,x30 at 0x{addr:05X}")
        break
    # Also check for sub sp, sp
    if (inst >> 24) == 0xD1 and (inst & 0x1F) == 0x1F and ((inst >> 5) & 0x1F) == 0x1F:
        print(f"  Found SUB SP at 0x{addr:05X}")
        break
    # RET instruction (previous function ends)
    if inst == 0xD65F03C0:
        addr += 4  # the function starts after the RET
        print(f"  Found RET at 0x{addr-4:05X}, function likely starts at 0x{addr:05X}")
        break

func_start = addr
print(f"\n  ReadDeviceInfo function estimated start: 0x{func_start:05X}")

# ============================================================
# 2. 反汇编 ReadDeviceInfo 完整函数
# ============================================================
print("\n" + "=" * 70)
print("=== 2. ReadDeviceInfo 完整反汇编 (0x{:05X} - 0x233B0) ===".format(func_start))
print("=" * 70)

with open(DISASM) as f:
    lines = f.readlines()

# Build address index
addr_to_line = {}
for i, line in enumerate(lines):
    m = re.match(r'\s*(0x[0-9a-fA-F]+):', line)
    if m:
        a = int(m.group(1), 16)
        addr_to_line[a] = i

# Print function
start_line = addr_to_line.get(func_start)
if start_line is None:
    # Try nearby addresses
    for delta in range(-8, 8, 4):
        if func_start + delta in addr_to_line:
            start_line = addr_to_line[func_start + delta]
            break

if start_line:
    for i in range(start_line, min(start_line + 80, len(lines))):
        print(f"  {lines[i].rstrip()}")
        if 'ret' in lines[i].lower() and i > start_line + 5:
            break
else:
    # Fallback: manual decode
    print("  (No disasm match, manual decode from binary)")
    for off in range(func_start, 0x233B0, 4):
        inst = struct.unpack_from("<I", pe, off)[0]
        s = f"  0x{off:05X}: 0x{inst:08X}"
        # Decode common instructions
        if inst == 0xD65F03C0:
            s += "  ret"
            print(s)
            break
        elif (inst >> 26) == 0x25:  # BL
            imm = inst & 0x3FFFFFF
            if imm & 0x2000000:
                imm |= ~0x3FFFFFF
            target = off + (imm << 2)
            s += f"  bl 0x{target & 0xFFFFFFFF:05X}"
        elif (inst >> 24) == 0x90:  # ADRP
            rd = inst & 0x1F
            immhi = (inst >> 5) & 0x7FFFF
            immlo = (inst >> 29) & 0x3
            imm = (immhi << 2) | immlo
            if imm & 0x100000:
                imm |= ~0x1FFFFF
            page = ((off & ~0xFFF) + (imm << 12)) & 0xFFFFFFFF
            s += f"  adrp x{rd}, 0x{page:05X}"
        elif (inst >> 22) == 0x244:  # ADD imm
            rd = inst & 0x1F
            rn = (inst >> 5) & 0x1F
            imm12 = (inst >> 10) & 0xFFF
            sh = (inst >> 22) & 1
            if sh:
                imm12 <<= 12
            s += f"  add x{rd}, x{rn}, #0x{imm12:X}"
        elif (inst & 0xFFC00000) == 0x39400000:  # LDRB
            rt = inst & 0x1F
            rn = (inst >> 5) & 0x1F
            imm12 = (inst >> 10) & 0xFFF
            s += f"  ldrb w{rt}, [x{rn}, #{imm12}]"
        elif (inst & 0xFFC00000) == 0x39000000:  # STRB
            rt = inst & 0x1F
            rn = (inst >> 5) & 0x1F
            imm12 = (inst >> 10) & 0xFFF
            s += f"  strb w{rt}, [x{rn}, #{imm12}]"
        elif inst >> 24 == 0xB4 or inst >> 24 == 0xB5 or inst >> 24 == 0x34 or inst >> 24 == 0x35:
            # CBZ/CBNZ
            rt = inst & 0x1F
            imm19 = (inst >> 5) & 0x7FFFF
            if imm19 & 0x40000:
                imm19 |= ~0x7FFFF
            target = off + (imm19 << 2)
            op = "cbz" if (inst >> 24) in (0xB4, 0x34) else "cbnz"
            s += f"  {op} x{rt if inst>>24>=0xB4 else 'w'+str(rt)}, 0x{target & 0xFFFFFFFF:05X}"
        print(s)

# ============================================================
# 3. 找到 ReadDeviceInfo 的所有调用者
# ============================================================
print("\n" + "=" * 70)
print("=== 3. ReadDeviceInfo 调用者 (BL 0x{:05X}) ===".format(func_start))
print("=" * 70)

# Search for BL to func_start
callers = []
for off in range(0, min(len(pe), 0x6A000), 4):
    inst = struct.unpack_from("<I", pe, off)[0]
    if (inst >> 26) == 0x25:  # BL
        imm = inst & 0x3FFFFFF
        if imm & 0x2000000:
            imm |= ~0x3FFFFFF
        target = off + (imm << 2)
        if (target & 0xFFFFFFFF) == func_start:
            callers.append(off)
            print(f"  BL at 0x{off:05X} → 0x{func_start:05X}")

if not callers:
    print("  (none found - might be called via function pointer)")
    # Also try nearby addresses
    for try_addr in range(func_start - 8, func_start + 8, 4):
        for off in range(0, min(len(pe), 0x6A000), 4):
            inst = struct.unpack_from("<I", pe, off)[0]
            if (inst >> 26) == 0x25:
                imm = inst & 0x3FFFFFF
                if imm & 0x2000000:
                    imm |= ~0x3FFFFFF
                target = off + (imm << 2)
                if (target & 0xFFFFFFFF) == try_addr and try_addr != func_start:
                    print(f"  BL at 0x{off:05X} → 0x{try_addr:05X} (nearby)")

# ============================================================
# 4. 搜索所有对 devinfo 偏移 0x0D 的写入（更全面搜索）
# ============================================================
print("\n" + "=" * 70)
print("=== 4. 所有对 devinfo[0x0D] 的写入指令 ===")
print("=" * 70)

# Search for STRB Wx, [Xn, #13]
print("\n--- STRB Wx, [Xn, #13] ---")
for off in range(0, min(len(pe), 0x6A000), 4):
    inst = struct.unpack_from("<I", pe, off)[0]
    if (inst & 0xFFC003E0) == 0x39003400:  # STRB Wt, [Xn, #13] where Xn varies
        rt = inst & 0x1F
        rn = (inst >> 5) & 0x1F
        print(f"  0x{off:05X}: STRB w{rt}, [x{rn}, #13]")

# Search for STR/STUR that could write to offset 13 within a structure
print("\n--- STR/STUR patterns that might affect offset 13 ---")
# STP that covers offset 8-23: STP Xt, Xt, [Xn, #8]
for off in range(0, min(len(pe), 0x6A000), 4):
    inst = struct.unpack_from("<I", pe, off)[0]
    # STP Xt1, Xt2, [Xn, #imm7*8] - check if offset covers 0x0D
    if (inst & 0x7FC00000) == 0x29000000:  # STP (32-bit)
        imm7 = (inst >> 15) & 0x7F
        if imm7 & 0x40: imm7 |= ~0x7F
        offset = imm7 * 4
        # Check if [offset, offset+7] overlaps with [13, 13]
        if offset <= 13 < offset + 8:
            rt = inst & 0x1F
            rt2 = (inst >> 10) & 0x1F
            rn = (inst >> 5) & 0x1F
            print(f"  0x{off:05X}: STP w{rt}, w{rt2}, [x{rn}, #{offset}] (covers offset 13)")
    if (inst & 0xFFC00000) == 0xA9000000:  # STP (64-bit)
        imm7 = (inst >> 15) & 0x7F
        if imm7 & 0x40: imm7 |= ~0x7F
        offset = imm7 * 8
        if offset <= 13 < offset + 16:
            rt = inst & 0x1F
            rt2 = (inst >> 10) & 0x1F
            rn = (inst >> 5) & 0x1F
            print(f"  0x{off:05X}: STP x{rt}, x{rt2}, [x{rn}, #{offset}] (64-bit, covers offset 13)")

# ============================================================
# 5. 搜索 memset / memcpy 到 devinfo buffer 的调用
# ============================================================
print("\n" + "=" * 70)
print("=== 5. 寻找可能的 memset/ZeroMem 对 devinfo buffer ===")
print("=" * 70)

# devinfo buffer is at ADRP 0x1BD000 + 0x978
# Look for ADRP 0x1BD000 followed by ADD #0x978 near a BL to memset/zeromem
# First, find SetMem/ZeroMem candidates (functions called with buffer + size)
# Look for patterns: ADRP x0, 0x1BD000; ADD x0, x0, #0x978; ... BL xxx
adrp_sites = []
for off in range(0, min(len(pe), 0x6A000), 4):
    inst = struct.unpack_from("<I", pe, off)[0]
    if inst >> 24 == 0x90:
        rd = inst & 0x1F
        immhi = (inst >> 5) & 0x7FFFF
        immlo = (inst >> 29) & 0x3
        imm = (immhi << 2) | immlo
        if imm & 0x100000: imm |= ~0x1FFFFF
        page = ((off & ~0xFFF) + (imm << 12)) & 0xFFFFFFFF
        if page == 0x1BD000:
            # Check next instruction for ADD with #0x978
            if off + 4 < len(pe):
                next_inst = struct.unpack_from("<I", pe, off + 4)[0]
                if (next_inst >> 22) == 0x244:
                    rd2 = next_inst & 0x1F
                    rn2 = (next_inst >> 5) & 0x1F
                    imm12 = (next_inst >> 10) & 0xFFF
                    if rn2 == rd and imm12 == 0x978:
                        adrp_sites.append(off)

print(f"  Found {len(adrp_sites)} ADRP+ADD to devinfo buffer (0x1BD978):")
for site in adrp_sites:
    print(f"\n  --- Site at 0x{site:05X} ---")
    # Show context: 4 instructions before, 12 after
    for delta in range(-16, 52, 4):
        a = site + delta
        if 0 <= a < len(pe):
            inst = struct.unpack_from("<I", pe, a)[0]
            marker = " >>>" if delta == 0 else "    "
            s = f"  {marker} 0x{a:05X}: 0x{inst:08X}"
            if inst == 0xD65F03C0:
                s += "  ret"
            elif (inst >> 26) == 0x25:
                imm = inst & 0x3FFFFFF
                if imm & 0x2000000: imm |= ~0x3FFFFFF
                target = a + (imm << 2)
                s += f"  bl 0x{target & 0xFFFFFFFF:05X}"
            elif inst >> 24 == 0x90:
                rd = inst & 0x1F
                immhi = (inst >> 5) & 0x7FFFF
                immlo = (inst >> 29) & 0x3
                imm_v = (immhi << 2) | immlo
                if imm_v & 0x100000: imm_v |= ~0x1FFFFF
                pg = ((a & ~0xFFF) + (imm_v << 12)) & 0xFFFFFFFF
                s += f"  adrp x{rd}, 0x{pg:05X}"
            elif (inst >> 22) == 0x244:
                rd = inst & 0x1F
                rn = (inst >> 5) & 0x1F
                imm12 = (inst >> 10) & 0xFFF
                s += f"  add x{rd}, x{rn}, #0x{imm12:X}"
            elif (inst & 0xFFC00000) == 0x39000000:
                rt = inst & 0x1F
                rn = (inst >> 5) & 0x1F
                imm12 = (inst >> 10) & 0xFFF
                s += f"  strb w{rt}, [x{rn}, #{imm12}]"
            elif (inst & 0xFFC00000) == 0x39400000:
                rt = inst & 0x1F
                rn = (inst >> 5) & 0x1F
                imm12 = (inst >> 10) & 0xFFF
                s += f"  ldrb w{rt}, [x{rn}, #{imm12}]"
            elif (inst & 0xFF000000) == 0xD2000000:  # MOVZ
                rd = inst & 0x1F
                imm16 = (inst >> 5) & 0xFFFF
                hw = (inst >> 21) & 0x3
                s += f"  movz x{rd}, #0x{imm16:X}" + (f", lsl #{hw*16}" if hw else "")
            elif (inst & 0xFF800000) == 0x52800000:  # MOV Wd, #imm
                rd = inst & 0x1F
                imm16 = (inst >> 5) & 0xFFFF
                s += f"  mov w{rd}, #0x{imm16:X}"
            print(s)

# ============================================================
# 6. 追踪 SetDeviceUnlocked (0x22DB8) 的所有调用者
# ============================================================
print("\n" + "=" * 70)
print("=== 6. SetDeviceUnlocked (0x22DB8) 调用者 ===")
print("=" * 70)

for off in range(0, min(len(pe), 0x6A000), 4):
    inst = struct.unpack_from("<I", pe, off)[0]
    if (inst >> 26) == 0x25:
        imm = inst & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        target = off + (imm << 2)
        if (target & 0xFFFFFFFF) == 0x22DB8:
            print(f"  BL at 0x{off:05X} → 0x22DB8")
            # Context
            for d in range(-12, 20, 4):
                a2 = off + d
                if 0 <= a2 < len(pe):
                    i2 = struct.unpack_from("<I", pe, a2)[0]
                    m = " >>>" if d == 0 else "    "
                    print(f"    {m} 0x{a2:05X}: 0x{i2:08X}")

# ============================================================
# 7. 搜索 0x22E4C 附近的 STRB (SetDeviceUnlocked 内的写入)
# ============================================================
print("\n" + "=" * 70)
print("=== 7. 完整反汇编 SetDeviceUnlocked (0x22DB8-0x22FB0) ===")
print("=" * 70)

for off in range(0x22DB8, 0x22FB0, 4):
    inst = struct.unpack_from("<I", pe, off)[0]
    s = f"  0x{off:05X}: 0x{inst:08X}"
    if inst == 0xD65F03C0:
        s += "  ret"
    elif (inst >> 26) == 0x25:
        imm = inst & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        target = off + (imm << 2)
        s += f"  bl 0x{target & 0xFFFFFFFF:05X}"
    elif inst >> 24 == 0x90:
        rd = inst & 0x1F
        immhi = (inst >> 5) & 0x7FFFF
        immlo = (inst >> 29) & 0x3
        imm_v = (immhi << 2) | immlo
        if imm_v & 0x100000: imm_v |= ~0x1FFFFF
        pg = ((off & ~0xFFF) + (imm_v << 12)) & 0xFFFFFFFF
        s += f"  adrp x{rd}, 0x{pg:05X}"
    elif (inst >> 22) == 0x244:
        rd = inst & 0x1F
        rn = (inst >> 5) & 0x1F
        imm12 = (inst >> 10) & 0xFFF
        s += f"  add x{rd}, x{rn}, #0x{imm12:X}"
    elif (inst & 0xFFC00000) == 0x39000000:
        rt = inst & 0x1F
        rn = (inst >> 5) & 0x1F
        imm12 = (inst >> 10) & 0xFFF
        s += f"  strb w{rt}, [x{rn}, #{imm12}]"
    elif (inst & 0xFFC00000) == 0x39400000:
        rt = inst & 0x1F
        rn = (inst >> 5) & 0x1F
        imm12 = (inst >> 10) & 0xFFF
        s += f"  ldrb w{rt}, [x{rn}, #{imm12}]"
    print(s)
    if inst == 0xD65F03C0 and off > 0x22E00:
        break

# ============================================================
# 8. 检查 ReadDeviceInfo 中的 partition read 调用
# ============================================================
print("\n" + "=" * 70)
print("=== 8. ReadDeviceInfo 以及 partition read 更宽范围 (0x23200-0x233B0) ===")
print("=" * 70)

for off in range(0x23200, 0x233B0, 4):
    inst = struct.unpack_from("<I", pe, off)[0]
    s = f"  0x{off:05X}: 0x{inst:08X}"
    if inst == 0xD65F03C0:
        s += "  ret"
    elif (inst >> 26) == 0x25:
        imm = inst & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        target = off + (imm << 2)
        s += f"  bl 0x{target & 0xFFFFFFFF:05X}"
    elif inst >> 24 == 0x90:
        rd = inst & 0x1F
        immhi = (inst >> 5) & 0x7FFFF
        immlo = (inst >> 29) & 0x3
        imm_v = (immhi << 2) | immlo
        if imm_v & 0x100000: imm_v |= ~0x1FFFFF
        pg = ((off & ~0xFFF) + (imm_v << 12)) & 0xFFFFFFFF
        s += f"  adrp x{rd}, 0x{pg:05X}"
    elif (inst >> 22) == 0x244:
        rd = inst & 0x1F
        rn = (inst >> 5) & 0x1F
        imm12 = (inst >> 10) & 0xFFF
        s += f"  add x{rd}, x{rn}, #0x{imm12:X}"
    elif (inst & 0xFFC00000) == 0x39000000:
        rt = inst & 0x1F
        rn = (inst >> 5) & 0x1F
        imm12 = (inst >> 10) & 0xFFF
        s += f"  strb w{rt}, [x{rn}, #{imm12}]"
    elif (inst & 0xFFC00000) == 0x39400000:
        rt = inst & 0x1F
        rn = (inst >> 5) & 0x1F
        imm12 = (inst >> 10) & 0xFFF
        s += f"  ldrb w{rt}, [x{rn}, #{imm12}]"
    elif (inst & 0xFF800000) == 0x52800000:
        rd = inst & 0x1F
        imm16 = (inst >> 5) & 0xFFFF
        s += f"  mov w{rd}, #0x{imm16:X}"
    elif (inst & 0xFFE0001F) == 0xAA0003E0:  # MOV Xd, Xm
        rd = inst & 0x1F
        rm = (inst >> 16) & 0x1F
        s += f"  mov x{rd}, x{rm}"
    elif (inst & 0x7F800000) == 0x6B000000:  # SUBS/CMP
        s += "  (cmp/subs)"
    elif (inst & 0xFF000000) == 0x54000000:  # B.cond
        imm19 = (inst >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 |= ~0x7FFFF
        target = off + (imm19 << 2)
        cond = inst & 0xF
        cond_names = {0:'EQ',1:'NE',2:'CS',3:'CC',4:'MI',5:'PL',6:'VS',7:'VC',
                      8:'HI',9:'LS',10:'GE',11:'LT',12:'GT',13:'LE',14:'AL'}
        cn = cond_names.get(cond, f'{cond}')
        s += f"  b.{cn} 0x{target & 0xFFFFFFFF:05X}"
    elif inst >> 24 == 0xB4:
        rt = inst & 0x1F
        imm19 = (inst >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 |= ~0x7FFFF
        target = off + (imm19 << 2)
        s += f"  cbz x{rt}, 0x{target & 0xFFFFFFFF:05X}"
    elif inst >> 24 == 0xB5:
        rt = inst & 0x1F
        imm19 = (inst >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 |= ~0x7FFFF
        target = off + (imm19 << 2)
        s += f"  cbnz x{rt}, 0x{target & 0xFFFFFFFF:05X}"
    elif inst >> 24 == 0x34:
        rt = inst & 0x1F
        imm19 = (inst >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 |= ~0x7FFFF
        target = off + (imm19 << 2)
        s += f"  cbz w{rt}, 0x{target & 0xFFFFFFFF:05X}"
    elif inst >> 24 == 0x35:
        rt = inst & 0x1F
        imm19 = (inst >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 |= ~0x7FFFF
        target = off + (imm19 << 2)
        s += f"  cbnz w{rt}, 0x{target & 0xFFFFFFFF:05X}"
    print(s)
