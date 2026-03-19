#!/usr/bin/env python3
"""
关键分析：为什么 init_defaults 在启动时运行？
两种可能：
  A. ReadDeviceInfo 中 magic 检查失败 → init_defaults
  B. OemCheckResetDevInfo 的内部标志 == 1 → init_defaults

需要检查：
  1. OemCheckResetDevInfo 完整流程 — 哪个标志触发 init_defaults
  2. 函数 0x29FE8 — 设置该标志的函数
  3. 0x1C757C 处的标志（控制 SetIsUnlocked）
  4. ReadDeviceInfo 第二次调用检查（0x233A8）
  5. ProcessParams 返回值 → 可能传给 OemCheckResetDevInfo
"""
import struct

PE = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
with open(PE, "rb") as f:
    pe = f.read()

def r32(off):
    return struct.unpack_from('<I', pe, off)[0]

def decode(off, inst):
    s = f"  0x{off:05X}: 0x{inst:08X}"
    if inst == 0xD65F03C0: return s + "  RET"
    if inst == 0x00000000: return s + "  (nop)"
    if (inst >> 26) == 0x25:
        imm = inst & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        t = off + (imm << 2)
        return s + f"  BL 0x{t & 0xFFFFFFFF:05X}"
    if (inst >> 26) == 0x05:
        imm = inst & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        t = off + (imm << 2)
        return s + f"  B 0x{t & 0xFFFFFFFF:05X}"
    if (inst & 0xFF000010) == 0x54000000:
        imm19 = (inst >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 |= ~0x7FFFF
        t = off + (imm19 << 2)
        cond = inst & 0xF
        c = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
        return s + f"  B.{c[cond]} 0x{t & 0xFFFFFFFF:05X}"
    if (inst & 0x7E000000) == 0x34000000:
        sf = (inst >> 31) & 1; op = (inst >> 24) & 1; rt = inst & 0x1F
        imm19 = (inst >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 |= ~0x7FFFF
        t = off + (imm19 << 2)
        rn = f"x{rt}" if sf else f"w{rt}"
        mn = "CBNZ" if op else "CBZ"
        return s + f"  {mn} {rn}, 0x{t & 0xFFFFFFFF:05X}"
    if (inst & 0x7E000000) == 0x36000000:
        op = (inst >> 24) & 1
        b5 = (inst >> 31) & 1; b40 = (inst >> 19) & 0x1F
        bit = (b5 << 5) | b40
        rt = inst & 0x1F
        imm14 = (inst >> 5) & 0x3FFF
        if imm14 & 0x2000: imm14 |= ~0x3FFF
        t = off + (imm14 << 2)
        mn = "TBNZ" if op else "TBZ"
        return s + f"  {mn} x{rt}, #{bit}, 0x{t & 0xFFFFFFFF:05X}"
    if (inst & 0x9F000000) == 0x90000000:
        rd = inst & 0x1F
        immhi = (inst >> 5) & 0x7FFFF; immlo = (inst >> 29) & 0x3
        iv = (immhi << 2) | immlo
        if iv & 0x100000: iv |= ~0x1FFFFF
        pg = ((off & ~0xFFF) + (iv << 12)) & 0xFFFFFFFF
        return s + f"  ADRP x{rd}, 0x{pg:X}"
    if (inst & 0xFF800000) == 0x91000000:
        rd = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm12 = (inst >> 10) & 0xFFF
        sh = (inst >> 22) & 1
        if sh: imm12 <<= 12
        return s + f"  ADD x{rd}, x{rn}, #0x{imm12:X}"
    if (inst & 0xFF800000) == 0xD1000000:
        rd = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm12 = (inst >> 10) & 0xFFF
        return s + f"  SUB x{rd}, x{rn}, #0x{imm12:X}"
    if (inst & 0xFFFFFC1F) == 0xD63F0000:
        rn = (inst >> 5) & 0x1F
        return s + f"  BLR x{rn}"
    if (inst & 0xFFC00000) == 0xF9400000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = ((inst >> 10) & 0xFFF) * 8
        return s + f"  LDR x{rt}, [x{rn}, #{imm}]"
    if (inst & 0xFFC00000) == 0xF9000000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = ((inst >> 10) & 0xFFF) * 8
        return s + f"  STR x{rt}, [x{rn}, #{imm}]"
    if (inst & 0xFFC00000) == 0xB9400000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = ((inst >> 10) & 0xFFF) * 4
        return s + f"  LDR w{rt}, [x{rn}, #{imm}]"
    if (inst & 0xFFC00000) == 0xB9000000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = ((inst >> 10) & 0xFFF) * 4
        return s + f"  STR w{rt}, [x{rn}, #{imm}]"
    if (inst & 0xFFC00000) == 0x39000000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = (inst >> 10) & 0xFFF
        return s + f"  STRB w{rt}, [x{rn}, #{imm}]"
    if (inst & 0xFFC00000) == 0x39400000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = (inst >> 10) & 0xFFF
        return s + f"  LDRB w{rt}, [x{rn}, #{imm}]"
    if (inst & 0xFF800000) == 0x52800000:
        rd = inst & 0x1F; imm16 = (inst >> 5) & 0xFFFF; hw = (inst >> 21) & 0x3
        return s + f"  MOV w{rd}, #0x{imm16 << (hw*16):X}"
    if (inst & 0xFF800000) == 0xD2800000:
        rd = inst & 0x1F; imm16 = (inst >> 5) & 0xFFFF; hw = (inst >> 21) & 0x3
        return s + f"  MOV x{rd}, #0x{imm16 << (hw*16):X}"
    if (inst & 0xFF3FFC00) == 0xAA1F0000:
        rd = inst & 0x1F; rm = (inst >> 16) & 0x1F
        return s + f"  MOV x{rd}, x{rm}"
    if (inst & 0xFF3FFC00) == 0x2A1F0000:
        rd = inst & 0x1F; rm = (inst >> 16) & 0x1F
        return s + f"  MOV w{rd}, w{rm}"
    if (inst & 0xFFE0001F) == 0x2A0003E0 or (inst & 0xFFE0001F) == 0xAA0003E0:
        sf = (inst >> 31) & 1
        rd = inst & 0x1F; rm = (inst >> 16) & 0x1F
        rp = 'x' if sf else 'w'
        return s + f"  MOV {rp}{rd}, {rp}{rm}"
    # CMP imm (SUBS Xzr variant)
    if (inst & 0xFF800000) == 0x71000000:
        rn = (inst >> 5) & 0x1F; imm12 = (inst >> 10) & 0xFFF
        return s + f"  CMP w{rn}, #{imm12}"
    if (inst & 0xFF800000) == 0xF1000000:
        rn = (inst >> 5) & 0x1F; imm12 = (inst >> 10) & 0xFFF
        return s + f"  CMP x{rn}, #{imm12}"
    # TST
    if (inst & 0xFF80001F) == 0x7200001F:
        rn = (inst >> 5) & 0x1F; imms = (inst >> 10) & 0x3F
        immr = (inst >> 16) & 0x3F
        return s + f"  TST w{rn}, #bitmask(imms={imms},immr={immr})"
    if (inst & 0xFF80001F) == 0xF200001F:
        rn = (inst >> 5) & 0x1F
        return s + f"  TST x{rn}, #bitmask"
    # LDUR
    if (inst & 0xFFE00C00) == 0xB8400000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F
        imm9 = (inst >> 12) & 0x1FF
        if imm9 & 0x100: imm9 |= ~0x1FF
        return s + f"  LDUR w{rt}, [x{rn}, #{imm9}]"
    if (inst & 0xFFE00C00) == 0xF8400000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F
        imm9 = (inst >> 12) & 0x1FF
        if imm9 & 0x100: imm9 |= ~0x1FF
        return s + f"  LDUR x{rt}, [x{rn}, #{imm9}]"
    # STUR
    if (inst & 0xFFE00C00) == 0xB8000000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F
        imm9 = (inst >> 12) & 0x1FF
        if imm9 & 0x100: imm9 |= ~0x1FF
        return s + f"  STUR w{rt}, [x{rn}, #{imm9}]"
    # STP
    if (inst & 0x7FC00000) == 0x29000000:
        opc = (inst >> 30) & 0x3; L = (inst >> 22) & 1
        imm7 = (inst >> 15) & 0x7F
        if imm7 & 0x40: imm7 |= ~0x7F
        rt2 = (inst >> 10) & 0x1F; rn = (inst >> 5) & 0x1F; rt = inst & 0x1F
        scale = 2 if opc == 0 else 3
        offset = imm7 << scale
        mn = "LDP" if L else "STP"
        rp = 'x' if opc else 'w'
        return s + f"  {mn} {rp}{rt}, {rp}{rt2}, [x{rn}, #{offset}]"
    return s

def find_bl_callers(target, start=0x1000, end=0x6A000):
    callers = []
    for off in range(start, end, 4):
        inst = r32(off)
        if (inst >> 26) == 0x25:
            imm = inst & 0x3FFFFFF
            if imm & 0x2000000: imm |= ~0x3FFFFFF
            t = off + (imm << 2)
            if (t & 0xFFFFFFFF) == target:
                callers.append(off)
    return callers

# ============================================================
# 1. OemCheckResetDevInfo 完整反汇编 (0x362D8 - 0x36700)
# ============================================================
print("=" * 70)
print("1. OemCheckResetDevInfo 完整反汇编 (0x362D8 - 0x36700)")
print("=" * 70)
for off in range(0x362D8, 0x36700, 4):
    inst = r32(off)
    d = decode(off, inst)
    # 标注关键指令
    if off == 0x363C0:
        d += "  ★★★ 关键比较：决定是否调用 init_defaults"
    if off == 0x363C4:
        d += "  ★★★ 若 != 1，跳过 init_defaults"
    if off == 0x363CC:
        d += "  ★★★ init_defaults 调用点"
    if off == 0x36654:
        d += "  ★★★ SetIsUnlocked（设 unlocked=1，不持久化）"
    print(d)
    if inst == 0xD65F03C0 and off > 0x36600:
        break

# ============================================================
# 2. 函数 0x29FE8 — 这是什么？
# ============================================================
print("\n" + "=" * 70)
print("2. 函数 0x29FE8 — OemCheckResetDevInfo 用它来获取标志值")
print("=" * 70)
for off in range(0x29FE8, 0x2A100, 4):
    print(decode(off, r32(off)))
    if r32(off) == 0xD65F03C0:
        break

# 0x29FE8 的所有调用者
callers_29fe8 = find_bl_callers(0x29FE8)
print(f"\n  0x29FE8 调用者: {len(callers_29fe8)} → {['0x{:05X}'.format(c) for c in callers_29fe8]}")

# ============================================================
# 3. 0x1C757C 标志位 — 控制 SetIsUnlocked
# ============================================================
print("\n" + "=" * 70)
print("3. 标志位 0x1C757C — 初始值和写入者")
print("=" * 70)
val = pe[0x1C757C] if 0x1C757C < len(pe) else None
if val is not None:
    print(f"  PE[0x1C757C] = 0x{val:02X}")
    # 也检查周围
    for i in range(0x1C7578, 0x1C7580):
        if i < len(pe):
            print(f"  PE[0x{i:X}] = 0x{pe[i]:02X}")

# 搜索所有写入 0x1C757C 的指令
# 0x1C757C = page 0x1C7000 + offset 0x57C
print("\n  搜索 ADRP 0x1C7000 + STRB 到偏移 0x57C...")
for off in range(0x1000, 0x6A000, 4):
    inst = r32(off)
    if (inst & 0x9F000000) == 0x90000000:
        rd = inst & 0x1F
        immhi = (inst >> 5) & 0x7FFFF; immlo = (inst >> 29) & 0x3
        iv = (immhi << 2) | immlo
        if iv & 0x100000: iv |= ~0x1FFFFF
        pg = ((off & ~0xFFF) + (iv << 12)) & 0xFFFFFFFF
        if pg == 0x1C7000:
            for off2 in range(off+4, min(off+24, 0x6A000), 4):
                inst2 = r32(off2)
                # STRB to offset 0x57C
                if (inst2 & 0xFFC00000) == 0x39000000:
                    rn = (inst2 >> 5) & 0x1F
                    imm = (inst2 >> 10) & 0xFFF
                    if imm == 0x57C:
                        print(f"  ★ STRB 到 0x1C757C 在 0x{off2:05X} (ADRP 在 0x{off:05X})")
                # STR w to offset that covers 0x57C
                if (inst2 & 0xFFC00000) == 0xB9000000:
                    rn = (inst2 >> 5) & 0x1F
                    imm = ((inst2 >> 10) & 0xFFF) * 4
                    if imm <= 0x57C < imm + 4:
                        rt = inst2 & 0x1F
                        print(f"  ★ STR w{rt} 覆盖 0x1C757C 在 0x{off2:05X} (ADRP 在 0x{off:05X})")

# ============================================================
# 4. OemCheckResetDevInfo 中 0x363BC 加载的值来源追踪
# ============================================================
print("\n" + "=" * 70)
print("4. 追踪 0x363BC-0x363C0 中 w8 的来源")
print("=" * 70)
# 0x363BC: LDUR w8, [x23, #-16]
# x23 来自函数开头 0x362F0: LDR x23, [x0, #0]
# x0 来自 BL 0x01370（栈帧设置）
# [x23-16] 被写入的地方：
# 0x36308: STP w31, w31, [x23, #-16] → 初始化为 0,0
# 然后 0x29FE8 被调用时 x0 指向 x23-16 区域

# 详细反汇编 0x3635C-0x363C8
print("  OemCheckResetDevInfo 0x3635C-0x363CC:")
for off in range(0x3635C, 0x363D0, 4):
    print(decode(off, r32(off)))

# ============================================================
# 5. 检查 ReadDeviceInfo 的 ReadWritePartition 调用
#    是否有可能 READ 本身就失败了？
# ============================================================
print("\n" + "=" * 70)
print("5. ReadDeviceInfo — ReadWritePartition 的返回值处理")
print("=" * 70)
print("  ReadDeviceInfo 流程:")
print("  0x232FC: BL ReadWritePartition(READ)")
print("  0x23300: CBZ x0, 0x2333C  ; SUCCESS(x0=0) → 设置标志+检查魔数")
print("  失败路径: 0x23304-0x23338 → 跳到 0x23398 返回错误")
print("  成功路径: 0x2333C → 设置标志 → 检查魔数")
print("  魔数不匹配: → 0x23390 BL init_defaults")
print()
print("  调用者 0x01558:")
print("  0x01558: BL ReadDeviceInfo")
print("  0x0155C: CBZ x0, 0x01614  ; 成功 → 正常启动")
print("  若失败 → 错误处理，但 fastboot 仍然工作")
print()
print("  ★ 如果 ReadDeviceInfo 返回错误，后续不会调用 0x367F0（主启动函数）")
print("  ★ 如果 FastbootInit 没调用，fastboot 不会工作")
print("  ★ 但 fastboot 可以工作 → ReadDeviceInfo 必须返回成功(0)")
print("  ★ ReadDeviceInfo 返回成功的两种情况：")
print("    a. READ 成功 + 魔数匹配 → 直接使用分区数据（应该有我们的值）")
print("    b. READ 成功 + 魔数不匹配 → init_defaults → 返回成功")
print("    c. READ 失败 → 返回错误 → not possible (fastboot works)")
print()

# Wait - let me re-check if ReadDeviceInfo error also returns success
print("  重新检查 ReadDeviceInfo 失败路径:")
for off in range(0x23300, 0x233A8, 4):
    inst = r32(off)
    d = decode(off, inst)
    if off == 0x23300:
        d += "  ← READ 返回检查"
    if off == 0x23338:
        d += "  ← 失败路径跳转到返回"
    if off == 0x23390:
        d += "  ← init_defaults 调用"
    if off == 0x23394:
        d += "  ← 设置返回值 = SUCCESS"
    print(d)

# ============================================================
# 6. 0x36938 函数 — 被 ProcessParams 调用
# ============================================================
print("\n" + "=" * 70)
print("6. 函数 0x36938 (被 ProcessParams 调用)")
print("=" * 70)
for off in range(0x36938, 0x36968, 4):
    print(decode(off, r32(off)))

# ============================================================
# 7. 检查 0x1AD000+72 处的数据（OemCheckResetDevInfo 使用）
# ============================================================
print("\n" + "=" * 70)
print("7. 数据区 0x1AD048 (0x1AD000+72) — OemCheckResetDevInfo 使用")
print("=" * 70)
if 0x1AD048 + 8 <= len(pe):
    val = struct.unpack_from('<Q', pe, 0x1AD048)[0]
    print(f"  PE[0x1AD048] = 0x{val:016X}")
    # 这是一个指针，运行时会被填充
    print(f"  （初始值为零 = 运行时分配的指针）")

# ============================================================
# 8. 全面检查 ReadWritePartition — 是否 READ 和 WRITE 都依赖同一个协议
# ============================================================
print("\n" + "=" * 70)
print("8. ReadWritePartition READ 路径 — 仔细看错误处理")
print("=" * 70)
for off in range(0x18248, 0x18360, 4):
    inst = r32(off)
    d = decode(off, inst)
    if off == 0x18294:
        d += "  ← GUID 0x69BE0 (协议定位)"
    if off == 0x182A4:
        d += "  ← LocatePartition(GUID)"
    if off == 0x182EC:
        d += "  ← 实际读写操作"
    print(d)

# ============================================================
# 9. 检查：init_defaults 的 WRITE 失败后会发生什么？
# ============================================================
print("\n" + "=" * 70)
print("9. init_defaults — WRITE 后的错误处理")
print("=" * 70)
for off in range(0x385B4, 0x38610, 4):
    inst = r32(off)
    d = decode(off, inst)
    if off == 0x385C4:
        d += "  ← ReadWritePartition(WRITE)"
    if off == 0x385CC:
        d += "  ← WRITE 失败检查"
    print(d)

# ============================================================
# 10. 关键：检查 OemCheckResetDevInfo 中 0x29FE8 的参数
# ============================================================
print("\n" + "=" * 70)
print("10. OemCheckResetDevInfo 中调用 0x29FE8 前的参数设置")
print("=" * 70)
for off in range(0x3635C, 0x36380, 4):
    print(decode(off, r32(off)))
print("  ↓")
print("  0x29FE8 被调用，x0=x21(=x23-0x10), x1=指向某数据结构")
print("  结果写入 [x23-16]，之后被读取为 w8 并与 1 比较")

# ============================================================
# 11. 检查 param 分区结构
# ============================================================
print("\n" + "=" * 70)
print("11. param 分区可能影响 OemCheckResetDevInfo 行为")
print("=" * 70)
import os
param_path = '/Users/xmxx/pinganhuijia/edl_backup/param.bin'
if os.path.exists(param_path):
    param = open(param_path, 'rb').read()
    print(f"  param.bin 大小: {len(param)} bytes")
    # 检查前64字节
    print(f"  前64字节: {param[:64].hex()}")
    # 检查是否有 magic
    print(f"  ASCII: {param[:64]}")
else:
    print(f"  {param_path} 不存在")

print("\nDone.")
