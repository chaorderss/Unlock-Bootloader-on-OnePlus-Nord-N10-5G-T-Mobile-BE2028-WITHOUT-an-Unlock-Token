#!/usr/bin/env python3
"""
关键调查: ReadDeviceInfo 失败后的启动流程
如果 ReadDeviceInfo 返回错误, 启动是否继续到 FastbootInit?
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
    if inst == 0x00000000: return s + "  (nop/padding)"
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
    if (inst & 0xFFC00000) == 0xB9400000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = ((inst >> 10) & 0xFFF) * 4
        return s + f"  LDR w{rt}, [x{rn}, #{imm}]"
    if (inst & 0xFFC00000) == 0x39400000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = (inst >> 10) & 0xFFF
        return s + f"  LDRB w{rt}, [x{rn}, #{imm}]"
    if (inst & 0xFFC00000) == 0x39000000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = (inst >> 10) & 0xFFF
        return s + f"  STRB w{rt}, [x{rn}, #{imm}]"
    if (inst & 0xFF800000) == 0x52800000:
        rd = inst & 0x1F; imm16 = (inst >> 5) & 0xFFFF; hw = (inst >> 21) & 0x3
        return s + f"  MOV w{rd}, #0x{imm16 << (hw*16):X}"
    if (inst & 0xFF800000) == 0xD2800000:
        rd = inst & 0x1F; imm16 = (inst >> 5) & 0xFFFF; hw = (inst >> 21) & 0x3
        return s + f"  MOV x{rd}, #0x{imm16 << (hw*16):X}"
    if (inst & 0xFF800000) == 0x71000000:
        rn = (inst >> 5) & 0x1F; imm12 = (inst >> 10) & 0xFFF
        return s + f"  CMP w{rn}, #{imm12}"
    if (inst & 0xFF800000) == 0xF1000000:
        rn = (inst >> 5) & 0x1F; imm12 = (inst >> 10) & 0xFFF
        return s + f"  CMP x{rn}, #{imm12}"
    if (inst & 0xFF80001F) == 0x7200001F:
        rn = (inst >> 5) & 0x1F
        return s + f"  TST w{rn}, #bitmask"
    if (inst & 0xFFC00000) == 0xF9000000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = ((inst >> 10) & 0xFFF) * 8
        return s + f"  STR x{rt}, [x{rn}, #{imm}]"
    if (inst & 0xFFE0001F) in [0x2A0003E0, 0xAA0003E0]:
        sf = (inst >> 31) & 1; rd = inst & 0x1F; rm = (inst >> 16) & 0x1F
        p = 'x' if sf else 'w'
        return s + f"  MOV {p}{rd}, {p}{rm}"
    # MOV from zero register
    if (inst & 0xFF3FFC1F) == 0xAA1F03E0:
        sf = (inst >> 31) & 1
        rd = inst & 0x1F
        p = 'x' if sf else 'w'
        return s + f"  MOV {p}{rd}, {p}zr"
    return s

# ============================================================
# 1. 启动函数 0x01500-0x01640 完整反汇编
# ============================================================
print("=" * 70)
print("1. 启动函数 0x01500-0x01640 完整反汇编")
print("=" * 70)
for off in range(0x01500, 0x01640, 4):
    inst = r32(off)
    d = decode(off, inst)
    if off == 0x01558: d += "  ★ ReadDeviceInfo"
    if off == 0x0155C: d += "  ★ 成功检查"
    if off == 0x01614: d += "  ★ ReadDeviceInfo 成功后继续"
    if off == 0x01620: d += "  ★ 主启动函数"
    print(d)

# ============================================================
# 2. ReadDeviceInfo 失败路径详细分析
# ============================================================
print("\n" + "=" * 70)
print("2. ReadDeviceInfo 错误路径 0x23300-0x23398")
print("=" * 70)

# 失败路径: ReadWritePartition 返回非零
# 0x23300: CBZ x0, 0x2333C  ← 成功跳过
# 0x23304: MOV x19, x0       ← 保存错误码
# ...
# 0x23338: B 0x23398          ← 跳到返回
# 返回: x0 = x19 (错误码)

# 成功但魔数不匹配路径:
# 0x2335C: CBZ x0, 0x23394  ← 匹配跳过
# 0x2338C: MOV w0, wzr       ← w0=0
# 0x23390: BL init_defaults
# 0x23394: MOV x19, xzr      ← 返回成功!

print("  ReadWritePartition READ 失败:")
print("  → x19 = error_code (非零)")
print("  → B 0x23398: 返回 error_code")
print()
print("  ReadWritePartition READ 成功但魔数不匹配:")
print("  → init_defaults 运行")
print("  → x19 = 0 (强制返回成功)")
print()
print("  结论: init_defaults 只在 READ 成功但魔数不匹配时触发")
print("  如果 READ 失败, ReadDeviceInfo 返回错误, 不调用 init_defaults")

# ============================================================
# 3. 检查 param.bin 中 reset_devinfo 的原始值
# ============================================================
print("\n" + "=" * 70)
print("3. param.bin 中 reset_devinfo 原始值")
print("=" * 70)
param = open("/Users/xmxx/pinganhuijia/edl_backup/param.bin", "rb").read()
v31a0 = struct.unpack_from('<I', param, 0x31A0)[0]
print(f"  param.bin[0x31A0] = 0x{v31a0:08X} (32位小端) = {v31a0}")
print(f"  param.bin[0x31A0] byte = 0x{param[0x31A0]:02X}")
print()
print(f"  OemCheckResetDevInfo:")
print(f"    CMP w8, #1")
print(f"    B.NE 0x365C4  ← if {v31a0} != 1, SKIP init_defaults")
print(f"    → reset_devinfo = {v31a0} ≠ 1 → ★★★ OemCheckResetDevInfo 不触发 init_defaults!")
print()

# ============================================================
# 4. 验证: ReadDeviceInfo 中 ReadWritePartition 是否读取成功
# ============================================================
print("=" * 70)
print("4. 分析: 为什么 ReadWritePartition 可能读不到正确数据?")
print("=" * 70)

# ReadWritePartition 使用的协议 GUID
guid_off = 0x69BE0
d1 = struct.unpack_from('<I', pe, guid_off)[0]
d2 = struct.unpack_from('<H', pe, guid_off+4)[0]
d3 = struct.unpack_from('<H', pe, guid_off+6)[0]
d4 = pe[guid_off+8:guid_off+16]
guid = f"{d1:08X}-{d2:04X}-{d3:04X}-{d4[0]:02X}{d4[1]:02X}-{d4[2]:02X}{d4[3]:02X}{d4[4]:02X}{d4[5]:02X}{d4[6]:02X}{d4[7]:02X}"
print(f"  ReadWritePartition 协议 GUID: {guid}")
print(f"  这个 GUID 对应的协议需要在 ReadDeviceInfo 调用前被注册")
print()

# 检查 0x1B990 (pre-init) 是否注册了这个协议
print("  pre-init 函数 0x1B990 (在 ReadDeviceInfo 前调用):")
for off in range(0x1B990, 0x1BA00, 4):
    print(decode(off, r32(off)))

print()

# ============================================================
# 5. 检查: 有多少个函数在 ReadDeviceInfo 之前注册协议?
# ============================================================
print("=" * 70)
print("5. 搜索协议 GUID 8E5EFF91 的引用位置")
print("=" * 70)
# Search for ADRP to 0x69000 followed by ADD #0xBE0
count = 0
for off in range(0x1000, 0x6A000, 4):
    inst = r32(off)
    if (inst & 0x9F000000) == 0x90000000:
        rd = inst & 0x1F
        immhi = (inst >> 5) & 0x7FFFF; immlo = (inst >> 29) & 0x3
        iv = (immhi << 2) | immlo
        if iv & 0x100000: iv |= ~0x1FFFFF
        pg = ((off & ~0xFFF) + (iv << 12)) & 0xFFFFFFFF
        if pg == 0x69000:
            for off2 in range(off+4, min(off+20, 0x6A000), 4):
                inst2 = r32(off2)
                if (inst2 & 0xFF800000) == 0x91000000:
                    rn2 = (inst2 >> 5) & 0x1F
                    if rn2 == rd:
                        imm12 = (inst2 >> 10) & 0xFFF
                        if imm12 == 0xBE0:
                            count += 1
                            # Find enclosing function
                            print(f"  0x{off:05X}: ADRP+ADD → GUID 0x69BE0 (ReadWritePartition)")

print(f"  总共 {count} 处引用")

# ============================================================
# 6. 实验的正确解释
# ============================================================
print("\n" + "=" * 70)
print("6. 实验的正确解释")
print("=" * 70)
print("""
  ★ param reset_devinfo = 2 (不是 1)
  ★ OemCheckResetDevInfo 中 CMP w8, #1 → 2 ≠ 1 → 跳过 init_defaults
  ★ 因此 init_defaults 是由 ReadDeviceInfo 的魔数检查失败触发的

  这意味着:
  1. ReadWritePartition READ 返回了成功 (x0=0)，但数据不正确
     → 数据中没有 "ANDROID-BOOT!" → CompareMem 失败 → init_defaults
  2. 或者: ReadWritePartition READ 返回了错误
     → ReadDeviceInfo 返回错误 → 启动继续（错误被忽略）
     → 但缓冲区全零 → init_defaults 不从这里触发
     → 但 fastboot 显示 charger=true，说明 init_defaults 确实运行了!

  结论: 最可能是情况 1:
  ReadWritePartition 读取成功，但返回的数据不是我们用 EDL 写入的数据。
  协议可能从不同的物理位置读取 devinfo。

  关键问题: 协议是从哪里读取 devinfo 的?
  → 可能不是通过 GPT 查找，而是通过内部映射
  → 需要追踪协议注册和数据源
""")

# ============================================================
# 7. ReadDeviceInfo 错误路径 — 完整启动流程
# ============================================================
print("=" * 70)
print("7. 如果 ReadDeviceInfo 返回错误, 启动能否继续?")
print("=" * 70)
# Check bytes between 0x01560 and 0x01614
for off in range(0x01560, 0x01620, 4):
    inst = r32(off)
    d = decode(off, inst)
    if off == 0x01560:
        d += "  ← ReadDeviceInfo 失败后到这里"
    if off == 0x01614:
        d += "  ← ReadDeviceInfo 成功后继续"
    if off == 0x01620:
        d += "  ← 主启动函数 (0x367F0)"
    print(d)

# 提取错误路径中的字符串引用
print("\n  错误路径中的字符串引用:")
for off in range(0x01560, 0x01614, 4):
    inst = r32(off)
    if (inst & 0x9F000000) == 0x90000000:
        rd = inst & 0x1F
        immhi = (inst >> 5) & 0x7FFFF; immlo = (inst >> 29) & 0x3
        iv = (immhi << 2) | immlo
        if iv & 0x100000: iv |= ~0x1FFFFF
        pg = ((off & ~0xFFF) + (iv << 12)) & 0xFFFFFFFF
        for off2 in range(off+4, min(off+16, 0x01614), 4):
            inst2 = r32(off2)
            if (inst2 & 0xFF800000) == 0x91000000:
                rd2 = inst2 & 0x1F; rn2 = (inst2 >> 5) & 0x1F
                if rn2 == rd:
                    imm12 = (inst2 >> 10) & 0xFFF
                    addr = pg + imm12
                    if 0x50000 <= addr < 0x6A000:
                        # Read string
                        s = b""
                        for i in range(200):
                            if addr + i >= len(pe): break
                            b = pe[addr + i]
                            if b == 0: break
                            s += bytes([b])
                        try:
                            print(f"    0x{off:05X} -> 0x{addr:05X}: \"{s.decode('ascii')}\"")
                        except:
                            pass

print("\nDone.")
