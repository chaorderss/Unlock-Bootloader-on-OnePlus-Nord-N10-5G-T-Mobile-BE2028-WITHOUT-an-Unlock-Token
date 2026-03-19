#!/usr/bin/env python3
"""追踪 ReadWritePartition 协议注册和 devinfo 位置"""
import struct, os

PE = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
with open(PE, "rb") as f:
    pe = f.read()

def r32(off):
    return struct.unpack_from('<I', pe, off)[0]

def read_str(offset, maxlen=200):
    s = b""
    for i in range(maxlen):
        if offset + i >= len(pe): break
        b = pe[offset + i]
        if b == 0: break
        s += bytes([b])
    try: return s.decode('ascii')
    except: return ""

# 1. 协议注册点 0x027CC 的函数上下文
print("=" * 70)
print("1. 0x027CC 附近代码 (协议 GUID 引用)")
print("=" * 70)
for off in range(0x02700, 0x02880, 4):
    inst = r32(off)
    s = f"  0x{off:05X}: 0x{inst:08X}"
    if (inst >> 26) == 0x25:
        imm = inst & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        t = (off + (imm << 2)) & 0xFFFFFFFF
        s += f"  BL 0x{t:05X}"
    elif (inst & 0x9F000000) == 0x90000000:
        rd = inst & 0x1F
        immhi = (inst >> 5) & 0x7FFFF; immlo = (inst >> 29) & 0x3
        iv = (immhi << 2) | immlo
        if iv & 0x100000: iv |= ~0x1FFFFF
        pg = ((off & ~0xFFF) + (iv << 12)) & 0xFFFFFFFF
        s += f"  ADRP x{rd}, 0x{pg:X}"
    elif (inst & 0xFF800000) == 0x91000000:
        rd = inst & 0x1F; rn = (inst >> 5) & 0x1F
        imm12 = (inst >> 10) & 0xFFF
        s += f"  ADD x{rd}, x{rn}, #0x{imm12:X}"
    elif (inst & 0xFFFFFC1F) == 0xD63F0000:
        rn = (inst >> 5) & 0x1F
        s += f"  BLR x{rn}"
    elif (inst & 0xFFC00000) == 0xF9400000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = ((inst >> 10) & 0xFFF) * 8
        s += f"  LDR x{rt}, [x{rn}, #{imm}]"
    elif (inst & 0xFFC00000) == 0xF9000000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = ((inst >> 10) & 0xFFF) * 8
        s += f"  STR x{rt}, [x{rn}, #{imm}]"
    elif inst == 0xD65F03C0:
        s += "  RET"
    if off == 0x027CC: s += "  ★"
    print(s)
    if inst == 0xD65F03C0 and off > 0x027D0:
        break

# 2. 搜索 devinfo 分区名
print("\n" + "=" * 70)
print("2. 搜索 'devinfo' 字符串")
print("=" * 70)
for needle in [b"devinfo", b"DevInfo", b"DEVINFO"]:
    pos = 0
    while True:
        idx = pe.find(needle, pos)
        if idx == -1: break
        s = read_str(max(0,idx-20))
        sec = ".text" if idx < 0x6A000 else ".data"
        print(f"  0x{idx:06X} [{sec}]: \"{s}\"")
        pos = idx + 7

# UCS-2
for name in ["devinfo", "DevInfo"]:
    needle = name.encode('utf-16-le')
    pos = 0
    while True:
        idx = pe.find(needle, pos)
        if idx == -1: break
        # read surrounding UCS-2
        start = idx
        while start >= 2 and pe[start-1] == 0 and 0x20 <= pe[start-2] < 0x7F:
            start -= 2
        end = idx + len(needle)
        while end+1 < len(pe) and pe[end+1] == 0 and 0x20 <= pe[end] < 0x7F:
            end += 2
        s = pe[start:end+2].decode('utf-16-le', errors='replace')
        print(f"  0x{idx:06X} [UCS2]: \"{s}\"")
        pos = idx + len(needle)

# 3. 协议 GUID 在 PE 中的位置
print("\n" + "=" * 70)
print("3. 协议 GUID 位置")
print("=" * 70)
proto_guid = bytes([0x91, 0xFF, 0x5E, 0x8E, 0xB6, 0x21, 0xD3, 0x47,
                    0xAF, 0x2B, 0xC1, 0x5A, 0x01, 0xE0, 0x20, 0xEC])
idx = 0
while True:
    idx = pe.find(proto_guid, idx)
    if idx == -1: break
    print(f"  协议 GUID 0x{idx:06X}")
    idx += 16

# 4. 检查 0x18A5C (第3个 GUID 引用)
print("\n" + "=" * 70)
print("4. 第3个 GUID 引用 0x18A5C 附近")
print("=" * 70)
for off in range(0x18A00, 0x18B80, 4):
    inst = r32(off)
    s = f"  0x{off:05X}: 0x{inst:08X}"
    if (inst >> 26) == 0x25:
        imm = inst & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        t = (off + (imm << 2)) & 0xFFFFFFFF
        s += f"  BL 0x{t:05X}"
    elif (inst & 0x9F000000) == 0x90000000:
        rd = inst & 0x1F
        immhi = (inst >> 5) & 0x7FFFF; immlo = (inst >> 29) & 0x3
        iv = (immhi << 2) | immlo
        if iv & 0x100000: iv |= ~0x1FFFFF
        pg = ((off & ~0xFFF) + (iv << 12)) & 0xFFFFFFFF
        s += f"  ADRP x{rd}, 0x{pg:X}"
    elif (inst & 0xFF800000) == 0x91000000:
        rd = inst & 0x1F; rn = (inst >> 5) & 0x1F
        imm12 = (inst >> 10) & 0xFFF
        s += f"  ADD x{rd}, x{rn}, #0x{imm12:X}"
    elif (inst & 0xFFFFFC1F) == 0xD63F0000:
        rn = (inst >> 5) & 0x1F
        s += f"  BLR x{rn}"
    elif (inst & 0xFFC00000) == 0xF9400000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = ((inst >> 10) & 0xFFF) * 8
        s += f"  LDR x{rt}, [x{rn}, #{imm}]"
    elif inst == 0xD65F03C0:
        s += "  RET"
    if off == 0x18A5C: s += "  ★ GUID ref"
    print(s)

# 5. 原始 devinfo 文件比较
print("\n" + "=" * 70)
print("5. 所有 devinfo 备份文件")
print("=" * 70)
for f in [
    "/Users/xmxx/pinganhuijia/edl_backup/lun4/devinfo.bin",
    "/Users/xmxx/pinganhuijia/edl_backup/devinfo.bin.original",
    "/Users/xmxx/pinganhuijia/edl_backup-tmo/devinfo.bin.original",
    "/Users/xmxx/pinganhuijia/edl_backup-tmo/devinfo.bin",
    "/Users/xmxx/pinganhuijia/edl_backup-tmo/devinfo_readback.bin",
]:
    if os.path.exists(f):
        d = open(f, 'rb').read()
        magic = d[:13]
        has_magic = magic == b"ANDROID-BOOT!"
        ul = d[0x0D] if len(d) > 0x0D else -1
        ch = d[0x0F] if len(d) > 0x0F else -1
        vr = d[0x90] if len(d) > 0x90 else -1
        nonzero = sum(1 for b in d if b != 0)
        print(f"  {os.path.basename(f):30s} size={len(d):5d} magic={'OK' if has_magic else 'NO':3s} unlock={ul} charger={ch} verity={vr} nonzero={nonzero}")

# 6. 搜索 "Unable to Read Device Info" 附近有没有分区名引用
print("\n" + "=" * 70)
print("6. ReadDeviceInfo 是如何指定读取 'devinfo' 分区的?")
print("=" * 70)
print("  ReadDeviceInfo 不指定分区名!")
print("  它调用 ReadWritePartition(mode=0, buffer, size)")
print("  ReadWritePartition 使用 LocateProtocol(GUID)")
print("  协议实现决定从哪里读取")
print()
print("  协议是由 0x027CC 处的代码注册的")
print("  协议的 readwrite 函数是一个函数指针 (vtable[1])")
print("  需要找到协议实例的创建代码来确定读取位置")

# 7. 检查 LUN0 上的 param.bin 与 LUN4 上的 param 是否不同
print("\n" + "=" * 70)
print("7. param.bin 比较 (LUN0 vs edl_backup)")
print("=" * 70)
p0 = "/Users/xmxx/pinganhuijia/edl_backup/lun0/param.bin"
p1 = "/Users/xmxx/pinganhuijia/edl_backup/param.bin"
if os.path.exists(p0) and os.path.exists(p1):
    d0 = open(p0, 'rb').read()
    d1 = open(p1, 'rb').read()
    if d0 == d1:
        print("  LUN0 param.bin == edl_backup param.bin (相同)")
    else:
        diff = sum(1 for a,b in zip(d0,d1) if a != b)
        print(f"  不同! {diff} 字节差异")

print("\nDone.")
