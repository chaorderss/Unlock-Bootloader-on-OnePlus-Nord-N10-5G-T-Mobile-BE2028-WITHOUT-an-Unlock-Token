#!/usr/bin/env python3
"""
静态分析 ABL 二进制，追踪 unlock state 读取路径。
目标：确认 ABL 是从 devinfo RPMB 还是其他地方读取解锁状态。
"""

import re
import struct
import sys
import lzma
import zlib

ABL_PATH = "edl_backup/abl_b.img"


def find_strings(data, min_len=6):
    """找出二进制中所有可打印ASCII字符串"""
    result = []
    pattern = rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}'
    for m in re.finditer(pattern, data):
        result.append((m.start(), m.group().decode('ascii', errors='replace')))
    return result


def try_decompress(data):
    """尝试各种解压方式提取内部 EFI payload"""
    results = []

    # 找 LZMA magic: 5D 00 00 + 4 字节字典大小 + 8 字节未压缩大小
    for i in range(len(data) - 13):
        if data[i] == 0x5d and data[i+1:i+3] == b'\x00\x00':
            try:
                dec = lzma.decompress(data[i:], format=lzma.FORMAT_ALONE)
                print(f"  LZMA decode success @ offset {hex(i)}, size {len(dec)} bytes")
                results.append((i, 'lzma', dec))
                break
            except Exception:
                pass

    # gzip
    for i in range(len(data) - 2):
        if data[i:i+2] == b'\x1f\x8b':
            try:
                import gzip, io
                dec = gzip.decompress(data[i:])
                print(f"  gzip decode success @ offset {hex(i)}, size {len(dec)} bytes")
                results.append((i, 'gzip', dec))
                break
            except Exception:
                pass

    return results


def search_unlock_refs(data, label=""):
    """搜索所有与 unlock、devinfo、RPMB 相关的字符串"""
    keywords = [
        b'devinfo',
        b'DEVINFO',
        b'ANDROID-BOOT',
        b'is_unlocked',
        b'unlock',
        b'Unlock',
        b'UNLOCK',
        b'oem_unlock',
        b'rpmb',
        b'RPMB',
        b'Rpmb',
        b'frp',
        b'FRP',
        b'devcfg',
        b'persist',
        b'CmdFlashComplete',
        b'CmdTokenFlash',
        b'op_token',
        b'unlock_token',
        b'token',
        b'Device unlocked',
        b'unlocked:',
        b'is_device_unlocked',
        b'DeviceIsUnlocked',
        b'CheckDevState',
        b'GetDevInfo',
        b'ReadDevInfo',
        b'WriteDevInfo',
        b'flash unlock token',
        b'Please flash',
        b'fastboot flashing unlock',
    ]

    print(f"\n{'='*60}")
    print(f"字符串搜索 [{label}]")
    print(f"{'='*60}")

    for kw in keywords:
        offset = 0
        while True:
            idx = data.find(kw, offset)
            if idx < 0:
                break
            # 打印周围上下文
            start = max(0, idx - 4)
            end = min(len(data), idx + len(kw) + 60)
            ctx = data[start:end]
            printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
            print(f"  +{hex(idx):>10}  {printable!r}")
            offset = idx + 1


def find_devinfo_struct_ops(data, label=""):
    """
    找所有引用 devinfo 数据结构偏移 0x10 (is_unlocked) 的二进制操作。
    在 ARM64 中，结构字段访问通常是 LDR/STR + immediate offset。
    offset 0x10 = 16 in decimal => 在 ARM64 中可能出现 0x10 作为 imm12
    """
    print(f"\n[ARM64 字节模式] is_unlocked @ struct+0x10 [{label}]")
    # ARM64 LDR byte: 0x39 4X XX XX - strb/ldrb w0, [x?, #0x10]
    # LDRB Wt, [Xn, #imm] = 0x39 | (imm12 << 10 | Rn << 5 | Rt)
    # imm12=0x10=16 => imm12 << 10 = 0x4000; for Rn=x0..x28
    # 39 40 00 39 for ldrb w0, [x0, #0]... need to compute properly

    # 搜 "ANDROID-BOOT!" 头部的偏移
    magic = b'ANDROID-BOOT!'
    idx = data.find(magic)
    if idx >= 0:
        print(f"  devinfo magic 'ANDROID-BOOT!' at: {hex(idx)}")

    # 找 devinfo 文件名字符串
    for s in [b'/dev/block/bootdevice/by-name/devinfo',
              b'devinfo',
              b'partition devinfo',
              b'GetDevInfo',
              b'ReadDevInfo']:
        idx = data.find(s)
        if idx >= 0:
            ctx = data[max(0,idx-8):idx+len(s)+64]
            print(f"  '{s.decode()}' at {hex(idx)}: {ctx!r}")


def check_integrity_verification(data, label=""):
    """搜索 CRC、hash、签名验证相关字符串，确认 devinfo 是否被校验"""
    print(f"\n[完整性校验迹象] [{label}]")
    integrity_kw = [
        b'crc',
        b'CRC',
        b'sha256',
        b'SHA256',
        b'hmac',
        b'HMAC',
        b'devinfo_crc',
        b'devinfo_magic',
        b'invalid devinfo',
        b'devinfo corrupt',
        b'devinfo invalid',
        b'Bad devinfo',
        b'devinfo check',
    ]
    for kw in integrity_kw:
        idx = data.find(kw)
        if idx >= 0:
            ctx = data[max(0,idx-16):idx+len(kw)+80]
            printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
            print(f"  '{kw.decode()!s}' at {hex(idx)}: {printable!r}")


def main():
    print(f"Loading {ABL_PATH}...")
    with open(ABL_PATH, 'rb') as f:
        raw = f.read()
    print(f"Raw size: {hex(len(raw))} ({len(raw)} bytes)")

    # 先搜原始 img
    search_unlock_refs(raw, "raw abl_b.img")
    find_devinfo_struct_ops(raw, "raw")
    check_integrity_verification(raw, "raw")

    # 尝试解压
    print("\n[尝试解压内部 payload]")
    decompressed = try_decompress(raw)

    for (off, fmt, dec) in decompressed:
        label = f"decompressed@{hex(off)} ({fmt})"
        search_unlock_refs(dec, label)
        find_devinfo_struct_ops(dec, label)
        check_integrity_verification(dec, label)
        # 保存
        out = f"edl_backup/abl_decompressed_{fmt}_{hex(off)}.bin"
        with open(out, 'wb') as f:
            f.write(dec)
        print(f"\n  Saved decompressed to: {out}")

    # 也分析 global_abl_raw.img
    print("\n\n" + "="*60)
    print("Loading global_abl_raw.img for comparison...")
    try:
        with open("global_abl_raw.img", 'rb') as f:
            global_raw = f.read()
        print(f"Global raw size: {hex(len(global_raw))}")
        search_unlock_refs(global_raw, "global_abl_raw.img")
        check_integrity_verification(global_raw, "global")
    except FileNotFoundError:
        print("global_abl_raw.img not found, skipping")


if __name__ == '__main__':
    main()
