#!/usr/bin/env python3
"""
fix_gpt_crc.py - 从备份恢复完整的 GPT 表（含正确的 CRC32）

问题: fix_slot_a.py 修改了 LUN4 的 GPT entries 但没有更新 header 中的
CRC32 校验和。导致 XBL 认为 GPT 损坏，直接进入 EDL。

修复: 从原始备份文件恢复 GPT（备份时 slot_a 就是 active 的，CRC32 正确）。
对于备份 GPT，需要从主 GPT header 构建一个正确的备份 GPT header。
"""

import struct
import subprocess
import sys
import os
import zlib

EDL = "edl"
DEVICE_MODEL = "20888"
BACKUP_DIR = "/Users/xmxx/pinganhuijia/edl_backup"
TMP = "/Users/xmxx/pinganhuijia/tmp"
SECTOR_SIZE = 4096


def run_edl(*args, check=True):
    cmd = [EDL] + list(args) + [f"--devicemodel={DEVICE_MODEL}"]
    print(f"[gpt] run: {' '.join(cmd)}")
    result = subprocess.run(cmd)
    if check and result.returncode != 0:
        print(f"[gpt] ERROR: exit={result.returncode}")
        sys.exit(1)
    return result


def crc32(data):
    """计算 CRC32 (与 GPT 规范一致)"""
    return zlib.crc32(data) & 0xFFFFFFFF


def parse_gpt_header(data):
    """解析 GPT header 的关键字段"""
    sig = data[:8]
    if sig != b"EFI PART":
        return None
    return {
        "signature": sig,
        "revision": struct.unpack_from("<I", data, 8)[0],
        "header_size": struct.unpack_from("<I", data, 12)[0],
        "header_crc32": struct.unpack_from("<I", data, 16)[0],
        "reserved": struct.unpack_from("<I", data, 20)[0],
        "my_lba": struct.unpack_from("<Q", data, 24)[0],
        "alternate_lba": struct.unpack_from("<Q", data, 32)[0],
        "first_usable_lba": struct.unpack_from("<Q", data, 40)[0],
        "last_usable_lba": struct.unpack_from("<Q", data, 48)[0],
        "disk_guid": data[56:72],
        "partition_entry_lba": struct.unpack_from("<Q", data, 72)[0],
        "num_partition_entries": struct.unpack_from("<I", data, 80)[0],
        "partition_entry_size": struct.unpack_from("<I", data, 84)[0],
        "partition_entry_crc32": struct.unpack_from("<I", data, 88)[0],
    }


def build_backup_gpt_header(primary_header_data, backup_header_lba, backup_entry_start_lba):
    """
    从主 GPT header 数据构建备份 GPT header。
    备份 header 的 my_lba 和 alternate_lba 互换，
    partition_entry_lba 指向备份 entries 位置。
    """
    hdr = bytearray(primary_header_data[:SECTOR_SIZE])

    ph = parse_gpt_header(primary_header_data)
    if ph is None:
        print("[gpt] ERROR: 无效的主 GPT header!")
        sys.exit(1)

    header_size = ph["header_size"]

    # 交换 my_lba 和 alternate_lba
    struct.pack_into("<Q", hdr, 24, backup_header_lba)      # my_lba = 备份 header 位置
    struct.pack_into("<Q", hdr, 32, ph["my_lba"])            # alternate_lba = 主 header 位置
    # 更新 partition_entry_lba 指向备份 entries
    struct.pack_into("<Q", hdr, 72, backup_entry_start_lba)

    # partition_entry_crc32 保持不变（entries 数据相同）

    # 重新计算 header CRC32
    struct.pack_into("<I", hdr, 16, 0)  # 先清零 header CRC32
    new_crc = crc32(bytes(hdr[:header_size]))
    struct.pack_into("<I", hdr, 16, new_crc)

    return bytes(hdr)


def restore_lun_gpt(lun, total_sectors=None):
    """恢复指定 LUN 的完整 GPT（主 + 备份）"""
    main_file = os.path.join(BACKUP_DIR, f"lun{lun}", f"gpt_main{lun}.bin")
    backup_file = os.path.join(BACKUP_DIR, f"lun{lun}", f"gpt_backup{lun}.bin")

    if not os.path.exists(main_file):
        print(f"[gpt] 跳过 LUN{lun}: 无备份 GPT 文件")
        return

    print(f"\n{'='*50}")
    print(f"  恢复 LUN{lun} GPT")
    print(f"{'='*50}")

    # 读取并验证主 GPT
    with open(main_file, "rb") as f:
        main_data = f.read()
    main_sectors = len(main_data) // SECTOR_SIZE
    print(f"[gpt] gpt_main{lun}.bin: {len(main_data)} bytes = {main_sectors} sectors")

    # 主 GPT: sector 0 = MBR, sector 1 = header, sector 2+ = entries
    primary_header = main_data[SECTOR_SIZE : 2*SECTOR_SIZE]
    ph = parse_gpt_header(primary_header)
    if ph is None:
        print(f"[gpt] ERROR: LUN{lun} 备份主 GPT header 无效!")
        return

    print(f"[gpt] 主 GPT header: my_lba={ph['my_lba']}, alternate_lba={ph['alternate_lba']}")
    print(f"[gpt]   entries_lba={ph['partition_entry_lba']}, count={ph['num_partition_entries']}, size={ph['partition_entry_size']}")
    print(f"[gpt]   entries_crc32=0x{ph['partition_entry_crc32']:08x}")

    # 验证 entries CRC32
    entries_start_off = 2 * SECTOR_SIZE  # entries start at sector 2 in the file
    entries_size = ph["num_partition_entries"] * ph["partition_entry_size"]
    entries_data = main_data[entries_start_off : entries_start_off + entries_size]
    calc_entries_crc = crc32(entries_data)
    print(f"[gpt]   entries_crc32 验证: 计算=0x{calc_entries_crc:08x}, 头部=0x{ph['partition_entry_crc32']:08x} {'✓' if calc_entries_crc == ph['partition_entry_crc32'] else '✗ 不匹配!'}")

    # 验证 header CRC32
    hdr_for_crc = bytearray(primary_header[:ph["header_size"]])
    struct.pack_into("<I", hdr_for_crc, 16, 0)  # 清零 CRC 字段
    calc_header_crc = crc32(bytes(hdr_for_crc))
    print(f"[gpt]   header_crc32 验证: 计算=0x{calc_header_crc:08x}, 头部=0x{ph['header_crc32']:08x} {'✓' if calc_header_crc == ph['header_crc32'] else '✗ 不匹配!'}")

    # 打印 slot 状态（简要）
    for i in range(ph["num_partition_entries"]):
        off = i * ph["partition_entry_size"]
        if off + ph["partition_entry_size"] > len(entries_data):
            break
        name_raw = entries_data[off+56:off+56+72]
        name = name_raw.decode("utf-16-le").rstrip("\x00")
        if not name:
            continue
        if name.startswith("boot_") or name.startswith("abl_"):
            flags = struct.unpack_from("<Q", entries_data, off+48)[0]
            flag_byte = (flags >> 48) & 0xFF
            active = "ACTIVE" if (flag_byte & 0x04) else "inactive"
            print(f"[gpt]   {name:20s} flags=0x{flags:016x} byte6=0x{flag_byte:02x} {active}")

    # Step 1: 写入主 GPT (sector 0 开始)
    print(f"\n[gpt] 写入主 GPT 到 LUN{lun} sector 0 ({main_sectors} sectors)...")
    run_edl("ws", "0", main_file, f"--lun={lun}", "--memory=ufs")

    # Step 2: 写入备份 GPT
    if total_sectors is None:
        # 从主 GPT header 获取 alternate_lba（备份 header 位置）
        total_sectors = ph["alternate_lba"] + 1
        print(f"[gpt] LUN{lun} 总 sectors（从 GPT 推算）: {total_sectors}")

    backup_header_lba = total_sectors - 1
    entry_sectors_count = (entries_size + SECTOR_SIZE - 1) // SECTOR_SIZE
    backup_entry_start_lba = backup_header_lba - entry_sectors_count

    if os.path.exists(backup_file):
        with open(backup_file, "rb") as f:
            backup_entries_data = f.read()
        backup_entry_sectors = len(backup_entries_data) // SECTOR_SIZE
        print(f"[gpt] gpt_backup{lun}.bin: {len(backup_entries_data)} bytes = {backup_entry_sectors} sectors")

        # 写入备份 entries
        print(f"[gpt] 写入备份 GPT entries 到 sector {backup_entry_start_lba}...")
        run_edl("ws", str(backup_entry_start_lba), backup_file, f"--lun={lun}", "--memory=ufs")
    else:
        # 没有备份 entries 文件，用主 GPT entries 代替
        print(f"[gpt] 无 gpt_backup{lun}.bin, 用主 GPT entries 构建...")
        entries_file = os.path.join(TMP, f"backup_entries_lun{lun}.bin")
        with open(entries_file, "wb") as f:
            f.write(main_data[entries_start_off : entries_start_off + entry_sectors_count * SECTOR_SIZE])
        print(f"[gpt] 写入备份 GPT entries 到 sector {backup_entry_start_lba}...")
        run_edl("ws", str(backup_entry_start_lba), entries_file, f"--lun={lun}", "--memory=ufs")

    # Step 3: 构建并写入备份 GPT header
    print(f"[gpt] 构建备份 GPT header (sector {backup_header_lba})...")
    backup_header = build_backup_gpt_header(primary_header, backup_header_lba, backup_entry_start_lba)

    # 验证构建的备份 header
    bh = parse_gpt_header(backup_header)
    print(f"[gpt]   backup header: my_lba={bh['my_lba']}, alternate_lba={bh['alternate_lba']}")
    print(f"[gpt]   entries_lba={bh['partition_entry_lba']}, crc32=0x{bh['header_crc32']:08x}")

    backup_header_file = os.path.join(TMP, f"backup_header_lun{lun}.bin")
    with open(backup_header_file, "wb") as f:
        f.write(backup_header)

    print(f"[gpt] 写入备份 GPT header 到 sector {backup_header_lba}...")
    run_edl("ws", str(backup_header_lba), backup_header_file, f"--lun={lun}", "--memory=ufs")

    print(f"[gpt] LUN{lun} GPT 恢复完成 ✓")


def main():
    print("=" * 60)
    print("  GPT CRC32 修复 - 从备份恢复完整 GPT 表")
    print("=" * 60)
    print()
    print("  问题: fix_slot_a.py 修改了 entries 但没更新 CRC32")
    print("  修复: 从原始备份恢复 GPT（slot_a 本来就是 active）")
    print()

    # 恢复所有 LUN 的 GPT
    # LUN4 是最关键的（包含 boot/abl/tz 等分区），total_sectors = 0x100000
    # LUN0, LUN1, LUN2 也需要恢复
    lun_sizes = {
        0: None,   # 从 GPT header 推算
        1: 0x800,   # LUN1: 2048 sectors (从 printgpt 输出)
        2: 0x800,   # LUN2: 2048 sectors
        4: 0x100000, # LUN4: 1048576 sectors
    }

    for lun in [4, 1, 2, 0]:
        restore_lun_gpt(lun, total_sectors=lun_sizes.get(lun))

    # 清除 misc
    print(f"\n{'='*50}")
    print("[gpt] 清除 misc 分区 BCB...")
    run_edl("e", "misc", "--memory=ufs")

    # 验证
    print(f"\n{'='*50}")
    print("[gpt] 验证 active slot...")
    run_edl("getactiveslot", "--memory=ufs")

    print()
    print("[gpt] GPT 修复完成! 准备重启...")
    print("[gpt] 输入 'yes' 重启设备:")
    ans = input().strip().lower()
    if ans == "yes":
        run_edl("reset")
        print("[gpt] 设备正在重启...")
    else:
        print("[gpt] 取消重启. 请手动运行: edl reset --devicemodel=20888")


if __name__ == "__main__":
    main()
