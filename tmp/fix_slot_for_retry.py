#!/usr/bin/env python3
"""
fix_slot_for_retry.py - Fix slot_a retry count and clear misc for fresh UBports attempt
"""
import struct, subprocess, sys, os, zlib

EDL = "edl"
DEVICE_MODEL = "20888"
TMP = "/Users/xmxx/pinganhuijia/tmp"
SECTOR_SIZE = 4096
TOTAL_SECTORS_LUN4 = 0x100000

def run_edl(*args):
    cmd = [EDL] + list(args) + [f"--devicemodel={DEVICE_MODEL}"]
    print(f"[fix] {' '.join(cmd)}")
    r = subprocess.run(cmd)
    if r.returncode != 0:
        print(f"[fix] ERROR exit={r.returncode}")
        sys.exit(1)

def crc32(data):
    return zlib.crc32(data) & 0xFFFFFFFF

def patch_and_write_gpt():
    # Read primary GPT header (sector 1) and entries (sector 2, 3 sectors)
    hdr_file = os.path.join(TMP, "retry_hdr.bin")
    ent_file = os.path.join(TMP, "retry_ent.bin")
    run_edl("rs", "1", "1", hdr_file, "--lun=4", "--memory=ufs")
    run_edl("rs", "2", "3", ent_file, "--lun=4", "--memory=ufs")

    with open(hdr_file, "rb") as f: hdr = bytearray(f.read())
    with open(ent_file, "rb") as f: ent = bytearray(f.read())

    if hdr[:8] != b"EFI PART":
        print("[fix] ERROR: invalid GPT header")
        sys.exit(1)

    header_size = struct.unpack_from("<I", hdr, 12)[0]
    num_entries = struct.unpack_from("<I", hdr, 80)[0]
    entry_size  = struct.unpack_from("<I", hdr, 84)[0]

    # Patch boot_a flags → 0x007f (retry=7, successful=1, active=1, priority=3)
    # Patch boot_b flags → 0x003a (retry=3, successful=0, inactive)
    for i in range(num_entries):
        off = i * entry_size
        if off + entry_size > len(ent): break
        name = ent[off+56:off+56+72].decode("utf-16-le").rstrip("\x00")
        if name == "boot_a":
            new_flags = 0x007f << 48
            struct.pack_into("<Q", ent, off+48, new_flags)
            print(f"[fix] boot_a flags reset to 0x007f (retry=7, active, successful)")
        elif name == "boot_b":
            new_flags = 0x003a << 48
            struct.pack_into("<Q", ent, off+48, new_flags)
            print(f"[fix] boot_b flags reset to 0x003a (inactive)")
        elif name.endswith("_a") and name != "boot_a":
            # Ensure all _a partitions have active flag
            flags = struct.unpack_from("<Q", ent, off+48)[0]
            byte6 = (flags >> 48) & 0xFF
            if not (byte6 & 0x04):
                new_flags = flags | (0x04 << 48)
                struct.pack_into("<Q", ent, off+48, new_flags)

    # Recalculate entries CRC32
    entries_size = num_entries * entry_size
    entries_crc = crc32(bytes(ent[:entries_size]))
    struct.pack_into("<I", hdr, 88, entries_crc)
    struct.pack_into("<I", hdr, 16, 0)
    hdr_crc = crc32(bytes(hdr[:header_size]))
    struct.pack_into("<I", hdr, 16, hdr_crc)
    print(f"[fix] Primary GPT CRC: 0x{hdr_crc:08x}")

    # Write primary entries + header
    with open(ent_file, "wb") as f: f.write(ent)
    run_edl("ws", "2", ent_file, "--lun=4", "--memory=ufs")
    with open(hdr_file, "wb") as f: f.write(hdr)
    run_edl("ws", "1", hdr_file, "--lun=4", "--memory=ufs")

    # Build and write backup GPT
    entry_sectors = 3
    bkup_ent_start = TOTAL_SECTORS_LUN4 - 1 - entry_sectors
    bkup_hdr_lba   = TOTAL_SECTORS_LUN4 - 1

    bkup_hdr = bytearray(hdr)
    struct.pack_into("<Q", bkup_hdr, 24, bkup_hdr_lba)
    struct.pack_into("<Q", bkup_hdr, 32, 1)
    struct.pack_into("<Q", bkup_hdr, 72, bkup_ent_start)
    struct.pack_into("<I", bkup_hdr, 88, entries_crc)
    struct.pack_into("<I", bkup_hdr, 16, 0)
    bkup_crc = crc32(bytes(bkup_hdr[:header_size]))
    struct.pack_into("<I", bkup_hdr, 16, bkup_crc)
    print(f"[fix] Backup GPT CRC: 0x{bkup_crc:08x}")

    bkup_ent_file = os.path.join(TMP, "retry_bkup_ent.bin")
    bkup_hdr_file = os.path.join(TMP, "retry_bkup_hdr.bin")
    with open(bkup_ent_file, "wb") as f: f.write(ent)
    with open(bkup_hdr_file, "wb") as f: f.write(bkup_hdr)
    run_edl("ws", str(bkup_ent_start), bkup_ent_file, "--lun=4", "--memory=ufs")
    run_edl("ws", str(bkup_hdr_lba), bkup_hdr_file, "--lun=4", "--memory=ufs")
    print("[fix] GPT written ✓")


def main():
    print("="*55)
    print("  修复 slot_a retry count，准备重新安装 Ubuntu Touch")
    print("="*55)

    # 1. Fix GPT slot metadata
    print("\n[1] 修复 boot_a/boot_b 标志位 + CRC32...")
    patch_and_write_gpt()

    # 2. Clear misc BCB
    print("\n[2] 清除 misc BCB...")
    run_edl("e", "misc", "--memory=ufs")

    # 3. Verify
    print("\n[3] 验证 active slot...")
    run_edl("getactiveslot", "--memory=ufs")

    # 4. Reboot to fastboot
    print("\n[4] 重启到 fastboot 模式...")
    print("    注意: 设备重启后会进 fastboot 界面")
    print("    然后重新打开 UBports Installer 进行安装")
    input("    按 ENTER 确认重启...")
    run_edl("reset")
    print("[fix] Done.")


if __name__ == "__main__":
    main()
