#!/usr/bin/env python3
"""
switch_to_slot_b.py - 通过修改 GPT 将 active slot 切换到 B
这是一个诊断测试：确认是全局 rollback 问题还是 slot_a 特定问题
"""
import struct
import subprocess
import sys
import os
import zlib

EDL = "edl"
DEVICE_MODEL = "20888"
TMP = "/Users/xmxx/pinganhuijia/tmp"
SECTOR_SIZE = 4096
TOTAL_SECTORS_LUN4 = 0x100000  # 1048576

def run_edl(*args):
    cmd = [EDL] + list(args) + [f"--devicemodel={DEVICE_MODEL}"]
    print(f"[sw_b] run: {' '.join(cmd)}")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print(f"[sw_b] ERROR: exit={result.returncode}")
        sys.exit(1)

def crc32(data):
    return zlib.crc32(data) & 0xFFFFFFFF

def patch_gpt_entries_slot_b(entries_data, num_entries, entry_size):
    """Patch GPT entries: make slot_b ACTIVE, slot_a inactive"""
    patched = False
    for i in range(num_entries):
        off = i * entry_size
        if off + entry_size > len(entries_data):
            break
        name_raw = entries_data[off+56:off+56+72]
        name = name_raw.decode("utf-16-le").rstrip("\x00")
        if not name:
            continue

        if not (name.endswith("_a") or name.endswith("_b")):
            continue

        is_b = name.endswith("_b")
        is_boot = name.startswith("boot_")
        flags = struct.unpack_from("<Q", entries_data, off+48)[0]
        flag_byte6 = (flags >> 48) & 0xFF

        if is_b:  # Make _b ACTIVE
            if is_boot:
                new_flags = 0x007f << 48  # priority=7, active, tries_max=7
            else:
                new_flag6 = flag_byte6 | 0x04
                new_flags = (flags & ~(0xFF << 48)) | (new_flag6 << 48)
        else:  # Make _a inactive
            if is_boot:
                new_flags = 0x003a << 48
            else:
                new_flag6 = flag_byte6 & ~0x04
                new_flags = (flags & ~(0xFF << 48)) | (new_flag6 << 48)

        if flags != new_flags:
            old_active = "ACTIVE" if (flag_byte6 & 0x04) else "inactive"
            new_byte6 = (new_flags >> 48) & 0xFF
            new_active = "ACTIVE" if (new_byte6 & 0x04) else "inactive"
            print(f"[sw_b]   {name:25s} 0x{flag_byte6:02x} {old_active} -> 0x{new_byte6:02x} {new_active}")
            struct.pack_into("<Q", entries_data, off+48, new_flags)
            patched = True

    return patched

def rewrite_gpt_with_new_entries(entries_data, lun, total_sectors, header_sector, entry_start_sector):
    """Write new entries + rebuild both GPT headers with correct CRC32"""
    # Calculate entries CRC32
    entries_crc = crc32(entries_data)
    print(f"[sw_b] New entries CRC32: 0x{entries_crc:08x}")

    # Write new entries to primary location (sector 2)
    prim_entries_file = os.path.join(TMP, f"slotb_prim_entries_lun{lun}.bin")
    with open(prim_entries_file, "wb") as f:
        f.write(entries_data)
    run_edl("ws", "2", prim_entries_file, f"--lun={lun}", "--memory=ufs")
    print(f"[sw_b] Primary entries written to sector 2 ✓")

    # Write same entries to backup location
    entry_sectors = len(entries_data) // SECTOR_SIZE
    backup_entry_start = total_sectors - 1 - entry_sectors
    backup_entries_file = os.path.join(TMP, f"slotb_bkup_entries_lun{lun}.bin")
    with open(backup_entries_file, "wb") as f:
        f.write(entries_data)
    run_edl("ws", str(backup_entry_start), backup_entries_file, f"--lun={lun}", "--memory=ufs")
    print(f"[sw_b] Backup entries written to sector {backup_entry_start} ✓")

    # Read primary header (sector 1) to use as template
    prim_hdr_file = os.path.join(TMP, f"slotb_prim_hdr_lun{lun}.bin")
    run_edl("rs", "1", "1", prim_hdr_file, f"--lun={lun}", "--memory=ufs")
    with open(prim_hdr_file, "rb") as f:
        prim_hdr = bytearray(f.read())

    if prim_hdr[:8] != b"EFI PART":
        print("[sw_b] ERROR: Primary header invalid!")
        sys.exit(1)

    header_size = struct.unpack_from("<I", prim_hdr, 12)[0]
    num_entries = struct.unpack_from("<I", prim_hdr, 80)[0]
    entry_size = struct.unpack_from("<I", prim_hdr, 84)[0]

    # Update entries CRC32 in primary header
    struct.pack_into("<I", prim_hdr, 88, entries_crc)
    struct.pack_into("<I", prim_hdr, 16, 0)  # clear header CRC
    prim_crc = crc32(bytes(prim_hdr[:header_size]))
    struct.pack_into("<I", prim_hdr, 16, prim_crc)
    print(f"[sw_b] Primary header CRC32: 0x{prim_crc:08x}")

    new_prim_hdr_file = os.path.join(TMP, f"slotb_new_prim_hdr_lun{lun}.bin")
    with open(new_prim_hdr_file, "wb") as f:
        f.write(prim_hdr)
    run_edl("ws", "1", new_prim_hdr_file, f"--lun={lun}", "--memory=ufs")
    print(f"[sw_b] Primary header updated ✓")

    # Build backup header
    bkup_hdr = bytearray(prim_hdr)
    backup_hdr_lba = total_sectors - 1
    struct.pack_into("<Q", bkup_hdr, 24, backup_hdr_lba)      # my_lba
    struct.pack_into("<Q", bkup_hdr, 32, 1)                   # alternate_lba = primary header
    struct.pack_into("<Q", bkup_hdr, 72, backup_entry_start)   # partition_entry_lba
    struct.pack_into("<I", bkup_hdr, 88, entries_crc)          # entries CRC (same)
    struct.pack_into("<I", bkup_hdr, 16, 0)                    # clear header CRC
    bkup_crc = crc32(bytes(bkup_hdr[:header_size]))
    struct.pack_into("<I", bkup_hdr, 16, bkup_crc)
    print(f"[sw_b] Backup header CRC32: 0x{bkup_crc:08x}")

    new_bkup_hdr_file = os.path.join(TMP, f"slotb_new_bkup_hdr_lun{lun}.bin")
    with open(new_bkup_hdr_file, "wb") as f:
        f.write(bkup_hdr)
    run_edl("ws", str(backup_hdr_lba), new_bkup_hdr_file, f"--lun={lun}", "--memory=ufs")
    print(f"[sw_b] Backup header updated ✓")


def main():
    print("="*60)
    print("  切换 active slot 到 B（诊断测试）")
    print("="*60)
    print()

    # Read primary GPT entries from LUN4
    print("[sw_b] 读取 LUN4 主 GPT entries...")
    prim_entries_raw = os.path.join(TMP, "slotb_curr_entries.bin")
    run_edl("rs", "2", "3", prim_entries_raw, "--lun=4", "--memory=ufs")

    with open(prim_entries_raw, "rb") as f:
        entries_data = bytearray(f.read())

    # Read primary header to get metadata
    prim_hdr_raw = os.path.join(TMP, "slotb_curr_hdr.bin")
    run_edl("rs", "1", "1", prim_hdr_raw, "--lun=4", "--memory=ufs")
    with open(prim_hdr_raw, "rb") as f:
        hdr = f.read()

    if hdr[:8] != b"EFI PART":
        print("[sw_b] ERROR: Invalid primary GPT header!")
        sys.exit(1)

    num_entries = struct.unpack_from("<I", hdr, 80)[0]
    entry_size = struct.unpack_from("<I", hdr, 84)[0]
    print(f"[sw_b] GPT: {num_entries} entries × {entry_size} bytes")

    # Patch entries
    patched = patch_gpt_entries_slot_b(entries_data, num_entries, entry_size)
    if not patched:
        print("[sw_b] Already slot_b? Or no changes needed.")
    else:
        # Write back with correct CRC32
        rewrite_gpt_with_new_entries(entries_data, 4, TOTAL_SECTORS_LUN4, 1, 2)

    # Verify
    print()
    run_edl("getactiveslot", "--memory=ufs")

    # Clear misc
    print("[sw_b] Clearing misc...")
    run_edl("e", "misc", "--memory=ufs")

    # Reboot
    print("[sw_b] Rebooting...")
    run_edl("reset")
    print("[sw_b] Done. Watch if device boots into Android!")


if __name__ == "__main__":
    main()
