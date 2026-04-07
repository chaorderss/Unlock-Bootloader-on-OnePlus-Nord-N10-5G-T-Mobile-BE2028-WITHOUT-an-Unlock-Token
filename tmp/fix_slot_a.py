#!/usr/bin/env python3
"""
fix_slot_a.py - Fix active slot back to A by patching backup GPT on device
Reads current backup GPT from LUN4, patches boot_a/boot_b flags, writes back.
"""
import struct
import subprocess
import sys
import os

EDL = "edl"
DEVICE_MODEL = "20888"
TMP = "/Users/xmxx/pinganhuijia/tmp"
SECTOR_SIZE = 4096

# LUN4 total sectors
TOTAL_SECTORS = 0x100000  # 1048576

# Backup GPT: header at last sector, entries before it
# Standard layout: entries at (last_sector - entry_sectors) .. (last_sector - 1), header at last_sector
BACKUP_GPT_HEADER_SECTOR = TOTAL_SECTORS - 1  # 1048575

# AB slot flag definitions (from edlclient)
AB_FLAG_OFFSET = 6  # byte offset within flags (byte 6 of 8-byte flags field)
AB_PARTITION_ATTR_SLOT_ACTIVE = 0x04


def run_edl(*args):
    cmd = [EDL] + list(args) + [f"--devicemodel={DEVICE_MODEL}"]
    print(f"[fix] run: {' '.join(cmd)}")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print(f"[fix] ERROR: exit={result.returncode}")
        sys.exit(1)


def main():
    # Step 1: Read backup GPT header to find partition entry location
    header_file = os.path.join(TMP, "bkgpt_header.bin")
    run_edl("rs", str(BACKUP_GPT_HEADER_SECTOR), "1", header_file, "--lun=4", "--memory=ufs")

    with open(header_file, "rb") as f:
        header = f.read()

    sig = header[:8]
    print(f"[fix] Backup GPT signature: {sig}")
    if sig != b"EFI PART":
        print("[fix] ERROR: Not a valid GPT header!")
        sys.exit(1)

    part_entry_start_lba = struct.unpack_from("<Q", header, 72)[0]
    num_entries = struct.unpack_from("<I", header, 80)[0]
    entry_size = struct.unpack_from("<I", header, 84)[0]
    print(f"[fix] Backup GPT: entries at LBA {part_entry_start_lba}, count={num_entries}, size={entry_size}")

    # Step 2: Read all partition entries
    entry_sectors = (num_entries * entry_size + SECTOR_SIZE - 1) // SECTOR_SIZE
    entries_file = os.path.join(TMP, "bkgpt_entries.bin")
    run_edl("rs", str(part_entry_start_lba), str(entry_sectors), entries_file, "--lun=4", "--memory=ufs")

    with open(entries_file, "rb") as f:
        entries_data = bytearray(f.read())

    # Step 3: Find and patch boot_a and boot_b flags
    patched = False
    for i in range(num_entries):
        off = i * entry_size
        if off + entry_size > len(entries_data):
            break
        name_raw = entries_data[off+56:off+56+72]
        name = name_raw.decode("utf-16-le").rstrip("\x00")
        if not name:
            continue

        flags = struct.unpack_from("<Q", entries_data, off+48)[0]
        flag_byte = (flags >> (AB_FLAG_OFFSET * 8)) & 0xFF

        # Check all _a and _b partitions
        if name.endswith("_a") or name.endswith("_b"):
            is_a = name.endswith("_a")
            is_boot = name.startswith("boot_")

            old_active = "ACTIVE" if (flag_byte & AB_PARTITION_ATTR_SLOT_ACTIVE) else "inactive"

            if is_a:
                # Make _a active
                if is_boot:
                    new_flags = 0x007f << (AB_FLAG_OFFSET * 8)  # boot_a: priority=7, active, tries=7
                else:
                    new_flags = flags | (AB_PARTITION_ATTR_SLOT_ACTIVE << (AB_FLAG_OFFSET * 8))
                    # Also keep the original high bits
                    # For non-boot _a partitions, set active bit
            else:
                # Make _b inactive
                if is_boot:
                    new_flags = 0x003a << (AB_FLAG_OFFSET * 8)  # boot_b: lower priority, inactive
                else:
                    new_flags = flags & ~(AB_PARTITION_ATTR_SLOT_ACTIVE << (AB_FLAG_OFFSET * 8))

            new_flag_byte = (new_flags >> (AB_FLAG_OFFSET * 8)) & 0xFF
            new_active = "ACTIVE" if (new_flag_byte & AB_PARTITION_ATTR_SLOT_ACTIVE) else "inactive"

            if flags != new_flags:
                print(f"[fix] {name:25s} 0x{flags:016x} ({old_active}) -> 0x{new_flags:016x} ({new_active})")
                struct.pack_into("<Q", entries_data, off+48, new_flags)
                patched = True

    if not patched:
        print("[fix] No changes needed - slot_a already active in backup GPT")
        return

    # Step 4: Write patched entries back
    patched_file = os.path.join(TMP, "bkgpt_entries_patched.bin")
    with open(patched_file, "wb") as f:
        f.write(entries_data)

    run_edl("ws", str(part_entry_start_lba), patched_file, "--lun=4", "--memory=ufs")
    print("[fix] Backup GPT entries patched successfully!")

    # Step 5: Also fix the primary GPT (already written from backup, but let's be safe)
    # Primary GPT entries start at LBA 2
    print("[fix] Also patching primary GPT entries...")

    prim_entries_file = os.path.join(TMP, "primgpt_entries.bin")
    run_edl("rs", "2", str(entry_sectors), prim_entries_file, "--lun=4", "--memory=ufs")

    with open(prim_entries_file, "rb") as f:
        prim_data = bytearray(f.read())

    for i in range(num_entries):
        off = i * entry_size
        if off + entry_size > len(prim_data):
            break
        name_raw = prim_data[off+56:off+56+72]
        name = name_raw.decode("utf-16-le").rstrip("\x00")
        if not name:
            continue

        if name.endswith("_a") or name.endswith("_b"):
            is_a = name.endswith("_a")
            is_boot = name.startswith("boot_")
            flags = struct.unpack_from("<Q", prim_data, off+48)[0]

            if is_a:
                if is_boot:
                    new_flags = 0x007f << (AB_FLAG_OFFSET * 8)
                else:
                    new_flags = flags | (AB_PARTITION_ATTR_SLOT_ACTIVE << (AB_FLAG_OFFSET * 8))
            else:
                if is_boot:
                    new_flags = 0x003a << (AB_FLAG_OFFSET * 8)
                else:
                    new_flags = flags & ~(AB_PARTITION_ATTR_SLOT_ACTIVE << (AB_FLAG_OFFSET * 8))

            if flags != new_flags:
                struct.pack_into("<Q", prim_data, off+48, new_flags)

    prim_patched_file = os.path.join(TMP, "primgpt_entries_patched.bin")
    with open(prim_patched_file, "wb") as f:
        f.write(prim_data)

    run_edl("ws", "2", prim_patched_file, "--lun=4", "--memory=ufs")
    print("[fix] Primary GPT entries patched successfully!")

    # Verify
    print()
    run_edl("getactiveslot", "--memory=ufs")


if __name__ == "__main__":
    main()
