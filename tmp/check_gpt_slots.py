#!/usr/bin/env python3
"""Check backup GPT for active slot flags"""
import struct

for lun in [4]:
    path = f"/Users/xmxx/pinganhuijia/edl_backup/lun{lun}/gpt_main{lun}.bin"
    with open(path, "rb") as f:
        data = f.read()

    header_off = 4096  # LBA 1, sector_size=4096 for UFS
    sig = data[header_off:header_off+8]
    print(f"LUN{lun} GPT signature: {sig}")

    part_entry_start = struct.unpack_from("<Q", data, header_off + 72)[0]
    num_parts = struct.unpack_from("<I", data, header_off + 80)[0]
    part_entry_size = struct.unpack_from("<I", data, header_off + 84)[0]
    print(f"  entries start LBA={part_entry_start}, count={num_parts}, size={part_entry_size}")

    entry_start = part_entry_start * 4096
    for i in range(num_parts):
        off = entry_start + i * part_entry_size
        if off + part_entry_size > len(data):
            break
        name_raw = data[off+56:off+56+72]
        name = name_raw.decode("utf-16-le").rstrip("\x00")
        if not name:
            continue
        flags = struct.unpack_from("<Q", data, off+48)[0]
        flag_byte = (flags >> 48) & 0xFF
        if any(x in name for x in ["boot_", "aop_", "abl_", "tz_"]):
            active = "ACTIVE" if (flag_byte & 0x04) else "inactive"
            print(f"  {name:25s} flags=0x{flags:016x} byte=0x{flag_byte:02x} {active}")
