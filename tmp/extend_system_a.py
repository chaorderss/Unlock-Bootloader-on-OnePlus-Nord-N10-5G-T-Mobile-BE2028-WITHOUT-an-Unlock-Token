#!/usr/bin/env python3
"""
Extend system_a in Android super partition (liblp v1.0 format).

Current sda14 layout (512-byte sectors):
  [metadata]  offset=0,         length=2048   (1MB)
  system_a    offset=2048,      length=6291456 (3.0 GB)
  [GAP]       offset=6293504,   length=1730560 (845 MB) ← we use this
  vendor_a    offset=8024064,   length=2690456 (1.3 GB)
  odm_a       offset=10715136,  length=1936
  [FREE]      offset=10717072,  length=18643056 (9.1 GB)

After: system_a occupies offset=2048, length=8022016 (~3.84 GB)
"""
import struct, hashlib, sys, os, subprocess

SUPER         = "/dev/sda14"
BACKUP_FILE   = "/userdata/system-data/super_meta_backup.bin"

ORIG_SECTORS  = 6291456   # current system_a sectors
NEW_SECTORS   = 8022016   # 6291456 + 1730560 (full gap up to vendor_a)
# Note: 2048 + 8022016 = 8024064 = exact start of vendor_a → no overlap

LP_RESERVED   = 4096      # LP_PARTITION_RESERVED_BYTES
GEO_SIZE      = 4096      # LP_METADATA_GEOMETRY_SIZE
META0_OFFSET  = LP_RESERVED + 2 * GEO_SIZE   # = 12288 (primary metadata)
HDR_MAGIC     = 0x414C5030

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def rblk(path, offset, size):
    with open(path, 'rb') as f:
        f.seek(offset)
        return bytearray(f.read(size))

def wblk(path, offset, data: bytes):
    with open(path, 'r+b') as f:
        f.seek(offset)
        f.write(data)

def super_size():
    r = subprocess.run(['blockdev', '--getsize64', SUPER],
                       capture_output=True, text=True, check=True)
    return int(r.stdout.strip())

# ── Read geometry ──────────────────────────────────────────────────────────────
geo = rblk(SUPER, LP_RESERVED, GEO_SIZE)
geo_magic     = struct.unpack_from('<I', geo, 0)[0]
meta_max_size = struct.unpack_from('<I', geo, 40)[0]
meta_slots    = struct.unpack_from('<I', geo, 44)[0]
print(f"[geo] magic=0x{geo_magic:08x}  meta_max={meta_max_size}  slots={meta_slots}")

# ── Backup primary metadata ────────────────────────────────────────────────────
total_primary = meta_max_size * meta_slots
raw = rblk(SUPER, META0_OFFSET, total_primary)
with open(BACKUP_FILE, 'wb') as f:
    f.write(raw)
print(f"[backup] {total_primary} bytes → {BACKUP_FILE}")

# ── Patch one metadata blob ────────────────────────────────────────────────────
def patch_meta(meta_bytes):
    """
    Patch extent[0].num_sectors, recompute both checksums.
    Returns (patched_bytes, status_str).
    """
    meta = bytearray(meta_bytes)

    magic = struct.unpack_from('<I', meta, 0)[0]
    if magic != HDR_MAGIC:
        return None, f"bad magic 0x{magic:08x}"

    hdr_size    = struct.unpack_from('<I', meta, 8)[0]
    tables_size = struct.unpack_from('<I', meta, 44)[0]

    # Header layout (v1.0, hdr_size=128):
    #   0:  magic(4)  major(2)  minor(2)  hdr_size(4)
    #  12:  header_checksum[32]
    #  44:  tables_size(4)
    #  48:  tables_checksum[32]
    #  80:  partitions descriptor (offset, count, entry_size) each 4B
    #  92:  extents  descriptor
    # 104:  groups   descriptor
    # 116:  block_devices descriptor
    # 128:  tables start

    _, ext_off, ext_cnt, ext_sz = struct.unpack_from('<IIII', meta, 88)
    # tables_start = hdr_size; extents table at tables_start + ext_off
    ext_table = hdr_size + ext_off
    ext0 = ext_table  # extent[0] is first entry (system_a)

    cur = struct.unpack_from('<Q', meta, ext0)[0]
    print(f"  extent[0].num_sectors = {cur}")
    if cur != ORIG_SECTORS:
        return None, f"unexpected sectors={cur} (expected {ORIG_SECTORS})"

    # ── Patch ──
    struct.pack_into('<Q', meta, ext0, NEW_SECTORS)

    # ── Recompute tables_checksum ──
    tables_data = bytes(meta[hdr_size : hdr_size + tables_size])
    meta[48:80] = sha256(tables_data)

    # ── Recompute header_checksum ──
    meta[12:44] = b'\x00' * 32   # zero field before computing
    meta[12:44] = sha256(bytes(meta[:hdr_size]))

    return bytes(meta), "OK"

# ── Update primary slots ───────────────────────────────────────────────────────
for slot in range(meta_slots):
    off = META0_OFFSET + slot * meta_max_size
    data = rblk(SUPER, off, meta_max_size)
    new_data, status = patch_meta(data)
    if new_data:
        wblk(SUPER, off, new_data)
        print(f"[slot {slot} primary  @ offset {off}] patched ✓")
    else:
        print(f"[slot {slot} primary  @ offset {off}] skipped: {status}")

# ── Update backup slots (at end of super) ─────────────────────────────────────
sz = super_size()
# Backup geometry is the last GEO_SIZE bytes; backup metadata is before that.
backup_meta_start = sz - GEO_SIZE - meta_max_size * meta_slots
print(f"[backup meta] super_size={sz}  backup_meta @ offset {backup_meta_start}")

for slot in range(meta_slots):
    off_p = META0_OFFSET + slot * meta_max_size          # already patched primary
    off_b = backup_meta_start + slot * meta_max_size
    data  = rblk(SUPER, off_p, meta_max_size)            # read patched primary
    magic = struct.unpack_from('<I', data, 0)[0]
    if magic != HDR_MAGIC:
        print(f"[slot {slot} backup   @ offset {off_b}] skipped: no valid header in primary")
        continue
    wblk(SUPER, off_b, bytes(data))
    print(f"[slot {slot} backup   @ offset {off_b}] patched ✓")

print()
print(f"✓  Metadata updated.")
print(f"   system_a: {ORIG_SECTORS} → {NEW_SECTORS} sectors")
print(f"             {ORIG_SECTORS*512//1024//1024} MB  → {NEW_SECTORS*512//1024//1024} MB")
print()
print("Now extending the live dm device and filesystem...")

import subprocess, time

def run(cmd, **kw):
    print(f"  $ {cmd}")
    r = subprocess.run(cmd, shell=True, **kw)
    if r.returncode != 0:
        print(f"  !! exit {r.returncode}")
    return r

run("sync")
run("mount -o remount,rw /")

# Build new dm table: same linear mapping, just longer
new_table = f"0 {NEW_SECTORS} linear 8:14 2048"
run("dmsetup suspend system_a")
run(f"dmsetup load system_a --table '{new_table}'")
run("dmsetup resume system_a")

# Resize ext4 to fill the new device size
run("resize2fs /dev/mapper/system_a")

print()
run("df -h /")
print()
print("Done!  Reboot to confirm persistence.")
