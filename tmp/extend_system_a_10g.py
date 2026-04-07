#!/usr/bin/env python3
"""
Extend system_a to ~10 GB by adding a second non-contiguous extent
in the free space after odm_a inside the super partition.

Current sda14 layout (sectors):
  system_a:  [2048, +8022016)       = 3.8 GB
  vendor_a:  [8024064, +2690456)    = 1.3 GB
  odm_a:     [10715136, +1936)      = 0.9 MB
  FREE:      [10719232 ... 29360127] = 9.1 GB  (aligned start)

After:
  system_a extent 0: physical 2048,     8022016 sectors  (3.8 GB, existing)
  system_a extent 1: physical 10719232, 12949504 sectors (6.2 GB, new)
  Total: 20971520 sectors = 10 GB
"""
import struct, hashlib, subprocess, sys

SUPER = "/dev/sda14"
BACKUP_FILE = "/userdata/system-data/super_meta_backup_10g.bin"

# Target
TARGET_TOTAL_SECTORS  = 20971520   # 10 GB
FIRST_EXTENT_SECTORS  = 8022016
FIRST_EXTENT_PHYSICAL = 2048
SECOND_EXTENT_PHYSICAL = 10719232  # 1MB-aligned after odm_a end (10717072)
SECOND_EXTENT_SECTORS = TARGET_TOTAL_SECTORS - FIRST_EXTENT_SECTORS  # 12949504

# Constants
LP_RESERVED  = 4096
GEO_SIZE     = 4096
META0_OFFSET = LP_RESERVED + 2 * GEO_SIZE   # 12288
HDR_MAGIC    = 0x414C5030
LP_TARGET_LINEAR = 0

def sha256(data):
    return hashlib.sha256(data).digest()

def read_dev(offset, size):
    with open(SUPER, 'rb') as f:
        f.seek(offset)
        return bytearray(f.read(size))

def write_dev(offset, data):
    with open(SUPER, 'r+b') as f:
        f.seek(offset)
        f.write(data)

def dev_sectors():
    r = subprocess.run(['blockdev', '--getsz', SUPER],
                       capture_output=True, text=True, check=True)
    return int(r.stdout.strip())

def dev_size():
    r = subprocess.run(['blockdev', '--getsize64', SUPER],
                       capture_output=True, text=True, check=True)
    return int(r.stdout.strip())

def run(cmd):
    print(f"  $ {cmd}")
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if r.stdout.strip():
        for line in r.stdout.strip().split('\n'):
            print(f"    {line}")
    if r.returncode != 0 and r.stderr.strip():
        for line in r.stderr.strip().split('\n'):
            print(f"    ERR: {line}")
    return r

# ── Safety checks ──────────────────────────────────────────────────────
total_sectors = dev_sectors()
end_sector = SECOND_EXTENT_PHYSICAL + SECOND_EXTENT_SECTORS
assert end_sector <= total_sectors, \
    f"Overflow! {end_sector} > {total_sectors}"
print(f"[check] New extent ends at sector {end_sector}, super has {total_sectors}. OK.")

# ── Read geometry ──────────────────────────────────────────────────────
geo = read_dev(LP_RESERVED, GEO_SIZE)
meta_max_size = struct.unpack_from('<I', geo, 40)[0]
meta_slots    = struct.unpack_from('<I', geo, 44)[0]
print(f"[geo] meta_max={meta_max_size}  slots={meta_slots}")

# ── Read & backup primary slot 0 ──────────────────────────────────────
slot0 = read_dev(META0_OFFSET, meta_max_size)
with open(BACKUP_FILE, 'wb') as f:
    f.write(slot0)
print(f"[backup] slot 0 → {BACKUP_FILE}")

# ── Parse header ──────────────────────────────────────────────────────
magic    = struct.unpack_from('<I', slot0, 0)[0]
assert magic == HDR_MAGIC, f"Bad magic 0x{magic:08x}"
hdr_size = struct.unpack_from('<I', slot0, 8)[0]
tables_size = struct.unpack_from('<I', slot0, 44)[0]
print(f"[hdr] hdr_size={hdr_size} tables_size={tables_size}")

# Table descriptors: 4 × {offset, count, entry_size} at hdr offset 80
desc_names = ['partitions', 'extents', 'groups', 'block_devices']
descs = {}
for i, name in enumerate(desc_names):
    off = 80 + i * 12
    d_off, d_cnt, d_esz = struct.unpack_from('<III', slot0, off)
    descs[name] = (d_off, d_cnt, d_esz)
    print(f"  {name:14s}: offset={d_off:4d} count={d_cnt} entry_size={d_esz}")

ts = hdr_size  # tables start in slot0

# ── Parse partitions ──────────────────────────────────────────────────
p_off, p_cnt, p_esz = descs['partitions']
parts = []
for i in range(p_cnt):
    o = ts + p_off + i * p_esz
    raw_name = bytes(slot0[o:o+36])
    name = raw_name.rstrip(b'\x00').decode()
    attrs      = struct.unpack_from('<I', slot0, o+36)[0]
    first_ext  = struct.unpack_from('<I', slot0, o+40)[0]
    num_ext    = struct.unpack_from('<I', slot0, o+44)[0]
    group_idx  = struct.unpack_from('<I', slot0, o+48)[0]
    parts.append(dict(raw_name=raw_name, name=name,
                      attrs=attrs, first_ext=first_ext,
                      num_ext=num_ext, group_idx=group_idx))
    print(f"  part[{i}] {name:12s}  first_ext={first_ext} num_ext={num_ext}")

# ── Parse extents ─────────────────────────────────────────────────────
e_off, e_cnt, e_esz = descs['extents']
exts = []
for i in range(e_cnt):
    o = ts + e_off + i * e_esz
    ns = struct.unpack_from('<Q', slot0, o)[0]
    tt = struct.unpack_from('<I', slot0, o+8)[0]
    td = struct.unpack_from('<Q', slot0, o+12)[0]
    src = struct.unpack_from('<I', slot0, o+20)[0]
    exts.append(dict(num_sectors=ns, target_type=tt,
                     target_data=td, target_source=src))
    print(f"  ext[{i}] sectors={ns:>10d}  type={tt}  physical={td:>10d}  src={src}")

# ── Read groups & block_devices raw (unchanged) ──────────────────────
g_off, g_cnt, g_esz = descs['groups']
groups_raw = bytes(slot0[ts+g_off : ts+g_off + g_cnt*g_esz])

b_off, b_cnt, b_esz = descs['block_devices']
blkdevs_raw = bytes(slot0[ts+b_off : ts+b_off + b_cnt*b_esz])

# ── Modify: insert new extent for system_a ───────────────────────────
sys_idx = next(i for i, p in enumerate(parts) if p['name'] == 'system_a')
sys_p = parts[sys_idx]

# Verify current state
assert sys_p['num_ext'] == 1, f"system_a already has {sys_p['num_ext']} extents"
assert exts[sys_p['first_ext']]['num_sectors'] == FIRST_EXTENT_SECTORS, \
    f"First extent sectors mismatch: {exts[sys_p['first_ext']]['num_sectors']}"

insert_at = sys_p['first_ext'] + sys_p['num_ext']  # right after system_a's extents

new_extent = dict(
    num_sectors=SECOND_EXTENT_SECTORS,
    target_type=LP_TARGET_LINEAR,
    target_data=SECOND_EXTENT_PHYSICAL,
    target_source=0
)

# Shift other partitions' first_ext that are >= insert_at
for p in parts:
    if p is not sys_p and p['first_ext'] >= insert_at:
        p['first_ext'] += 1

# Insert
exts.insert(insert_at, new_extent)
sys_p['num_ext'] += 1

print(f"\n[modify] Inserted extent[{insert_at}]: "
      f"sectors={SECOND_EXTENT_SECTORS} physical={SECOND_EXTENT_PHYSICAL}")
for p in parts:
    print(f"  {p['name']:12s}  first_ext={p['first_ext']} num_ext={p['num_ext']}")
for i, e in enumerate(exts):
    print(f"  ext[{i}] sectors={e['num_sectors']:>10d} physical={e['target_data']:>10d}")

# ── Rebuild tables binary ─────────────────────────────────────────────
new_e_cnt = len(exts)
new_p_off = 0
new_e_off = p_cnt * p_esz
new_g_off = new_e_off + new_e_cnt * e_esz
new_b_off = new_g_off + g_cnt * g_esz
new_tables_size = new_b_off + b_cnt * b_esz

print(f"\n[rebuild] tables_size: {tables_size} → {new_tables_size}")

tbl = bytearray(new_tables_size)

# Partitions
for i, p in enumerate(parts):
    o = new_p_off + i * p_esz
    tbl[o:o+36] = p['raw_name']
    struct.pack_into('<I', tbl, o+36, p['attrs'])
    struct.pack_into('<I', tbl, o+40, p['first_ext'])
    struct.pack_into('<I', tbl, o+44, p['num_ext'])
    struct.pack_into('<I', tbl, o+48, p['group_idx'])

# Extents
for i, e in enumerate(exts):
    o = new_e_off + i * e_esz
    struct.pack_into('<Q', tbl, o,    e['num_sectors'])
    struct.pack_into('<I', tbl, o+8,  e['target_type'])
    struct.pack_into('<Q', tbl, o+12, e['target_data'])
    struct.pack_into('<I', tbl, o+20, e['target_source'])

# Groups & block_devices (unchanged)
tbl[new_g_off:new_g_off+len(groups_raw)] = groups_raw
tbl[new_b_off:new_b_off+len(blkdevs_raw)] = blkdevs_raw

# ── Rebuild metadata block ────────────────────────────────────────────
meta = bytearray(meta_max_size)
meta[:hdr_size] = slot0[:hdr_size]   # copy header as base

# Update descriptors
struct.pack_into('<III', meta, 80,  new_p_off, p_cnt,    p_esz)
struct.pack_into('<III', meta, 92,  new_e_off, new_e_cnt, e_esz)
struct.pack_into('<III', meta, 104, new_g_off, g_cnt,    g_esz)
struct.pack_into('<III', meta, 116, new_b_off, b_cnt,    b_esz)

# Update tables_size
struct.pack_into('<I', meta, 44, new_tables_size)

# Write tables
meta[hdr_size:hdr_size+new_tables_size] = tbl

# Recompute tables checksum
meta[48:80] = sha256(bytes(meta[hdr_size:hdr_size+new_tables_size]))

# Recompute header checksum
meta[12:44] = b'\x00' * 32
meta[12:44] = sha256(bytes(meta[:hdr_size]))

# ── Write primary slot 0  ─────────────────────────────────────────────
print("\n[write] Primary slot 0 ...")
write_dev(META0_OFFSET, bytes(meta))
# Verify
v = read_dev(META0_OFFSET, meta_max_size)
assert bytes(v) == bytes(meta), "Primary verify FAILED"
print("  ✓ verified")

# ── Write backup slot 0 ──────────────────────────────────────────────
sz = dev_size()
backup_meta_start = sz - GEO_SIZE - meta_max_size * meta_slots
print(f"[write] Backup slot 0 @ {backup_meta_start} ...")
write_dev(backup_meta_start, bytes(meta))
v = read_dev(backup_meta_start, meta_max_size)
assert bytes(v) == bytes(meta), "Backup verify FAILED"
print("  ✓ verified")

# ── Extend live dm device ─────────────────────────────────────────────
print("\n[live] Extending dm device + filesystem ...")
run("sync")
run("mount -o remount,rw /")

# Build two-segment dm table
seg1 = f"0 {FIRST_EXTENT_SECTORS} linear 8:14 {FIRST_EXTENT_PHYSICAL}"
seg2 = f"{FIRST_EXTENT_SECTORS} {SECOND_EXTENT_SECTORS} linear 8:14 {SECOND_EXTENT_PHYSICAL}"
table_str = f"{seg1}\\n{seg2}"

run("dmsetup suspend system_a")
run(f"printf '{table_str}' | dmsetup load system_a")
run("dmsetup resume system_a")
run("resize2fs /dev/mapper/system_a")
print()
run("df -h /")

print(f"""
╔══════════════════════════════════════════╗
║  system_a expanded to 10 GB             ║
║  Extent 0: 3.8 GB (physical 2048)       ║
║  Extent 1: 6.2 GB (physical 10719232)   ║
║  Persistent across reboots              ║
╚══════════════════════════════════════════╝""")
