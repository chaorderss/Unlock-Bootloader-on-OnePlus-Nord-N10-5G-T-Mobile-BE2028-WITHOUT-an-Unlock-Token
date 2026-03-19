#!/usr/bin/env python3
"""Prepare ALL files needed for the unlock attempt and print flash procedure"""
import hashlib
import struct
import os

# Paths
BASE = "/Users/xmxx/pinganhuijia"
BACKUP = os.path.join(BASE, "edl_backup/lun0")
OUTPUT = os.path.join(BASE, "tmp")

# AES implementation using openssl (portable)
import subprocess, tempfile
def aes_cbc(key, iv, data, decrypt=True):
    with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
        f.write(data)
        infile = f.name
    outfile = infile + '.out'
    op = '-d' if decrypt else '-e'
    cmd = ['openssl', 'enc', '-aes-128-cbc', op, '-nopad',
           '-K', key.hex(), '-iv', iv.hex(),
           '-in', infile, '-out', outfile]
    subprocess.run(cmd, check=True, capture_output=True)
    with open(outfile, 'rb') as f:
        result = f.read()
    os.unlink(infile)
    os.unlink(outfile)
    return result

def md5(data):
    return hashlib.md5(data).digest()

AES_IV = bytes.fromhex("562E17996D093D28DDB3BA695A2E6F58")
DEFAULT_KEY = bytes.fromhex("3030304F6E65506C7573383138303030")

# ============================================================
# 1. PARAM PARTITION - Two versions
# ============================================================
print("=" * 60)
print("1. PREPARING PARAM PARTITION")
print("=" * 60)

with open(os.path.join(BACKUP, "param.bin"), "rb") as f:
    param_data = bytearray(f.read())

SID = 0x12C
sid_offset = SID * 0x400
sid_data = param_data[sid_offset:sid_offset + 0x1000]
magic_val = struct.unpack_from('<I', sid_data, 0)[0]
assert magic_val == 0xA0AD646A, f"Bad SID magic: 0x{magic_val:08X}"

hv, cv = sid_data[4], sid_data[5]
updatecounter = sid_data[0x10]
encdata = bytes(sid_data[0x400:0x400 + 0xC00])

# Decrypt
decdata = aes_cbc(DEFAULT_KEY, AES_IV, encdata, decrypt=True)
dechash = decdata[:16]
itemdata = bytearray(decdata[-0xB80:])
assert md5(itemdata) == dechash, "Decrypt hash mismatch!"

print(f"  Current: intranet={struct.unpack_from('<I', itemdata, 0)[0]}, "
      f"boottype=0x{struct.unpack_from('<I', itemdata, 4)[0]:X}")

def make_param_mod(itemdata_in, intranet, boottype, name):
    """Create modified param with given values"""
    items = bytearray(itemdata_in)
    struct.pack_into('<I', items, 0, intranet)
    struct.pack_into('<I', items, 4, boottype)

    header = bytearray(0x80)
    header[0:16] = md5(bytes(items))
    dec_full = bytes(header) + bytes(items)
    enc_new = aes_cbc(DEFAULT_KEY, AES_IV, dec_full, decrypt=False)

    new_sid = bytearray(0x1000)
    new_sid[:6] = struct.pack('<IBB', 0xA0AD646A, hv, cv)
    new_sid[0x10] = updatecounter + 1
    new_sid[0x80:0x90] = md5(enc_new)
    new_sid[0x400:0x400 + 0xC00] = enc_new

    # Verify
    vdec = aes_cbc(DEFAULT_KEY, AES_IV, bytes(enc_new), decrypt=True)
    vitems = vdec[-0xB80:]
    assert md5(vitems) == vdec[:16], "Re-encrypt verify failed!"
    assert struct.unpack_from('<I', vitems, 0)[0] == intranet
    assert struct.unpack_from('<I', vitems, 4)[0] == boottype

    result = bytearray(param_data)
    result[sid_offset:sid_offset + 0x1000] = new_sid
    # Also update duplicate SID if exists
    dup_offset = (SID + 0x200) * 0x400
    if dup_offset + 0x1000 <= len(result):
        dup_magic = struct.unpack_from('<I', result, dup_offset)[0]
        if dup_magic == 0xA0AD646A:
            result[dup_offset:dup_offset + 0x1000] = new_sid

    outpath = os.path.join(OUTPUT, name)
    with open(outpath, "wb") as f:
        f.write(result)
    print(f"  {name}: intranet={intranet}, boottype=0x{boottype:X} -> {outpath}")
    return outpath

# Version A: intranet=3 only (enable ops, keep normal boot)
param_a = make_param_mod(itemdata, 3, 0, "param_ops_only.bin")
# Version B: intranet=3 + boottype=sdebug
param_b = make_param_mod(itemdata, 3, 0xA9E, "param_ops_sdebug.bin")

# ============================================================
# 2. CONFIG PARTITION
# ============================================================
print(f"\n{'=' * 60}")
print("2. PREPARING CONFIG PARTITION")
print("=" * 60)

with open(os.path.join(BACKUP, "config.bin"), "rb") as f:
    config_data = bytearray(f.read())

print(f"  Config size: {len(config_data)} bytes")
print(f"  config[0x7FFF] = 0x{config_data[0x7FFF]:02X}")
print(f"  config[0x7FFFF] = 0x{config_data[0x7FFFF]:02X}")

# Set BOTH oem_unlock bytes
config_mod = bytearray(config_data)
config_mod[0x7FFF] = 0x01   # generic.py target (PDB-style 32KB)
config_mod[0x7FFFF] = 0x01  # last byte of partition (PDB-style 512KB)

outpath = os.path.join(OUTPUT, "config_unlocked.bin")
with open(outpath, "wb") as f:
    f.write(config_mod)
print(f"  config_unlocked.bin: [0x7FFF]=0x01, [0x7FFFF]=0x01 -> {outpath}")

# ============================================================
# 3. FRP PARTITION
# ============================================================
print(f"\n{'=' * 60}")
print("3. PREPARING FRP PARTITION")
print("=" * 60)

with open(os.path.join(BACKUP, "frp.bin"), "rb") as f:
    frp_data = bytearray(f.read())

print(f"  FRP size: {len(frp_data)} bytes")
print(f"  frp[0x7FFF] = 0x{frp_data[0x7FFF]:02X}")
print(f"  frp[0x7FFFF] = 0x{frp_data[0x7FFFF]:02X}")

frp_mod = bytearray(frp_data)
frp_mod[0x7FFF] = 0x01
frp_mod[0x7FFFF] = 0x01

outpath = os.path.join(OUTPUT, "frp_unlocked.bin")
with open(outpath, "wb") as f:
    f.write(frp_mod)
print(f"  frp_unlocked.bin: [0x7FFF]=0x01, [0x7FFFF]=0x01 -> {outpath}")

# ============================================================
# 4. FLASH PROCEDURE
# ============================================================
print(f"\n{'=' * 60}")
print("4. FLASH PROCEDURE")
print("=" * 60)

print("""
=== APPROACH A: OPS + IsAllowUnlock (recommended first) ===
1. Boot device into EDL mode (hold Vol+ & Vol- during power on)
2. Flash modified partitions:

   edl w lun0 param tmp/param_ops_only.bin
   edl w lun0 config tmp/config_unlocked.bin
   edl w lun0 frp tmp/frp_unlocked.bin

3. Reboot to fastboot:
   edl reset
   (Then hold Vol- for fastboot mode)

4. Check device info:
   fastboot oem device-info

5. Try OEM unlock:
   fastboot oem unlock

6. If prompted, confirm with volume keys on device

=== APPROACH B: OPS + SDEBUG mode ===
(Use this if Approach A fails)
1. Boot device into EDL mode
2. Flash:

   edl w lun0 param tmp/param_ops_sdebug.bin
   edl w lun0 config tmp/config_unlocked.bin
   edl w lun0 frp tmp/frp_unlocked.bin

3. Reboot and retry steps 3-6 from Approach A

=== APPROACH C: Full EDL module authentication ===
(Use this if direct param write is rejected)
1. Boot device into EDL mode
2. Run:
   edl modules ops,enable
3. Then manually set boottype if needed:
   edl r lun0 param tmp/param_from_device.bin
   python3 tmp/set_boottype.py
   edl w lun0 param tmp/param_boottype.bin

=== RECOVERY: Restore original partitions ===
If anything goes wrong:
   edl w lun0 param edl_backup/lun0/param.bin
   edl w lun0 config edl_backup/lun0/config.bin
   edl w lun0 frp edl_backup/lun0/frp.bin
""")

# ============================================================
# 5. SUMMARY
# ============================================================
print(f"{'=' * 60}")
print("5. FILES PREPARED")
print(f"{'=' * 60}")

for f in ["param_ops_only.bin", "param_ops_sdebug.bin",
          "config_unlocked.bin", "frp_unlocked.bin"]:
    path = os.path.join(OUTPUT, f)
    if os.path.exists(path):
        size = os.path.getsize(path)
        print(f"  OK  {f} ({size} bytes)")

print(f"\nOriginal backups preserved in:")
print(f"  {os.path.join(BASE, 'edl_backup/lun0/')}")
