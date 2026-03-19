#!/usr/bin/env python3
"""Write correct SWID and proc magic to SID 0x13C.

FIXED bugs from write_swid2.py:
1. Missing magic number 0xA0AD646A at bytes 0-3
2. Outer MD5 was at block[4:20] instead of block[0x80:0x90]
3. Using STATIC key (ABL re-encrypted with static key after RPMB restore)
4. Updated block structure to match edl tool's encryptsid exactly

Block structure (from edl tool oneplus_param.py):
  block[0:4]      = magic 0xA0AD646A (LE)
  block[4]        = hv (hw_version)
  block[5]        = cv (crypto_version)
  block[0x10]     = updatecounter
  block[0x80:0x90] = outer MD5 (MD5 of encrypted data)
  block[0x400:0x400+0xC00] = encrypted data
"""
import hashlib
import struct
import subprocess
from Crypto.Cipher import AES

MAGIC = 0xA0AD646A
IV = bytes.fromhex('562E17996D093D28DDB3BA695A2E6F58')
STATIC_KEY = bytes.fromhex('3030304F6E65506C7573383138303030')

SWID_20886 = 0xB8BD9E39   # CM hash for model 20886 (non-TMO)
PROC_MAGIC = 0xDC9EF893    # Magic value ABL checks for "backup to RPMB"


def decrypt_sid(block, key):
    """Decrypt a SID block, returning (dec_bytes, itemdata) or (None, None)."""
    magic = struct.unpack_from('<I', block, 0)[0]
    if magic != MAGIC:
        print(f"    Bad magic: 0x{magic:08X}")
        return None, None

    enc = block[0x400:0x400 + 0xC00]

    # Check outer MD5
    outer_stored = block[0x80:0x90]
    outer_computed = hashlib.md5(enc).digest()
    if outer_stored != outer_computed:
        print(f"    Outer MD5 mismatch!")
        print(f"      stored:   {outer_stored.hex()}")
        print(f"      computed: {outer_computed.hex()}")
        return None, None

    cipher = AES.new(key, AES.MODE_CBC, IV)
    dec = cipher.decrypt(enc)
    inner_md5 = dec[:16]
    itemdata = dec[-0xB80:]
    if hashlib.md5(itemdata).digest() != inner_md5:
        print(f"    Inner MD5 mismatch (wrong key?)")
        return None, None

    return bytearray(dec), bytearray(itemdata)


def encrypt_sid(dec_data, hv, cv, updatecounter, key):
    """Encrypt and build a SID block matching edl tool format."""
    block = bytearray(0x1000)

    # Magic + hv + cv (matching edl tool: pack("<IBB", magic, hv, cv))
    struct.pack_into('<I', block, 0, MAGIC)
    block[4] = hv
    block[5] = cv

    # Update counter (edl tool increments by 1)
    block[0x10] = (updatecounter + 1) & 0xFF

    # Encrypt
    cipher = AES.new(key, AES.MODE_CBC, IV)
    enc = cipher.encrypt(bytes(dec_data))

    # Outer MD5 at block[0x80:0x90]
    outer_md5 = hashlib.md5(enc).digest()
    block[0x80:0x90] = outer_md5

    # Encrypted data at block[0x400:]
    block[0x400:0x400 + 0xC00] = enc

    return bytes(block)


# Read current param from device
print("[*] Reading param partition from device...")
result = subprocess.run(['adb', 'shell', 'dd if=/dev/block/sda6 2>/dev/null'],
                       capture_output=True)
param = bytearray(result.stdout)
assert len(param) == 1048576, f"Unexpected param size: {len(param)}"
print(f"    Size: {len(param)} bytes OK")

# Process both primary and backup SIDs
for sid_val, sid_name in [(0x13C, "primary"), (0x33C, "backup")]:
    offset = sid_val * 0x400
    block = param[offset:offset + 0x1000]
    hv = block[4]
    cv = block[5]
    uc = block[0x10]
    print(f"\n[*] SID 0x{sid_val:X} ({sid_name}): hv={hv}, cv={cv}, uc={uc}")

    dec, itemdata = decrypt_sid(block, STATIC_KEY)
    if dec is None:
        print(f"[!] Failed to decrypt SID 0x{sid_val:X}!")
        exit(1)

    sf = struct.unpack('<I', itemdata[0:4])[0]
    swid = struct.unpack('<I', itemdata[4:8])[0]
    proc = struct.unpack('<I', itemdata[8:12])[0]
    print(f"    Current: supported={sf}, SWID=0x{swid:08X}, proc=0x{proc:08X}")

    # Modify
    struct.pack_into('<I', itemdata, 0x04, SWID_20886)
    struct.pack_into('<I', itemdata, 0x08, PROC_MAGIC)

    # Update dec (itemdata starts at dec[0x80])
    dec[0x80 + 0x04:0x80 + 0x08] = struct.pack('<I', SWID_20886)
    dec[0x80 + 0x08:0x80 + 0x0C] = struct.pack('<I', PROC_MAGIC)

    # Recompute inner MD5
    dec[0:16] = hashlib.md5(bytes(itemdata)).digest()

    # Verify consistency
    assert dec[0x80:0x80 + 0xB80] == bytes(itemdata)

    # Encrypt with STATIC key, preserving hv/cv from ABL
    new_block = encrypt_sid(dec, hv, cv, uc, STATIC_KEY)

    # Verify roundtrip
    v_dec, v_item = decrypt_sid(new_block, STATIC_KEY)
    assert v_dec is not None, f"Roundtrip decrypt failed for SID 0x{sid_val:X}!"
    v_swid = struct.unpack('<I', v_item[0x04:0x08])[0]
    v_proc = struct.unpack('<I', v_item[0x08:0x0C])[0]
    assert v_swid == SWID_20886, f"SWID verify failed: 0x{v_swid:08X}"
    assert v_proc == PROC_MAGIC, f"proc verify failed: 0x{v_proc:08X}"
    print(f"    New: SWID=0x{SWID_20886:08X}, proc=0x{PROC_MAGIC:08X} [verified]")

    param[offset:offset + 0x1000] = new_block

# Save modified param
with open('/tmp/param_modified3.bin', 'wb') as f:
    f.write(param)
print(f"\n[*] Saved modified param to /tmp/param_modified3.bin")

# Write to device
print("[*] Writing modified param to device...")
result = subprocess.run(
    ['adb', 'shell', 'dd of=/dev/block/sda6 bs=1048576 2>/dev/null'],
    input=bytes(param), capture_output=True
)
print(f"    dd exit code: {result.returncode}")
if result.returncode != 0:
    print(f"    stderr: {result.stderr[:200]}")

# Verify by reading back
print("[*] Verifying write by readback...")
result2 = subprocess.run(['adb', 'shell', 'dd if=/dev/block/sda6 2>/dev/null'],
                        capture_output=True)
readback = result2.stdout

for sid_val, sid_name in [(0x13C, "primary"), (0x33C, "backup")]:
    offset = sid_val * 0x400
    rb_block = readback[offset:offset + 0x1000]
    rb_dec, rb_item = decrypt_sid(rb_block, STATIC_KEY)
    if rb_dec is not None:
        rb_swid = struct.unpack('<I', rb_item[0x04:0x08])[0]
        rb_proc = struct.unpack('<I', rb_item[0x08:0x0C])[0]
        ok_s = "OK" if rb_swid == SWID_20886 else "MISMATCH"
        ok_p = "OK" if rb_proc == PROC_MAGIC else "MISMATCH"
        print(f"    SID 0x{sid_val:X}: SWID=0x{rb_swid:08X} ({ok_s}), proc=0x{rb_proc:08X} ({ok_p})")
    else:
        print(f"    SID 0x{sid_val:X}: Readback decrypt FAILED!")

print("\n[+] Done! Ready to reboot.")
print("    Expected: ABL reads proc=0xDC9EF893 → 'start backup SPI to RPMB'")
print("    → RPMB gets SWID=0xB8BD9E39 (model 20886) → carrier check passes")
