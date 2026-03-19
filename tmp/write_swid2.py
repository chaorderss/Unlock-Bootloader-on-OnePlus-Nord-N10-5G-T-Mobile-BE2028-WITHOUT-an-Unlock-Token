#!/usr/bin/env python3
"""Write correct SWID and proc magic to SID 0x13C to trigger RPMB backup.

Key findings from ABL disassembly:
- Fields are at ITEMDATA offsets 0x00, 0x04, 0x08 (NOT 0x80, 0x84, 0x88)
- ABL ReadParam(SID, offset) reads from decrypted[offset], where itemdata starts at dec[0x80]
  So ReadParam offset 0x80 = itemdata[0x00], offset 0x84 = itemdata[0x04], offset 0x88 = itemdata[0x08]
- ABL checks proc == 0xDC9EF893 (not 1) to trigger "backup to RPMB" path
- Model 20886 CM hash = 0xB8BD9E39
"""
import hashlib
import struct
import subprocess

KEY = hashlib.sha256(b'a9264fbf8a75655d5b6b4487ea').digest()[:16]
IV = bytes.fromhex('562E17996D093D28DDB3BA695A2E6F58')
STATIC_KEY = bytes.fromhex('3030304F6E65506C7573383138303030')

SWID_20886 = 0xB8BD9E39  # CM hash for model 20886 (non-TMO)
PROC_MAGIC = 0xDC9EF893   # Magic value ABL checks for "backup to RPMB"

def decrypt_sid(block, key):
    from Crypto.Cipher import AES
    enc = block[0x400:0x400 + 0xC00]
    cipher = AES.new(key, AES.MODE_CBC, IV)
    dec = cipher.decrypt(enc)
    dechash = dec[:16]
    itemdata = dec[-0xB80:]
    if hashlib.md5(itemdata).digest() != dechash:
        return None, None
    return bytearray(dec), bytearray(itemdata)

def encrypt_sid(dec_data, hv, cv, update_counter, key):
    from Crypto.Cipher import AES
    # Build the full block
    block = bytearray(0x1000)
    block[0] = hv
    block[1] = cv
    struct.pack_into('<H', block, 2, update_counter)

    # Encrypt
    cipher = AES.new(key, AES.MODE_CBC, IV)
    enc = cipher.encrypt(bytes(dec_data))

    # Outer MD5 of ciphertext
    outer_md5 = hashlib.md5(enc).digest()
    block[4:20] = outer_md5

    # Store encrypted data
    block[0x400:0x400 + 0xC00] = enc
    return bytes(block)

# Read current param from device
print("[*] Reading param partition from device...")
result = subprocess.run(['adb', 'shell', 'dd if=/dev/block/sda6 2>/dev/null'],
                       capture_output=True)
param = bytearray(result.stdout)
assert len(param) == 1048576, f"Unexpected param size: {len(param)}"

# Also read original backup for comparison
with open('/Users/xmxx/pinganhuijia/edl_backup/pre_convert/param.bin', 'rb') as f:
    orig_param = f.read()

# Process SID 0x13C (primary)
sid_13c_offset = 0x13C * 0x400
block_13c = param[sid_13c_offset:sid_13c_offset + 0x1000]
hv = block_13c[0]
cv = block_13c[1]
uc = struct.unpack_from('<H', block_13c, 2)[0]
print(f"[*] SID 0x13C: hv={hv}, cv={cv}, update_counter={uc}")

dec, itemdata = decrypt_sid(block_13c, KEY)
if dec is None:
    print("[!] Failed to decrypt SID 0x13C!")
    exit(1)

print(f"[*] Current values:")
print(f"    supported_flag (itemdata[0x00]): {struct.unpack('<I', itemdata[0:4])[0]}")
print(f"    SWID (itemdata[0x04]): 0x{struct.unpack('<I', itemdata[4:8])[0]:08X}")
print(f"    proc (itemdata[0x08]): 0x{struct.unpack('<I', itemdata[8:12])[0]:08X}")

# Modify values
print(f"\n[*] Writing new values:")
print(f"    SWID = 0x{SWID_20886:08X} (model 20886)")
print(f"    proc = 0x{PROC_MAGIC:08X} (magic trigger)")

# Write to itemdata offsets 0x04 and 0x08
struct.pack_into('<I', itemdata, 0x04, SWID_20886)
struct.pack_into('<I', itemdata, 0x08, PROC_MAGIC)

# Also update dec (which includes header + itemdata)
# itemdata starts at dec[0x80]
dec[0x80 + 0x04:0x80 + 0x08] = struct.pack('<I', SWID_20886)
dec[0x80 + 0x08:0x80 + 0x0C] = struct.pack('<I', PROC_MAGIC)

# Recompute inner MD5
new_md5 = hashlib.md5(bytes(itemdata)).digest()
dec[0:16] = new_md5

# Verify consistency
assert dec[0x80:0x80 + 0xB80] == bytes(itemdata), "Dec/itemdata mismatch!"

# Encrypt and build new block
new_block = encrypt_sid(dec, hv, cv, uc, KEY)

# Verify by decrypting
verify_dec, verify_item = decrypt_sid(new_block, KEY)
assert verify_dec is not None, "Verification decryption failed!"
assert struct.unpack('<I', verify_item[0x00:0x04])[0] == 1, "supported_flag wrong"
assert struct.unpack('<I', verify_item[0x04:0x08])[0] == SWID_20886, "SWID wrong"
assert struct.unpack('<I', verify_item[0x08:0x0C])[0] == PROC_MAGIC, "proc wrong"
print("[+] Primary block encryption verified!")

# Update primary SID 0x13C
param[sid_13c_offset:sid_13c_offset + 0x1000] = new_block

# Process backup SID 0x33C
sid_33c_offset = 0x33C * 0x400
block_33c = param[sid_33c_offset:sid_33c_offset + 0x1000]
hv_b = block_33c[0]
cv_b = block_33c[1]
uc_b = struct.unpack_from('<H', block_33c, 2)[0]
print(f"\n[*] SID 0x33C (backup): hv={hv_b}, cv={cv_b}, update_counter={uc_b}")

dec_b, itemdata_b = decrypt_sid(block_33c, KEY)
if dec_b is not None:
    print(f"    Current SWID: 0x{struct.unpack('<I', itemdata_b[4:8])[0]:08X}")
    print(f"    Current proc: 0x{struct.unpack('<I', itemdata_b[8:12])[0]:08X}")

    # Apply same modifications
    struct.pack_into('<I', itemdata_b, 0x04, SWID_20886)
    struct.pack_into('<I', itemdata_b, 0x08, PROC_MAGIC)
    dec_b[0x80 + 0x04:0x80 + 0x08] = struct.pack('<I', SWID_20886)
    dec_b[0x80 + 0x08:0x80 + 0x0C] = struct.pack('<I', PROC_MAGIC)
    dec_b[0:16] = hashlib.md5(bytes(itemdata_b)).digest()

    new_block_b = encrypt_sid(dec_b, hv_b, cv_b, uc_b, KEY)
    verify_dec_b, verify_item_b = decrypt_sid(new_block_b, KEY)
    assert verify_dec_b is not None, "Backup verification failed!"
    assert struct.unpack('<I', verify_item_b[0x04:0x08])[0] == SWID_20886
    assert struct.unpack('<I', verify_item_b[0x08:0x0C])[0] == PROC_MAGIC
    print("[+] Backup block encryption verified!")

    param[sid_33c_offset:sid_33c_offset + 0x1000] = new_block_b
else:
    print("[!] Could not decrypt backup SID 0x33C, skipping")

# Write modified param back to device
print("\n[*] Writing modified param to device...")
with open('/tmp/param_modified.bin', 'wb') as f:
    f.write(param)

result = subprocess.run(
    ['adb', 'shell', f'dd of=/dev/block/sda6 bs=1048576 2>/dev/null'],
    input=bytes(param), capture_output=True
)
print(f"    dd exit code: {result.returncode}")

# Verify write
print("[*] Verifying write...")
result2 = subprocess.run(['adb', 'shell', 'dd if=/dev/block/sda6 2>/dev/null'],
                        capture_output=True)
readback = result2.stdout

rb_block = readback[sid_13c_offset:sid_13c_offset + 0x1000]
rb_dec, rb_item = decrypt_sid(rb_block, KEY)
if rb_dec is not None:
    rb_swid = struct.unpack('<I', rb_item[0x04:0x08])[0]
    rb_proc = struct.unpack('<I', rb_item[0x08:0x0C])[0]
    print(f"    Readback SWID: 0x{rb_swid:08X} ({'OK' if rb_swid == SWID_20886 else 'MISMATCH!'})")
    print(f"    Readback proc: 0x{rb_proc:08X} ({'OK' if rb_proc == PROC_MAGIC else 'MISMATCH!'})")
else:
    print("[!] Readback decryption FAILED!")

print("\n[+] Done! Reboot to test.")
print("    Expected flow: ABL reads proc=0xDC9EF893 → 'start backup to RPMB'")
print("    → writes SWID 0xB8BD9E39 (model 20886) to RPMB")
print("    → cleans proc flag → next boot uses RPMB SWID")
