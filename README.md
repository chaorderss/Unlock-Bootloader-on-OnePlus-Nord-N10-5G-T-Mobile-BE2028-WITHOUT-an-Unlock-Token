[GUIDE] Unlock Bootloader on OnePlus Nord N10 5G T-Mobile (BE2028) WITHOUT an Unlock Token

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚠️ DISCLAIMER / WARNING ⚠️

- This process will FACTORY RESET your device (all data will be erased).
- Unlocking the bootloader voids your warranty.
- An unlocked bootloader means your device shows an orange warning screen on every boot — this is normal.
- I am not responsible for bricked devices, data loss, or any other damage.
- Only attempt this if you are comfortable with ADB/fastboot and understand the risks.
- This has been tested on ONE device (BE2028, T-Mobile, security patch 2021-02-01). Results may vary.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

BACKGROUND

The T-Mobile variant of the OnePlus Nord N10 5G is carrier-locked at the bootloader level. Running <b>fastboot oem unlock</b> gives you:

<pre>FAILED (remote: 'Please flash unlock token first.')</pre>

OnePlus requires a signed unlock token from T-Mobile — a process that is completely closed to regular users. This guide bypasses that requirement entirely by manipulating a single flag in the <b>param</b> partition that causes the ABL (Android Boot Loader) to write a non-T-Mobile Software Project ID into RPMB on the next boot, making the carrier check pass.

<b>No token, no EDL flashing, no hardware modification required.</b>

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

REQUIREMENTS

• OnePlus Nord N10 5G T-Mobile (BE2028, model ID 20888)
  - Security patch ≤ 2021-02 (unpatched Adreno/kernel — needed only if you
    don't already have root; if you have root another way this doesn't matter)
• USB debugging enabled
• ADB root access (<b>adb root</b> must work, i.e. ro.debuggable=1)
  - Factory engineering builds or rooted via Magisk on an earlier OTA work fine
• SELinux Permissive (or at least permissive enough to write /dev/block/sda6)
• Python 3 on your computer with pycryptodome:
<pre>pip3 install pycryptodome</pre>
• ADB + fastboot installed on your computer

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

HOW IT WORKS (brief technical summary)

The ABL carrier check reads a <b>SoftwareProjectID</b> (SWID) from RPMB. If it matches the T-Mobile model hash, it blocks the unlock. RPMB cannot be written directly from Android — but ABL has a built-in "backup" path that writes the SWID from the <b>param</b> partition into RPMB when it sees a specific magic value in a companion field (<b>sw_proj_id_proc</b>).

So we:
1. Write a non-TMO model's SWID + the magic trigger value into <b>param</b>
2. Reboot — ABL sees the magic, writes the non-TMO SWID into RPMB, and clears the flag
3. <b>fastboot oem unlock</b> now passes the carrier check → device unlocks

The magic values were extracted by decompiling the ABL binary (AARCH64 PE inside an EDK2 FV container) with Capstone.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

STEP-BY-STEP GUIDE

──────────────────────────────────────────────────────────
STEP 0 — Back up your param partition (IMPORTANT)
──────────────────────────────────────────────────────────

Before touching anything, back up <b>param</b>. If something goes wrong you can restore it.

<pre>adb root
adb shell dd if=/dev/block/sda6 2>/dev/null > param_backup.bin</pre>

Keep this file safe.

──────────────────────────────────────────────────────────
STEP 1 — Download the unlock script
──────────────────────────────────────────────────────────

Save the following as <b>write_swid3.py</b> on your computer:

<pre>#!/usr/bin/env python3
"""
OnePlus Nord N10 5G T-Mobile (BE2028) Bootloader Unlock Helper
Patches param partition SID 0x13C to trigger ABL RPMB backup path.
"""
import hashlib, struct, subprocess
from Crypto.Cipher import AES

MAGIC      = 0xA0AD646A
IV         = bytes.fromhex('562E17996D093D28DDB3BA695A2E6F58')
STATIC_KEY = bytes.fromhex('3030304F6E65506C7573383138303030')
SWID_20886 = 0xB8BD9E39   # model 20886 (non-TMO) CM hash
PROC_MAGIC = 0xDC9EF893   # ABL "backup to RPMB" trigger value

def decrypt_sid(block, key):
    magic = struct.unpack_from('&lt;I', block, 0)[0]
    if magic != MAGIC:
        return None, None
    enc = block[0x400:0x400 + 0xC00]
    if hashlib.md5(enc).digest() != block[0x80:0x90]:
        return None, None
    dec = AES.new(key, AES.MODE_CBC, IV).decrypt(enc)
    itemdata = dec[-0xB80:]
    if hashlib.md5(itemdata).digest() != dec[:16]:
        return None, None
    return bytearray(dec), bytearray(itemdata)

def encrypt_sid(dec_data, hv, cv, uc, key):
    block = bytearray(0x1000)
    struct.pack_into('&lt;I', block, 0, MAGIC)
    block[4] = hv
    block[5] = cv
    block[0x10] = (uc + 1) &amp; 0xFF
    enc = AES.new(key, AES.MODE_CBC, IV).encrypt(bytes(dec_data))
    block[0x80:0x90] = hashlib.md5(enc).digest()
    block[0x400:0x400 + 0xC00] = enc
    return bytes(block)

print("[*] Reading param from device...")
result = subprocess.run(['adb', 'shell', 'dd if=/dev/block/sda6 2>/dev/null'],
                       capture_output=True)
param = bytearray(result.stdout)
assert len(param) == 1048576, f"Unexpected size: {len(param)}"
print(f"    OK ({len(param)} bytes)")

for sid_val, name in [(0x13C, "primary"), (0x33C, "backup")]:
    offset = sid_val * 0x400
    blk = param[offset:offset + 0x1000]
    hv, cv, uc = blk[4], blk[5], blk[0x10]
    dec, item = decrypt_sid(blk, STATIC_KEY)
    assert dec is not None, f"Decrypt failed for SID 0x{sid_val:X}!"
    swid = struct.unpack('&lt;I', item[4:8])[0]
    proc = struct.unpack('&lt;I', item[8:12])[0]
    print(f"[*] SID 0x{sid_val:X} ({name}): SWID=0x{swid:08X}, proc=0x{proc:08X}")
    struct.pack_into('&lt;I', item, 4, SWID_20886)
    struct.pack_into('&lt;I', item, 8, PROC_MAGIC)
    dec[0x80:0x80+8] = item[0:8]
    dec[0:16] = hashlib.md5(bytes(item)).digest()
    param[offset:offset+0x1000] = encrypt_sid(dec, hv, cv, uc, STATIC_KEY)
    # verify roundtrip
    _, v = decrypt_sid(param[offset:offset+0x1000], STATIC_KEY)
    assert struct.unpack('&lt;I', v[4:8])[0] == SWID_20886
    assert struct.unpack('&lt;I', v[8:12])[0] == PROC_MAGIC
    print(f"    → SWID=0x{SWID_20886:08X}, proc=0x{PROC_MAGIC:08X} [verified]")

print("[*] Writing to device...")
r = subprocess.run(['adb', 'shell', 'dd of=/dev/block/sda6 bs=1048576 2>/dev/null'],
                   input=bytes(param), capture_output=True)
assert r.returncode == 0, f"Write failed! {r.stderr}"
print("[+] Done! Now run: adb reboot bootloader &amp;&amp; fastboot oem unlock")</pre>

──────────────────────────────────────────────────────────
STEP 2 — Run the script
──────────────────────────────────────────────────────────

Make sure your device is connected with adb root active:

<pre>adb root
python3 write_swid3.py</pre>

Expected output:

<pre>[*] Reading param from device...
    OK (1048576 bytes)
[*] SID 0x13C (primary): SWID=0x142F1BD7, proc=0xEFF7A27F
    → SWID=0xB8BD9E39, proc=0xDC9EF893 [verified]
[*] SID 0x33C (backup): SWID=0x142F1BD7, proc=0xEFF7A27F
    → SWID=0xB8BD9E39, proc=0xDC9EF893 [verified]
[*] Writing to device...
[+] Done! Now run: adb reboot bootloader &amp;&amp; fastboot oem unlock</pre>

If it prints "Decrypt failed" — your device may be on a different software version or the param layout differs. <b>DO NOT proceed; restore your backup.</b>

──────────────────────────────────────────────────────────
STEP 3 — Reboot to bootloader & unlock
──────────────────────────────────────────────────────────

<pre>adb reboot bootloader</pre>

Wait ~15 seconds for the fastboot screen to appear, then:

<pre>fastboot oem unlock</pre>

You should see:

<pre>OKAY [  0.024s]
Finished. Total time: 0.024s</pre>

The device will reboot, display the unlock warning screen, and perform a factory reset. This is expected. Let it complete.

──────────────────────────────────────────────────────────
STEP 4 — Verify
──────────────────────────────────────────────────────────

After the device boots into Android:

<pre>adb shell getprop ro.boot.verifiedbootstate   # should print: orange
adb shell getprop ro.boot.flash.locked        # should print: 0</pre>

Or from fastboot mode:

<pre>fastboot getvar unlocked   # should print: unlocked: yes</pre>

If you see <b>orange</b> and <b>0</b> — congratulations, your bootloader is unlocked! 🎉

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

TROUBLESHOOTING

<b>Q: Script prints "Decrypt failed for SID 0x13C"</b>
A: Your param has been modified or is on a different firmware. Restore your backup first:
<pre>adb shell dd if=- of=/dev/block/sda6 &lt; param_backup.bin</pre>

<b>Q: fastboot oem unlock still says "Please flash unlock token first"</b>
A: The reboot didn't trigger the ABL backup path. Check the ABL log:
<pre>adb shell dd if=/dev/block/by-name/abl_log 2>/dev/null | strings | grep -i "proj"</pre>
You should see "start backup spi to rpmb". If you see "check and restore" instead, the write didn't take — re-run the script and try again.

<b>Q: Device is stuck in a bootloop</b>
A: Boot to EDL mode (Vol+ + Vol- while connecting USB, or <b>adb reboot edl</b>) and restore the param backup via edl tool:
<pre>edl w param param_backup.bin</pre>

<b>Q: I don't have adb root / ro.debuggable=0</b>
A: You need an exploitable build. Security patch 2021-02-01 (the one this device shipped with) is vulnerable to CVE-2021-1905/1906 (Adreno KGSL UAF) and CVE-2021-1048 + CVE-2021-0920 (epoll + unix GC UAF). Those CVEs can be used to escalate to root from a normal shell.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

TECHNICAL DEEP DIVE

For those who want to understand exactly what's happening under the hood.

The ABL function <b>init_param_sw_prj_id</b> (disassembled from /dev/block/sde8):

<pre>1. Calls ReadParam(SID=0x13C, offset=0x88) to get sw_proj_id_proc
2. Compares it against the constant 0xDC9EF893
   - If EQUAL   → "start backup spi to rpmb"
                  Calls StoreToRPMB(ReadParam(0x13C, 0x84))
                  i.e. writes the SWID from param into RPMB
                  Then clears the proc field
   - If NOT EQUAL → "check and restore from RPMB"
                  Reads SWID from RPMB, compares with param
                  Restores param from RPMB if they differ</pre>

The carrier check (CARRIER_CHECK, called by fastboot oem unlock):
<pre>  - Computes CRC/CM hash of the model string read from RPMB
  - If hash == 0x142F1BD7 (model 20888 / T-Mobile) → BLOCKED
  - Otherwise                                       → PASS</pre>

By overwriting the SWID in RPMB with <b>0xB8BD9E39</b> (the hash for model 20886, the global/non-TMO variant), the carrier check sees a non-T-Mobile device and allows the unlock.

The param partition block format (critical — wrong values here cause silent failure):
<pre>Offset 0x000–0x003  : magic = 0xA0AD646A       ← must be present!
Offset 0x004        : hv (hw version byte)
Offset 0x005        : cv (crypto version byte)
Offset 0x010        : update counter
Offset 0x080–0x08F  : MD5(encrypted_data)      ← must be at 0x80, not 0x04!
Offset 0x400–0xFFF  : AES-128-CBC encrypted blob (0xC00 bytes)

Decrypted blob layout:
  [0x000:0x010]  inner MD5 of itemdata
  [0x010:0x080]  zero padding
  [0x080:0xC00]  itemdata (field data starts here)

Encryption key (cv=74, post-RPMB-restore state):
  static key "000OnePlus818000" = 3030304F6E65506C7573383138303030
  IV = 562E17996D093D28DDB3BA695A2E6F58</pre>

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CREDITS & REFERENCES

- bkerler / edl (https://github.com/bkerler/edl) — edl tool and oneplus_param.py which documented the param block format and key derivation scheme
- Capstone disassembly framework (https://www.capstone-engine.org/)
- Qualcomm ABL source (CodeAurora / AOSP bootloader/edk2)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

TESTED ON

| Firmware | Security patch | Result |
|----------|---------------|--------|
| OxygenOS 10 (RKQ1.201217.002) | 2021-02-01 | ✅ Success |

If you test on other firmware versions, please report back!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Q&A / DISCUSSION WELCOME

If this helped you or you ran into issues, drop a comment below.
If you're on a later security patch that patched the root exploit, and you found another way to get root first, let us know — this param write method itself should still work as long as you have root.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
