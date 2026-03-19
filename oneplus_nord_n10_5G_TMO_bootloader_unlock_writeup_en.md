# OnePlus Nord N10 5G T-Mobile Bootloader Unlock — Full Technical Writeup

> **Device:** OnePlus Nord N10 5G (BE2028, T-Mobile, model ID 20888)
> **Result:** `fastboot getvar unlocked` → **yes** · `ro.boot.verifiedbootstate` = **orange**

---

## Table of Contents

1. [Background & Prerequisites](#1-background--prerequisites)
2. [High-Level Strategy](#2-high-level-strategy)
3. [Phase 1 — Root Access & Initial Recon](#3-phase-1--root-access--initial-recon)
4. [Phase 2 — Reverse Engineering ABL Unlock Logic](#4-phase-2--reverse-engineering-abl-unlock-logic)
5. [Phase 3 — Understanding the param Partition Structure](#5-phase-3--understanding-the-param-partition-structure)
6. [Phase 4 — Finding the SID 0x13C Encryption Key](#6-phase-4--finding-the-sid-0x13c-encryption-key)
7. [Phase 5 — Finding Critical Constants (proc Magic & SWID Hash)](#7-phase-5--finding-critical-constants-proc-magic--swid-hash)
8. [Phase 6 — First Write Attempt (Failure)](#8-phase-6--first-write-attempt-failure)
9. [Phase 7 — Root Cause Analysis: Wrong Block Format](#9-phase-7--root-cause-analysis-wrong-block-format)
10. [Phase 8 — Final Write & Successful Unlock](#10-phase-8--final-write--successful-unlock)
11. [Key Values Reference](#11-key-values-reference)
12. [Complete Unlock Script (write_swid3.py)](#12-complete-unlock-script-write_swid3py)

---

## 1. Background & Prerequisites

The T-Mobile variant of the OnePlus Nord N10 5G (BE2028, model ID 20888) rejects `fastboot oem unlock` with:

```
FAILED (remote: 'Please flash unlock token first.')
```

The ABL (Android Bootloader) contains a carrier-lock check: when it detects the device is a T-Mobile unit, it requires a signed unlock token obtained from OnePlus/T-Mobile — a channel that is closed to end users.

**Prerequisites:**

- USB debugging enabled on the device
- `adb root` works (`ro.debuggable=1`)
- SELinux in Permissive mode
- macOS host with `adb`, `fastboot`, `python3`, `pycryptodome`, `capstone`

---

## 2. High-Level Strategy

```
fastboot oem unlock
  ├─ Check IsAllowUnlock
  ├─ BL CARRIER_CHECK
  │   ├─ Model ≠ T-Mobile  →  pass (unlock proceeds)
  │   └─ Model == T-Mobile →  check RPMB SoftwareProjectID (SWID)
  │       ├─ SWID ≠ model-20888 CM hash  →  pass (treated as non-TMO)
  │       └─ SWID == model-20888 CM hash →  "Please flash unlock token first"
  └─ Pass → execute unlock
```

**The exploit chain:**

The RPMB `SoftwareProjectID` is seeded from the `param` partition SID 0x13C. ABL has a built-in "backup to RPMB" path that fires when it reads `sw_proj_id_proc == 0xDC9EF893`. When triggered, ABL writes the current SWID from param into RPMB and clears the proc flag.

So the full chain is:

```
Patch param partition SID 0x13C
  →  SWID = 0xB8BD9E39  (model 20886, non-TMO CM hash)
  →  proc = 0xDC9EF893  (magic constant that triggers ABL "backup to RPMB")
  →  Reboot
  →  ABL writes SWID 0xB8BD9E39 into RPMB
  →  fastboot oem unlock → OKAY
```

---

## 3. Phase 1 — Root Access & Initial Recon

```bash
adb root
adb shell id          # uid=0(root)
adb shell getenforce  # Permissive

adb shell getprop ro.product.model                    # BE2028
adb shell getprop ro.build.version.security_patch     # 2021-02-01
adb shell getprop ro.product.name                     # OnePlusNord N10 5G
```

Back up critical partitions:

```bash
# param partition (1 MB) — /dev/block/sda6
adb shell dd if=/dev/block/sda6 2>/dev/null > edl_backup/param_original.bin

# ABL partition (8 MB) — /dev/block/sde8
adb shell dd if=/dev/block/sde8 2>/dev/null > /tmp/abl_a.bin
```

Three world-writable high-value device nodes identified:

| Node | Permissions | Purpose |
|------|------------|---------|
| `/dev/kgsl-3d0` | rw-rw-rw- | Adreno GPU driver |
| `/dev/qseecom`  | rw-rw-rw- | TrustZone interface |
| `/dev/diag`     | rw-rw-rw- | Qualcomm diagnostics |

---

## 4. Phase 2 — Reverse Engineering ABL Unlock Logic

### 4.1 Extracting the ABL Binary

The `abl_a` partition stores a compressed AARCH64 PE image inside an EDK2 Firmware Volume (FV) container.

```bash
# Parse the FV structure to find the LZMA-compressed PE blob
python3 tmp/parse_fv2.py
# → /tmp/abl_dec.bin  (1,872,072 bytes, AARCH64 PE)
```

ABL PE layout:

| Section | RVA | Size | Notes |
|---------|-----|------|-------|
| .text | 0x1000 | 0x69000 | Code + embedded strings |
| .data | 0x6A000 | 0x15E000 | Global variables |
| .reloc | 0x1C8000 | 0x1000 | |

MZ header is at offset 0xB8 within the decompressed blob; imageBase = 0.

### 4.2 Locating Key Functions

Install the disassembler:

```bash
pip3 install capstone pycryptodome
```

Search embedded log strings in the binary to find the relevant function:

```
"sw_proj_id_proc:"        →  RVA 0x4C0E6
"start backup spi"        →  RVA 0x4C12E
"check and restore"       →  RVA 0x4C163
"Software ID equals!"     →  RVA 0x4C17B
```

Cross-referencing those strings via ADRP+ADD pairs (20-instruction search window) leads to `init_param_sw_prj_id`, whose core logic sits around RVA **0x35900–0x36000**.

### 4.3 Key Disassembly

**proc magic comparison (RVA 0x35C88):**

```asm
mov  w8, #0xf893
movk w8, #0xdc9e, lsl #16     ; w8 = 0xDC9EF893
cmp  w20, w8                   ; w20 = ReadParam(0x13C, 0x88) = proc
b.ne #0x35d24                  ; ≠  →  "check and restore from RPMB"
                               ; =  →  "start backup spi to rpmb"
```

**ReadParam calls confirming the offset mapping:**

```asm
; Read sw_proj_id_proc
bl #0x32AB0   ; ReadParam(SID=0x13C, offset=0x88, &buf, size=4)

; Read SoftwareProjectID
bl #0x32AB0   ; ReadParam(SID=0x13C, offset=0x84, &buf, size=4)
```

**Control flow summary:**

```
proc == 0xDC9EF893
  →  StoreToRPMB(SWID)        ←  this is the path we want
  →  clear proc flag

proc != 0xDC9EF893
  →  ReadFromRPMB(SWID)
  →  compare param SWID vs RPMB SWID
  →  if mismatch: overwrite param with RPMB value
     ("Software ID equals!" means they matched)
```

---

## 5. Phase 3 — Understanding the param Partition Structure

The param partition (1 MB) is indexed by SID number. Each SID occupies 0x1000 bytes at offset `SID × 0x400`.

**SID block layout (0x1000 bytes):**

```
block[0x000:0x004]    magic = 0xA0AD646A  (uint32 LE)   ← MUST be present
block[0x004]          hv     (hw_version)
block[0x005]          cv     (crypto_version)
block[0x010]          updatecounter
block[0x080:0x090]    outer_md5 = MD5(encrypted_data)   ← MUST be at 0x80
block[0x400:0x1000]   AES-CBC encrypted data  (0xC00 bytes)
```

**Decrypted data layout (0xC00 bytes):**

```
dec[0x000:0x010]    inner_md5 = MD5(itemdata)
dec[0x010:0x080]    zero padding  (0x70 bytes)
dec[0x080:0xC00]    itemdata  (0xB80 bytes)
```

**SID 0x13C itemdata field mapping:**

| ReadParam offset | itemdata offset | Field | Original value |
|-----------------|----------------|-------|---------------|
| 0x80 | itemdata[0x00] | supported_flag | 1 |
| 0x84 | itemdata[0x04] | SoftwareProjectID (SWID) | 0x142F1BD7 |
| 0x88 | itemdata[0x08] | sw_proj_id_proc | 0xEFF7A27F |

---

## 6. Phase 4 — Finding the SID 0x13C Encryption Key

The edl tool (`oneplus_param.py`) implements two key modes:

```python
# cv == 1  →  static key ("000OnePlus818000")
STATIC_KEY = bytes.fromhex('3030304F6E65506C7573383138303030')

# cv == 2  →  SoC-serial-derived key
serial = 0x75655d5b   # obtained from ABL log / ADB
seed   = bytes.fromhex("a9264fbf8a" + "%08x" % serial + "6b4487ea")[:0x1A]
DERIVED_KEY = hashlib.sha256(seed).digest()[:16]
# → 1b1d3b58148c316a1cca1cc298074b9e
```

After an RPMB restore, ABL re-encrypts SID 0x13C using the **static key** (cv changes from 2 to 74). Therefore our write must also use the **static key**.

Verify correct decryption:

```python
dec = AES.new(STATIC_KEY, AES.MODE_CBC, IV).decrypt(enc)
assert hashlib.md5(dec[-0xB80:]).digest() == dec[:16]   # inner MD5 must match
```

---

## 7. Phase 5 — Finding Critical Constants (proc Magic & SWID Hash)

### proc magic constant

Read directly from the disassembly at RVA 0x35C88:

```
proc_magic = 0xDC9EF893
```

### model 20886 CM hash (SWID)

Read from edl tool source (`oneplus.py`, line 87):

```python
"20886": dict(cm="b8bd9e39")
# SWID_20886 = 0xB8BD9E39
```

---

## 8. Phase 6 — First Write Attempt (Failure)

`write_swid2.py` had two critical bugs that caused ABL to reject the block and restore from RPMB.

### Bug 1 — Missing magic number

```python
# ❌ Wrong: magic never written, hv/cv at wrong byte offsets
block[0] = hv
block[1] = cv

# ✅ Correct
struct.pack_into('<I', block, 0, 0xA0AD646A)
block[4] = hv
block[5] = cv
```

ABL's `decryptsid` checks `if magic != 0xA0AD646A: return None` as its very first operation. A missing magic aborts decryption entirely.

### Bug 2 — outer MD5 at wrong offset

```python
# ❌ Wrong: MD5 placed at block[4:20]
block[4:20] = hashlib.md5(enc).digest()

# ✅ Correct: MD5 belongs at block[0x80:0x90]
block[0x80:0x90] = hashlib.md5(enc).digest()
```

### Symptom

Every boot entry in the ABL log showed:

```
init_param_sw_prj_id[00000893] sw_proj_id_proc: 0
init_param_sw_prj_id[000008B1] Process: check and restore software ID from RPMB
init_param_sw_prj_id[000008C6] Software ID equals!
GetParamSoftwareProjectID 0
androidboot.swprojid=20888
```

Despite the write being verified by readback, ABL discarded our block due to the bad magic, fell back to RPMB, and restored the original values.

---

## 9. Phase 7 — Root Cause Analysis: Wrong Block Format

### Diagnosis

After reboot, `check_param2.py` re-read the param partition:

```
SID 0x13C: magic OK, outer MD5 MATCH, static key → Inner MD5 MATCH
  SWID = 0x142F1BD7   ← restored by ABL from RPMB
  proc = 0xEFF7A27F   ← restored by ABL from RPMB
  hv=0, cv=74         ← ABL's re-encryption parameters
```

ABL had completely overwritten our modified block. The readback we verified earlier was our written data, but ABL discarded it at runtime and written back the RPMB copy.

### Cross-referencing with the edl tool

Comparing `write_swid2.py`'s `encrypt_sid` function against the edl tool's `encryptsid` in `oneplus_param.py` immediately revealed both bugs:

```python
# edl tool (correct):
siddata[:4+1+1] = pack("<IBB", magic, hv, cv)   # magic at 0:4, hv at 4, cv at 5
siddata[0x10] = updatecounter + 1
# ...
siddata[0x80:0x90] = genenchash                  # outer MD5 at 0x80
```

---

## 10. Phase 8 — Final Write & Successful Unlock

Run the fixed script:

```bash
python3 tmp/write_swid3.py
```

Output:

```
[*] Reading param partition from device...
    Size: 1048576 bytes OK

[*] SID 0x13C (primary): hv=0, cv=74, uc=250
    Current: supported=1, SWID=0x142F1BD7, proc=0xEFF7A27F
    New: SWID=0xB8BD9E39, proc=0xDC9EF893 [verified]

[*] SID 0x33C (backup): hv=0, cv=74, uc=250
    Current: supported=1, SWID=0x142F1BD7, proc=0xEFF7A27F
    New: SWID=0xB8BD9E39, proc=0xDC9EF893 [verified]

[*] Writing modified param to device...
    dd exit code: 0
[*] Verifying write by readback...
    SID 0x13C: SWID=0xB8BD9E39 (OK), proc=0xDC9EF893 (OK)
    SID 0x33C: SWID=0xB8BD9E39 (OK), proc=0xDC9EF893 (OK)

[+] Done! Ready to reboot.
```

Reboot to bootloader and unlock:

```bash
adb reboot bootloader
sleep 15
fastboot oem unlock
# OKAY [  0.024s]
# Finished. Total time: 0.024s
```

Verify:

```bash
fastboot getvar unlocked
# unlocked: yes

# After rebooting to Android:
adb shell getprop ro.boot.verifiedbootstate   # orange
adb shell getprop ro.boot.flash.locked        # 0
```

**Bootloader successfully unlocked.**

---

## 11. Key Values Reference

| Name | Value |
|------|-------|
| Device model | BE2028, model ID 20888 (T-Mobile) |
| SoC serial | 0x75655d5b |
| Target model (non-TMO) | 20886 |
| Static AES key | `3030304F6E65506C7573383138303030` ("000OnePlus818000") |
| AES IV | `562E17996D093D28DDB3BA695A2E6F58` |
| proc magic | `0xDC9EF893` (ABL "backup to RPMB" trigger) |
| model 20886 CM hash (SWID) | `0xB8BD9E39` |
| param block device | `/dev/block/sda6` |
| ABL block device | `/dev/block/sde8` |
| SID 0x13C primary offset | `0x13C × 0x400 = 0x4F000` |
| SID 0x33C backup offset | `0x33C × 0x400 = 0xCF000` |

---

## 12. Complete Unlock Script (write_swid3.py)

Script located at `tmp/write_swid3.py`. Core logic:

```python
MAGIC      = 0xA0AD646A
IV         = bytes.fromhex('562E17996D093D28DDB3BA695A2E6F58')
STATIC_KEY = bytes.fromhex('3030304F6E65506C7573383138303030')

SWID_20886 = 0xB8BD9E39   # model 20886 CM hash (non-T-Mobile)
PROC_MAGIC = 0xDC9EF893   # ABL "backup to RPMB" trigger


def encrypt_sid(dec_data, hv, cv, updatecounter, key):
    block = bytearray(0x1000)

    # 1. Write magic, hv, cv  (previously missing — root cause of failure)
    struct.pack_into('<I', block, 0, MAGIC)
    block[4] = hv
    block[5] = cv
    block[0x10] = (updatecounter + 1) & 0xFF

    # 2. Encrypt
    enc = AES.new(key, AES.MODE_CBC, IV).encrypt(bytes(dec_data))

    # 3. outer MD5 at 0x80  (previously placed at 0x04 — root cause of failure)
    block[0x80:0x90] = hashlib.md5(enc).digest()
    block[0x400:0x400 + 0xC00] = enc
    return bytes(block)


# For both SID 0x13C (primary) and SID 0x33C (backup):
#   1. Decrypt with static key
#   2. Patch itemdata[0x04] = SWID_20886
#      Patch itemdata[0x08] = PROC_MAGIC
#   3. Recompute inner MD5
#   4. Re-encrypt
#   5. Write back to /dev/block/sda6
```

**Run once, then `fastboot oem unlock` succeeds immediately.**

---

*Written: 2026-03-20*
