#!/usr/bin/env python3
import hashlib

def sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def read(path):
    with open(path, "rb") as f:
        return f.read()

# ── devinfo ──
orig    = read("edl_backup/lun4/devinfo.bin")
patched = read("tmp/devinfo_unlocked.bin")
actual  = read("tmp/devinfo_readback_after_reboot.bin")

print("=== devinfo ===")
print(f"  原始 SHA256:     {sha256('edl_backup/lun4/devinfo.bin')}")
print(f"  预期刷入 SHA256: {sha256('tmp/devinfo_unlocked.bin')}")
print(f"  设备读回 SHA256: {sha256('tmp/devinfo_readback_after_reboot.bin')}")
print(f"  match patched?   {'YES' if actual == patched else 'NO'}")
print(f"  原始 [0x0D] is_unlocked:  0x{orig[0x0D]:02X}")
print(f"  读回 [0x0D] is_unlocked:  0x{actual[0x0D]:02X}  ({'UNLOCKED' if actual[0x0D]==1 else 'LOCKED'})")
print(f"  读回 [0x0E] is_unlock_critical: 0x{actual[0x0E]:02X}")
print(f"  读回 magic: {actual[0:13]}")

print("\n=== devinfo 逐字节差异 (readback vs original) ===")
count = 0
for i, (a, b) in enumerate(zip(actual, orig)):
    if a != b:
        print(f"  offset 0x{i:04X} ({i:4d}): orig=0x{b:02X}  readback=0x{a:02X}")
        count += 1
        if count >= 20:
            print("  ...")
            break
if count == 0:
    print("  (无差异 - 完全相同)")

# ── param ──
param_orig    = read("edl_backup/param.bin")
param_patched = read("edl_backup/param_global_patched.bin")
param_actual  = read("tmp/param_readback_after_reboot.bin")

print("\n=== param ===")
print(f"  原始 SHA256:     {sha256('edl_backup/param.bin')}")
print(f"  预期刷入 SHA256: {sha256('edl_backup/param_global_patched.bin')}")
print(f"  设备读回 SHA256: {sha256('tmp/param_readback_after_reboot.bin')}")
print(f"  match patched?   {'YES' if param_actual == param_patched else 'NO'}")
print(f"  match original?  {'YES (same as original)' if param_actual == param_orig else 'NO (different from original)'}")

diffs = sum(1 for a, b in zip(param_actual, param_patched) if a != b)
print(f"  vs patched:      {diffs} bytes different")
diffs2 = sum(1 for a, b in zip(param_actual, param_orig) if a != b)
print(f"  vs original:     {diffs2} bytes different")
