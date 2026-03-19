#!/usr/bin/env python3
import hashlib, sys

def sha256(data): return hashlib.sha256(data).hexdigest()[:16]

files = {
    "devinfo": {
        "original": "/Users/xmxx/pinganhuijia/edl_backup/lun4/devinfo.bin",
        "flashed":  "/Users/xmxx/pinganhuijia/tmp/devinfo_unlocked.bin",
        "readback": "/Users/xmxx/pinganhuijia/tmp/devinfo_readback.bin",
    },
    "param": {
        "original": "/Users/xmxx/pinganhuijia/edl_backup/param.bin",
        "flashed":  "/Users/xmxx/pinganhuijia/edl_backup/param_global_patched.bin",
        "readback": "/Users/xmxx/pinganhuijia/tmp/param_readback.bin",
    },
}

for name, paths in files.items():
    print(f"\n{'='*60}")
    print(f"  {name.upper()} partition")
    print(f"{'='*60}")
    orig   = open(paths["original"], "rb").read()
    flashed= open(paths["flashed"],  "rb").read()
    rb     = open(paths["readback"], "rb").read()

    print(f"  original  size={len(orig):8d}  sha256={sha256(orig)}")
    print(f"  flashed   size={len(flashed):8d}  sha256={sha256(flashed)}")
    print(f"  readback  size={len(rb):8d}  sha256={sha256(rb)}")

    if rb == flashed:
        print(f"  ✅ 刷入成功: readback == flashed")
    elif rb == orig:
        print(f"  ❌ 刷入失败: readback == original (未变化)")
    else:
        # partial match check
        match_flashed = sum(a==b for a,b in zip(rb, flashed))
        match_orig    = sum(a==b for a,b in zip(rb, orig))
        print(f"  ⚠️  readback 与 flashed/original 都不完全一致")
        print(f"     与 flashed 相同字节: {match_flashed}/{min(len(rb),len(flashed))}")
        print(f"     与 original 相同字节: {match_orig}/{min(len(rb),len(orig))}")
        # show diffs vs flashed
        diffs = [(i, orig[i] if i<len(orig) else None, flashed[i] if i<len(flashed) else None, rb[i] if i<len(rb) else None)
                 for i in range(min(len(rb),len(flashed),len(orig)))
                 if not (rb[i]==flashed[i])]
        if diffs:
            print(f"\n  Diff vs flashed (first 30 positions where readback != flashed):")
            print(f"  {'offset':>8}  {'orig':>6}  {'flashed':>8}  {'readback':>9}")
            for off, o, fl, rd in diffs[:30]:
                flag = " ← UNLOCK FLAG" if off == 0x0D and name=="devinfo" else ""
                print(f"  0x{off:06x}  0x{o:02x}    0x{fl:02x}      0x{rd:02x}{flag}")
            if len(diffs) > 30:
                print(f"  ... and {len(diffs)-30} more differences")

    # special: always show devinfo critical bytes
    if name == "devinfo":
        print(f"\n  DevInfo critical bytes (readback):")
        print(f"    [0x00-0x0C] magic     = {rb[0:13]}")
        print(f"    [0x0D]  is_unlocked   = 0x{rb[0x0D]:02x}  {'✅ UNLOCKED' if rb[0x0D]==1 else '❌ LOCKED'}")
        print(f"    [0x0E]  is_unlock_crit= 0x{rb[0x0E]:02x}")
        print(f"    [0x0F]  charger_screen= 0x{rb[0x0F]:02x}")
