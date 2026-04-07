#!/usr/bin/env python3
"""
recover_clean_android10.py

目标:
- 在 EDL 模式下把设备从 UBports 中途刷机残留恢复到干净 Android 10 备份状态
- 修复 crash dump/无法进入 fastboot 的状态

策略:
1) 按 LUN 顺序使用 edl wl 刷回备份
2) 清除 misc BCB
3) 校验 active slot
4) reset
"""

import os
import subprocess
import sys

BACKUP_DIR = "/Users/xmxx/pinganhuijia/edl_backup"
EDL = "edl"
DEVICE_MODEL = "20888"
SKIP_PARTS = "ALIGN_TO_128K_1,ALIGN_TO_128K_2"


def run_edl(*args, check=True):
    cmd = [EDL] + list(args) + [f"--devicemodel={DEVICE_MODEL}"]
    print("[recover] " + " ".join(cmd))
    r = subprocess.run(cmd)
    if check and r.returncode != 0:
        print(f"[recover] ERROR: exit={r.returncode}")
        sys.exit(r.returncode)


def ensure_backup_layout():
    for lun in range(6):
        p = os.path.join(BACKUP_DIR, f"lun{lun}")
        if not os.path.isdir(p):
            print(f"[recover] missing backup dir: {p}")
            return False
    return True


def main():
    print("=" * 64)
    print("  Clean Recovery To Android 10 (EDL)")
    print("=" * 64)

    if not ensure_backup_layout():
        sys.exit(1)

    # 与你之前验证过的顺序一致，先引导链后系统。
    flash_order = [3, 1, 2, 5, 4, 0]

    for i, lun in enumerate(flash_order, start=1):
        src = os.path.join(BACKUP_DIR, f"lun{lun}")
        print(f"\n[{i}/{len(flash_order)}] Flash LUN{lun}: {src}")
        if lun == 0:
            print("[recover] LUN0 包含 super.bin，大文件写入时间较长")
        run_edl("wl", src, f"--lun={lun}", f"--skip={SKIP_PARTS}", "--memory=ufs")

    print("\n[recover] Erase misc...")
    run_edl("e", "misc", "--memory=ufs")

    print("\n[recover] Check active slot...")
    run_edl("getactiveslot", "--memory=ufs", check=False)

    print("\n[recover] Reset device...")
    run_edl("reset", check=False)

    print("\n[recover] Done. Device should reboot to Android/fastboot path.")


if __name__ == "__main__":
    main()
