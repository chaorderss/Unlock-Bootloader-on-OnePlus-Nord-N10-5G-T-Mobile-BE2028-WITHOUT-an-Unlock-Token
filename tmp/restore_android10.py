#!/usr/bin/env python3
"""
restore_android10.py
从 edl_backup/ 恢复 Android 10 完整备份到 OnePlus Nord N10 5G (billie)

说明:
  - 使用 edl_backup/lun0-5/ 中的所有备份文件
  - 跳过 userdata.bin (备份中无此文件, 通过 erase 单独清空)
  - 使用备份中的 param.bin (解锁后状态, RPMB SWID 不受影响)
  - devinfo.bin 来自解锁后的备份, 保持 BL 解锁状态
"""
import os
import sys
import subprocess

BACKUP_DIR    = "/Users/xmxx/pinganhuijia/edl_backup"
EDL           = "edl"
DEVICE_MODEL  = "20886"


def log(msg):
    print(f"[restore] {msg}")


def run_edl(*args, check=True):
    cmd = [EDL] + list(args) + [f"--devicemodel={DEVICE_MODEL}"]
    log("run: " + " ".join(cmd))
    result = subprocess.run(cmd)
    if check and result.returncode != 0:
        log(f"ERROR: 命令失败 exit={result.returncode}")
        sys.exit(1)
    return result


def preflight():
    """检查所有关键备份文件"""
    checks = [
        ("lun0/super.bin",    "Android 10 system (super)"),
        ("lun0/param.bin",    "param (SWID/proc, 解锁后)"),
        ("lun0/persist.bin",  "persist (校准数据)"),
        ("lun1/xbl_a.bin",    "XBL bootloader slot-a"),
        ("lun2/xbl_b.bin",    "XBL bootloader slot-b"),
        ("lun4/boot_a.bin",   "boot_a (Android 10 kernel)"),
        ("lun4/modem_a.bin",  "modem_a (基带)"),
        ("lun4/abl_a.bin",    "abl_a (ABL)"),
        ("lun4/devinfo.bin",  "devinfo (BL 解锁状态)"),
        ("lun5/modemst1.bin", "modemst1 (EFS)"),
    ]
    ok = True
    for rel, desc in checks:
        full = os.path.join(BACKUP_DIR, rel)
        if os.path.exists(full):
            size_mb = os.path.getsize(full) / (1024 * 1024)
            log(f"  ✓ {desc:40s} {size_mb:.1f} MB")
        else:
            log(f"  ✗ MISSING: {desc} ({rel})")
            ok = False
    return ok


def main():
    print("=" * 65)
    print("  Android 10 完整 EDL 恢复  -  OnePlus Nord N10 5G (billie)")
    print("=" * 65)
    print(f"  备份目录: {BACKUP_DIR}")
    print()

    # 检查备份目录
    for lun in range(6):
        d = os.path.join(BACKUP_DIR, f"lun{lun}")
        if not os.path.isdir(d):
            log(f"ERROR: 备份目录不存在: {d}")
            sys.exit(1)

    log("检查关键备份文件...")
    if not preflight():
        log("ERROR: 部分关键文件缺失, 中止!")
        sys.exit(1)

    print()
    print("  !! 重要说明 !!")
    print("  - 刷回 Android 10 备份 (2026-03-18)")
    print("  - Android 11 的所有更改将被完全覆盖")
    print("  - userdata (用户数据) 将被完全清空 (wipe)")
    print("  - param.bin 使用备份版本 (解锁后状态, RPMB SWID 不变)")
    print("  - devinfo.bin 来自备份 = Bootloader UNLOCKED 状态")
    print("  - RPMB 中的 BE2026 SWID 不受 EDL 影响, 保持不变")
    print()
    ans = input("  确认继续? 输入 'yes' 开始: ").strip().lower()
    if ans != "yes":
        print("已取消.")
        sys.exit(0)

    print()
    # 不再需要 rawprogram XML — 改用 edl wl 按目录刷写
    # edl wl 会自动匹配文件名到 GPT 分区名, 跳过 gpt_* 和 *.xml

    # 需要跳过的非分区文件 (ALIGN 填充文件等)
    SKIP_PARTS = "ALIGN_TO_128K_1,ALIGN_TO_128K_2"

    log("准备完毕. 请现在让设备进入 EDL 模式:")
    log("  方法: 在另一个终端运行:  adb reboot edl")
    log("  等待 USB 枚举为 9008 (手机 LED 熄灭或变红)")
    print()
    input("  设备已进入 EDL 后按 ENTER 继续...")
    print()

    # 刷写顺序:
    # 3: cdt/ddr (平台基础)
    # 1: xbl_a   (slot-a bootloader)
    # 2: xbl_b   (slot-b bootloader)
    # 5: modemst1/2 + fsg/fsc (EFS modem storage)
    # 4: abl/tz/hyp/boot/recovery/modem/dtbo 等所有 slot 分区
    # 0: super (Android 10 system) + param + persist + misc 等
    flash_order = [3, 1, 2, 5, 4, 0]

    total = len(flash_order)
    done  = 0

    for lun in flash_order:
        done += 1
        src_dir = os.path.join(BACKUP_DIR, f"lun{lun}")
        print()
        print(f"  [{done}/{total}] LUN{lun} 刷写中...")

        # lun0 有 super.bin (14GB), 会耗时较长
        if lun == 0:
            log("  ⚠ LUN0 包含 super.bin (14GB), 预计耗时 15-20 分钟, 请勿断开!")

        # edl wl <directory> --lun=<N> --memory=ufs --skip=<non-partition files>
        # wl 会: 1) 调用 writeprepare() 完成 OnePlus setprocstart 认证
        #        2) 读取设备 GPT, 自动匹配文件名→分区名
        #        3) 跳过 gpt_* 和 *.xml 文件
        run_edl(
            "wl",
            src_dir,
            f"--lun={lun}",
            f"--skip={SKIP_PARTS}",
            "--memory=ufs",
        )

    # 清除 misc 中的 BCB (备份中可能残留 bootonce-bootloader 指令)
    print()
    log("清除 misc 分区 BCB 指令...")
    run_edl("e", "misc", "--memory=ufs")

    # 清空 userdata
    print()
    log("清空 userdata 分区...")
    run_edl("e", "userdata", "--memory=ufs")

    # 重启
    print()
    log("重启设备...")
    run_edl("reset")

    print()
    print("=" * 65)
    print("  恢复完成! 设备正在重启至 Android 10.")
    print("  首次启动可能需要 3-5 分钟, 请耐心等待.")
    print("  注意: 所有用户数据已清除, 需要重新设置.")
    print("=" * 65)


if __name__ == "__main__":
    main()
