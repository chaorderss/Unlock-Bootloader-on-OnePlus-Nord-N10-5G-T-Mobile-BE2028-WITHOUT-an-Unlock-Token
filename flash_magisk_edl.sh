#!/bin/zsh
set -e
OPTS="--devicemodel 20888"
BASE=/Users/xmxx/pinganhuijia

echo "=== 等待 EDL 设备 ==="
while ! edl nop $OPTS 2>&1 | grep -q "Nop succeeded"; do
  echo "$(date '+%H:%M:%S') 等待 EDL..."
  sleep 3
done
echo "EDL 已连接！"

echo "--- 1/3 刷入 Magisk-patched boot_b ---"
edl w boot_b "$BASE/magisk_patch/new-boot.img" $OPTS 2>&1 | grep -E "Wrote|Error|success"

echo "--- 2/3 刷入禁用 AVB 的 vbmeta_b ---"
edl w vbmeta_b "$BASE/edl_backup/vbmeta_b_disabled.img" $OPTS 2>&1 | grep -E "Wrote|Error|success"

echo "--- 3/3 刷入 devinfo (OEM unlock=1) ---"
edl w devinfo "$BASE/edl_backup/devinfo_unlocked.bin" $OPTS 2>&1 | grep -E "Wrote|Error|success"

echo "=== 全部完成，重启中 ==="
edl reset $OPTS 2>&1 | tail -3
echo ""
echo "设备将正常启动，启动后："
echo "1. 安装 Magisk APP（从 magisk_patch/stub.apk）"
echo "2. Magisk APP 会检测到已安装并完成初始化"
