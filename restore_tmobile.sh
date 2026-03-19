#!/bin/zsh
OPTS="--devicemodel 20888"
B=/Users/xmxx/pinganhuijia/edl_backup

echo "=== 等待 EDL ==="
while ! edl nop $OPTS 2>&1 | grep -q "Nop succeeded"; do
  echo "$(date '+%H:%M:%S') 等待..."; sleep 3
done
echo "EDL 已连接！开始恢复 T-Mobile 原版分区..."

for PART in xbl_b xbl_config_b imagefv_b tz_b hyp_b devcfg_b aop_b featenabler_b storsec_b uefisecapp_b keymaster_b qupfw_b abl_b; do
  if [ -f "$B/${PART}.img" ]; then
    echo "--- 恢复 $PART ---"
    edl w "$PART" "$B/${PART}.img" $OPTS 2>&1 | grep -E "Wrote|Error"
  else
    echo "[跳过] $PART 备份不存在"
  fi
done

echo "--- 恢复 vbmeta_b (原版 AVB 启用) ---"
edl w vbmeta_b "$B/vbmeta_b.img" $OPTS 2>&1 | grep -E "Wrote|Error"

echo "--- 恢复 boot_b (原版) ---"
edl w boot_b "$B/boot_b.img" $OPTS 2>&1 | grep -E "Wrote|Error"

echo "--- 恢复 devinfo (原版) ---"
edl w devinfo "$B/devinfo.bin.original" $OPTS 2>&1 | grep -E "Wrote|Error"

echo "=== 恢复完成，重启 ==="
edl reset $OPTS 2>&1 | tail -3
echo "手机应恢复到完整的 T-Mobile 原始状态"
