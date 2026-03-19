#!/bin/zsh
echo "Waiting for EDL device to flash PATCHED ABL..."
while true; do
  if edl nop --devicemodel 20888 2>&1 | grep -q "Nop succeeded"; then
    echo "EDL CONNECTED!"
    break
  fi
  echo "$(date '+%H:%M:%S') waiting..."
  sleep 3
done

echo "--- Flashing patched ABL to abl_b ---"
edl w abl_b /Users/xmxx/pinganhuijia/global_abl_patched_padded.img --devicemodel 20888 2>&1 | grep -E "Wrote|Error"

echo "--- Writing misc (bootonce-bootloader for fastboot) ---"
edl w misc /tmp/misc_bootloader.bin --devicemodel 20888 2>&1 | grep -E "Wrote|Error"

echo "--- Confirming vbmeta_b (AVB disabled) ---"
edl w vbmeta_b /Users/xmxx/pinganhuijia/edl_backup/vbmeta_b_disabled.img --devicemodel 20888 2>&1 | grep -E "Wrote|Error"

echo "--- Confirming multiimgoem (zeroed) ---"
edl w multiimgoem /tmp/zero_32k.bin --devicemodel 20888 2>&1 | grep -E "Wrote|Error"

echo "--- Confirming devinfo (oem_unlock_allowed=1) ---"
edl w devinfo /Users/xmxx/pinganhuijia/edl_backup/devinfo_unlocked.bin --devicemodel 20888 2>&1 | grep -E "Wrote|Error"

echo "=== ALL DONE - Rebooting to fastboot ==="
edl reset --devicemodel 20888 2>&1 | tail -3
echo "Device should boot directly to fastboot!"
echo "Run: fastboot flashing unlock"
