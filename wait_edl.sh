#!/bin/zsh
echo "Waiting for EDL device..."
while true; do
  if edl nop --devicemodel 20888 2>&1 | grep -q "Nop succeeded"; then
    echo "EDL CONNECTED!"
    break
  fi
  echo "$(date '+%H:%M:%S') waiting..."
  sleep 3
done

echo "--- Writing misc (bootonce-bootloader) ---"
edl w misc /tmp/misc_bootloader.bin --devicemodel 20888 2>&1 | grep -E "Wrote|Error|NAK|succeeded"

echo "--- Writing vbmeta_b (AVB disabled) ---"
edl w vbmeta_b /Users/xmxx/pinganhuijia/edl_backup/vbmeta_b_disabled.img --devicemodel 20888 2>&1 | grep -E "Wrote|Error|NAK|succeeded"

echo "--- Zeroing multiimgoem ---"
edl w multiimgoem /tmp/zero_32k.bin --devicemodel 20888 2>&1 | grep -E "Wrote|Error|NAK|succeeded"

echo "--- Writing devinfo (oem_unlock_allowed=1) ---"
edl w devinfo /Users/xmxx/pinganhuijia/edl_backup/devinfo_unlocked.bin --devicemodel 20888 2>&1 | grep -E "Wrote|Error|NAK|succeeded"

echo "--- ALL WRITES DONE - Rebooting ---"
edl reset --devicemodel 20888 2>&1 | tail -3
echo "Done. Hold Vol Down to enter fastboot!"
