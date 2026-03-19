#!/bin/zsh
echo "=== Waiting for clean EDL connection ==="
echo "Please: unplug USB -> hold power 20s -> wait 10s -> hold Vol Up+Down -> plug USB"
echo "Will keep trying for 5 minutes..."
echo ""

START=$(date +%s)
TIMEOUT=300

while true; do
  NOW=$(date +%s)
  ELAPSED=$((NOW - START))
  if [ $ELAPSED -gt $TIMEOUT ]; then
    echo "Timed out after ${TIMEOUT}s"
    exit 1
  fi

  REMAINING=$((TIMEOUT - ELAPSED))
  RESULT=$(edl nop --devicemodel 20888 2>&1)
  if echo "$RESULT" | grep -q "Nop succeeded"; then
    echo ""
    echo "$(date '+%H:%M:%S') EDL CONNECTED! (firehose active)"
    echo ""

    echo "--- Step 1: Restoring original signed Global ABL ---"
    edl w abl_b /Users/xmxx/pinganhuijia/global_abl_padded.img --devicemodel 20888 2>&1
    echo ""

    echo "--- Step 2: Writing misc (bootonce-bootloader) ---"
    edl w misc /tmp/misc_bootloader.bin --devicemodel 20888 2>&1
    echo ""

    echo "--- Step 3: Confirming vbmeta_b (AVB disabled) ---"
    edl w vbmeta_b /Users/xmxx/pinganhuijia/edl_backup/vbmeta_b_disabled.img --devicemodel 20888 2>&1
    echo ""

    echo "--- Step 4: Confirming multiimgoem (zeroed) ---"
    edl w multiimgoem /tmp/zero_32k.bin --devicemodel 20888 2>&1
    echo ""

    echo "--- Step 5: Confirming devinfo (oem_unlock_allowed=1) ---"
    edl w devinfo /Users/xmxx/pinganhuijia/edl_backup/devinfo_unlocked.bin --devicemodel 20888 2>&1
    echo ""

    echo "=== ALL WRITES COMPLETE ==="
    echo "--- Rebooting device ---"
    edl reset --devicemodel 20888 2>&1
    echo ""
    echo "DONE! Device should boot to fastboot (misc has bootonce-bootloader)"
    echo "Run: fastboot flashing unlock"
    exit 0
  fi

  # Check if mode is sahara (not yet firehose)
  if echo "$RESULT" | grep -q "Mode detected: sahara"; then
    echo "$(date '+%H:%M:%S') [${REMAINING}s left] Sahara detected but firehose not loaded - retrying..."
  elif echo "$RESULT" | grep -q "Waiting for the device"; then
    echo "$(date '+%H:%M:%S') [${REMAINING}s left] No device yet..."
  else
    echo "$(date '+%H:%M:%S') [${REMAINING}s left] Waiting..."
  fi

  sleep 5
done
