#!/bin/bash
# Setup monitor mode + kpatch on the device
# Run via: adb push setup_monitor.sh /tmp/ && adb shell 'chmod +x /tmp/setup_monitor.sh && sudo /tmp/setup_monitor.sh'
set -e

echo "=== Step 1: Bind mount patched driver ==="
mount --bind /tmp/qca_cld3_wlan_p4.ko /android/vendor/lib/modules/qca_cld3_wlan.ko
echo "Bind mount OK"

echo "=== Step 2: Load driver ==="
insmod /android/vendor/lib/modules/qca_cld3_wlan.ko
echo "Driver loaded"

echo "=== Step 3: Switch to monitor mode ==="
sleep 2
echo 4 > /sys/module/wlan/parameters/con_mode
sleep 1
echo "Monitor mode set"

echo "=== Step 4: Build and load kpatch ==="
cd /tmp
as -o kpatch2.o kpatch2.S
ld -r -o kpatch2.ko kpatch2.o
insmod kpatch2.ko
echo "kpatch loaded"

echo "=== Step 5: Set channel 1 (2412 MHz) ==="
iw dev wlan0 set freq 2412 2>/dev/null || true

echo "=== Done ==="
iw dev wlan0 info
dmesg | grep kpatch | tail -5
