#!/bin/bash
# Diagnostic devinfo flash & verify script
# Run this with the device in EDL mode

set -e
EDL="/Library/Frameworks/Python.framework/Versions/3.14/bin/edl"
DIR="/Users/xmxx/pinganhuijia"
TMP="$DIR/tmp"

echo "=== Step 1: Backup current devinfo ==="
$EDL r devinfo "$TMP/devinfo_before_test.bin" --lun=4
echo "Current devinfo byte 0x0D (is_unlocked):"
xxd -s 0x0D -l 4 "$TMP/devinfo_before_test.bin"

echo ""
echo "=== Step 2: Flash diagnostic devinfo ==="
$EDL w devinfo "$TMP/devinfo_diagnostic.bin" --lun=4 --devicemodel 20888

echo ""
echo "=== Step 3: Verify flash ==="
$EDL r devinfo "$TMP/devinfo_readback_pre.bin" --lun=4
echo "Readback verification:"
xxd -s 0x0D -l 4 "$TMP/devinfo_readback_pre.bin"
echo "End marker:"
xxd -s 0xFFC -l 4 "$TMP/devinfo_readback_pre.bin"

echo ""
echo "=== Step 4: Reset device ==="
echo "After reset, hold Volume Down to enter fastboot mode."
echo "Then run: fastboot oem device-info"
echo ""
echo "Press Enter to reset device..."
read
$EDL reset

echo ""
echo "=== After fastboot check, reconnect EDL and run: ==="
echo "  $EDL r devinfo $TMP/devinfo_readback_post.bin --lun=4"
echo "  python3 $TMP/analyze_diagnostic.py"
