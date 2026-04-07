#!/bin/bash
# Passive monitoring - wait for natural EAPOL on busy channels
# Runs on PHONE
# Args: FREQ DURATION_SEC [PCAP_PREFIX]
FREQ="$1"
DUR="${2:-300}"
PREFIX="${3:-passive}"
DRIVER="/tmp/qca_cld3_wlan.ko"
HOME_BSSID="8C:DE:F9:B3:9E:1F"
HOME_PSK="9006609b29404a"

echo "========================================="
echo " Passive Capture: freq=$FREQ dur=${DUR}s"
echo "========================================="

wait_wlan0() {
    for i in $(seq 1 100); do
        [ -e /sys/class/net/wlan0 ] && return 0
        sleep 0.05
    done
    return 1
}

cleanup() {
    echo "[*] Cleaning up..."
    killall tcpdump 2>/dev/null
    rmmod wlan 2>/dev/null; sleep 2
    insmod "$DRIVER" 2>/dev/null
    wait_wlan0 && sleep 3
    systemctl start NetworkManager 2>/dev/null; sleep 2
    nmcli device wifi connect "$HOME_BSSID" password "$HOME_PSK" ifname wlan0 2>/dev/null
    echo "[*] WiFi restored."
}
trap cleanup EXIT

# Stop NetworkManager and load monitor mode
systemctl stop NetworkManager 2>/dev/null
killall wpa_supplicant 2>/dev/null; sleep 0.5
rmmod wlan 2>/dev/null; sleep 1
insmod "$DRIVER" con_mode_monitor=4
wait_wlan0 || { echo "[!] wlan0 not found"; exit 1; }
ip link set wlan0 up
iw dev wlan0 set freq "$FREQ"
echo "[*] Monitor mode on $FREQ MHz"

# Start capture
PCAP="/tmp/${PREFIX}_${FREQ}.pcap"
echo "[*] Capturing for ${DUR}s to $PCAP ..."
timeout "$DUR" tcpdump -i wlan0 -w "$PCAP" 2>/dev/null &
TCPID=$!

# Monitor EAPOL count every 30s
ELAPSED=0
while kill -0 $TCPID 2>/dev/null; do
    sleep 30
    ELAPSED=$((ELAPSED + 30))
    if [ -f "$PCAP" ] && [ "$(stat -c%s "$PCAP" 2>/dev/null)" -gt 24 ]; then
        ECOUNT=$(tcpdump -r "$PCAP" -nn 2>/dev/null | grep -ic "EAPOL\|802.1X" || true)
        FSIZE=$(stat -c%s "$PCAP" 2>/dev/null)
        echo "  [${ELAPSED}s] ${FSIZE}B captured, EAPOL: $ECOUNT"
        if [ "$ECOUNT" -gt 0 ]; then
            echo "  [!!!] EAPOL DETECTED!"
            kill $TCPID 2>/dev/null
            cp "$PCAP" "/tmp/handshake_passive_${FREQ}.pcap"
            break
        fi
    fi
done

wait $TCPID 2>/dev/null

# Final check
if [ -f "$PCAP" ] && [ "$(stat -c%s "$PCAP" 2>/dev/null)" -gt 24 ]; then
    ECOUNT=$(tcpdump -r "$PCAP" -nn 2>/dev/null | grep -ic "EAPOL\|802.1X" || true)
    FSIZE=$(stat -c%s "$PCAP" 2>/dev/null)
    echo ""
    echo "========================================="
    echo " RESULT: ${FSIZE}B, EAPOL: $ECOUNT"
    echo "========================================="
fi
