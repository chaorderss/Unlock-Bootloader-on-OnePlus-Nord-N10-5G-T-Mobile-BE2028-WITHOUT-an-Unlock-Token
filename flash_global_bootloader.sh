#!/bin/bash
# Backup T-Mobile bootloader partitions then flash Global equivalents
# Active slot is _b

BACKUP=/Users/xmxx/pinganhuijia/edl_backup
GLOBAL=/Users/xmxx/pinganhuijia
EDL_OPTS="--devicemodel 20888"

echo "=== Phase 1: Backup T-Mobile bootloader partitions ==="

PARTITIONS="xbl_b xbl_config_b imagefv_b tz_b hyp_b devcfg_b aop_b featenabler_b storsec_b uefisecapp_b keymaster_b qupfw_b"

for PART in $PARTITIONS; do
    BASE="${PART%_b}"
    OUT="$BACKUP/${PART}.img"
    if [ -f "$OUT" ]; then
        echo "  [SKIP] $PART - already backed up ($OUT)"
    else
        echo "  [BACKUP] $PART -> $OUT"
        edl r "$PART" "$OUT" $EDL_OPTS 2>&1 | grep -E "Read|Error|Progress|success" | tail -3
    fi
done

echo ""
echo "=== Phase 2: Flash Global bootloader partitions to _b slot ==="

# Flash in dependency order: xbl first (XBL init SMEM), then ABL, then others
FLASH_PLAN=(
    "xbl_b:global_xbl.img"
    "xbl_config_b:global_xbl_config.img"
    "imagefv_b:global_imagefv.img"
    "tz_b:global_tz.img"
    "hyp_b:global_hyp.img"
    "devcfg_b:global_devcfg.img"
    "aop_b:global_aop.img"
    "featenabler_b:global_featenabler.img"
    "storsec_b:global_storsec.img"
    "uefisecapp_b:global_uefisecapp.img"
    "keymaster_b:global_keymaster.img"
    "qupfw_b:global_qupfw.img"
    "abl_b:global_abl.img"
)

for ENTRY in "${FLASH_PLAN[@]}"; do
    PART="${ENTRY%%:*}"
    FILE="$GLOBAL/${ENTRY##*:}"
    if [ ! -f "$FILE" ]; then
        echo "  [SKIP] $FILE not found"
        continue
    fi
    echo "  [FLASH] $PART <- $FILE ($(wc -c < "$FILE") bytes)"
    edl w "$PART" "$FILE" $EDL_OPTS 2>&1 | grep -E "Wrote|Error|Progress|success" | tail -3
    if [ $? -ne 0 ]; then
        echo "  [ERROR] Failed to flash $PART - aborting!"
        exit 1
    fi
done

echo ""
echo "=== Phase 3: Flash devinfo with OEM unlock enabled ==="
edl w devinfo "$BACKUP/devinfo_unlocked.bin" $EDL_OPTS 2>&1 | grep -E "Wrote|Error|success" | tail -3

echo ""
echo "=== All done! Rebooting... ==="
edl reset $EDL_OPTS 2>&1 | tail -3
