#!/bin/bash
# run_fuzz5.sh - Run scm_fuzz5 advanced attack vectors
# Usage: ./run_fuzz5.sh <phase>
#   phase 0: SCM arg overflow (op=0)
#   phase 1: ELF parser fuzz (op=1)
#   phase 2: Integer overflow (op=2)
#   phase 3: Memory confusion (op=3)
#   phase 4: Rollback (op=4)
#   phase 5: Type confusion (op=5)
#   phase 6: State machine abuse (op=6)
#   phase 7: Overlapping PIL (op=7)
#   phase 8: Modem/DSP explore (op=8)
#   phase 9: Large metadata (op=9)
#   phase all: Run all safely (skip modem shutdown)

set -e

MODULE=scm_fuzz5
KO="${MODULE}.ko"
PHASE="${1:-0}"

load_and_log() {
    local op=$1
    local extra="$2"
    local label="$3"

    echo "=== Phase $op: $label ==="
    adb shell "rmmod $MODULE 2>/dev/null; true"
    sleep 0.3
    adb shell "insmod /tmp/$KO op=$op $extra" 2>&1 || true
    sleep 0.5
    adb shell "dmesg | grep scm_fuzz5 | tail -60"
    adb shell "rmmod $MODULE 2>/dev/null; true"
    echo ""
}

# Push module
echo "Pushing $KO..."
adb push "$KO" /tmp/
adb push venus.mdt /tmp/fw_meta.bin 2>/dev/null || true

case "$PHASE" in
    0) load_and_log 0 "sub_test=0 max_tests=14" "SCM arg overflow";;
    1) load_and_log 1 "sub_test=0 max_tests=20" "ELF parser fuzz";;
    2) load_and_log 2 "sub_test=0 max_tests=10" "Integer overflow segs";;
    3) load_and_log 3 "sub_test=0 max_tests=13" "Memory confusion";;
    4) load_and_log 4 "sub_test=0 max_tests=7" "Rollback tests";;
    5) load_and_log 5 "sub_test=0 max_tests=8" "Type confusion";;
    6) load_and_log 6 "sub_test=0 max_tests=11" "State machine abuse";;
    7) load_and_log 7 "" "Overlapping PIL regions";;
    8) load_and_log 8 "sub_test=0 max_tests=8" "Modem/DSP exploration";;
    9) load_and_log 9 "sub_test=0 max_tests=8" "Large metadata";;
    all)
        for p in 0 1 2 3 4 5 6 9; do
            $0 $p
            echo "--- waiting 2s ---"
            sleep 2
        done
        echo "=== Skipped phases 7 (overlapping PIL) and 8 (modem) - run manually ==="
        ;;
    *)
        echo "Usage: $0 {0|1|2|3|4|5|6|7|8|9|all}"
        exit 1
        ;;
esac

echo "Done."
