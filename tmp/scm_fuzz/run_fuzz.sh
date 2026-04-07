#!/bin/bash
# scm_fuzz_runner.sh - Run SCM fuzzer operations one at a time
# Usage: ./scm_fuzz_runner.sh
# Results saved to tmp/scm_fuzz/results.txt

RESULTS="/Users/xmxx/pinganhuijia/tmp/scm_fuzz/results.txt"
MODULE="/tmp/scm_fuzz3.ko"
echo "=== SCM Fuzz Results ===" > "$RESULTS"
echo "Started: $(date)" >> "$RESULTS"

run_fuzz() {
    local params="$1"
    local desc="$2"

    echo ">>> $desc ($params)" | tee -a "$RESULTS"

    # Check device
    if ! adb devices | grep -q "device$"; then
        echo "DEVICE_OFFLINE - waiting 60s..." | tee -a "$RESULTS"
        sleep 60
        if ! adb devices | grep -q "device$"; then
            echo "DEVICE_STILL_OFFLINE - SKIP" | tee -a "$RESULTS"
            return 1
        fi
    fi

    # Rmmod if loaded
    adb shell "sudo rmmod scm_fuzz3 2>/dev/null"
    sleep 1

    # Load with params
    local output
    output=$(adb shell "sudo insmod $MODULE $params 2>&1; sleep 1; sudo dmesg | grep 'scm_fuzz3: RESULT' | tail -1" 2>&1)
    local rc=$?

    if [ $rc -ne 0 ]; then
        echo "ADB_ERROR rc=$rc - device may have crashed" | tee -a "$RESULTS"
        sleep 30
        return 1
    fi

    echo "$output" | tee -a "$RESULTS"
    echo "" >> "$RESULTS"
    return 0
}

# Push module
echo "Pushing module..."
adb push /Users/xmxx/pinganhuijia/tmp/scm_fuzz/scm_fuzz3.ko $MODULE

echo ""
echo "=========================================="
echo "Phase A: Raw SCM info queries (safe)"
echo "=========================================="

# Query all Info service commands (svc=0x06)
for cmd in 0x01 0x03 0x04 0x06 0x07 0x08; do
    run_fuzz "op=6 svc_val=6 cmd_val=$((cmd))" "INFO svc=0x06 cmd=$cmd"
done

echo ""
echo "=========================================="
echo "Phase B: Boot service queries"
echo "=========================================="

for cmd in 0x07 0x08 0x09 0x0a 0x0d 0x0e 0x0f 0x11 0x13 0x1d 0x1e; do
    run_fuzz "op=6 svc_val=1 cmd_val=$((cmd))" "BOOT svc=0x01 cmd=$cmd"
done

echo ""
echo "=========================================="
echo "Phase C: Fuse service queries"
echo "=========================================="

for cmd in 0x01 0x02 0x06 0x08; do
    run_fuzz "op=6 svc_val=8 cmd_val=$((cmd))" "FUSE svc=0x08 cmd=$cmd"
done

echo ""
echo "=========================================="
echo "Phase D: PIL service queries"
echo "=========================================="

# PIL undocumented commands (skip 0x01=init,0x02=memsetup,0x05=auth_reset)
for cmd in 0x06 0x07 0x08 0x09 0x0e 0x0f; do
    run_fuzz "op=4 svc_val=2 cmd_val=$((cmd)) pid_val=0" "PIL svc=0x02 cmd=$cmd pid=0"
done

echo ""
echo "=========================================="
echo "Phase E: PAS supported probe (safe per-ID)"
echo "=========================================="

for pid in 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27; do
    run_fuzz "op=0 pid_val=$pid" "PAS_SUPPORTED pid=$pid"
done
# ICNSS WLAN
run_fuzz "op=0 pid_val=166" "PAS_SUPPORTED pid=0xa6(ICNSS)"

echo ""
echo "=========================================="
echo "Phase F: PAS shutdown probe"
echo "=========================================="

# Only test known-supported PIDs (from Phase E results)
for pid in 0 1 4 6 9 13 18 23 24 27; do
    run_fuzz "op=2 pid_val=$pid" "PAS_SHUTDOWN pid=$pid"
done

echo ""
echo "=========================================="
echo "Phase G: PAS init_image with zero metadata"
echo "=========================================="

# Test with known-supported PIDs
for pid in 1 4 6 9 13 18 23 24 27; do
    run_fuzz "op=1 pid_val=$pid meta_type=0 meta_size=52" "PAS_INIT zero pid=$pid"
done
run_fuzz "op=1 pid_val=166 meta_type=0 meta_size=52" "PAS_INIT zero pid=0xa6"

echo ""
echo "=========================================="
echo "Phase H: PAS init_image with ELF header"
echo "=========================================="

for pid in 1 4 9 18 24; do
    run_fuzz "op=1 pid_val=$pid meta_type=1 meta_size=52" "PAS_INIT elf pid=$pid"
done

echo ""
echo "=========================================="
echo "Phase I: PAS init_image size boundary"
echo "=========================================="

for size in 1 4 16 32 48 52 64 128 256 512 1024 2048 4096; do
    run_fuzz "op=1 pid_val=24 meta_type=0 meta_size=$size" "PAS_INIT pid=0x18 size=$size"
done

echo ""
echo "=========================================="
echo "Phase J: Unknown service exploration"
echo "=========================================="

# svc 0x18 (8 cmds!) - this is interesting
for cmd in 1 2 3 5 6 7 8 9; do
    run_fuzz "op=6 svc_val=24 cmd_val=$cmd" "UNK svc=0x18 cmd=$cmd"
done

# svc 0x19 (5 cmds)
for cmd in 1 2 3 4 5; do
    run_fuzz "op=6 svc_val=25 cmd_val=$cmd" "UNK svc=0x19 cmd=$cmd"
done

# svc 0x0e (3 cmds)
for cmd in 1 2 3; do
    run_fuzz "op=6 svc_val=14 cmd_val=$cmd" "UNK svc=0x0e cmd=$cmd"
done

# svc 0x1a, 0x1c, 0x1d, 0x1e
run_fuzz "op=6 svc_val=26 cmd_val=1" "UNK svc=0x1a cmd=0x01"
run_fuzz "op=6 svc_val=28 cmd_val=1" "UNK svc=0x1c cmd=0x01"
run_fuzz "op=6 svc_val=28 cmd_val=2" "UNK svc=0x1c cmd=0x02"
run_fuzz "op=6 svc_val=29 cmd_val=1" "UNK svc=0x1d cmd=0x01"
run_fuzz "op=6 svc_val=30 cmd_val=5" "UNK svc=0x1e cmd=0x05"

echo ""
echo "=========================================="
echo "DONE"
echo "=========================================="
echo "Finished: $(date)" >> "$RESULTS"
echo "Results saved to $RESULTS"
