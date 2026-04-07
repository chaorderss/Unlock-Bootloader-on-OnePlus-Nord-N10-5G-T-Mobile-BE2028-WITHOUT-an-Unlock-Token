#!/bin/bash
# scm_fuzz_runner2.sh - Safer version
RESULTS="/Users/xmxx/pinganhuijia/tmp/scm_fuzz/results2.txt"
MODULE="/tmp/scm_fuzz3.ko"
echo "=== SCM Fuzz Results v2 ===" > "$RESULTS"
echo "Started: $(date)" >> "$RESULTS"

run_fuzz() {
    local params="$1"
    local desc="$2"

    echo ">>> $desc" | tee -a "$RESULTS"

    if ! adb devices 2>/dev/null | grep -q "device$"; then
        echo "DEVICE_OFFLINE - waiting 60s" | tee -a "$RESULTS"
        sleep 60
        if ! adb devices 2>/dev/null | grep -q "device$"; then
            echo "STILL_OFFLINE" | tee -a "$RESULTS"
            return 1
        fi
        adb push /Users/xmxx/pinganhuijia/tmp/scm_fuzz/scm_fuzz3.ko $MODULE 2>/dev/null
    fi

    adb shell "sudo rmmod scm_fuzz3 2>/dev/null" 2>/dev/null
    sleep 1

    local output
    output=$(adb shell "sudo insmod $MODULE $params 2>&1; sleep 1; sudo dmesg | grep 'scm_fuzz3: RESULT' | tail -1" 2>&1)
    local rc=$?

    if [ $rc -ne 0 ]; then
        echo "CRASH rc=$rc" | tee -a "$RESULTS"
        sleep 45
        if adb devices 2>/dev/null | grep -q "device$"; then
            adb push /Users/xmxx/pinganhuijia/tmp/scm_fuzz/scm_fuzz3.ko $MODULE 2>/dev/null
        fi
        return 1
    fi

    echo "$output" | tee -a "$RESULTS"
    echo "" >> "$RESULTS"
    return 0
}

echo ""
echo "== Phase E: PAS supported probe =="

for pid in 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 166; do
    run_fuzz "op=0 pid_val=$pid" "PAS_SUPPORTED pid=$pid"
done

echo ""
echo "== Phase G: PAS init_image zero meta =="

for pid in 1 4 6 9 13 18 24 27 166; do
    run_fuzz "op=1 pid_val=$pid meta_type=0 meta_size=52" "PAS_INIT zero pid=$pid"
done

echo ""
echo "== Phase H: PAS init_image ELF meta =="

for pid in 1 4 9 18 24 166; do
    run_fuzz "op=1 pid_val=$pid meta_type=1 meta_size=52" "PAS_INIT elf pid=$pid"
done

echo ""
echo "== Phase I: PAS init_image size boundary pid=0x18 =="

for size in 1 4 16 32 48 52 64 128 256 512 1024 2048 4096; do
    run_fuzz "op=1 pid_val=24 meta_type=0 meta_size=$size" "PAS_INIT pid=0x18 size=$size"
done

echo ""
echo "== Phase J: Unknown service exploration =="

for cmd in 1 2 3 5 6 7 8 9; do
    run_fuzz "op=6 svc_val=24 cmd_val=$cmd" "SVC_0x18 cmd=$cmd"
done

for cmd in 1 2 3 4 5; do
    run_fuzz "op=6 svc_val=25 cmd_val=$cmd" "SVC_0x19 cmd=$cmd"
done

for cmd in 1 2 3; do
    run_fuzz "op=6 svc_val=14 cmd_val=$cmd" "SVC_0x0e cmd=$cmd"
done

run_fuzz "op=6 svc_val=26 cmd_val=1" "SVC_0x1a cmd=1"
run_fuzz "op=6 svc_val=28 cmd_val=1" "SVC_0x1c cmd=1"
run_fuzz "op=6 svc_val=28 cmd_val=2" "SVC_0x1c cmd=2"
run_fuzz "op=6 svc_val=29 cmd_val=1" "SVC_0x1d cmd=1"
run_fuzz "op=6 svc_val=30 cmd_val=5" "SVC_0x1e cmd=5"

echo ""
echo "== Phase K: PIL safe queries =="
for cmd in 7 8 9; do
    run_fuzz "op=4 svc_val=2 cmd_val=$cmd pid_val=0" "PIL cmd=$cmd pid=0"
done
for cmd in 14 15; do
    run_fuzz "op=4 svc_val=2 cmd_val=$cmd pid_val=0" "PIL cmd=$cmd pid=0"
done

echo ""
echo "== Phase L: CP service =="
for cmd in 2 3 4 5 8 14 15 22 23 24 25 26 27 28 29 30 31; do
    run_fuzz "op=6 svc_val=12 cmd_val=$cmd" "CP svc=0x0c cmd=$cmd"
done

echo ""
echo "== Phase M: DCVS/Memory protection service =="
for cmd in 7 8 9 10 11 12 13; do
    run_fuzz "op=6 svc_val=13 cmd_val=$cmd" "DCVS svc=0x0d cmd=$cmd"
done

echo ""
echo "== Phase N: LMH service (0x13) =="
for cmd in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17; do
    run_fuzz "op=6 svc_val=19 cmd_val=$cmd" "LMH svc=0x13 cmd=$cmd"
done

echo ""
echo "DONE"
echo "Finished: $(date)" >> "$RESULTS"
