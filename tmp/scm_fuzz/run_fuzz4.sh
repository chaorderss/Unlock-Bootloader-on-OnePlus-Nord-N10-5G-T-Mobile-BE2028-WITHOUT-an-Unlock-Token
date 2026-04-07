#!/bin/bash
# run_fuzz4.sh - SCM fuzzer v4 runner
# Usage: ./run_fuzz4.sh <phase>
#   phase 1: PAS supported scan (all PIDs 0-31)
#   phase 2: Service exploration (safe services)
#   phase 3: PAS init_image fuzz
#   phase 4: Unknown service deep dive

set -e

MODULE="scm_fuzz4"
KO_FILE="${MODULE}.ko"
RESULTS="results_v4.txt"

load_mod() {
    echo "[*] Loading: insmod $KO_FILE $@"
    adb shell "sudo rmmod $MODULE 2>/dev/null; true"
    sleep 0.5
    adb shell "sudo insmod /tmp/$KO_FILE $*"
    sleep 1
    adb shell "sudo dmesg | grep scm_fuzz4 | tail -40"
    echo ""
}

collect() {
    adb shell "sudo dmesg | grep 'scm_fuzz4: RESULT'" >> "$RESULTS"
}

push_module() {
    echo "[*] Pushing module to device..."
    adb push "$KO_FILE" /tmp/
    echo "[*] Module pushed."
}

phase1_pas_scan() {
    echo "=== PHASE 1: PAS SUPPORTED SCAN ==="  | tee -a "$RESULTS"
    push_module
    load_mod "op=7"
    collect
    adb shell "sudo rmmod $MODULE 2>/dev/null; true"
    echo "=== PHASE 1 COMPLETE ===" | tee -a "$RESULTS"
}

phase2_svc_explore() {
    echo "=== PHASE 2: SERVICE EXPLORATION ===" | tee -a "$RESULTS"
    push_module

    # Safe services to explore with 0 args
    for svc in 0x01 0x03 0x06 0x08 0x09 0x0a 0x0c 0x0d 0x0e 0x10 0x13 0x14 0x15 0x16 0x18 0x19 0x1a 0x1c 0x1d 0x1e; do
        echo "[*] Exploring service $svc ..."
        load_mod "op=8 svc_val=$svc" 2>&1 | tee -a "$RESULTS"
        collect
        adb shell "sudo rmmod $MODULE 2>/dev/null; true"
        sleep 1
        # Check device is still alive
        if ! adb shell "echo alive" 2>/dev/null | grep -q alive; then
            echo "[!] Device may have crashed on svc=$svc! Waiting for recovery..."
            sleep 30
            adb wait-for-device
            push_module
        fi
    done
    echo "=== PHASE 2 COMPLETE ===" | tee -a "$RESULTS"
}

phase3_pas_init_fuzz() {
    echo "=== PHASE 3: PAS INIT_IMAGE FUZZ ===" | tee -a "$RESULTS"
    push_module

    # First need to know which PIDs are supported (run phase 1 first!)
    # Try common WLAN-related PIDs: 0x0c (WCNSS), 0x12, 0x18
    for pid in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        for mtype in 0 1 2; do
            echo "[*] pas_init_image pid=$pid meta_type=$mtype ..."
            load_mod "op=1 pid_val=$pid meta_type=$mtype meta_size=52" 2>&1 | tee -a "$RESULTS"
            collect
            adb shell "sudo rmmod $MODULE 2>/dev/null; true"
            sleep 1
            if ! adb shell "echo alive" 2>/dev/null | grep -q alive; then
                echo "[!] CRASH on pid=$pid mtype=$mtype! Waiting..."
                echo "CRASH: pas_init_image pid=$pid meta_type=$mtype" >> "$RESULTS"
                sleep 30
                adb wait-for-device
                push_module
            fi
        done
    done
    echo "=== PHASE 3 COMPLETE ===" | tee -a "$RESULTS"
}

phase4_unknown_deep() {
    echo "=== PHASE 4: UNKNOWN SERVICE DEEP DIVE ===" | tee -a "$RESULTS"
    push_module

    # svc=0x18 has 8 commands - try with 1 arg
    echo "[*] Deep dive: svc=0x18 with args..."
    for cmd in 1 2 3 5 6 7 8 9; do
        for narg in 0 1; do
            echo "[*] svc=0x18 cmd=$cmd nargs=$narg arg1=0 ..."
            load_mod "op=4 svc_val=0x18 cmd_val=$cmd nargs=$narg arg1_val=0" 2>&1 | tee -a "$RESULTS"
            collect
            adb shell "sudo rmmod $MODULE 2>/dev/null; true"
            sleep 1
            if ! adb shell "echo alive" 2>/dev/null | grep -q alive; then
                echo "[!] CRASH svc=0x18 cmd=$cmd nargs=$narg" >> "$RESULTS"
                sleep 30
                adb wait-for-device
                push_module
            fi
        done
    done

    # svc=0x19 has 5 commands
    echo "[*] Deep dive: svc=0x19 with args..."
    for cmd in 1 2 3 4 5; do
        for narg in 0 1; do
            echo "[*] svc=0x19 cmd=$cmd nargs=$narg arg1=0 ..."
            load_mod "op=4 svc_val=0x19 cmd_val=$cmd nargs=$narg arg1_val=0" 2>&1 | tee -a "$RESULTS"
            collect
            adb shell "sudo rmmod $MODULE 2>/dev/null; true"
            sleep 1
            if ! adb shell "echo alive" 2>/dev/null | grep -q alive; then
                echo "[!] CRASH svc=0x19 cmd=$cmd nargs=$narg" >> "$RESULTS"
                sleep 30
                adb wait-for-device
                push_module
            fi
        done
    done

    # PIL svc=0x02 remaining cmds (0x08, 0x09, 0x0e, 0x0f)
    echo "[*] Deep dive: PIL svc=0x02 extra cmds..."
    for cmd in 0x08 0x09 0x0e 0x0f; do
        for narg in 0 1; do
            echo "[*] svc=0x02 cmd=$cmd nargs=$narg arg1=0 ..."
            load_mod "op=4 svc_val=0x02 cmd_val=$cmd nargs=$narg arg1_val=0" 2>&1 | tee -a "$RESULTS"
            collect
            adb shell "sudo rmmod $MODULE 2>/dev/null; true"
            sleep 1
            if ! adb shell "echo alive" 2>/dev/null | grep -q alive; then
                echo "[!] CRASH svc=0x02 cmd=$cmd nargs=$narg" >> "$RESULTS"
                sleep 30
                adb wait-for-device
                push_module
            fi
        done
    done

    echo "=== PHASE 4 COMPLETE ===" | tee -a "$RESULTS"
}

case "${1:-}" in
    1) phase1_pas_scan ;;
    2) phase2_svc_explore ;;
    3) phase3_pas_init_fuzz ;;
    4) phase4_unknown_deep ;;
    *)
        echo "Usage: $0 <phase>"
        echo "  1 = PAS supported scan (all PIDs)"
        echo "  2 = Service exploration (safe 0-arg queries)"
        echo "  3 = PAS init_image fuzzing"
        echo "  4 = Unknown service deep dive"
        ;;
esac
