#!/bin/bash
SVC=${1:-1}
START=${2:-0}
END=${3:-16}

for c in $(seq $START $END); do
    echo "--- SVC 0x$(printf '%02x' $SVC) CMD 0x$(printf '%02x' $c) ---"
    adb shell "sudo insmod /tmp/scm_fuzz5.ko op=10 sub_test=14 svc_val=$SVC cmd_val=$c" 2>&1
    RC=$?
    if [ $RC -ne 0 ]; then
        echo "CRASH at SVC=$SVC CMD=$c!"
        exit 1
    fi
    adb shell "dmesg | grep 'EXTPAS svc' | tail -1"
    adb shell "sudo rmmod scm_fuzz5"
done
echo "All commands safe for SVC 0x$(printf '%02x' $SVC)"
