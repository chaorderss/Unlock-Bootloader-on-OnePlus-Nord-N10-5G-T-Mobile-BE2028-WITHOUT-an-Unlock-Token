#!/usr/bin/env python3
"""
Monitor USB for crashdump -> reset cycle.
When 9091 disappears (device resets), alert user to press BOTH vol buttons.
Window: ~0.6 seconds from reset to XBL EDL check.
"""
import subprocess
import time
import sys

def check_usb_pid(pid_hex):
    """Check if a USB device with given product ID is connected."""
    result = subprocess.run(
        ['system_profiler', 'SPUSBDataType'],
        capture_output=True, text=True, timeout=5
    )
    return pid_hex.lower() in result.stdout.lower()

def ioreg_check():
    """Use ioreg to check for Qualcomm USB devices."""
    result = subprocess.run(
        ['ioreg', '-p', 'IOUSB', '-l', '-w0'],
        capture_output=True, text=True, timeout=5
    )
    out = result.stdout
    has_9008 = '0x9008' in out or '"idProduct" = 36872' in out
    has_9091 = '0x9091' in out or '"idProduct" = 37009' in out
    return has_9008, has_9091

def run_edl_check():
    """Quick edl check."""
    result = subprocess.run(
        ['edl', 'nop', '--devicemodel', '20888'],
        capture_output=True, text=True, timeout=5
    )
    return 'succeeded' in result.stdout.lower() or 'succeeded' in result.stderr.lower()

print("=" * 60)
print("EDL TIMING ASSISTANT")
print("=" * 60)
print()
print("This script monitors USB for the reset cycle.")
print("When you see '>>> PRESS BUTTONS NOW <<<'")
print("immediately press and hold BOTH Vol-Up + Vol-Down")
print("Keep holding for 3 seconds")
print()
print("Watching USB... (Ctrl+C to stop)")
print()

was_in_crashdump = False
cycle_count = 0

try:
    while True:
        try:
            has_9008, has_9091 = ioreg_check()
        except Exception:
            time.sleep(0.2)
            continue

        if has_9008:
            print(f"\n{'='*60}")
            print("*** DEVICE DETECTED IN EDL MODE (9008)! ***")
            print("Flashing original abl_b now...")
            print(f"{'='*60}\n")
            result = subprocess.run([
                'edl', 'w', 'abl_b',
                '/Users/xmxx/pinganhuijia/edl_backup/abl_b.img',
                '--devicemodel', '20888'
            ], capture_output=False, timeout=120)
            if result.returncode == 0:
                print("\n*** SUCCESS! Original ABL restored! ***")
                print("Rebooting device...")
                subprocess.run(['edl', 'reset', '--devicemodel', '20888'], timeout=30)
            else:
                print("\nFlash may have failed. Check output above.")
            break

        if has_9091:
            if not was_in_crashdump:
                print(f"[Cycle #{cycle_count+1}] Crashdump mode detected (9091)...")
            was_in_crashdump = True
        else:
            if was_in_crashdump:
                # Device just left crashdump = it RESET
                cycle_count += 1
                print()
                print(f"{'!'*60}")
                print(f"  >>> PRESS BOTH VOL-UP + VOL-DOWN NOW <<<")
                print(f"  Keep holding for 3 seconds!")
                print(f"  (Cycle #{cycle_count} - device is resetting)")
                print(f"{'!'*60}")
                was_in_crashdump = False
            # else: device not connected at all, or between states

        time.sleep(0.15)  # Check every 150ms for fast response

except KeyboardInterrupt:
    print("\nStopped.")
