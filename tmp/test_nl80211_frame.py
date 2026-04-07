#!/usr/bin/env python3
"""Test nl80211 CMD_FRAME from monitor mode after kernel patch."""
import socket
import struct
import os

# Netlink constants
NETLINK_GENERIC = 16
NLM_F_REQUEST = 1
NLM_F_ACK = 4

# nl80211 commands
NL80211_CMD_FRAME = 59

# nl80211 attributes
NL80211_ATTR_IFINDEX = 3
NL80211_ATTR_WIPHY_FREQ = 38
NL80211_ATTR_FRAME = 51
NL80211_ATTR_DONT_WAIT_FOR_ACK = 118

def get_nl80211_family_id():
    """Get nl80211 generic netlink family ID."""
    CTRL_CMD_GETFAMILY = 3
    CTRL_ATTR_FAMILY_NAME = 2
    CTRL_ATTR_FAMILY_ID = 1

    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
    sock.bind((0, 0))

    # Build CTRL_CMD_GETFAMILY request
    attr = struct.pack('HH', len(b'nl80211\0') + 4, CTRL_ATTR_FAMILY_NAME) + b'nl80211\0'
    genlhdr = struct.pack('BBH', CTRL_CMD_GETFAMILY, 1, 0)
    nlhdr = struct.pack('IHHII', 16 + len(genlhdr) + len(attr), 16, NLM_F_REQUEST | NLM_F_ACK, 1, 0)

    sock.send(nlhdr + genlhdr + attr)
    resp = sock.recv(4096)

    # Parse response - find family ID
    nllen, nltype = struct.unpack_from('IH', resp, 0)
    if nltype == 2:  # NLMSG_ERROR
        errno = struct.unpack_from('i', resp, 16)[0]
        print(f"Error getting family: {errno}")
        sock.close()
        return None

    # Skip nlmsghdr (16) + genlmsghdr (4) = 20
    off = 20
    while off < nllen:
        alen, atype = struct.unpack_from('HH', resp, off)
        if atype == CTRL_ATTR_FAMILY_ID:
            fid = struct.unpack_from('H', resp, off + 4)[0]
            sock.close()
            return fid
        off += (alen + 3) & ~3

    sock.close()
    return None

def get_ifindex(ifname):
    """Get interface index."""
    import fcntl
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    result = fcntl.ioctl(sock.fileno(), 0x8933, struct.pack('256s', ifname.encode()))
    sock.close()
    return struct.unpack('i', result[16:20])[0]

def nla_put(atype, data):
    """Create netlink attribute."""
    alen = 4 + len(data)
    padded = (alen + 3) & ~3
    return struct.pack('HH', alen, atype) + data + b'\0' * (padded - alen)

def nla_put_u32(atype, val):
    return nla_put(atype, struct.pack('I', val))

def nla_put_flag(atype):
    return struct.pack('HH', 4, atype)

def test_cmd_frame():
    """Send management frame via nl80211 CMD_FRAME."""
    family_id = get_nl80211_family_id()
    if family_id is None:
        print("FAIL: Could not get nl80211 family ID")
        return
    print(f"nl80211 family ID: {family_id}")

    ifindex = get_ifindex('wlan0')
    print(f"wlan0 ifindex: {ifindex}")

    # Build a probe request frame (management frame, type 0, subtype 4)
    # Frame control: 0x0040 = probe request
    # Duration: 0
    # DA: broadcast
    # SA: our MAC
    # BSSID: broadcast
    fc = struct.pack('<H', 0x0040)
    duration = struct.pack('<H', 0)
    da = b'\xff\xff\xff\xff\xff\xff'  # broadcast
    sa = bytes.fromhex('5c17cfbca4e3')  # our MAC
    bssid = b'\xff\xff\xff\xff\xff\xff'
    seq = struct.pack('<H', 0)

    # SSID element (empty = broadcast probe)
    ssid_ie = b'\x00\x00'
    # Supported rates
    rates_ie = b'\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24'

    frame = fc + duration + da + sa + bssid + seq + ssid_ie + rates_ie

    # Build nl80211 CMD_FRAME
    attrs = b''
    attrs += nla_put_u32(NL80211_ATTR_IFINDEX, ifindex)
    attrs += nla_put_u32(NL80211_ATTR_WIPHY_FREQ, 2412)  # channel 1
    attrs += nla_put(NL80211_ATTR_FRAME, frame)
    attrs += nla_put_flag(NL80211_ATTR_DONT_WAIT_FOR_ACK)

    genlhdr = struct.pack('BBH', NL80211_CMD_FRAME, 1, 0)
    payload = genlhdr + attrs
    nlhdr = struct.pack('IHHII', 16 + len(payload), family_id, NLM_F_REQUEST | NLM_F_ACK, 1, 0)

    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
    sock.bind((0, 0))
    sock.settimeout(5)

    msg = nlhdr + payload
    print(f"Sending CMD_FRAME ({len(frame)} byte frame, {len(msg)} byte msg)...")
    sock.send(msg)

    try:
        resp = sock.recv(4096)
        # Parse response
        nllen, nltype, nlflags, nlseq, nlpid = struct.unpack_from('IHHII', resp, 0)

        if nltype == 2:  # NLMSG_ERROR
            errno = struct.unpack_from('i', resp, 16)[0]
            if errno == 0:
                print(f"SUCCESS! CMD_FRAME accepted (error=0)")
            else:
                errnames = {
                    -1: "EPERM", -95: "EOPNOTSUPP", -22: "EINVAL",
                    -16: "EBUSY", -19: "ENODEV", -11: "EAGAIN"
                }
                name = errnames.get(errno, f"errno={errno}")
                print(f"FAILED: CMD_FRAME returned {name} ({errno})")
        else:
            print(f"Response: type={nltype} len={nllen}")
            # Could be CMD_FRAME response with cookie
            print("Got non-error response (possibly success with cookie)")
    except socket.timeout:
        print("Timeout waiting for response")

    sock.close()

if __name__ == '__main__':
    test_cmd_frame()
