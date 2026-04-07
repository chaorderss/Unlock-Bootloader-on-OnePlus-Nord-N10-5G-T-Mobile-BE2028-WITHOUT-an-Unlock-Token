#!/usr/bin/env python3
"""
Passive handshake capture with real-time EAPOL detection.
Put wlan0 in monitor mode on target channel, then manually reconnect a device.
Uses raw AF_PACKET socket for instant capture.
"""
import socket, struct, time, os, subprocess, sys

TARGET_BSSID = "8C:DE:F9:B3:9E:1F"
CHANNEL = 8
FREQ = 2447
PCAP_FILE = "/tmp/hs_passive.pcap"
CAPTURE_SECONDS = 120  # 2 minutes

# PCAP header
PCAP_GLOBAL_HEADER = struct.pack('<IHHIIII',
    0xa1b2c3d4, 2, 4, 0, 0, 65535, 127)

def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, timeout=10)

def setup_monitor():
    run("killall hostapd 2>/dev/null")
    run("killall airodump-ng 2>/dev/null")
    run("iw dev ap0 del 2>/dev/null")
    run("ip link set wlan0 down")
    run("iw dev wlan0 set type monitor")
    run("ip link set wlan0 up")
    run(f"iw dev wlan0 set freq {FREQ}")

def is_from_target(data, rt_len, target_bytes):
    """Check if frame involves target BSSID (in DA, SA, or BSSID fields)"""
    if len(data) < rt_len + 22:
        return False
    # Check addr1 (DA), addr2 (SA), addr3 (BSSID)
    for off in [4, 10, 16]:
        if data[rt_len+off:rt_len+off+6] == target_bytes:
            return True
    return False

def is_eapol_frame(data, rt_len):
    """Properly detect EAPOL frames by checking LLC/SNAP header after 802.11 data frame"""
    fc = struct.unpack('<H', data[rt_len:rt_len+2])[0]
    ftype = (fc >> 2) & 3

    if ftype != 2:  # not data frame
        return False

    fsubtype = (fc >> 4) & 0xf

    # Calculate 802.11 header length
    # Standard: 24 bytes, QoS: 26 bytes, A4: 30 bytes
    to_ds = fc & 0x0100
    from_ds = fc & 0x0200
    hdr_len = 24
    if to_ds and from_ds:
        hdr_len = 30  # WDS / 4-addr
    if fsubtype & 0x8:  # QoS
        hdr_len += 2

    # Check for LLC/SNAP header: AA AA 03 00 00 00 [ethertype]
    llc_start = rt_len + hdr_len
    if len(data) < llc_start + 8:
        return False

    llc_snap = data[llc_start:llc_start+6]
    if llc_snap != b'\xaa\xaa\x03\x00\x00\x00':
        return False

    ethertype = struct.unpack('>H', data[llc_start+6:llc_start+8])[0]
    return ethertype == 0x888e  # EAPOL

def get_eapol_info(data, rt_len):
    """Extract EAPOL key message number"""
    fc = struct.unpack('<H', data[rt_len:rt_len+2])[0]
    fsubtype = (fc >> 4) & 0xf
    to_ds = fc & 0x0100
    from_ds = fc & 0x0200

    hdr_len = 24
    if to_ds and from_ds:
        hdr_len = 30
    if fsubtype & 0x8:
        hdr_len += 2

    # LLC/SNAP (8 bytes) + EAPOL header (4 bytes) + Key type (1) + Key Info (2)
    eapol_start = rt_len + hdr_len + 8  # after LLC/SNAP
    if len(data) < eapol_start + 7:
        return "?"

    eapol_ver = data[eapol_start]
    eapol_type = data[eapol_start + 1]

    if eapol_type == 3:  # EAPOL-Key
        key_info = struct.unpack('>H', data[eapol_start + 5:eapol_start + 7])[0]
        # Key Info bits:
        # Bit 3: Install
        # Bit 6: Key ACK
        # Bit 7: Key MIC
        # Bit 8: Secure
        install = (key_info >> 6) & 1
        ack = (key_info >> 7) & 1
        mic = (key_info >> 8) & 1
        secure = (key_info >> 9) & 1

        # Determine message number:
        # M1: ACK=1, MIC=0
        # M2: ACK=0, MIC=1, Install=0
        # M3: ACK=1, MIC=1, Install=1
        # M4: ACK=0, MIC=1, Install=0, Secure=1
        if ack and not mic:
            return "M1 (ANonce)"
        elif not ack and mic and not install and not secure:
            return "M2 (SNonce)"
        elif ack and mic and install:
            return "M3 (GTK)"
        elif not ack and mic and secure:
            return "M4 (ACK)"
        else:
            return f"KeyInfo=0x{key_info:04x}"

    return f"EAPOLtype={eapol_type}"

def main():
    target_bytes = bytes(int(b, 16) for b in TARGET_BSSID.split(':'))

    print(f"Target: {TARGET_BSSID} ch{CHANNEL} ({FREQ}MHz)")
    print(f"Capture: {CAPTURE_SECONDS}s")
    print(f"Output: {PCAP_FILE}")
    print()
    print(">>> Reconnect a device to the WiFi NOW <<<")
    print()

    setup_monitor()

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        sock.bind(("wlan0", 0))
        sock.settimeout(1.0)
    except Exception as e:
        print(f"Socket error: {e}")
        return 1

    pcap = open(PCAP_FILE, 'wb')
    pcap.write(PCAP_GLOBAL_HEADER)

    total = 0
    target_pkts = 0
    eapol_count = 0
    eapol_msgs = []
    start = time.time()

    print(f"[{time.strftime('%H:%M:%S')}] Monitoring...")

    try:
        while time.time() - start < CAPTURE_SECONDS:
            try:
                data = sock.recv(65535)
            except socket.timeout:
                elapsed = int(time.time() - start)
                if elapsed % 10 == 0 and elapsed > 0:
                    sys.stdout.write(f"\r  {elapsed}s: {total} pkts, {target_pkts} target, {eapol_count} EAPOL")
                    sys.stdout.flush()
                continue

            total += 1
            ts = time.time()

            if len(data) < 4:
                continue
            rt_len = struct.unpack('<H', data[2:4])[0]
            if rt_len >= len(data):
                continue

            # Write ALL packets to pcap
            sec = int(ts)
            usec = int((ts - sec) * 1e6)
            pcap.write(struct.pack('<IIII', sec, usec, len(data), len(data)))
            pcap.write(data)

            # Filter for target BSSID
            if not is_from_target(data, rt_len, target_bytes):
                continue

            target_pkts += 1

            # Check for EAPOL
            if is_eapol_frame(data, rt_len):
                eapol_count += 1
                msg_type = get_eapol_info(data, rt_len)
                eapol_msgs.append(msg_type)

                # Get client MAC
                da = data[rt_len+4:rt_len+10].hex(':')
                sa = data[rt_len+10:rt_len+16].hex(':')
                elapsed = time.time() - start

                print(f"\n  *** EAPOL {msg_type}: SA={sa} DA={da} (+{elapsed:.1f}s) ***")
                pcap.flush()

                if eapol_count >= 4:
                    print(f"\n  Got 4 EAPOL frames - complete handshake!")
                    break

    except KeyboardInterrupt:
        print("\n  Interrupted")

    sock.close()
    pcap.close()

    print(f"\n\n{'='*50}")
    print(f"Total: {total} pkts, {target_pkts} from target, {eapol_count} EAPOL")
    if eapol_msgs:
        print(f"EAPOL messages: {', '.join(eapol_msgs)}")
    print(f"PCAP: {PCAP_FILE}")

    if eapol_count > 0:
        print("\nVerifying with aircrack-ng...")
        result = subprocess.run(f"aircrack-ng {PCAP_FILE}", shell=True,
                                capture_output=True, text=True, timeout=30)
        print(result.stdout[:500] if result.stdout else "")

    return 0 if eapol_count >= 2 else 1

if __name__ == "__main__":
    sys.exit(main())
