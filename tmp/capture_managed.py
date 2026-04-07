#!/usr/bin/env python3
"""
Capture EAPOL handshake from managed mode by reconnecting to saved WiFi.
Uses AF_PACKET to capture EAPOL frames during wpa_supplicant's handshake.
"""
import socket, struct, time, subprocess, sys, os

TARGET_SSID = "9899a5b77"
TARGET_BSSID = "8C:DE:F9:B3:9E:20"  # 5GHz BSSID
TARGET_BSSID_24 = "8C:DE:F9:B3:9E:1F"  # 2.4GHz BSSID
PCAP_FILE = "/tmp/hs_managed.pcap"
PCAP_FILE_22000 = "/tmp/hs_managed.22000"

# PCAP with Ethernet linktype
PCAP_HDR = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)  # linktype=1 (Ethernet)

def run(cmd, timeout=15):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None

def parse_eapol_key(data):
    """Parse EAPOL-Key frame from Ethernet frame.
    Ethernet: DA(6) + SA(6) + EtherType(2) + EAPOL
    EAPOL: Version(1) + Type(1) + Length(2) + Body
    EAPOL-Key: Descriptor(1) + KeyInfo(2) + KeyLen(2) + ReplayCounter(8) +
               Nonce(32) + KeyIV(16) + KeyRSC(8) + KeyID(8) + KeyMIC(16) + KeyDataLen(2) + KeyData
    """
    if len(data) < 14:
        return None

    dst = data[0:6]
    src = data[6:12]
    ethertype = struct.unpack('>H', data[12:14])[0]

    if ethertype != 0x888e:
        return None

    eapol = data[14:]
    if len(eapol) < 4:
        return None

    eapol_ver = eapol[0]
    eapol_type = eapol[1]
    eapol_len = struct.unpack('>H', eapol[2:4])[0]

    result = {
        'dst': dst.hex(':'),
        'src': src.hex(':'),
        'eapol_ver': eapol_ver,
        'eapol_type': eapol_type,
        'eapol_len': eapol_len,
        'raw_eapol': eapol[:4+eapol_len],
    }

    if eapol_type == 3 and len(eapol) >= 4 + 95:  # EAPOL-Key
        key_body = eapol[4:]
        descriptor_type = key_body[0]
        key_info = struct.unpack('>H', key_body[1:3])[0]
        key_len = struct.unpack('>H', key_body[3:5])[0]
        replay_counter = key_body[5:13]
        nonce = key_body[13:45]
        key_iv = key_body[45:61]
        key_rsc = key_body[61:69]
        key_id = key_body[69:77]
        key_mic = key_body[77:93]
        key_data_len = struct.unpack('>H', key_body[93:95])[0]

        ack = (key_info >> 7) & 1
        mic = (key_info >> 8) & 1
        install = (key_info >> 6) & 1
        secure = (key_info >> 9) & 1

        if ack and not mic:
            msg_num = 1
        elif not ack and mic and not secure:
            msg_num = 2
        elif ack and mic and install:
            msg_num = 3
        elif not ack and mic and secure:
            msg_num = 4
        else:
            msg_num = 0

        result.update({
            'key_info': key_info,
            'key_len': key_len,
            'replay_counter': replay_counter.hex(),
            'nonce': nonce.hex(),
            'key_mic': key_mic.hex(),
            'key_data_len': key_data_len,
            'msg_num': msg_num,
            'descriptor_type': descriptor_type,
        })

    return result

def main():
    print(f"=== Managed Mode EAPOL Capture ===")
    print(f"Target: {TARGET_SSID}")
    print()

    # Step 1: Clean up and restore managed mode
    print("[1] Restoring managed mode...")
    run("killall hostapd 2>/dev/null")
    run("killall airodump-ng 2>/dev/null")
    run("iw dev ap0 del 2>/dev/null")
    run("ip link set wlan0 down")
    run("iw dev wlan0 set type managed")
    run("ip link set wlan0 up")
    time.sleep(1)

    # Step 2: Make sure NetworkManager is running
    print("[2] Starting NetworkManager...")
    run("systemctl start NetworkManager")
    time.sleep(2)

    # Step 3: Disconnect from any current WiFi
    print("[3] Disconnecting from WiFi...")
    run("nmcli device disconnect wlan0")
    time.sleep(1)

    # Step 4: Open raw socket BEFORE connecting
    print("[4] Opening capture socket...")
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sock.bind(("wlan0", 0))
    sock.settimeout(0.5)

    pcap = open(PCAP_FILE, 'wb')
    pcap.write(PCAP_HDR)

    # Step 5: Connect to WiFi (in background)
    print(f"[5] Connecting to {TARGET_SSID}...")
    proc = subprocess.Popen(
        f"sleep 1 && nmcli connection up '{TARGET_SSID}'",
        shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    # Step 6: Capture frames for 30 seconds
    print("[6] Capturing EAPOL frames (30s)...")
    eapol_frames = []
    total = 0
    start = time.time()

    while time.time() - start < 30:
        try:
            data = sock.recv(65535)
        except socket.timeout:
            continue

        total += 1
        ts = time.time()

        # Write all frames to pcap
        sec = int(ts)
        usec = int((ts - sec) * 1e6)
        pcap.write(struct.pack('<IIII', sec, usec, len(data), len(data)))
        pcap.write(data)

        # Check for EAPOL
        if len(data) >= 14:
            ethertype = struct.unpack('>H', data[12:14])[0]
            if ethertype == 0x888e:
                parsed = parse_eapol_key(data)
                if parsed:
                    eapol_frames.append(parsed)
                    msg = parsed.get('msg_num', '?')
                    elapsed = time.time() - start
                    print(f"    *** EAPOL M{msg}: {parsed['src']} -> {parsed['dst']} (+{elapsed:.1f}s) ***")
                    if 'nonce' in parsed:
                        print(f"        Nonce: {parsed['nonce'][:32]}...")
                        print(f"        MIC:   {parsed.get('key_mic', 'N/A')}")

                    if len(eapol_frames) >= 4:
                        print("\n    Got 4 EAPOL messages - complete handshake!")
                        time.sleep(1)  # capture a bit more
                        break

        # Print progress
        if total % 500 == 0:
            elapsed = int(time.time() - start)
            print(f"    {elapsed}s: {total} pkts, {len(eapol_frames)} EAPOL")

    sock.close()
    pcap.close()

    # Wait for nmcli to finish
    try:
        proc.wait(timeout=5)
        stdout = proc.stdout.read().decode()
        stderr = proc.stderr.read().decode()
        print(f"\n  nmcli: {stdout.strip()} {stderr.strip()}")
    except:
        proc.kill()

    print(f"\n{'='*50}")
    print(f"Total: {total} packets, {len(eapol_frames)} EAPOL frames")
    print(f"PCAP: {PCAP_FILE}")

    if eapol_frames:
        print("\nEAPOL Summary:")
        for i, frame in enumerate(eapol_frames):
            msg = frame.get('msg_num', '?')
            print(f"  M{msg}: {frame['src']} -> {frame['dst']}")
            if 'nonce' in frame:
                print(f"       Nonce={frame['nonce'][:16]}... MIC={frame['key_mic'][:16]}...")

        # Generate hashcat format if we have M1+M2 or M2+M3
        has_anonce = any(f.get('msg_num') == 1 for f in eapol_frames)
        has_snonce = any(f.get('msg_num') == 2 for f in eapol_frames)

        if has_anonce and has_snonce:
            print("\n  Have both ANonce and SNonce - handshake should be crackable!")
            m1 = next(f for f in eapol_frames if f.get('msg_num') == 1)
            m2 = next(f for f in eapol_frames if f.get('msg_num') == 2)
            print(f"  ANonce: {m1['nonce']}")
            print(f"  SNonce: {m2['nonce']}")
            print(f"  AP MAC: {m1['src']}")
            print(f"  STA MAC: {m2['src']}")
            print(f"  M2 MIC: {m2['key_mic']}")

        # Try aircrack-ng on the pcap
        print("\nTrying aircrack-ng...")
        result = run(f"aircrack-ng {PCAP_FILE}", timeout=30)
        if result and result.stdout:
            for line in result.stdout.split('\n'):
                if 'handshake' in line.lower() or 'WPA' in line or '#' in line:
                    print(f"  {line.strip()}")
    else:
        print("\nNo EAPOL frames captured in managed mode.")
        print("The driver may handle EAPOL internally without passing to userspace.")

    return 0 if len(eapol_frames) >= 2 else 1

if __name__ == "__main__":
    sys.exit(main())
