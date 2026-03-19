#!/usr/bin/env python3
"""
Check if Global ABL verifies vbmeta and devinfo partitions,
and how devinfo is read/trusted.
"""

with open("global_abl_decompressed.bin", 'rb') as f:
    data = f.read()

print(f"=== Global ABL: vbmeta & devinfo verification analysis ===\n")
print(f"File size: 0x{len(data):X} bytes\n")

targets = {
    # devinfo related
    "ANDROID-BOOT!":          b"ANDROID-BOOT!",
    "device-info":            b"device-info",
    "devinfo":                b"devinfo",
    "is_unlocked":            b"is_unlocked",
    "is_unlock_critical":     b"is_unlock_critical",
    "is_tampered":            b"is_tampered",
    "oem_unlock_allowed":     b"oem_unlock_allowed",
    "Device unlocked":        b"Device unlocked",
    "Device state":           b"Device state",
    "unlocked":               b"unlocked",
    "UpdateDevInfo":          b"UpdateDevInfo",
    "WriteDevInfo":           b"WriteDevInfo",
    "ReadDevInfo":            b"ReadDevInfo",
    "devinfo_magic":          b"devinfo_magic",
    "DEVICE_MAGIC":           b"DEVICE_MAGIC",
    # vbmeta related
    "vbmeta":                 b"vbmeta",
    "avb_slot_verify":        b"avb_slot_verify",
    "avb_":                   b"avb_",
    "AVB":                    b"AVB",
    "hashtree":               b"hashtree",
    "hashtree_error":         b"hashtree_error",
    "dm-verity":              b"dm-verity",
    "VBMeta":                 b"VBMeta",
    "UNLOCKED":               b"UNLOCKED",
    "ORANGE":                 b"ORANGE",
    "YELLOW":                 b"YELLOW",
    "GREEN":                  b"GREEN",
    "RED":                    b"RED state",
    "rollback":               b"rollback",
    "Verified Boot":          b"Verified Boot",
    "verified boot":          b"verified boot",
    "boot state":             b"boot state",
}

found = {}
not_found = []
for name, pat in targets.items():
    idx = data.find(pat)
    if idx != -1:
        found[name] = idx
    else:
        not_found.append(name)

print("=== FOUND strings ===")
for name, idx in sorted(found.items(), key=lambda x: x[1]):
    snippet = data[idx:idx+60]
    printable = ''.join(chr(b) if 32<=b<127 else '.' for b in snippet)
    print(f"  0x{idx:06X}  {name:25s}  '{printable[:55]}'")

print(f"\n=== NOT FOUND ===")
for name in not_found:
    print(f"  {name}")

# Deep context: dump everything around "ANDROID-BOOT!"
print("\n\n=== Context around 'ANDROID-BOOT!' (devinfo magic check) ===")
magic_off = data.find(b"ANDROID-BOOT!")
if magic_off != -1:
    start = max(0, magic_off - 32)
    end = min(len(data), magic_off + 200)
    seg = data[start:end]
    printable = ''.join(chr(b) if 32<=b<127 else '.' for b in seg)
    for i in range(0, len(printable), 80):
        print(f"  0x{start+i:06X}: {printable[i:i+80]}")

# Look for ORANGE/YELLOW/GREEN state strings (Verified Boot color states)
print("\n\n=== Verified Boot state strings context ===")
for color in [b"ORANGE", b"YELLOW", b"GREEN"]:
    off = data.find(color)
    if off != -1:
        start = max(0, off - 100)
        end = min(len(data), off + 200)
        seg = data[start:end]
        printable = ''.join(chr(b) if 32<=b<127 else '.' for b in seg)
        print(f"\n  --- {color.decode()} @ 0x{off:X} ---")
        for i in range(0, len(printable), 80):
            print(f"  0x{start+i:06X}: {printable[i:i+80]}")

# Look for vbmeta flag check strings
print("\n\n=== vbmeta / AVB related context ===")
for s in [b"vbmeta", b"AVB", b"Verified Boot"]:
    pos = 0
    count = 0
    while count < 3:
        idx = data.find(s, pos)
        if idx == -1:
            break
        start = max(0, idx - 20)
        end = min(len(data), idx + 100)
        seg = data[start:end]
        printable = ''.join(chr(b) if 32<=b<127 else '.' for b in seg)
        print(f"  0x{idx:06X} [{s.decode()}]: {printable[:120]}")
        pos = idx + 1
        count += 1
