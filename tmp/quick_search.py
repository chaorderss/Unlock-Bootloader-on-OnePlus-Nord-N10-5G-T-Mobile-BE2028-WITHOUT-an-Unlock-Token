#!/usr/bin/env python3
import os, sys

BACKUP_DIR = '/Users/xmxx/pinganhuijia/edl_backup'
MAGIC = b'ANDROID-BOOT!'
PROTO_GUID = bytes.fromhex('91ff5e8eb621d347af2bc15a01e020ec')

results = []

for root, dirs, files in os.walk(BACKUP_DIR):
    for f in sorted(files):
        if not f.endswith('.bin'):
            continue
        fp = os.path.join(root, f)
        try:
            data = open(fp, 'rb').read()
        except Exception:
            continue
        rel = os.path.relpath(fp, BACKUP_DIR)
        offset = 0
        while True:
            idx = data.find(MAGIC, offset)
            if idx < 0:
                break
            unlocked = data[idx+0x0D] if idx+0x0D < len(data) else -1
            charger = data[idx+0x0F] if idx+0x0F < len(data) else -1
            verity = data[idx+0x90] if idx+0x90 < len(data) else -1
            results.append((rel, idx, unlocked, charger, verity, len(data)))
            offset = idx + 1

        idx = data.find(PROTO_GUID)
        if idx >= 0:
            print("PROTO_GUID in %s @ 0x%X" % (rel, idx))

print("Found ANDROID-BOOT! in %d locations:" % len(results))
for name, off, unlock, charger, verity, sz in results:
    print("  %s @ 0x%X (size=%d) unlocked=0x%02X charger=0x%02X verity=0x%02X" % (name, off, sz, unlock, charger, verity))
