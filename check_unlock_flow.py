#!/usr/bin/env python3
"""Dump detailed context around the most important findings."""

with open("global_abl_decompressed.bin", 'rb') as f:
    data = f.read()

def dump_ctx(label, offset, before=300, after=300):
    start = max(0, offset - before)
    end = min(len(data), offset + after)
    seg = data[start:end]
    printable = ''.join(chr(b) if 32<=b<127 else '.' for b in seg)
    print(f"\n{'='*70}")
    print(f"  {label}  @ 0x{offset:06X}")
    print(f"{'='*70}")
    for i in range(0, len(printable), 100):
        print(f"  0x{start+i:06X}: {printable[i:i+100]}")

# 1. "unlocked, Skipping boot verification" - THE KEY
off = data.find(b"unlocked, Skipping boot verification")
dump_ctx("'unlocked, Skipping boot verification'", off, 400, 400)

# 2. ANDROID-BOOT! magic check context
off2 = data.find(b"ANDROID-BOOT!")
dump_ctx("'ANDROID-BOOT!' magic check", off2, 200, 300)

# 3. devinfo context
off3 = data.find(b"devinfo %d IsSecureBootEnabled")
dump_ctx("devinfo IsSecureBootEnabled", off3, 100, 200)

# 4. boot state
off4 = data.find(b"boot state is:")
dump_ctx("boot state is:", off4, 300, 300)
