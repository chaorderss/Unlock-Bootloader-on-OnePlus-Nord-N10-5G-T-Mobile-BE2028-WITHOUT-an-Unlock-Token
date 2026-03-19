#!/usr/bin/env python3
"""
Analyze ABL PE32+ binary to understand CmdCustUnlockFlash token generation
for model 20888 (OnePlus Nord N10 5G T-Mobile).
"""
import base64
import struct
import hashlib
import hmac

with open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb') as f:
    data = f.read()

def get_str(o):
    e = data.index(b'\x00', o)
    return data[o:e].decode('ascii', errors='replace')

def hexdump(data, offset=0, length=None):
    if length:
        data = data[:length]
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        asc = ''.join(chr(b) if 32<=b<127 else '.' for b in chunk)
        print(f'  {offset+i:06x}: {hex_str:<48}  {asc}')

# ============================================================
# 1. Find model 208xx references
# ============================================================
print("=== Model 208xx references in binary ===")
for m in [b'20880', b'20882', b'20885', b'20888']:
    pos = 0
    while True:
        idx = data.find(m, pos)
        if idx == -1: break
        ctx = data[idx-2:idx+60]
        printable = ''.join(chr(b) if 32<=b<127 else '.' for b in ctx)
        print(f"  {m.decode()} @ 0x{idx:06x}: {printable}")
        pos = idx + 1
print()

# ============================================================
# 2. Decode per-model key table (models with HMAC keys)
# ============================================================
model_entry_starts = [0x62213, 0x62273, 0x622d3, 0x62333, 0x62393]
print("=== Per-model HMAC key table ===")
for model_off in model_entry_starts:
    off = model_off
    strings = []
    for _ in range(10):
        try:
            s = get_str(off)
            strings.append((off, s))
            off += len(s) + 1
        except:
            break
        if off > 0x62490:
            break
    model_str = strings[0][1] if strings else '??'
    print(f"Model {model_str}:")
    for (soff, s) in strings[1:]:
        try:
            padding = '=' * (-len(s) % 4)
            decoded = base64.b64decode(s + padding)
            print(f"  @ 0x{soff:06x}: b64 -> hex: {decoded.hex()}")
        except:
            print(f"  @ 0x{soff:06x}: raw key: {s!r}")
    print()

# ============================================================
# 3. Decode the pointer table at 0x624a0+
# This maps model numbers to their per-model entry
# ============================================================
print("=== Model dispatch table at 0x624a0 ===")
offs = 0x624a0
for i in range(16):
    off = offs + i*8
    val = int.from_bytes(data[off:off+8], 'little')
    if 0x56000 <= val <= 0x69fff:
        try:
            s = get_str(val)
            print(f"  0x{off:06x}: ptr -> 0x{val:06x} = {s!r}")
        except:
            print(f"  0x{off:06x}: ptr -> 0x{val:06x}")
    elif 10000 < val < 100000:
        print(f"  0x{off:06x}: int = {val} (model number?)")
    elif val == 0:
        print(f"  0x{off:06x}: NULL")
    else:
        print(f"  0x{off:06x}: 0x{val:016x}")

# ============================================================
# 4. Look at the key strings in context
# ============================================================
print()
print("=== Key strings near 0x61db7 ===")
hexdump(data, 0x61db0, length=0x80)

print()
print("=== Area before model table (0x621f0 - 0x62215) ===")
hexdump(data, 0x621f0, length=0x30)

# ============================================================
# 5. ASN.1 / X.509 certificate search
# ============================================================
print()
print("=== Searching for X.509 certificate markers ===")
# DER certificate starts with 30 82 (SEQUENCE of length > 127)
der_markers = [b'\x30\x82', b'\x30\x83', b'\x30\x84']
for marker in der_markers:
    pos = 0
    count = 0
    while count < 3:
        idx = data.find(marker, pos)
        if idx == -1: break
        size = int.from_bytes(data[idx+2:idx+4], 'big')
        print(f"  DER SEQUENCE at 0x{idx:06x}, size=0x{size:x} ({size})")
        # show more context
        if size > 100:
            print(f"    data: {data[idx:idx+20].hex()}")
        pos = idx + 1
        count += 1

# ============================================================
# 6. Show the global keys (9sLeM7j..., C6PMgHL..., 07ltETG...)
# ============================================================
print()
print("=== Global HMAC keys ===")
global_keys_area = 0x61db7
off = global_keys_area
for _ in range(5):
    try:
        s = get_str(off)
        print(f"  @ 0x{off:06x}: {s!r}")
        off += len(s) + 1
    except:
        break
