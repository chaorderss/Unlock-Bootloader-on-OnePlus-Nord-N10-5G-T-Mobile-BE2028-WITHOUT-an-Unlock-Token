#!/usr/bin/env python3
"""Analyze unlock token check in Global ABL - find token format and bypass"""
import re
import sys
import struct

sys.path.insert(0, '/Library/Frameworks/Python.framework/Versions/3.14/lib/python3.14/site-packages')
import uefi_firmware

fname = '/Users/xmxx/pinganhuijia/global_abl.img'
with open(fname, 'rb') as f:
    raw = f.read()

fv_data = raw[0x3000:]
parser = uefi_firmware.AutoParser(fv_data)
fw = parser.parse()

# Get the decompressed LinuxLoader data
# Based on earlier run: it's in GuidDefinedSection depth=4

def collect_big_sections(obj, cur_depth=0, results=None):
    if results is None:
        results = []
    data = getattr(obj, 'data', None)
    if data and len(data) > 100000:
        results.append((cur_depth, type(obj).__name__, data))
    objects = getattr(obj, 'objects', None) or []
    for child in objects:
        collect_big_sections(child, cur_depth+1, results)
    return results

sections = collect_big_sections(fw)
print(f"Large sections: {[(d, t, len(dt)) for d,t,dt in sections]}")

# Get the decompressed data at depth=4
target = None
for depth, typename, data in sections:
    if depth == 4 and typename == 'GuidDefinedSection':
        target = data
        print(f"\nUsing GuidDefinedSection at depth={depth}, size={len(data)}")
        break

if target is None:
    # Fall back to first large section
    target = sections[0][2] if sections else b''
    print(f"Using fallback, size={len(target)}")

# ===== ANALYZE TOKEN CHECK =====
TOKEN_STR = b'Please flash unlock token first.'
hits = [m.start() for m in re.finditer(re.escape(TOKEN_STR), target, re.I)]
print(f"\nToken string '{TOKEN_STR.decode()}' at: {[hex(h) for h in hits]}")

for h in hits:
    # Show large context
    ctx_start = max(0, h-200)
    ctx_end = min(len(target), h+500)
    ctx = target[ctx_start:ctx_end]

    print(f"\n--- Context at {hex(h)} ---")
    print(f"Raw hex (around string):")
    # Show hex dump
    for i in range(0, min(len(ctx), 400), 32):
        row = ctx[i:i+32]
        hx = ' '.join(f'{b:02x}' for b in row)
        asc = ''.join(chr(b) if 32<=b<127 else '.' for b in row)
        print(f"  {ctx_start+i:08x}: {hx}  |{asc}|")

# ===== SEARCH FOR TOKEN-RELATED FUNCTIONS =====
print("\n=== Token-related strings ===")
token_patterns = [
    b'token',
    b'unlock_token',
    b'multiimgoem',
    b'multiimg',
    b'custpartition',
    b'FlattenedDevTree',
    b'cust',
    b'GetTokenFromMultiImg',
    b'CheckUnlockToken',
    b'unlock_bootloader',
    b'oemdeviceinfo',
]
for pat in token_patterns:
    found_hits = [m.start() for m in re.finditer(re.escape(pat), target, re.I)]
    if found_hits:
        print(f"\n'{pat.decode()}' at {[hex(h) for h in found_hits[:5]]}:")
        for h in found_hits[:3]:
            ctx = target[max(0,h-60):h+100]
            pr = bytes(b if 32<=b<127 else ord('.') for b in ctx)
            print(f"  {pr.decode()}")

# ===== LOOK FOR devinfo STRUCTURE ACCESS PATTERNS =====
print("\n=== DevInfo related strings ===")
devinfo_pats = [b'OemUnlock', b'is_unlock', b'charger_screen', b'DevInfo',
                b'device_info', b'IsUnlocked', b'OEMUnlock', b'unlock_allowed']
for pat in devinfo_pats:
    found_hits = [m.start() for m in re.finditer(re.escape(pat), target, re.I)]
    if found_hits:
        print(f"\n'{pat.decode()}' at {[hex(h) for h in found_hits[:5]]}:")
        for h in found_hits[:2]:
            ctx = target[max(0,h-40):h+80]
            pr = bytes(b if 32<=b<127 else ord('.') for b in ctx)
            print(f"  {pr.decode()}")

# Save decompressed data for further analysis with external tools
outpath = '/Users/xmxx/pinganhuijia/global_abl_decompressed.bin'
with open(outpath, 'wb') as f:
    f.write(target)
print(f"\nDecompressed data saved to: {outpath} ({len(target)} bytes)")

import re
import sys

sys.path.insert(0, '/Library/Frameworks/Python.framework/Versions/3.14/lib/python3.14/site-packages')
import uefi_firmware

fname = '/Users/xmxx/pinganhuijia/global_abl.img'
with open(fname, 'rb') as f:
    raw = f.read()

fv_data = raw[0x3000:]
parser = uefi_firmware.AutoParser(fv_data)
fw = parser.parse()

def find_data(obj, target_depth=None, cur_depth=0):
    """Recursively find all data blobs from parsed FV tree"""
    data = getattr(obj, 'data', None)
    if data and len(data) > 1000:
        yield (cur_depth, type(obj).__name__, data)
    objects = getattr(obj, 'objects', None) or []
    for child in objects:
        yield from find_data(child, target_depth, cur_depth+1)

print("Searching all decompressed data sections for unlock strings...")
SEARCH_PATTERNS = [
    b'Please flash',
    b'unlock token',
    b'token first',
    b'fastboot flashing',
    b'oem_unlock',
    b'is_oem_unlock',
    b'OEMUnlock',
    b'unlock_allowed',
    b'allow_oem_unlock',
    b'devinfo',
    b'cust-unlock',
    b'carrier_unlock',
    b'FAIL',  # fastboot fail prefix
]

biggest_data = None
biggest_size = 0

for depth, typename, data in find_data(fw):
    hits = []
    for pat in SEARCH_PATTERNS:
        for m in re.finditer(re.escape(pat), data, re.I):
            ctx = data[max(0, m.start()-50):m.start()+100]
            hits.append((pat.decode(), m.start(), ctx))

    if hits:
        print(f"\n[depth={depth}, {typename}, size={len(data)}b] HITS:")
        for pat, offset, ctx in hits[:20]:
            printable = bytes(b if 32<=b<127 else ord('.') for b in ctx)
            print(f"  '{pat}' @ {hex(offset)}: {printable.decode()}")

    if len(data) > biggest_size:
        biggest_size = len(data)
        biggest_data = (depth, typename, data)

print(f"\nBiggest data blob: depth={biggest_data[0]}, {biggest_data[1]}, {biggest_data[2].__len__()}b")

# Search biggest blob for ALL strings
if biggest_data:
    d = biggest_data[2]
    all_strs = re.findall(b'[\x20-\x7e]{8,}', d)
    print(f"Total strings in biggest blob: {len(all_strs)}")

    # Print all strings containing relevant keywords
    for s in all_strs:
        sl = s.lower()
        if any(k in sl for k in [b'unlock', b'token', b'devinfo', b'fastboot', b'please', b'oem']):
            print(f"  KEYWORD: {s.decode()}")

import re
import sys

def find_strings(data, min_len=6):
    return re.findall(b'[\x20-\x7e]{' + str(min_len).encode() + b',}', data)

def search_interesting(data):
    strs = find_strings(data)
    keywords = [b'unlock', b'token', b'fastboot', b'devinfo', b'Please',
                b'flash', b'oem', b'carrier', b'UNLOCK', b'secure']
    return [s for s in strs if any(k in s.lower() for k in keywords)]

# Use uefi_firmware (Python 3.14)
sys.path.insert(0, '/Library/Frameworks/Python.framework/Versions/3.14/lib/python3.14/site-packages')
import uefi_firmware

fname = '/Users/xmxx/pinganhuijia/global_abl.img'
with open(fname, 'rb') as f:
    raw = f.read()

print(f"File: {fname}, size: {len(raw)}")

# FV starts at ELF LOAD segment offset 0x3000
fv_data = raw[0x3000:]
parser = uefi_firmware.AutoParser(fv_data)
fw = parser.parse()
print(f"Parsed as: {type(fw).__name__}")

def traverse(obj, path=""):
    """Recursively traverse UEFI objects and search for strings"""
    name = getattr(obj, 'name', None) or ""
    guid = getattr(obj, 'guid', None) or ""
    cur_path = f"{path}/{type(obj).__name__}[{name or guid}]"

    data = getattr(obj, 'data', None)
    if data and len(data) > 0:
        hits = search_interesting(data)
        if hits:
            print(f"\n  HIT at {cur_path} (data={len(data)}b):")
            for s in hits[:10]:
                print(f"    -> {s.decode('ascii', errors='replace')}")

    objects = getattr(obj, 'objects', None) or []
    for child in objects:
        traverse(child, cur_path)

traverse(fw)

# Also extract all objects and dump everything
print("\n\n=== Full tree ===")
def print_tree(obj, depth=0):
    prefix = "  " * depth
    name = getattr(obj, 'name', None) or ""
    guid = str(getattr(obj, 'guid', None) or "")
    data = getattr(obj, 'data', None)
    data_len = len(data) if data else 0
    print(f"{prefix}[{type(obj).__name__}] guid={guid[:36]} name={name!r} data={data_len}b")

    if data and data_len > 0:
        # Try strings
        strs = find_strings(data)
        if strs and depth <= 5:
            for s in strs[:3]:
                print(f"{prefix}  str: {s[:60].decode('ascii','replace')}")

    objects = getattr(obj, 'objects', None) or []
    for child in objects:
        print_tree(child, depth+1)

print_tree(fw)
print("\nDone.")
