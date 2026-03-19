#!/usr/bin/env python3
"""Dump raw hex of first xbl InstallOperation bytes."""

def read_varint(data, pos):
    result, shift = 0, 0
    while pos < len(data):
        b = data[pos]; pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80): break
        shift += 7
    return result, pos

def iter_fields(data):
    pos, end = 0, len(data)
    while pos < end:
        tag, pos = read_varint(data, pos)
        fn, wt = tag >> 3, tag & 7
        if wt == 0:
            val, pos = read_varint(data, pos)
            yield fn, 0, val, b''
        elif wt == 1:
            val = int.from_bytes(data[pos:pos+8], 'little'); pos += 8
            yield fn, 1, val, b''
        elif wt == 2:
            ln, pos = read_varint(data, pos)
            raw = data[pos:pos+ln]; pos += ln
            yield fn, 2, ln, raw
        elif wt == 5:
            val = int.from_bytes(data[pos:pos+4], 'little'); pos += 4
            yield fn, 5, val, b''
        else:
            break

with open('/Users/xmxx/pinganhuijia/ota_manifest_raw.bin', 'rb') as f:
    manifest = f.read()

# Walk manifest, find xbl PartitionUpdate, get ops
for fn, wt, val, raw in iter_fields(manifest):
    if fn == 13 and wt == 2:
        # Is this xbl?
        name = None
        for f2, w2, v2, r2 in iter_fields(raw):
            if f2 == 1 and w2 == 2:
                name = r2.decode('utf-8', errors='replace')
                break
        if name != 'xbl':
            continue
        # Print all fields in this PartitionUpdate
        print(f"=== xbl PartitionUpdate raw ({len(raw)} bytes) ===")
        for f2, w2, v2, r2 in iter_fields(raw):
            if f2 == 8 and w2 == 2:
                print(f"\nInstallOperation (field 8, {len(r2)} bytes):")
                print("  hex: " + ' '.join(f'{b:02x}' for b in r2))
                print("  Decode field-by-field:")
                for f3, w3, v3, r3 in iter_fields(r2):
                    if w3 == 2:
                        print(f"    field {f3} wt={w3} len={v3}  hex={r3[:32].hex()}")
                    else:
                        print(f"    field {f3} wt={w3} val={v3} (0x{v3:x})")
        break
