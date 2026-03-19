#!/usr/bin/env python3
"""Diagnose why manifest shows ops=0 - analyze raw protobuf fields."""

import struct
import urllib.request

OTA_URL = "https://otafsg1.h2os.com/patch/amazone2/GLO/OnePlusN10Oxygen/OnePlusN10Oxygen_14.E.11_GLO_011_2103252042/OnePlusN10Oxygen_14.E.11_OTA_011_all_2103252042_8c3ba4b4e0.zip"

def fetch_range(url, start, length):
    req = urllib.request.Request(url, headers={
        'Range': f'bytes={start}-{start+length-1}',
        'User-Agent': 'Mozilla/5.0'
    })
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()

def read_varint(data, pos):
    result, shift = 0, 0
    while pos < len(data):
        b = data[pos]; pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80): break
        shift += 7
    return result, pos

def iter_fields(data, start=0, end=None):
    if end is None: end = len(data)
    pos = start
    while pos < end:
        try:
            tag, pos = read_varint(data, pos)
        except Exception:
            break
        field_num = tag >> 3
        wire_type = tag & 7
        if wire_type == 0:
            val, pos = read_varint(data, pos)
            yield field_num, 0, val, None
        elif wire_type == 1:
            if pos + 8 > end: break
            val = struct.unpack_from('<Q', data, pos)[0]; pos += 8
            yield field_num, 1, val, None
        elif wire_type == 2:
            length, pos = read_varint(data, pos)
            if pos + length > end: break
            val = data[pos:pos+length]; pos += length
            yield field_num, 2, len(val), val
        elif wire_type == 5:
            if pos + 4 > end: break
            val = struct.unpack_from('<I', data, pos)[0]; pos += 4
            yield field_num, 5, val, None
        else:
            break

# Load cached manifest
import os
manifest_cache = '/Users/xmxx/pinganhuijia/ota_manifest_raw.bin'
if os.path.exists(manifest_cache):
    with open(manifest_cache, 'rb') as f:
        manifest_data = f.read()
    print(f"Loaded manifest from cache: {len(manifest_data):,} bytes")
else:
    print("Downloading manifest...")
    # First get payload start
    file_size = 2_532_186_608
    payload_data_start = 47860
    header = fetch_range(OTA_URL, payload_data_start, 24)
    manifest_len = struct.unpack_from('>Q', header, 12)[0]
    print(f"manifest_len = {manifest_len:,}")
    manifest_data = fetch_range(OTA_URL, payload_data_start + 24, manifest_len)
    with open(manifest_cache, 'wb') as f:
        f.write(manifest_data)
    print("Saved manifest cache")

# Find xbl partition entry in manifest
print("\n=== Scanning for partition entries (field 13) ===")

partition_count = 0
for fnum, wtype, val, raw in iter_fields(manifest_data):
    if fnum == 13 and wtype == 2:
        # This is a PartitionUpdate message
        # First find name (field 1)
        name = None
        op_count = 0
        op_types = []
        for ff, fwt, fval, fraw in iter_fields(raw):
            if ff == 1 and fwt == 2:
                name = fraw.decode('utf-8', errors='replace')
            elif ff == 8 and fwt == 2:  # operations
                op_count += 1
                # Get op type
                for off, owt, oval, _ in iter_fields(fraw):
                    if off == 1:
                        op_types.append(oval)
                        break

        if name in ('xbl', 'abl', 'tz', 'boot'):
            print(f"\n  Partition: {name}")
            print(f"    Total ops (field 8): {op_count}")
            op_type_names = {0:'REPLACE',1:'REPLACE_BZ',2:'MOVE',3:'BSDIFF',
                            4:'SOURCE_COPY',5:'SOURCE_BSDIFF',6:'ZERO',7:'DISCARD',
                            8:'REPLACE_XZ',9:'PUFFDIFF',10:'BROTLI_BSDIFF'}
            counts = {}
            for t in op_types:
                counts[op_type_names.get(t,f'UNKNOWN_{t}')] = counts.get(op_type_names.get(t,f'UNKNOWN_{t}'),0)+1
            print(f"    Op types: {counts}")

            # Also dump raw field numbers present
            field_nums = {}
            for ff, fwt, _, _ in iter_fields(raw):
                field_nums[ff] = field_nums.get(ff, 0) + 1
            print(f"    All field numbers present: {field_nums}")

        partition_count += 1

print(f"\nTotal partitions found: {partition_count}")

# Also check top-level manifest fields
print("\n=== Top-level manifest fields ===")
top_fields = {}
for fnum, wtype, val, raw in iter_fields(manifest_data):
    top_fields[fnum] = top_fields.get(fnum, 0) + 1
print(f"Field distribution: {top_fields}")
print(f"(Field 13 = partitions, Field 1 = block_size, Field 2 = signatures_offset)")
