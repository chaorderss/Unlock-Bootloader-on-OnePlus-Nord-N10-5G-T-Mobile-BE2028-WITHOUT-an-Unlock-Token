#!/usr/bin/env python3
"""
Extract XBL (and other bootloader) images from Global OTA payload.bin.
Parses the payload.bin CrAU format without needing the protobuf library.
"""

import struct
import urllib.request
import zlib
import lzma
import io
import os
import sys

OTA_URL = "https://otafsg1.h2os.com/patch/amazone2/GLO/OnePlusN10Oxygen/OnePlusN10Oxygen_14.E.11_GLO_011_2103252042/OnePlusN10Oxygen_14.E.11_OTA_011_all_2103252042_8c3ba4b4e0.zip"
OUT_DIR = "/Users/xmxx/pinganhuijia"

# Partitions we want to extract
WANTED = ['xbl', 'xbl_config', 'abl', 'imagefv', 'tz', 'hyp', 'devcfg',
          'aop', 'featenabler', 'storsec', 'uefisecapp', 'keymaster',
          'qupfw', 'vbmeta', 'oem_stanvbk']

def fetch_range(url, start, length):
    req = urllib.request.Request(url, headers={
        'Range': f'bytes={start}-{start+length-1}',
        'User-Agent': 'Mozilla/5.0'
    })
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()

def get_file_size(url):
    req = urllib.request.Request(url, method='HEAD', headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return int(resp.headers['Content-Length'])

def read_varint(data, pos):
    result, shift = 0, 0
    while pos < len(data):
        b = data[pos]; pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80): break
        shift += 7
    return result, pos

def parse_protobuf_fields(data, start=0, end=None):
    """Yield (field_num, wire_type, value/bytes) tuples."""
    if end is None: end = len(data)
    pos = start
    while pos < end:
        tag, pos = read_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 7
        if wire_type == 0:   # varint
            val, pos = read_varint(data, pos)
            yield (field_num, 0, val)
        elif wire_type == 1: # 64-bit
            val = struct.unpack_from('<Q', data, pos)[0]
            pos += 8
            yield (field_num, 1, val)
        elif wire_type == 2: # length-delimited
            length, pos = read_varint(data, pos)
            val = data[pos:pos+length]
            pos += length
            yield (field_num, 2, val)
        elif wire_type == 5: # 32-bit
            val = struct.unpack_from('<I', data, pos)[0]
            pos += 4
            yield (field_num, 5, val)
        else:
            # Unknown wire type, skip
            break

def parse_install_operation(op_data):
    """
    InstallOperation proto (OnePlus N10 OTA custom field layout):
      1: type (varint)
      2: data_offset (varint)   <-- non-standard: standard has this at field 7
      3: data_length (varint)   <-- non-standard: standard has this at field 8
      6: dst_extents (repeated Extent, wire_type 2)
      8: data_sha256_hash (bytes)
    Extent sub-message: field 1=start_block, field 2=num_blocks
    """
    op = {'type': 0, 'data_offset': None, 'data_length': None, 'dst_extents': []}
    for f, wt, v in parse_protobuf_fields(op_data):
        if f == 1 and wt == 0:
            op['type'] = v
        elif f == 2 and wt == 0:   # data_offset
            op['data_offset'] = v
        elif f == 3 and wt == 0:   # data_length
            op['data_length'] = v
        elif f == 6 and wt == 2:   # dst_extents (Extent message)
            extent = {}
            for ef, ewt, ev in parse_protobuf_fields(v):
                if ef == 1 and ewt == 0: extent['start'] = ev
                elif ef == 2 and ewt == 0: extent['num_blocks'] = ev
            op['dst_extents'].append(extent)
        # field 7/8 (standard data_offset/data_length) also checked as fallback
        elif f == 7 and wt == 0:
            if op['data_offset'] is None: op['data_offset'] = v
        elif f == 8 and wt == 0:
            if op['data_length'] is None: op['data_length'] = v
    return op

def parse_partition_update(pu_data):
    """
    PartitionUpdate proto:
      1: partition_name (string)
      7: new_partition_info (PartitionInfo, field 1=size)
      8: operations (repeated InstallOperation)
    """
    name = None
    operations = []
    new_size = None
    for f, wt, v in parse_protobuf_fields(pu_data):
        if f == 1 and wt == 2:
            name = v.decode('utf-8', errors='replace')
        elif f == 7 and wt == 2:  # new_partition_info
            for ff, fwt, fv in parse_protobuf_fields(v):
                if ff == 1 and fwt == 0: new_size = fv  # PartitionInfo.size
        elif f == 8 and wt == 2:  # operations
            op = parse_install_operation(v)
            # All op types included (REPLACE, REPLACE_XZ, ZERO, etc.)
            operations.append(op)
    return name, operations, new_size

def parse_manifest(manifest_data):
    """Parse DeltaArchiveManifest to get partition list."""
    partitions = {}
    for f, wt, v in parse_protobuf_fields(manifest_data):
        if f == 13 and wt == 2:  # repeated PartitionUpdate
            name, ops, new_size = parse_partition_update(v)
            if name:
                partitions[name] = {'operations': ops, 'new_size': new_size}
                print(f"  Partition: {name:30s}  ops={len(ops)}  new_size={new_size}")
    return partitions

INSTALL_OP_TYPES = {
    0: 'REPLACE', 1: 'REPLACE_BZ', 2: 'MOVE', 3: 'BSDIFF',
    4: 'SOURCE_COPY', 5: 'SOURCE_BSDIFF', 6: 'ZERO', 7: 'DISCARD',
    8: 'REPLACE_XZ', 9: 'PUFFDIFF', 10: 'BROTLI_BSDIFF'
}

BLOCK_SIZE = 4096  # standard Android payload block size

def apply_operation(op, payload_data_url, payload_data_start_in_zip, out_file):
    """Download and apply one install operation."""
    op_type = op['type']
    data_offset = op['data_offset']
    data_length = op['data_length']
    dst_extents = op['dst_extents']
    type_name = INSTALL_OP_TYPES.get(op_type, f'UNKNOWN_{op_type}')

    if op_type == 6:  # ZERO
        total = sum(e.get('num_blocks', 0) * BLOCK_SIZE for e in dst_extents)
        print(f"    Op ZERO: {total} bytes")
        out_file.write(b'\x00' * total)
        return

    if op_type == 7:  # DISCARD
        total = sum(e.get('num_blocks', 0) * BLOCK_SIZE for e in dst_extents)
        print(f"    Op DISCARD: {total} bytes")
        out_file.write(b'\x00' * total)
        return

    if data_offset is None or data_length is None:
        print(f"    Op {type_name}: missing data_offset/length, skipping")
        total = sum(e.get('num_blocks', 0) * BLOCK_SIZE for e in dst_extents)
        out_file.write(b'\x00' * total)
        return

    abs_offset = payload_data_start_in_zip + data_offset
    print(f"    Op {type_name}: {data_length:,} bytes @ zip+0x{abs_offset:x}")
    compressed = fetch_range(payload_data_url, abs_offset, data_length)

    if op_type == 0:  # REPLACE (raw)
        decompressed = compressed
    elif op_type == 1:  # REPLACE_BZ
        import bz2
        decompressed = bz2.decompress(compressed)
    elif op_type == 8:  # REPLACE_XZ
        decompressed = lzma.decompress(compressed)
    else:
        print(f"    WARNING: Unsupported op type {type_name} - writing zeros")
        total = sum(e.get('num_blocks', 0) * BLOCK_SIZE for e in dst_extents)
        out_file.write(b'\x00' * total)
        return

    # Write decompressed data to dst_extents positions
    # For simple sequential partitions, extents are usually one contiguous range
    if dst_extents:
        src_pos = 0
        for extent in dst_extents:
            start_block = extent.get('start', 0)
            num_blocks = extent.get('num_blocks', 0)
            length = num_blocks * BLOCK_SIZE
            chunk = decompressed[src_pos:src_pos + length]
            # Pad if needed
            if len(chunk) < length:
                chunk += b'\x00' * (length - len(chunk))
            out_file.seek(start_block * BLOCK_SIZE)
            out_file.write(chunk)
            src_pos += length
    else:
        out_file.write(decompressed)

    print(f"      -> {len(decompressed):,} bytes decompressed")


def get_payload_data_start(zip_url, file_size):
    """Find where payload.bin data starts in the zip file."""
    eocd_size = min(65557, file_size)
    eocd_data = fetch_range(zip_url, file_size - eocd_size, eocd_size)
    eocd_pos = eocd_data.rfind(b'\x50\x4b\x05\x06')
    eocd = eocd_data[eocd_pos:]
    cd_size = struct.unpack_from('<I', eocd, 12)[0]
    cd_offset = struct.unpack_from('<I', eocd, 16)[0]

    if cd_offset == 0xFFFFFFFF:
        z64_locator = eocd_data.rfind(b'\x50\x4b\x06\x07')
        if z64_locator >= 0:
            z64_offset = struct.unpack_from('<Q', eocd_data, z64_locator + 8)[0]
            z64_data = fetch_range(zip_url, z64_offset, 56)
            cd_size = struct.unpack_from('<Q', z64_data, 40)[0]
            cd_offset = struct.unpack_from('<Q', z64_data, 48)[0]

    cd_data = fetch_range(zip_url, cd_offset, cd_size)
    pos = 0
    while pos < len(cd_data):
        if cd_data[pos:pos+4] != b'\x50\x4b\x01\x02': break
        fname_len = struct.unpack_from('<H', cd_data, pos+28)[0]
        extra_len = struct.unpack_from('<H', cd_data, pos+30)[0]
        comment_len = struct.unpack_from('<H', cd_data, pos+32)[0]
        local_offset = struct.unpack_from('<I', cd_data, pos+42)[0]
        fname = cd_data[pos+46:pos+46+fname_len].decode('utf-8', errors='replace')

        if local_offset == 0xFFFFFFFF:
            extra = cd_data[pos+46+fname_len:pos+46+fname_len+extra_len]
            ep = 0
            while ep < len(extra)-4:
                eid = struct.unpack_from('<H', extra, ep)[0]
                elen = struct.unpack_from('<H', extra, ep+2)[0]
                if eid == 0x0001:
                    off = ep+4
                    if struct.unpack_from('<I', cd_data, pos+24)[0] == 0xFFFFFFFF: off+=8  # skip uncompr
                    if struct.unpack_from('<I', cd_data, pos+20)[0] == 0xFFFFFFFF: off+=8  # skip compr
                    local_offset = struct.unpack_from('<Q', extra, off)[0]
                    break
                ep += 4+elen

        if fname == 'payload.bin':
            # Read local file header to get exact data start
            local_hdr = fetch_range(zip_url, local_offset, 30)
            lfname_len = struct.unpack_from('<H', local_hdr, 26)[0]
            lextra_len = struct.unpack_from('<H', local_hdr, 28)[0]
            data_start = local_offset + 30 + lfname_len + lextra_len
            print(f"payload.bin data starts at zip offset 0x{data_start:x} ({data_start:,})")
            return data_start

        pos += 46 + fname_len + extra_len + comment_len
    raise ValueError("payload.bin not found in zip")

# ─── Main ────────────────────────────────────────────────────────────────────
print("[1] Getting OTA file size...")
file_size = get_file_size(OTA_URL)
print(f"    OTA size: {file_size:,} bytes ({file_size/(1024**3):.2f} GB)")

print("[2] Finding payload.bin offset in zip...")
payload_data_start = get_payload_data_start(OTA_URL, file_size)

print("[3] Reading payload.bin header...")
header = fetch_range(OTA_URL, payload_data_start, 24)
magic = header[:4]
if magic != b'CrAU':
    raise ValueError(f"Bad payload magic: {magic}")
version = struct.unpack_from('>Q', header, 4)[0]
manifest_len = struct.unpack_from('>Q', header, 12)[0]
metadata_sig_size = struct.unpack_from('>I', header, 20)[0]
data_offset = 24 + manifest_len + metadata_sig_size
print(f"    version={version}, manifest_len={manifest_len:,}, metadata_sig={metadata_sig_size}")
print(f"    Partition data starts at payload offset 0x{data_offset:x}")

# Use cached manifest if available
import os
manifest_cache = '/Users/xmxx/pinganhuijia/ota_manifest_raw.bin'
if os.path.exists(manifest_cache):
    with open(manifest_cache, 'rb') as f:
        manifest_data = f.read()
    print(f"[4] Using cached manifest ({len(manifest_data):,} bytes)")
else:
    print(f"[4] Downloading manifest ({manifest_len:,} bytes)...")
    manifest_data = fetch_range(OTA_URL, payload_data_start + 24, manifest_len)
    with open(manifest_cache, 'wb') as mf:
        mf.write(manifest_data)

print("[5] Parsing manifest...")
partitions = parse_manifest(manifest_data)
print(f"\n    Found {len(partitions)} partitions total")

# Absolute offset of payload's partition data in the zip file
partition_data_abs = payload_data_start + data_offset

print("\n[6] Extracting wanted partitions:")
for pname in WANTED:
    if pname not in partitions:
        print(f"  {pname}: NOT FOUND in OTA")
        continue
    pinfo = partitions[pname]
    ops = pinfo['operations']
    new_size = pinfo['new_size']
    if not ops:
        print(f"  {pname}: no operations (maybe empty or already up to date)")
        continue

    out_path = os.path.join(OUT_DIR, f"global_{pname}.img")
    print(f"\n  [{pname}] new_size={new_size:,}, ops={len(ops)} -> {out_path}")

    with open(out_path, 'w+b') as f:
        # Pre-allocate with zeros to new_size
        if new_size:
            f.seek(new_size - 1)
            f.write(b'\x00')
            f.seek(0)
        for i, op in enumerate(ops):
            apply_operation(op, OTA_URL, partition_data_abs, f)
        actual_size = f.tell() if not new_size else new_size

    sz_mb = os.path.getsize(out_path) / (1024*1024)
    print(f"  -> Saved {sz_mb:.2f} MB")

print("\n[7] Done! Files in", OUT_DIR)
for pname in WANTED:
    path = os.path.join(OUT_DIR, f"global_{pname}.img")
    if os.path.exists(path):
        print(f"  {path}  ({os.path.getsize(path):,} bytes)")