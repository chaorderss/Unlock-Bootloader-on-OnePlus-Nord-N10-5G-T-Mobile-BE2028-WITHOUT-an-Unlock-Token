#!/usr/bin/env python3
"""List all files in OTA zip and find bootloader partition images."""

import struct
import urllib.request

OTA_URL = "https://otafsg1.h2os.com/patch/amazone2/GLO/OnePlusN10Oxygen/OnePlusN10Oxygen_14.E.11_GLO_011_2103252042/OnePlusN10Oxygen_14.E.11_OTA_011_all_2103252042_8c3ba4b4e0.zip"

def fetch_range(url, start, length):
    req = urllib.request.Request(url, headers={
        'Range': f'bytes={start}-{start+length-1}',
        'User-Agent': 'Mozilla/5.0'
    })
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()

def get_file_size(url):
    req = urllib.request.Request(url, method='HEAD', headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return int(resp.headers['Content-Length'])

def list_zip_entries(url):
    file_size = get_file_size(url)
    print(f"OTA file size: {file_size:,} bytes ({file_size/(1024**3):.2f} GB)")

    eocd_size = min(65557, file_size)
    eocd_data = fetch_range(url, file_size - eocd_size, eocd_size)
    eocd_pos = eocd_data.rfind(b'\x50\x4b\x05\x06')
    if eocd_pos < 0:
        raise ValueError("EOCD not found")

    eocd = eocd_data[eocd_pos:]
    cd_size = struct.unpack_from('<I', eocd, 12)[0]
    cd_offset = struct.unpack_from('<I', eocd, 16)[0]

    if cd_offset == 0xFFFFFFFF:
        z64_locator = eocd_data.rfind(b'\x50\x4b\x06\x07')
        if z64_locator >= 0:
            z64_offset = struct.unpack_from('<Q', eocd_data, z64_locator + 8)[0]
            z64_data = fetch_range(url, z64_offset, 56)
            cd_size = struct.unpack_from('<Q', z64_data, 40)[0]
            cd_offset = struct.unpack_from('<Q', z64_data, 48)[0]

    print(f"Central directory: offset=0x{cd_offset:x}, size={cd_size:,}")
    cd_data = fetch_range(url, cd_offset, cd_size)

    entries = []
    pos = 0
    while pos < len(cd_data):
        if cd_data[pos:pos+4] != b'\x50\x4b\x01\x02':
            break
        fname_len = struct.unpack_from('<H', cd_data, pos + 28)[0]
        extra_len = struct.unpack_from('<H', cd_data, pos + 30)[0]
        comment_len = struct.unpack_from('<H', cd_data, pos + 32)[0]
        local_offset = struct.unpack_from('<I', cd_data, pos + 42)[0]
        compress_method = struct.unpack_from('<H', cd_data, pos + 10)[0]
        compressed_size = struct.unpack_from('<I', cd_data, pos + 20)[0]
        uncompressed_size = struct.unpack_from('<I', cd_data, pos + 24)[0]
        fname = cd_data[pos+46:pos+46+fname_len].decode('utf-8', errors='replace')

        # Handle ZIP64
        if local_offset == 0xFFFFFFFF or compressed_size == 0xFFFFFFFF or uncompressed_size == 0xFFFFFFFF:
            extra = cd_data[pos+46+fname_len:pos+46+fname_len+extra_len]
            ep = 0
            vals = []
            while ep < len(extra) - 4:
                eid = struct.unpack_from('<H', extra, ep)[0]
                elen = struct.unpack_from('<H', extra, ep+2)[0]
                if eid == 0x0001:
                    off = ep + 4
                    if uncompressed_size == 0xFFFFFFFF:
                        uncompressed_size = struct.unpack_from('<Q', extra, off)[0]; off += 8
                    if compressed_size == 0xFFFFFFFF:
                        compressed_size = struct.unpack_from('<Q', extra, off)[0]; off += 8
                    if local_offset == 0xFFFFFFFF:
                        local_offset = struct.unpack_from('<Q', extra, off)[0]; off += 8
                    break
                ep += 4 + elen

        entries.append({
            'name': fname,
            'compressed_size': compressed_size,
            'uncompressed_size': uncompressed_size,
            'compress_method': compress_method,
            'local_offset': local_offset
        })
        pos += 46 + fname_len + extra_len + comment_len

    return entries

print("[1] Getting OTA file list...")
entries = list_zip_entries(OTA_URL)
print(f"\nTotal files: {len(entries)}\n")

print("=== All files ===")
for e in sorted(entries, key=lambda x: x['name']):
    sz = e['uncompressed_size']
    print(f"  {e['name']:60s}  {sz:>12,} bytes  method={e['compress_method']}")

print("\n=== Bootloader-related images ===")
bootloader_keywords = ['xbl', 'abl', 'sbl', 'tz', 'hyp', 'rpm', 'devcfg', 'cmnlib',
                       'keymaster', 'qseecom', 'imagefv', 'featenabler', 'boot',
                       'vbmeta', 'logo', 'devinfo', 'misc', 'splash']
for e in entries:
    name_lower = e['name'].lower()
    if any(k in name_lower for k in bootloader_keywords) and name_lower.endswith('.img'):
        print(f"  {e['name']:60s}  {e['uncompressed_size']:>12,} bytes")
