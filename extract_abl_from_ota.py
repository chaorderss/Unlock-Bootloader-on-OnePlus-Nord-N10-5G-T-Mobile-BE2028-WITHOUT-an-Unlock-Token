#!/usr/bin/env python3
"""
Extract abl.img from Android OTA zip using HTTP range requests.
Downloads only minimal data instead of the full 2.5GB file.
"""

import struct
import urllib.request
import io
import sys
import os

OTA_URL = "https://otafsg1.h2os.com/patch/amazone2/GLO/OnePlusN10Oxygen/OnePlusN10Oxygen_14.E.11_GLO_011_2103252042/OnePlusN10Oxygen_14.E.11_OTA_011_all_2103252042_8c3ba4b4e0.zip"
OUTPUT = "/Users/xmxx/pinganhuijia/global_abl.img"

def fetch_range(url, start, length):
    """Fetch bytes [start, start+length) from url."""
    req = urllib.request.Request(url, headers={
        'Range': f'bytes={start}-{start+length-1}',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X) AppleWebKit/537.36'
    })
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = resp.read()
    return data

def get_file_size(url):
    req = urllib.request.Request(url, method='HEAD', headers={
        'User-Agent': 'Mozilla/5.0'
    })
    with urllib.request.urlopen(req, timeout=10) as resp:
        return int(resp.headers['Content-Length'])

def find_zip_entry(url, file_size, target_name):
    """Find a file entry in a ZIP file using range requests."""
    # Download last 65557 bytes to find End of Central Directory
    eocd_size = min(65557, file_size)
    eocd_data = fetch_range(url, file_size - eocd_size, eocd_size)

    # Find EOCD signature (0x06054b50 = PK56)
    sig = b'\x50\x4b\x05\x06'
    eocd_pos = eocd_data.rfind(sig)
    if eocd_pos < 0:
        raise ValueError("EOCD not found")

    eocd = eocd_data[eocd_pos:]
    cd_size = struct.unpack_from('<I', eocd, 12)[0]
    cd_offset = struct.unpack_from('<I', eocd, 16)[0]
    print(f"  Central directory: offset=0x{cd_offset:x}, size={cd_size}")

    # Handle ZIP64
    if cd_offset == 0xFFFFFFFF:
        # Look for ZIP64 end of central directory locator
        z64_locator = eocd_data.rfind(b'\x50\x4b\x06\x07')
        if z64_locator >= 0:
            z64_offset = struct.unpack_from('<Q', eocd_data, z64_locator + 8)[0]
            # Download ZIP64 EOCD
            z64_data = fetch_range(url, z64_offset, 56)
            cd_size = struct.unpack_from('<Q', z64_data, 40)[0]
            cd_offset = struct.unpack_from('<Q', z64_data, 48)[0]
            print(f"  ZIP64 Central directory: offset=0x{cd_offset:x}, size={cd_size}")

    # Download central directory
    print(f"  Downloading central directory ({cd_size} bytes)...")
    cd_data = fetch_range(url, cd_offset, cd_size)

    # Parse central directory entries
    pos = 0
    while pos < len(cd_data):
        if cd_data[pos:pos+4] != b'\x50\x4b\x01\x02':
            break
        fname_len = struct.unpack_from('<H', cd_data, pos + 28)[0]
        extra_len = struct.unpack_from('<H', cd_data, pos + 30)[0]
        comment_len = struct.unpack_from('<H', cd_data, pos + 32)[0]
        local_header_offset = struct.unpack_from('<I', cd_data, pos + 42)[0]
        compress_method = struct.unpack_from('<H', cd_data, pos + 10)[0]
        compressed_size = struct.unpack_from('<I', cd_data, pos + 20)[0]
        fname = cd_data[pos+46:pos+46+fname_len].decode('utf-8', errors='replace')

        # Handle ZIP64 extended info in extra field
        if local_header_offset == 0xFFFFFFFF or compressed_size == 0xFFFFFFFF:
            extra = cd_data[pos+46+fname_len:pos+46+fname_len+extra_len]
            ep = 0
            while ep < len(extra) - 4:
                eid = struct.unpack_from('<H', extra, ep)[0]
                elen = struct.unpack_from('<H', extra, ep+2)[0]
                if eid == 0x0001:  # ZIP64 extended info
                    if compressed_size == 0xFFFFFFFF:
                        compressed_size = struct.unpack_from('<Q', extra, ep+4)[0]
                    if local_header_offset == 0xFFFFFFFF:
                        lho_off = 4
                        if compressed_size != 0xFFFFFFFF:
                            lho_off += 8
                        # Uncompressed size
                        lho_off += 8 if struct.unpack_from('<I', cd_data, pos+24)[0] == 0xFFFFFFFF else 0
                        local_header_offset = struct.unpack_from('<Q', extra, ep+4+lho_off)[0]
                    break
                ep += 4 + elen

        if fname == target_name:
            print(f"  Found '{target_name}': local_offset=0x{local_header_offset:x}, compress_method={compress_method}, compressed_size={compressed_size}")
            return local_header_offset, compress_method, compressed_size
        pos += 46 + fname_len + extra_len + comment_len

    raise ValueError(f"'{target_name}' not found in ZIP")

def read_payload_manifest(url, payload_data_start, manifest_len):
    """Read the OTA manifest."""
    try:
        # Try importing protobuf
        import update_metadata_pb2 as um
        has_proto = True
    except ImportError:
        has_proto = False

    if not has_proto:
        # Manual scan for abl partition
        # Protobuf format: field_number << 3 | wire_type
        # We look for partition names in the manifest bytes
        manifest_data = fetch_range(url, payload_data_start + 24, manifest_len)
        # Scan for "abl" string in protobuf
        abl_pos = manifest_data.find(b'\x03abl')
        if abl_pos < 0:
            abl_pos = manifest_data.find(b'nabl')  # field 14 (0x72=0x70+2, n=0x6e... no)
        print(f"  Manifest size: {manifest_len} bytes")
        # Save manifest for offline analysis
        with open('/Users/xmxx/pinganhuijia/ota_manifest.bin', 'wb') as f:
            f.write(manifest_data)
        print(f"  Manifest saved to ota_manifest.bin for analysis")
        return manifest_data
    return None

def parse_payload_header(payload_header):
    """Parse payload.bin header to get manifest length and data offset."""
    # Header format:
    # 4 bytes: magic = "CrAU"
    # 8 bytes: file format version
    # 8 bytes: manifest length
    # 4 bytes: metadata signature size
    magic = payload_header[:4]
    if magic != b'CrAU':
        raise ValueError(f"Invalid payload magic: {magic}")
    version = struct.unpack_from('>Q', payload_header, 4)[0]
    manifest_len = struct.unpack_from('>Q', payload_header, 12)[0]
    metadata_sig_size = struct.unpack_from('>I', payload_header, 20)[0]
    data_offset = 24 + manifest_len + metadata_sig_size
    print(f"  Payload version={version}, manifest_len={manifest_len}, metadata_sig={metadata_sig_size}, data_offset=0x{data_offset:x}")
    return manifest_len, metadata_sig_size, data_offset

def find_partition_in_manifest(manifest_data, partition_name):
    """
    Parse protobuf manifest to find partition data offset and length.
    DeltaArchiveManifest.partitions[] is field 13 (repeated message)
    PartitionUpdate.partition_name is field 1 (string)
    PartitionUpdate.operations[] is field 8 (repeated message)
    InstallOperation.data_offset is field 5 (uint64)
    InstallOperation.data_length is field 6 (uint64)
    """
    # Simple protobuf scanner - look for partition name
    name_bytes = partition_name.encode()
    pos = 0
    while pos < len(manifest_data):
        # Look for the string directly with a length prefix
        idx = manifest_data.find(name_bytes, pos)
        if idx < 0:
            break
        # Protobuf string field: tag byte(s) + varint length + data
        # Check if preceding byte is the length of the name
        if idx > 0 and manifest_data[idx-1] == len(name_bytes):
            print(f"  Found partition name '{partition_name}' at manifest offset 0x{idx:x}")
            # The operations with data_offset/data_length should follow
            # Look for data_offset (field 5, wire_type 0 = varint, tag = 0x28)
            search_area = manifest_data[idx:idx+4096]
            # For operation type REPLACE (2), scan for data_offset and data_length
            return idx, search_area
        pos = idx + 1

    return None, None

def decode_varint(data, pos):
    """Decode protobuf varint at pos, return (value, new_pos)."""
    result = 0
    shift = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not (byte & 0x80):
            break
    return result, pos

def scan_partitions_in_manifest(manifest_data):
    """Scan manifest for all partition names and their data offsets/lengths."""
    # Field 13 (partitions) tag = 13 << 3 | 2 = 0x6a (length-delimited)
    results = {}
    pos = 0
    while pos < len(manifest_data) - 4:
        tag_byte = manifest_data[pos]
        # Tag for field 13 (partitions) = 0x6a
        if tag_byte == 0x6a:
            pos += 1
            msg_len, pos = decode_varint(manifest_data, pos)
            msg_end = pos + msg_len
            if msg_end > len(manifest_data):
                continue
            # Parse PartitionUpdate message
            partition_msg = manifest_data[pos:msg_end]
            name = None
            data_offset = None
            data_length = None

            p = 0
            while p < len(partition_msg):
                if p >= len(partition_msg):
                    break
                tag = partition_msg[p]
                wire_type = tag & 0x07
                field_num = tag >> 3
                p += 1

                if wire_type == 2:  # length-delimited
                    length, p = decode_varint(partition_msg, p)
                    value_bytes = partition_msg[p:p+length]
                    if field_num == 1:  # partition_name
                        name = value_bytes.decode('utf-8', errors='replace')
                    elif field_num == 8:  # operations (repeated)
                        # Parse InstallOperation
                        op_p = 0
                        while op_p < len(value_bytes):
                            op_tag = value_bytes[op_p]
                            op_wire = op_tag & 0x07
                            op_field = op_tag >> 3
                            op_p += 1
                            if op_wire == 0:  # varint
                                v, op_p = decode_varint(value_bytes, op_p)
                                if op_field == 2:  # data_offset
                                    data_offset = v
                                elif op_field == 3:  # data_length
                                    data_length = v
                            elif op_wire == 2:  # length-delimited
                                l, op_p = decode_varint(value_bytes, op_p)
                                op_p += l
                            elif op_wire == 5:  # 32-bit
                                op_p += 4
                            elif op_wire == 1:  # 64-bit
                                op_p += 8
                            else:
                                break
                    p += length
                elif wire_type == 0:  # varint
                    _, p = decode_varint(partition_msg, p)
                elif wire_type == 1:  # 64-bit
                    p += 8
                elif wire_type == 5:  # 32-bit
                    p += 4
                else:
                    break

            if name:
                results[name] = (data_offset, data_length)
            pos = msg_end
        else:
            # Skip other fields
            wire_type = tag_byte & 0x07
            field_num = tag_byte >> 3
            pos += 1
            if wire_type == 0:
                _, pos = decode_varint(manifest_data, pos)
            elif wire_type == 1:
                pos += 8
            elif wire_type == 2:
                l, pos = decode_varint(manifest_data, pos)
                pos += l
            elif wire_type == 5:
                pos += 4
            else:
                break

    return results

def main():
    print(f"Target: {OTA_URL}")
    print(f"Output: {OUTPUT}")

    # Step 1: Get file size
    print("\n[1] Getting file size...")
    file_size = get_file_size(OTA_URL)
    print(f"  File size: {file_size:,} bytes ({file_size/1024/1024:.1f} MB)")

    # Step 2: Find payload.bin in ZIP
    print("\n[2] Finding payload.bin in ZIP central directory...")
    payload_local_offset, compress_method, compressed_size = find_zip_entry(
        OTA_URL, file_size, 'payload.bin')

    if compress_method != 0:
        print(f"  WARNING: payload.bin uses compression method {compress_method} (expected 0 for stored)")

    # Step 3: Get local file header to find actual data start
    print("\n[3] Reading local file header...")
    lh_data = fetch_range(OTA_URL, payload_local_offset, 1024)
    if lh_data[:4] != b'\x50\x4b\x03\x04':
        raise ValueError("Invalid local file header")
    fname_len = struct.unpack_from('<H', lh_data, 26)[0]
    extra_len = struct.unpack_from('<H', lh_data, 28)[0]
    payload_data_start = payload_local_offset + 30 + fname_len + extra_len
    print(f"  payload.bin data starts at ZIP offset: 0x{payload_data_start:x}")

    # Step 4: Read payload.bin header
    print("\n[4] Reading payload.bin header...")
    header_data = fetch_range(OTA_URL, payload_data_start, 1024)
    manifest_len, metadata_sig_size, data_section_offset_in_payload = parse_payload_header(header_data)

    # Step 5: Download manifest
    print(f"\n[5] Downloading OTA manifest ({manifest_len} bytes)...")
    manifest_start = payload_data_start + 24  # after 24-byte header
    manifest_data = fetch_range(OTA_URL, manifest_start, manifest_len)
    print(f"  Manifest downloaded: {len(manifest_data)} bytes")

    # Step 6: Parse manifest for abl partition
    print("\n[6] Parsing manifest for partition info...")
    partitions = scan_partitions_in_manifest(manifest_data)
    print(f"  Found {len(partitions)} partitions:")
    for name, (offset, length) in sorted(partitions.items()):
        flag = " <-- TARGET" if name == 'abl' else ""
        print(f"    {name}: offset={offset}, length={length}{flag}")

    if 'abl' not in partitions:
        print("  ERROR: 'abl' not found in manifest!")
        # Save manifest for debug
        with open('/Users/xmxx/pinganhuijia/ota_manifest.bin', 'wb') as f:
            f.write(manifest_data)
        print("  Manifest saved to ota_manifest.bin for debugging")
        return

    abl_offset, abl_length = partitions['abl']
    if abl_offset is None or abl_length is None:
        print("  ERROR: Could not determine abl data offset/length from manifest")
        return

    # Step 7: Calculate absolute position of abl data in ZIP
    # data_section starts at payload_data_start + data_section_offset_in_payload
    data_section_abs = payload_data_start + data_section_offset_in_payload
    abl_abs_start = data_section_abs + abl_offset
    print(f"\n[7] Downloading abl.img ({abl_length:,} bytes)...")
    print(f"  File offset: 0x{abl_abs_start:x}")

    # Download in chunks
    chunk_size = 1024 * 1024  # 1MB chunks
    total = 0
    with open(OUTPUT, 'wb') as out_f:
        while total < abl_length:
            remaining = abl_length - total
            to_fetch = min(chunk_size, remaining)
            chunk = fetch_range(OTA_URL, abl_abs_start + total, to_fetch)
            out_f.write(chunk)
            total += len(chunk)
            print(f"  Progress: {total:,}/{abl_length:,} bytes ({100*total//abl_length}%)")

    print(f"\n[8] Done! abl.img saved to {OUTPUT} ({total:,} bytes)")

if __name__ == '__main__':
    main()
