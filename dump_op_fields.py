#!/usr/bin/env python3
"""Dump raw bytes of first InstallOperation for xbl partition to debug field parsing."""
import struct

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
        tag_start = pos
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
            print(f"  UNKNOWN wire_type={wire_type} field={field_num} at pos={tag_start}")
            break

# Load manifest
with open('/Users/xmxx/pinganhuijia/ota_manifest_raw.bin', 'rb') as f:
    manifest = f.read()

# Find xbl partition and dump the raw operations
print("=== Looking for 'xbl' partition ===")
for fnum, wtype, val, raw in iter_fields(manifest):
    if fnum == 13 and wtype == 2:
        # Scan for partition name
        name = None
        for ff, fwt, fval, fraw in iter_fields(raw):
            if ff == 1 and fwt == 2:
                name = fraw.decode('utf-8', errors='replace')
                break

        if name == 'xbl':
            print(f"Found xbl partition entry ({len(raw)} bytes)")
            print("\n=== All fields in PartitionUpdate for xbl ===")
            for ff, fwt, fval, fraw in iter_fields(raw):
                if fwt == 2:
                    txt = fraw[:30].hex() if fraw else ''
                    tag_name = {1:'partition_name', 7:'new_partition_info', 8:'operations'}.get(ff, f'field_{ff}')
                    if fwt == 2 and fraw:
                        try:
                            decoded = fraw.decode('utf-8')
                            txt = f'"{decoded}"'
                        except:
                            txt = fraw[:30].hex()
                    print(f"  field {ff} ({tag_name}): wire_type={fwt}, len={fval}")

                    if ff == 8:  # operation
                        print("  ── InstallOperation contents ──")
                        for of, owt, oval, oraw in iter_fields(fraw):
                            op_names = {1:'type',2:'data_sha256',3:'src_extents',4:'src_length',
                                       5:'dst_extents',6:'dst_length',7:'data_offset',8:'data_length'}
                            oname = op_names.get(of, f'field_{of}')
                            if owt == 2:
                                print(f"    field {of} ({oname}): wire_type={owt} len={oval}  bytes={oraw[:20].hex()}")
                                # If it's dst_extents, parse inner
                                if of == 5:
                                    for ef, ewt, eval_, _ in iter_fields(oraw):
                                        enames = {1:'start_block', 2:'num_blocks'}
                                        print(f"      extent field {ef} ({enames.get(ef,f'f{ef}')}): {eval_}")
                            else:
                                type_names = {0:'REPLACE',1:'REPLACE_BZ',2:'MOVE',3:'BSDIFF',
                                             4:'SOURCE_COPY',5:'SOURCE_BSDIFF',6:'ZERO',7:'DISCARD',
                                             8:'REPLACE_XZ',9:'PUFFDIFF',10:'BROTLI_BSDIFF'}
                                display = type_names.get(oval, oval) if of == 1 else oval
                                print(f"    field {of} ({oname}): wire_type={owt} value={display} (0x{oval:x})")
                        print("  ──────────────────────────────")
                else:
                    print(f"  field {ff}: wire_type={fwt}, value={fval}")
            break
