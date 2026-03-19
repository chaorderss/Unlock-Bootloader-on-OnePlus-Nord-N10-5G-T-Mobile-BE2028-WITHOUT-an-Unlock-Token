#!/usr/bin/env python3
"""Parse UEFI variable store (uefivarstore.bin) looking for devinfo data."""

import struct
import sys
import os

VARSTORE = "/Users/xmxx/pinganhuijia/edl_backup/lun4/uefivarstore.bin"

def read_guid(data, off):
    if off + 16 > len(data):
        return None, ""
    d1, d2, d3 = struct.unpack_from('<IHH', data, off)
    d4 = data[off+8:off+16]
    s = f"{d1:08X}-{d2:04X}-{d3:04X}-{d4[0]:02X}{d4[1]:02X}-" + \
        ''.join(f"{b:02X}" for b in d4[2:])
    return data[off:off+16], s

def main():
    with open(VARSTORE, 'rb') as f:
        data = f.read()

    print(f"uefivarstore.bin size: {len(data)} bytes")

    # Check for UEFI Firmware Volume header
    # FV signature "_FVH" at offset 0x28
    print(f"\n=== Checking for FV header ===")
    if len(data) >= 0x30:
        sig = data[0x28:0x2C]
        print(f"Signature at 0x28: {sig} ({sig.hex()})")
        if sig == b'_FVH':
            print("Valid Firmware Volume header!")
            fv_len = struct.unpack_from('<Q', data, 0x20)[0]
            print(f"FV Length: {fv_len} (0x{fv_len:X})")
            hdr_len = struct.unpack_from('<H', data, 0x30)[0]
            print(f"Header Length: {hdr_len}")
            # Filesystem GUID at offset 0x10
            _, fs_guid = read_guid(data, 0x10)
            print(f"Filesystem GUID: {fs_guid}")
        else:
            print("Not a standard FV header")
            print(f"First 64 bytes: {data[:64].hex()}")

    # Search for UEFI Variable Store header
    # Variable store starts with signature: 0xAAFE (authenticated) or specific GUID
    # Standard GUID: {FFF12B8D-7696-4C8B-A985-2747075B4F50} for authenticated var store
    # Or: {DDCF3616-3275-4164-98B6-FE85707FFE7D} for standard var store

    print(f"\n=== Searching for variable store signatures ===")
    # Authenticated variable store GUID
    auth_var_guid = bytes.fromhex("8D2BF1FF9676C84BA98527075B4F5047")  # mixed endian
    std_var_guid = bytes.fromhex("1636CFDD75326441988B6FE85707FFE7")[:16]

    # Search for variable entries (StartId = 0x55AA)
    print(f"\n=== Searching for EFI variable entries (0x55AA / 0xAA55) ===")
    var_starts = []
    for i in range(0, len(data) - 2):
        val = struct.unpack_from('<H', data, i)[0]
        if val == 0x55AA:
            var_starts.append(i)
    print(f"Found {len(var_starts)} potential variable start markers (0x55AA)")
    if var_starts:
        print(f"First 20 offsets: {[f'0x{x:X}' for x in var_starts[:20]]}")

    # Try parsing from common variable store header offset
    # After FV header, there's usually a VARIABLE_STORE_HEADER
    # Let's try multiple starting points

    print(f"\n=== Trying to parse UEFI authenticated variables ===")
    # Authenticated variable format:
    # uint16 StartId (0x55AA)
    # uint8  State
    # uint8  Reserved
    # uint32 Attributes
    # uint64 MonotonicCount
    # EFI_TIME TimeStamp (16 bytes)
    # uint32 PubKeyIndex
    # uint32 NameSize
    # uint32 DataSize
    # EFI_GUID VendorGuid (16 bytes)
    # CHAR16 Name[NameSize/2]
    # uint8  Data[DataSize]

    AUTH_VAR_HEADER_SIZE = 60  # 2+1+1+4+8+16+4+4+4+16 = 60

    parsed_vars = []

    for start_off in var_starts[:200]:  # check first 200
        if start_off + AUTH_VAR_HEADER_SIZE > len(data):
            continue

        start_id = struct.unpack_from('<H', data, start_off)[0]
        if start_id != 0x55AA:
            continue

        state = data[start_off + 2]
        attrs = struct.unpack_from('<I', data, start_off + 4)[0]

        # For authenticated variables:
        name_size = struct.unpack_from('<I', data, start_off + 48)[0]
        data_size = struct.unpack_from('<I', data, start_off + 52)[0]

        # Sanity checks
        if name_size == 0 or name_size > 1024 or data_size > 65536:
            # Try standard (non-authenticated) variable format:
            # uint16 StartId, uint8 State, uint8 Reserved, uint32 Attributes
            # uint32 NameSize, uint32 DataSize, EFI_GUID VendorGuid
            # = 2+1+1+4+4+4+16 = 32 bytes header
            name_size2 = struct.unpack_from('<I', data, start_off + 8)[0]
            data_size2 = struct.unpack_from('<I', data, start_off + 12)[0]
            if 0 < name_size2 <= 1024 and 0 < data_size2 <= 65536:
                _, vendor_guid = read_guid(data, start_off + 16)
                name_off = start_off + 32
                if name_off + name_size2 <= len(data):
                    try:
                        name = data[name_off:name_off+name_size2].decode('utf-16-le').rstrip('\x00')
                    except:
                        name = "<decode error>"
                    data_off = name_off + name_size2
                    var_data = data[data_off:data_off+data_size2] if data_off + data_size2 <= len(data) else b''
                    parsed_vars.append({
                        'offset': start_off, 'type': 'std', 'state': state,
                        'attrs': attrs, 'name': name, 'guid': vendor_guid,
                        'name_size': name_size2, 'data_size': data_size2,
                        'data': var_data
                    })
            continue

        _, vendor_guid = read_guid(data, start_off + 56)
        name_off = start_off + AUTH_VAR_HEADER_SIZE + 16  # after GUID
        # Actually GUID is included in AUTH_VAR_HEADER_SIZE
        name_off = start_off + 60  # right after the header

        if name_off + name_size > len(data):
            continue

        try:
            name = data[name_off:name_off+name_size].decode('utf-16-le').rstrip('\x00')
        except:
            name = "<decode error>"

        data_off = name_off + name_size
        var_data = data[data_off:data_off+data_size] if data_off + data_size <= len(data) else b''

        parsed_vars.append({
            'offset': start_off, 'type': 'auth', 'state': state,
            'attrs': attrs, 'name': name, 'guid': vendor_guid,
            'name_size': name_size, 'data_size': data_size,
            'data': var_data
        })

    print(f"\nParsed {len(parsed_vars)} variables")
    for v in parsed_vars:
        data_preview = v['data'][:64].hex() if v['data'] else '<empty>'
        has_android_boot = b'ANDROID-BOOT!' in v['data']
        flag = " *** ANDROID-BOOT! ***" if has_android_boot else ""
        devinfo_in_name = 'devinfo' in v['name'].lower() or 'device' in v['name'].lower() or 'unlock' in v['name'].lower()
        flag2 = " *** DEVINFO RELATED ***" if devinfo_in_name else ""
        print(f"  [{v['type']}] @0x{v['offset']:05X} state=0x{v['state']:02X} "
              f"attrs=0x{v['attrs']:08X} name='{v['name']}' guid={v['guid']} "
              f"name_sz={v['name_size']} data_sz={v['data_size']}{flag}{flag2}")
        if has_android_boot or devinfo_in_name:
            print(f"    DATA: {v['data'][:128].hex()}")

    # Direct binary search for key strings
    print(f"\n=== Direct binary search ===")

    # Search for "ANDROID-BOOT!"
    needle = b'ANDROID-BOOT!'
    pos = 0
    found = []
    while True:
        idx = data.find(needle, pos)
        if idx < 0:
            break
        found.append(idx)
        pos = idx + 1
    print(f"'ANDROID-BOOT!' found at: {[f'0x{x:X}' for x in found]}")

    # Search for "devinfo" (ASCII and UCS-2)
    for needle_str in ["devinfo", "DeviceInfo", "device_info"]:
        for enc in ['ascii', 'utf-16-le']:
            needle = needle_str.encode(enc)
            pos = 0
            found = []
            while True:
                idx = data.find(needle, pos)
                if idx < 0:
                    break
                found.append(idx)
                pos = idx + 1
            if found:
                print(f"'{needle_str}' ({enc}) found at: {[f'0x{x:X}' for x in found]}")

    # Search for protocol GUID 8E5EFF91-21B6-47D3-AF2B-C15A01E020EC
    guid_bytes = bytes([0x91, 0xFF, 0x5E, 0x8E, 0xB6, 0x21, 0xD3, 0x47,
                        0xAF, 0x2B, 0xC1, 0x5A, 0x01, 0xE0, 0x20, 0xEC])
    idx = data.find(guid_bytes)
    if idx >= 0:
        print(f"Protocol GUID found at offset 0x{idx:X}!")
        print(f"  Context: {data[idx-16:idx+32].hex()}")
    else:
        print("Protocol GUID 8E5EFF91... NOT found in varstore")

    # Search for devinfo Type GUID 65ADDCF4-0C5C-4D9A-AC2D-D90B5CBFCD03
    guid_bytes2 = bytes([0xF4, 0xDC, 0xAD, 0x65, 0x5C, 0x0C, 0x9A, 0x4D,
                         0xAC, 0x2D, 0xD9, 0x0B, 0x5C, 0xBF, 0xCD, 0x03])
    idx = data.find(guid_bytes2)
    if idx >= 0:
        print(f"devinfo Type GUID found at offset 0x{idx:X}!")
        print(f"  Context: {data[idx-16:idx+32].hex()}")
    else:
        print("devinfo Type GUID NOT found in varstore")

    # Search for devinfo Unique GUID 728BCCD1-D2D7-130D-4583-01F0B7BDA372
    guid_bytes3 = bytes([0xD1, 0xCC, 0x8B, 0x72, 0xD7, 0xD2, 0x0D, 0x13,
                         0x45, 0x83, 0x01, 0xF0, 0xB7, 0xBD, 0xA3, 0x72])
    idx = data.find(guid_bytes3)
    if idx >= 0:
        print(f"devinfo Unique GUID found at offset 0x{idx:X}!")
        print(f"  Context: {data[idx-16:idx+32].hex()}")
    else:
        print("devinfo Unique GUID NOT found in varstore")

    # Show hex dump of first 256 bytes for format analysis
    print(f"\n=== First 256 bytes of varstore ===")
    for i in range(0, 256, 16):
        hex_str = ' '.join(f'{data[i+j]:02X}' for j in range(16) if i+j < len(data))
        ascii_str = ''.join(chr(data[i+j]) if 32 <= data[i+j] < 127 else '.' for j in range(16) if i+j < len(data))
        print(f"  {i:04X}: {hex_str:<48s} {ascii_str}")

    # Check if the store is all FF after some point
    ff_start = None
    for i in range(len(data)):
        if data[i] != 0xFF:
            ff_start = None
        elif ff_start is None:
            ff_start = i

    # Find last non-FF byte
    last_data = 0
    for i in range(len(data)-1, -1, -1):
        if data[i] != 0xFF:
            last_data = i
            break
    print(f"\nLast non-FF byte at offset 0x{last_data:X}")
    print(f"Used space: ~{last_data+1} bytes ({(last_data+1)*100//len(data)}%)")

if __name__ == '__main__':
    main()
