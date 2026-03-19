#!/usr/bin/env python3
"""Read GUIDs at 0x69AB0, 0x69AC0, 0x69AD0, 0x69960 used in CorePartSearch.
Also check for other FFS modules and search for DXE driver."""

import struct, os, glob

PE = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
with open(PE, "rb") as f:
    pe = f.read()

def format_guid(data):
    a, b, c = struct.unpack_from('<IHH', data, 0)
    d = data[8:16]
    return f"{a:08X}-{b:04X}-{c:04X}-{d[0]:02X}{d[1]:02X}-{d[2]:02X}{d[3]:02X}{d[4]:02X}{d[5]:02X}{d[6]:02X}{d[7]:02X}"

print("=" * 60)
print("  GUIDs used in CorePartSearch (0x17C90)")
print("=" * 60)

# These are the offsets referenced in the disassembly
for off in range(0x69900, 0x69D00, 0x10):
    g = pe[off:off+16]
    if g != b'\x00' * 16:
        gs = format_guid(g)
        print(f"  0x{off:05X}: {gs}")

# Known UEFI GUIDs for comparison
print("\n" + "=" * 60)
print("  Known UEFI Block I/O and Partition GUIDs")
print("=" * 60)
known = {
    "EFI_BLOCK_IO_PROTOCOL":      bytes.fromhex("215B4E96596411D28E3900A0C969723B"),
    "EFI_BLOCK_IO2_PROTOCOL":     bytes.fromhex("7224B4A2E28211DC8E4F00A0C969723B"),
    "EFI_DEVICE_PATH_PROTOCOL":   bytes.fromhex("916E5709 3FD6 11D2 8E39 00A0C969723B".replace(" ","")),
    "EFI_DISK_IO_PROTOCOL":       bytes.fromhex("715134CE0BBA11D28E4F00A0C969723B"),
    "EFI_PARTITION_INFO":         bytes.fromhex("2CF6F62C9BBC214880D8EC9EC421A1A0"),
}

# Also search for specific known GUIDs in our PE binary
known_guids_search = {
    "964E5B21-6459-11D2-8E39-00A0C969723B": "EFI_BLOCK_IO_PROTOCOL",
    "09576E91-6D3F-11D2-8E39-00A0C969723B": "EFI_DEVICE_PATH_PROTOCOL",
    "CE345171-BA0B-11D2-8E4F-00A0C969723B": "EFI_DISK_IO_PROTOCOL",
    "8CF2F62C-BC9B-4821-808D-EC9EC421A1A0": "EFI_PARTITION_INFO",
    "8E5EFF91-21B6-47D3-AF2B-C15A01E020EC": "ReadWritePartition PROTOCOL",
}

for guid_str, name in known_guids_search.items():
    # Convert GUID string to little-endian bytes
    parts = guid_str.split('-')
    a = int(parts[0], 16)
    b = int(parts[1], 16)
    c = int(parts[2], 16)
    d = bytes.fromhex(parts[3] + parts[4])
    guid_bytes = struct.pack('<IHH', a, b, c) + d

    pos = pe.find(guid_bytes)
    if pos >= 0:
        print(f"  Found {name} ({guid_str}) at offset 0x{pos:X}")
    else:
        print(f"  NOT FOUND: {name} ({guid_str})")

# Check what files exist in /tmp/ffs_modules/
print("\n" + "=" * 60)
print("  FFS modules in /tmp/ffs_modules/")
print("=" * 60)
ffs_dir = "/tmp/ffs_modules/"
if os.path.isdir(ffs_dir):
    files = sorted(os.listdir(ffs_dir))
    for f in files:
        fp = os.path.join(ffs_dir, f)
        sz = os.path.getsize(fp)
        # Check first bytes for PE signature or other type
        with open(fp, 'rb') as fh:
            hdr = fh.read(4)
        sig = ""
        if hdr[:2] == b'MZ': sig = "PE/MZ"
        elif hdr[:4] == b'\x00\x00\xa0\xe1': sig = "ARM"
        elif hdr[:4] == b'\xd0\x0d\xfe\xed': sig = "FDT"
        print(f"  {f}: {sz:,} bytes {sig}")

        # Search for our key GUID (8E5EFF91) in non-PE modules
        if f != "pe32_59d536f5_1.bin":
            with open(fp, 'rb') as fh:
                data = fh.read()
            guid_bytes = bytes.fromhex("91ff5e8eb62147d3af2bc15a01e020ec")
            # Also search little-endian
            guid_le = struct.pack('<IHH', 0x8E5EFF91, 0x21B6, 0x47D3) + bytes.fromhex("AF2BC15A01E020EC")
            for pattern, label in [(guid_bytes, "raw"), (guid_le, "LE")]:
                pos = data.find(pattern)
                if pos >= 0:
                    print(f"    *** GUID 8E5EFF91 found ({label}) at 0x{pos:X}!")

# Check XBL firmware for the GUID
print("\n" + "=" * 60)
print("  Searching XBL/ABL firmware for GUID 8E5EFF91")
print("=" * 60)
guid_le = struct.pack('<IHH', 0x8E5EFF91, 0x21B6, 0x47D3) + bytes.fromhex("AF2BC15A01E020EC")

edl = "/Users/xmxx/pinganhuijia/edl_backup"
for lun_dir in sorted(glob.glob(f"{edl}/lun*")):
    for fname in ["xbl_a.bin", "xbl_config_a.bin", "abl_a.bin"]:
        fp = os.path.join(lun_dir, fname)
        if os.path.exists(fp):
            with open(fp, 'rb') as fh:
                data = fh.read()
            pos = data.find(guid_le)
            if pos >= 0:
                print(f"  Found in {fp} at 0x{pos:X}")
                # Show context
                ctx = data[max(0,pos-32):pos+48]
                print(f"    Context: {ctx.hex()}")
            # Also search for the GUID in other byte orders
            guid_raw = bytes.fromhex("8E5EFF9121B647D3AF2BC15A01E020EC")
            pos2 = data.find(guid_raw)
            if pos2 >= 0:
                print(f"  Found (raw) in {fp} at 0x{pos2:X}")

# Finally, check if there's RPMB data accessible
# Search for "RPMB" strings in the PE binary
print("\n" + "=" * 60)
print("  RPMB/SFS references in PE binary")
print("=" * 60)
for needle in [b"RPMB", b"rpmb", b"SFS", b"sfs", b"ScmCmd", b"TzBsp", b"SmcCall"]:
    pos = 0
    while True:
        pos = pe.find(needle, pos)
        if pos < 0:
            break
        # Show context
        ctx_start = max(0, pos - 8)
        ctx = pe[ctx_start:pos+len(needle)+32]
        print(f"  \"{needle.decode('ascii', errors='replace')}\" at 0x{pos:X}: {ctx!r}")
        pos += len(needle)

# Search for UCS-2 "RPMB"
ucs2_rpmb = b'R\x00P\x00M\x00B\x00'
pos = pe.find(ucs2_rpmb)
while pos >= 0:
    print(f"  UCS-2 \"RPMB\" at 0x{pos:X}")
    pos = pe.find(ucs2_rpmb, pos + 1)
