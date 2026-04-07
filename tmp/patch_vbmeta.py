#!/usr/bin/env python3
"""分析 vbmeta_a.bin 的 AVB header，然后用 fastboot 刷入禁用验证的 vbmeta"""
import struct
import sys
import subprocess

VBMETA = "/Users/xmxx/pinganhuijia/edl_backup/lun4/vbmeta_a.bin"
TMP = "/Users/xmxx/pinganhuijia/tmp"

data = open(VBMETA, "rb").read()
idx = data.find(b"AVB0")
if idx < 0:
    print("AVB0 magic not found!")
    sys.exit(1)

print(f"AVB0 magic at offset {idx}")

# AVB header layout (big-endian):
# +0:   magic[4] = "AVB0"
# +4:   required_libavb_version_major uint32
# +8:   required_libavb_version_minor uint32
# +12:  authentication_data_block_size uint64
# +20:  auxiliary_data_block_size uint64
# +28:  algorithm_type uint32
# +32:  hash_offset uint64
# +40:  hash_size uint64
# +48:  signature_offset uint64
# +56:  signature_size uint64
# +64:  public_key_offset uint64
# +72:  public_key_size uint64
# +80:  public_key_metadata_offset uint64
# +88:  public_key_metadata_size uint64
# +96:  descriptors_offset uint64
# +104: descriptors_size uint64
# +112: rollback_index uint64
# +120: flags uint32
# +124: rollback_index_location uint32  (AVB 1.2+)

base = idx
major = struct.unpack_from(">I", data, base+4)[0]
minor = struct.unpack_from(">I", data, base+8)[0]
algo = struct.unpack_from(">I", data, base+28)[0]
ri = struct.unpack_from(">Q", data, base+112)[0]
flags = struct.unpack_from(">I", data, base+120)[0]

print(f"AVB version: {major}.{minor}")
print(f"Algorithm type: {algo}")
print(f"Rollback index: {ri}")
print(f"Flags: 0x{flags:08x}")
if flags & 1:
    print("  -> HASHTREE_DISABLED")
if flags & 2:
    print("  -> VERIFICATION_DISABLED")
if flags == 0:
    print("  -> All verification ENABLED")

# Create a disabled vbmeta
print("\n--- Creating vbmeta with disabled verification ---")
patched = bytearray(data)
# Set flags = 3 (disable hashtree + disable verification)
struct.pack_into(">I", patched, base+120, 3)
# Zero out authentication block (hash + signature) to make it unsigned
# This is needed because changing flags invalidates the existing signature
auth_size = struct.unpack_from(">Q", data, base+12)[0]
if auth_size > 0:
    # Authentication data starts right after the 256-byte header
    auth_start = base + 256
    print(f"Zeroing authentication block: offset {auth_start}, size {auth_size}")
    for i in range(auth_start, auth_start + int(auth_size)):
        if i < len(patched):
            patched[i] = 0
    # Set algorithm to NONE (0)
    struct.pack_into(">I", patched, base+28, 0)

out = f"{TMP}/vbmeta_disabled.bin"
with open(out, "wb") as f:
    f.write(patched)
print(f"Written: {out}")

# Verify
v_flags = struct.unpack_from(">I", patched, base+120)[0]
v_algo = struct.unpack_from(">I", patched, base+28)[0]
print(f"Patched flags: 0x{v_flags:08x} (should be 0x00000003)")
print(f"Patched algo: {v_algo} (should be 0 = NONE)")
