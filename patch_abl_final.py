#!/usr/bin/env python3
"""
Patch T-Mobile ABL to bypass AVB verification.

Patch location:
  VA 0x6810 (file offset in decompressed: 0x68c8)
  Instruction: CBZ w24, #0x6870   (if AVB result==0, jump to success path)
  Patch to:    B   #0x6870        (ALWAYS jump to success path)

Then recompress and rebuild the full abl_b.img.
"""
import struct, lzma, shutil, os

DECOMP_BIN = '/Users/xmxx/pinganhuijia/tmobile_abl_decompressed.bin'
ABL_ORIG   = '/Users/xmxx/pinganhuijia/edl_backup/abl_b.img'
ABL_OUT    = '/Users/xmxx/pinganhuijia/tmobile_abl_avb_patched.img'

DELTA = 0xb8   # VA = file_offset - DELTA

# ========== 1. Verify patch location ==========
print("Loading decompressed ABL...")
with open(DECOMP_BIN, 'rb') as f:
    d = bytearray(f.read())

# Patch site: VA 0x6810, file offset = 0x6810 + 0xb8 = 0x68c8
PATCH_VA    = 0x6810
PATCH_OFF   = PATCH_VA + DELTA  # 0x68c8
SUCCESS_VA  = 0x6870

# Expected CBZ w24, #0x6870
# CBZ 32-bit encoding: op[31:24]=0x34, imm19[23:5]=(offset/4), Rt[4:0]=24
offset = SUCCESS_VA - PATCH_VA   # 0x60
imm19  = offset // 4             # 0x18
Rt     = 24                      # w24
CBZ_EXPECTED = (0x34 << 24) | (imm19 << 5) | Rt
CBZ_LE = struct.pack('<I', CBZ_EXPECTED)

# B #0x6870
# B encoding: op[31:26]=0b000101=0x05, imm26[25:0]=(offset/4)
B_INSN = (0x14 << 24) | imm19  # 0x14000018
B_LE   = struct.pack('<I', B_INSN)

print(f"Patch offset in decompressed: {hex(PATCH_OFF)}")
print(f"  Expected CBZ bytes: {CBZ_LE.hex()}  ({hex(CBZ_EXPECTED)})")

actual = bytes(d[PATCH_OFF:PATCH_OFF+4])
print(f"  Actual bytes:       {actual.hex()}")

if actual == CBZ_LE:
    print("  ✓ Instruction matches CBZ w24, #0x6870")
else:
    actual_insn = struct.unpack_from('<I', d, PATCH_OFF)[0]
    print(f"  WARNING: bytes don't match expected CBZ.")
    print(f"  Actual instruction word: {hex(actual_insn)}")
    # Try to identify
    top8 = actual_insn >> 24
    if top8 == 0x34:
        print("  (Still a CBZ - rt and/or imm might differ)")
        rt_actual  = actual_insn & 0x1f
        imm_actual = (actual_insn >> 5) & 0x7FFFF
        tgt_actual = PATCH_VA + imm_actual * 4
        print(f"  Decoded: CBZ w{rt_actual}, #{hex(tgt_actual)}")
    elif top8 == 0x35:
        print("  (CBNZ)")
        rt_actual  = actual_insn & 0x1f
        imm_actual = (actual_insn >> 5) & 0x7FFFF
        tgt_actual = PATCH_VA + imm_actual * 4
        print(f"  Decoded: CBNZ w{rt_actual}, #{hex(tgt_actual)}")
    elif top8 == 0x54:
        print("  (B.cond)")
        cond = actual_insn & 0xF
        cnames=['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
        imm19a = (actual_insn >> 5) & 0x7FFFF
        if imm19a & (1<<18): imm19a -= (1<<19)
        tgt = PATCH_VA + imm19a*4
        print(f"  Decoded: B.{cnames[cond]} #{hex(tgt)}")
    import sys
    print("\nAbort - manual verification needed.")
    sys.exit(1)

# ========== 2. Also verify surrounding context ==========
print()
print("Context verification (5 instructions around patch):")
for off in range(PATCH_OFF - 8, PATCH_OFF + 20, 4):
    w = struct.unpack_from('<I', d, off)[0]
    va = off - DELTA
    marker = " <<< PATCH HERE" if off == PATCH_OFF else ""
    print(f"  file {hex(off)} va {hex(va)}: {w:08x}{marker}")

# ========== 3. Apply patch ==========
print()
print("Applying patch...")
d[PATCH_OFF:PATCH_OFF+4] = B_LE
patched_va = struct.unpack_from('<I', d, PATCH_OFF)[0]
print(f"  Written: {B_LE.hex()} ({hex(patched_va)}) = B #{hex(SUCCESS_VA)}")

# ========== 4. Recompress with LZMA ==========
print()
print("Recompressing with LZMA (FORMAT_ALONE)...")
decompressed_bytes = bytes(d)
# Use lzma with FORMAT_ALONE (same as original)
# Original LZMA was decoded with lzma.decompress(data, format=lzma.FORMAT_ALONE)
lzma_filters = [
    {'id': lzma.FILTER_LZMA1,
     'preset': 6,
     'dict_size': 1 * 1024 * 1024}  # 1MB dict to match original '5d 00 00 10 00'
]

compressed = lzma.compress(decompressed_bytes,
                            format=lzma.FORMAT_ALONE,
                            filters=lzma_filters)
print(f"  Compressed size: {hex(len(compressed))} ({len(compressed):,} bytes)")

# ========== 5. Rebuild abl_b.img ==========
# Structure of original abl_b.img:
#   [0x0000]: ELF header (covers start before FV)
#   [0x3000]: FV header (EFI_FIRMWARE_VOLUME_HEADER)
#   [0x3048]: FFS file header
#   [0x3060]: EFI_SECTION_GUID_DEFINED header (24 bytes)
#   [0x3078]: LZMA payload (original)
#   Zeros to end of file (original 8MB)
print()
print("Reading original abl_b.img to identify FV structure...")
with open(ABL_ORIG, 'rb') as f:
    orig = bytearray(f.read())
orig_size = len(orig)
print(f"  Original size: {hex(orig_size)} ({orig_size:,} bytes)")

# LZMA payload starts at 0x3078 (after 24-byte GUID_DEFINED section header)
LZMA_PAYLOAD_OFF = 0x3078

# Verify original LZMA header at that offset (should start with 5d 00 ...)
orig_lzma_hdr = orig[LZMA_PAYLOAD_OFF:LZMA_PAYLOAD_OFF+5]
print(f"  Original LZMA header at 0x3078: {orig_lzma_hdr.hex()}")
if orig_lzma_hdr[0] != 0x5d:
    print("  WARNING: Unexpected LZMA header byte!")
    import sys; sys.exit(1)
print("  ✓ LZMA header OK")

# The LZMA section's size fields in the FFS/GUID_DEFINED headers need updating
# EFI_COMMON_SECTION_HEADER at 0x3060:
#   [0..2]: Size (3 bytes LE) = total section size including header
#   [3]:    Type = 0x02 (EFI_SECTION_GUID_DEFINED)
# Then 24-byte GUID_DEFINED_SECTION_HEADER:
#   [4..19]: GUID
#   [20..21]: DataOffset = 24 (header size)
#   [22..23]: Attributes
# Then LZMA data starts at 0x3078

# Calculate new sizes
SECTION_HDR_SIZE = 0x18  # 24 bytes (EFI_SECTION_GUID_DEFINED including section type hdr)
LZMA_SECTION_SIZE = SECTION_HDR_SIZE + len(compressed)

# EFI_FFS_FILE_HEADER at 0x3048 (size 24 bytes):
#   [0..15]: GUID (Name)
#   [16..17]: IntegrityCheck
#   [18]:     Type = 0x02 (EFI_FV_FILETYPE_FREEFORM or similar)
#   [19..21]: Size (3-byte LE) = total file size including header
#   [22]:     Attributes
#   [23]:     State
FFS_HDR_OFF  = 0x3048
FFS_HDR_SIZE = 0x18  # 24 bytes
FFS_FILE_SIZE = FFS_HDR_SIZE + LZMA_SECTION_SIZE

# EFI_FIRMWARE_VOLUME_HEADER at 0x3000 (size 0x48 typically):
#   The FvLength field: [0x20..0x27] = total FV size (8 bytes)
# The entire FV until end-of-file area
FV_HDR_OFF = 0x3000
# Let's compute how much the FV grows vs original
ORIG_LZMA_SIZE = orig_size - LZMA_PAYLOAD_OFF - sum(1 for b in orig[orig_size-1::-1] if b == 0)
# Actually just use: original compressed size = first non-zero-padded area
# Better: count bytes from 0x3078 to the pad start
# For simplicity: use the compressed payload size with the rest padded to original size
orig_fv_size_bytes = orig[FV_HDR_OFF + 0x20:FV_HDR_OFF + 0x28]
orig_fv_size = struct.unpack_from('<Q', orig, FV_HDR_OFF + 0x20)[0]
print(f"  Original FV size: {hex(orig_fv_size)}")
print(f"  Original file size: {hex(orig_size)}")

# New section size at 0x3060+2 (3-byte field):
new_section_size = LZMA_SECTION_SIZE  # includes its own 24-byte header
# New FFS file size at 0x3048+19:
new_ffs_size     = FFS_FILE_SIZE
# FV length: FV header (0x48) + FFS header (0x18) + LZMA section + padding
# OR: keep FV size same and just pad. For simplest approach: keep all sizes same as original,
# as long as new payload fits.

ORIG_PAYLOAD_SIZE = orig_size - LZMA_PAYLOAD_OFF  # bytes available for LZMA + padding
if len(compressed) > ORIG_PAYLOAD_SIZE:
    print(f"  ERROR: Compressed data ({len(compressed)}) too large for available space ({ORIG_PAYLOAD_SIZE})")
    import sys; sys.exit(1)

print(f"  New compressed size: {len(compressed)} bytes, available: {ORIG_PAYLOAD_SIZE} bytes, fits: YES")

# ========== 6. Write output ==========
print()
print("Building patched image...")

patched_img = bytearray(orig)

# Write new LZMA compressed payload
patched_img[LZMA_PAYLOAD_OFF:LZMA_PAYLOAD_OFF + len(compressed)] = compressed
# Zero-pad the rest (in case new payload is shorter)
pad_start = LZMA_PAYLOAD_OFF + len(compressed)
for i in range(pad_start, len(patched_img)):
    patched_img[i] = 0xFF  # NAND erased = 0xFF, more authentic than 0x00

# Update EFI_COMMON_SECTION_HEADER (3-byte size at 0x3060)
section_size_new = SECTION_HDR_SIZE + len(compressed)
patched_img[0x3060] = section_size_new & 0xFF
patched_img[0x3061] = (section_size_new >> 8) & 0xFF
patched_img[0x3062] = (section_size_new >> 16) & 0xFF

# Update FFS file header (3-byte size at 0x3048+19=0x305b)
ffs_size_new = FFS_HDR_SIZE + section_size_new
patched_img[0x305b] = ffs_size_new & 0xFF
patched_img[0x305c] = (ffs_size_new >> 8) & 0xFF
patched_img[0x305d] = (ffs_size_new >> 16) & 0xFF

print(f"  Section size updated: {hex(section_size_new)}")
print(f"  FFS file size updated: {hex(ffs_size_new)}")
print(f"  Total image size: {hex(len(patched_img))} bytes")

# Recalculate FFS integrity check (header checksum)
# FFS header checksum covers bytes 0x3048+0 to 0x3048+22 with byte[17]=0
ffs_hdr = bytearray(patched_img[0x3048:0x3048+0x18])
ffs_hdr[16] = 0  # zero out checksum bytes before computing (header checksum)
ffs_hdr[17] = 0
hdr_sum = (-sum(ffs_hdr)) & 0xFF
patched_img[0x3048 + 16] = hdr_sum
print(f"  FFS header checksum updated: {hex(hdr_sum)}")

# Write output file
with open(ABL_OUT, 'wb') as f:
    f.write(patched_img)
print(f"\nSaved to: {ABL_OUT}")
print(f"Size: {len(patched_img):,} bytes ({hex(len(patched_img))})")

# ========== 7. Verification ==========
print()
print("Verification: decompress new payload and check patch...")
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
new_payload = bytes(patched_img[LZMA_PAYLOAD_OFF:LZMA_PAYLOAD_OFF+len(compressed)])
test_decomp = lzma.decompress(new_payload, format=lzma.FORMAT_ALONE)
print(f"  Re-decompressed size: {hex(len(test_decomp))} (expected: {hex(len(decompressed_bytes))})")
assert len(test_decomp) == len(decompressed_bytes), "Size mismatch!"

patched_word = struct.unpack_from('<I', test_decomp, PATCH_OFF)[0]
print(f"  Instruction at patch site: {hex(patched_word)}")
if patched_word == B_INSN:
    print(f"  ✓ Patch verified: B #{hex(SUCCESS_VA)}")
else:
    print(f"  ✗ PATCH MISMATCH: expected {hex(B_INSN)}, got {hex(patched_word)}")

print()
print("="*60)
print("PATCH COMPLETE!")
print("="*60)
print(f"Output: {ABL_OUT}")
print()
print("Next steps:")
print("  1. Enter EDL mode (fastboot oem edl, or vol+vol- in bootloader)")
print(f"  2. edl w abl_b {ABL_OUT} --devicemodel 20888")
print(f"  3. edl w boot_b /Users/xmxx/pinganhuijia/magisk_patch/new-boot-device.img --devicemodel 20888")
print(f"  4. edl w vbmeta_b /Users/xmxx/pinganhuijia/edl_backup/vbmeta_b_disabled.img --devicemodel 20888")
print(f"  5. edl reset --devicemodel 20888")
