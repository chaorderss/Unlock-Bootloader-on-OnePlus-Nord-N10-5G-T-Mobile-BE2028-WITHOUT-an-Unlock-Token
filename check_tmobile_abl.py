#!/usr/bin/env python3
"""
Extract and decompress the PT_LOAD segment from T-Mobile ABL (abl_b.img ELF wrapper),
then check for the same 'unlocked, Skipping boot verification' and devinfo strings.
"""
import struct, zlib

with open("edl_backup/abl_b.img", 'rb') as f:
    data = f.read()

print(f"T-Mobile abl_b.img size: 0x{len(data):X}")

# Parse ELF32 header
magic = data[:4]
assert magic == b'\x7fELF', f"Not ELF: {magic.hex()}"
e_phoff = struct.unpack_from('<I', data, 0x1C)[0]
e_phnum = struct.unpack_from('<H', data, 0x2C)[0]
e_phentsize = struct.unpack_from('<H', data, 0x2A)[0]
print(f"ELF32: phoff=0x{e_phoff:X}, phnum={e_phnum}")

# Find the biggest PT_LOAD segment (that's the actual UEFI payload)
segments = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type   = struct.unpack_from('<I', data, off)[0]
    p_offset = struct.unpack_from('<I', data, off+4)[0]
    p_vaddr  = struct.unpack_from('<I', data, off+8)[0]
    p_filesz = struct.unpack_from('<I', data, off+16)[0]
    p_memsz  = struct.unpack_from('<I', data, off+20)[0]
    print(f"  seg[{i}] type=0x{p_type:X} off=0x{p_offset:X} vaddr=0x{p_vaddr:X} filesz=0x{p_filesz:X}")
    segments.append((p_type, p_offset, p_vaddr, p_filesz, p_memsz))

# The PT_LOAD with the largest filesz is the main payload
pt_loads = [(s[3], s) for s in segments if s[0] == 1]
if pt_loads:
    biggest = sorted(pt_loads, reverse=True)[0][1]
    _, p_offset, p_vaddr, p_filesz, p_memsz = biggest
    print(f"\nMain PT_LOAD payload: file off=0x{p_offset:X}, size=0x{p_filesz:X}")
    payload = data[p_offset:p_offset+p_filesz]

    # Check if it's compressed (LZ4 / ZLIB / gzip / ELF inside ELF)
    print(f"First 16 bytes of payload: {payload[:16].hex()}")
    print(f"First 4 bytes: {payload[:4]}")

    # Search key strings directly in raw abl_b.img
    print("\n--- Searching key strings in raw abl_b.img ---")
    targets = {
        "unlocked, Skipping boot verification": b"unlocked, Skipping boot verification",
        "ANDROID-BOOT!":                        b"ANDROID-BOOT!",
        "Device unlocked":                      b"Device unlocked",
        "Please flash unlock token first":      b"Please flash unlock token first",
        "boot state is:":                       b"boot state is:",
        "Your device is corrupt":               b"Your device is corrupt",
        "avb_slot_verify":                      b"avb_slot_verify",
        "OemCheckResetDevInfo":                 b"OemCheckResetDevInfo",
        "Is_secure_boot_enabled":               b"IsSecureBootEnabled",
    }
    for name, pat in targets.items():
        idx = data.find(pat)
        if idx != -1:
            snippet = data[idx:idx+70]
            printable = ''.join(chr(b) if 32<=b<127 else '.' for b in snippet)
            print(f"  [FOUND] 0x{idx:06X} {name}: '{printable[:65]}'")
        else:
            print(f"  [NOT FOUND] {name}")
