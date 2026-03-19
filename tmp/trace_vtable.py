#!/usr/bin/env python3
"""Disassemble the actual partition I/O methods from PartitionOpen vtable."""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

with open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb') as f:
    pe = f.read()

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = False

known = {
    0x18248: "ReadWritePartition",
    0x384D0: "init_defaults",
    0x232D8: "ReadDeviceInfo",
    0x280FC: "LogPrint",
    0x28574: "DebugA",
    0x285A0: "DebugB",
    0x1370: "GetStackPtr",
    0xD290: "AllocatePool",
    0x8304: "Alloc2",
    0xB114: "PartitionOpen",
    0x4FD10: "CompareMem",
    0x9FC8: "VT_Read?",
    0xA78C: "VT_2",
    0xA794: "VT_3",
    0xAAB4: "VT_4",
    0xAB44: "VT_5",
    0xAC24: "VT_6",
    0xAC74: "VT_7",
    0xB01C: "VT_8",
    0xA9B8: "VT_9",
}

def disasm(name, start, length=0x200):
    print(f"\n{'='*60}")
    print(f"  {name} @ 0x{start:X}")
    print(f"{'='*60}")
    code = pe[start:start+length]
    for inst in md.disasm(code, start):
        line = f"  0x{inst.address:05X}: {inst.mnemonic:8s} {inst.op_str}"
        if inst.mnemonic == 'bl':
            try:
                target = int(inst.op_str.replace('#', ''), 16)
                if target in known:
                    line += f"  ; {known[target]}"
            except:
                pass
        if inst.mnemonic == 'adrp':
            parts = inst.op_str.split('#')
            if len(parts) > 1:
                page = int(parts[1], 16)
                if 0x50000 <= page <= 0x68000:
                    line += "  ; STRING area"
        print(line)
        if inst.mnemonic == 'ret':
            break

# PartitionOpen vtable methods
vtable_methods = [
    (0x9FC8, "VT[0x18] 0x9FC8"),
    (0xA78C, "VT[0x20] 0xA78C"),
    (0xA794, "VT[0x28] 0xA794"),
    (0xAAB4, "VT[0x30] 0xAAB4"),
    (0xAB44, "VT[0x38] 0xAB44"),
    (0xAC24, "VT[0x40] 0xAC24"),
    (0xAC74, "VT[0x48] 0xAC74"),
    (0xB01C, "VT[0x50] 0xB01C"),
    (0xA9B8, "VT[0x58] 0xA9B8"),
]

for addr, name in vtable_methods:
    disasm(name, addr, 0x180)

# Also parse the FAT12 root directory in logfs
print(f"\n{'='*60}")
print("  logfs FAT12 root directory")
print(f"{'='*60}")
logfs_path = '/Users/xmxx/pinganhuijia/edl_backup/lun4/logfs.bin'
import os
if os.path.isfile(logfs_path):
    with open(logfs_path, 'rb') as f:
        data = f.read()
    # Root dir at sector 3 (offset 3*4096 = 0x3000)
    root_off = 3 * 4096
    for i in range(16):  # Check more entries
        entry_off = root_off + i * 32
        entry = data[entry_off:entry_off+32]
        if entry[0] == 0x00:
            break
        if entry[0] == 0xE5:
            continue
        name = entry[0:8].decode('ascii', errors='replace').strip()
        ext = entry[8:11].decode('ascii', errors='replace').strip()
        attr = entry[11]
        size = struct.unpack('<I', entry[28:32])[0]
        cluster = struct.unpack('<H', entry[26:28])[0]
        if name:
            print(f"  {name}.{ext}  attr=0x{attr:02X} cluster={cluster} size={size}")

    # Also show raw hex of root dir area
    print(f"\n  Root dir raw (offset 0x{root_off:X}):")
    for i in range(0, 128, 16):
        off = root_off + i
        hx = ' '.join(f'{data[off+j]:02X}' for j in range(16))
        asc = ''.join(chr(data[off+j]) if 32 <= data[off+j] < 127 else '.' for j in range(16))
        print(f"    {off:04X}: {hx}  {asc}")

    # Search for data after the FAT12 area (sector 4+)
    data_start = 4 * 4096
    print(f"\n  Data after FAT12 area (offset 0x{data_start:X}):")
    # Check first non-zero region
    for scan in range(data_start, min(len(data), data_start + 0x100000), 4096):
        block = data[scan:scan+4096]
        if any(b != 0 for b in block):
            print(f"    Non-zero block at offset 0x{scan:X}")
            for i in range(0, min(64, len(block)), 16):
                hx = ' '.join(f'{block[i+j]:02X}' for j in range(16))
                asc = ''.join(chr(block[i+j]) if 32 <= block[i+j] < 127 else '.' for j in range(16))
                print(f"      {scan+i:06X}: {hx}  {asc}")
            if scan > data_start + 0x20000:
                break

print("\nDone.")
