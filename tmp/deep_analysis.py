#!/usr/bin/env python3
"""
1. Find all unique buffer addresses used by ReadWritePartition callers
2. Search for string references near non-devinfo callers to identify partitions
3. Search XBL for the protocol GUID
"""
import struct, os
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

with open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb') as f:
    pe = f.read()

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = False

# All callers
callers = [
    0x1D310, 0x22CDC, 0x22D6C, 0x22E54, 0x22EA8, 0x22F14, 0x23004,
    0x23208, 0x232FC, 0x2352C, 0x23648, 0x236DC, 0x30A94, 0x370F4,
    0x37570, 0x37C54, 0x38448, 0x385C4, 0x38638, 0x3A140, 0x3A19C,
    0x3A414, 0x3A6E8, 0x3A7D0, 0x3A8B0, 0x3BC70, 0x3BCE4, 0x3BD18,
    0x3BD4C, 0x3BD78, 0x3C1B8, 0x3C2D8, 0x3C384, 0x3C3B0, 0x3C5B8,
    0x3C698, 0x3C848, 0x3C9A4, 0x3CA60,
]

# For each caller, find buffer address (look for ADRP+ADD pattern that sets x1)
print("Buffer addresses analysis:")
print("="*60)
buffers = {}
for addr in callers:
    start = max(0, addr - 60)
    code = pe[start:addr+4]
    adrp_page = None
    add_off = None
    last_add_x1 = None
    for inst in md.disasm(code, start):
        if inst.mnemonic == 'adrp' and 'x1' in inst.op_str:
            parts = inst.op_str.split('#')
            if len(parts) > 1:
                adrp_page = int(parts[1], 16)
        elif inst.mnemonic == 'add' and inst.op_str.startswith('x1,') and '#' in inst.op_str:
            parts = inst.op_str.split('#')
            if len(parts) > 1:
                add_off = int(parts[1], 16)
                if adrp_page is not None:
                    last_add_x1 = adrp_page + add_off
        elif inst.mnemonic == 'add' and inst.op_str.startswith('x8,') and '#0x978' in inst.op_str:
            last_add_x1 = 0x1BD978  # x8 used as buffer via x1

    if last_add_x1:
        buf = last_add_x1
    else:
        buf = None

    if buf not in buffers:
        buffers[buf] = []
    buffers[buf].append(addr)

for buf, addrs in sorted(buffers.items(), key=lambda x: (x[0] is None, x[0])):
    buf_str = f"0x{buf:X}" if buf else "UNKNOWN"
    addrs_str = ", ".join(f"0x{a:X}" for a in addrs)
    print(f"  Buffer {buf_str}: callers [{addrs_str}]")

# For non-devinfo callers, look at surrounding function for strings
print(f"\n{'='*60}")
print("String references near non-devinfo callers:")
print(f"{'='*60}")

non_devinfo = [a for a in callers if a not in buffers.get(0x1BD978, [])]

for addr in non_devinfo:
    # Search +-0x100 around the caller for ADRP+ADD to string areas (0x50000-0x67000)
    start = max(0, addr - 0x100)
    end = min(len(pe), addr + 0x100)
    code = pe[start:end]
    strings_found = []
    prev_page = None
    for inst in md.disasm(code, start):
        if inst.mnemonic == 'adrp':
            parts = inst.op_str.split('#')
            if len(parts) > 1:
                prev_page = int(parts[1], 16)
        elif inst.mnemonic == 'add' and prev_page and '#' in inst.op_str:
            parts = inst.op_str.split('#')
            if len(parts) > 1:
                off = int(parts[1], 16)
                target = prev_page + off
                if 0x50000 <= target < 0x68000:
                    # Try to read ASCII string
                    s = pe[target:target+80]
                    end_idx = s.find(b'\x00')
                    if end_idx > 0:
                        try:
                            text = s[:end_idx].decode('ascii')
                            if len(text) > 3 and text.isprintable():
                                strings_found.append((target, text))
                        except:
                            pass
    if strings_found:
        print(f"\n  Caller 0x{addr:05X}:")
        for tgt, text in strings_found[:5]:
            print(f"    0x{tgt:05X}: \"{text}\"")

# Search XBL for the GUID
print(f"\n{'='*60}")
print("Searching XBL for GUID 8E5EFF91-21B6-47D3-AF2B-C15A01E020EC:")
print(f"{'='*60}")
guid_bytes = bytes([0x91, 0xFF, 0x5E, 0x8E, 0xB6, 0x21, 0xD3, 0x47,
                    0xAF, 0x2B, 0xC1, 0x5A, 0x01, 0xE0, 0x20, 0xEC])

xbl_paths = [
    '/Users/xmxx/pinganhuijia/edl_backup/lun4/abl_a.bin',
    '/Users/xmxx/pinganhuijia/edl_backup/lun4/abl_b.bin',
]
# Check XBL on LUN1/LUN2
for lun in ['lun1', 'lun2']:
    d = f'/Users/xmxx/pinganhuijia/edl_backup/{lun}'
    if os.path.isdir(d):
        for fn in os.listdir(d):
            xbl_paths.append(os.path.join(d, fn))

for path in xbl_paths:
    if not os.path.isfile(path):
        continue
    sz = os.path.getsize(path)
    if sz > 50 * 1024 * 1024:  # skip >50MB
        print(f"  SKIP {os.path.basename(path)} (too large: {sz})")
        continue
    try:
        with open(path, 'rb') as f:
            chunk_size = 4 * 1024 * 1024
            offset = 0
            while True:
                data = f.read(chunk_size)
                if not data:
                    break
                idx = data.find(guid_bytes)
                if idx >= 0:
                    pos = offset + idx
                    print(f"  FOUND in {os.path.basename(path)} at offset 0x{pos:X}")
                offset += len(data) - 16
                f.seek(offset)
    except Exception as e:
        print(f"  Error reading {os.path.basename(path)}: {e}")

print("\nDone.")
