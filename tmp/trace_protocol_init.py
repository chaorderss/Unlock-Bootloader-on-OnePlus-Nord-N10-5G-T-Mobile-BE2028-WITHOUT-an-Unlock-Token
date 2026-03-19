#!/usr/bin/env python3
"""
Deep trace of partition protocol initialization:
1. Function 0xB114 (partition open/connect)
2. Search for devinfo Type/Unique GUIDs in PE binary
3. Check GPT header sector size
4. Disassemble the protocol setup around 0x2844
"""
import struct, os
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

with open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb') as f:
    pe = f.read()

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = False

known_funcs = {
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
    0x29D90: "CopyStr?",
    0x2A108: "StrLen?",
    0x4FD10: "CompareMem",
}

def disasm_range(name, start, end_or_len, is_len=True):
    print(f"\n{'='*60}")
    print(f"  {name} @ 0x{start:X}")
    print(f"{'='*60}")
    length = end_or_len if is_len else end_or_len - start
    code = pe[start:start+length]
    for inst in md.disasm(code, start):
        line = f"  0x{inst.address:05X}: {inst.mnemonic:8s} {inst.op_str}"
        if inst.mnemonic == 'bl':
            try:
                target = int(inst.op_str.replace('#', ''), 16)
                if target in known_funcs:
                    line += f"  ; {known_funcs[target]}"
            except:
                pass
        print(line)
        if inst.mnemonic == 'ret':
            break

# 1. Function 0xB114
disasm_range("PartitionOpen (0xB114)", 0xB114, 0x300)

# 2. Protocol init at 0x2844 (full)
disasm_range("Protocol Init (0x2844)", 0x2844, 0x200)

# 3. Search GUIDs
print(f"\n{'='*60}")
print("  GUID searches in PE binary")
print(f"{'='*60}")

# devinfo Type GUID: 65ADDCF4-0C5C-4D9A-AC2D-D90B5CBFCD03
type_guid = bytes([0xF4, 0xDC, 0xAD, 0x65, 0x5C, 0x0C, 0x9A, 0x4D,
                   0xAC, 0x2D, 0xD9, 0x0B, 0x5C, 0xBF, 0xCD, 0x03])
idx = pe.find(type_guid)
print(f"  devinfo Type GUID: {'0x'+hex(idx) if idx >= 0 else 'NOT FOUND'}")

# 95A9A93E-A86E-4926-AAEF-9918E772D987
guid2 = bytes([0x3E, 0xA9, 0xA9, 0x95, 0x6E, 0xA8, 0x26, 0x49,
               0xAA, 0xEF, 0x99, 0x18, 0xE7, 0x72, 0xD9, 0x87])
idx = pe.find(guid2)
print(f"  GUID 95A9A93E: {'0x'+hex(idx) if idx >= 0 else 'NOT FOUND'}")
if idx >= 0:
    # Find all ADRP refs to this GUID's page
    page = idx & ~0xFFF
    print(f"    On page 0x{page:X}")

# 4. GPT header
print(f"\n{'='*60}")
print("  GPT header analysis")
print(f"{'='*60}")
for lun in range(6):
    gpt_path = f'/Users/xmxx/pinganhuijia/edl_backup/lun{lun}/gpt_main{lun}.bin'
    if not os.path.isfile(gpt_path):
        continue
    with open(gpt_path, 'rb') as f:
        gpt = f.read()
    for hdr_off in [512, 4096]:
        if hdr_off >= len(gpt):
            continue
        sig = gpt[hdr_off:hdr_off+8]
        if sig == b'EFI PART':
            my_lba = struct.unpack('<Q', gpt[hdr_off+24:hdr_off+32])[0]
            alt_lba = struct.unpack('<Q', gpt[hdr_off+32:hdr_off+40])[0]
            first_usable = struct.unpack('<Q', gpt[hdr_off+40:hdr_off+48])[0]
            last_usable = struct.unpack('<Q', gpt[hdr_off+48:hdr_off+56])[0]
            print(f"  LUN{lun}: Header at offset {hdr_off} (sector_size={hdr_off})")
            print(f"    MyLBA={my_lba} AltLBA={alt_lba} First={first_usable} Last={last_usable}")

# 5. Check what string is at offset that 0x0B114 might reference
# Also check 0x51530 (loaded at 0x02878)
print(f"\n{'='*60}")
print("  Strings referenced in protocol init")
print(f"{'='*60}")
for addr, desc in [(0x51530, "loaded at 0x2878"), (0x51C05, "error msg?")]:
    s = pe[addr:addr+40]
    end = s.find(b'\x00')
    if end > 0:
        text = s[:end].decode('ascii', errors='replace')
        print(f"  0x{addr:X} ({desc}): \"{text}\"")

print("\nDone.")
