#!/usr/bin/env python3
"""Disassemble the function around 0x027CC that references the same GUID."""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

with open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb') as f:
    pe = f.read()

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = False

def disasm_range(name, start, length):
    print(f"\n{'='*60}")
    print(f"  {name} @ 0x{start:X}")
    print(f"{'='*60}")
    code = pe[start:start+length]
    for inst in md.disasm(code, start):
        line = f"  0x{inst.address:05X}: {inst.mnemonic:8s} {inst.op_str}"
        if inst.mnemonic == 'bl':
            try:
                target = int(inst.op_str.replace('#', ''), 16)
                known = {
                    0x18248: "ReadWritePartition",
                    0x384D0: "init_defaults",
                    0x232D8: "ReadDeviceInfo",
                    0x280FC: "LogPrint",
                    0x28574: "DebugA",
                    0x285A0: "DebugB",
                    0x1370: "GetStackPtr",
                }
                if target in known:
                    line += f"  ; {known[target]}"
            except:
                pass
        print(line)

# Find the function that starts before 0x027CC
# Look backwards for a function prologue (STP)
start = 0x027CC
while start > 0x02600:
    word = struct.unpack('<I', pe[start:start+4])[0]
    # Check for common function prologues
    if (word & 0xFFC003E0) == 0xA9000000:  # STP
        break
    if (word & 0xFF000000) == 0xF8000000:  # STR pre-index
        break
    if word == 0xD503201F:  # NOP (padding)
        start += 4
        break
    start -= 4

disasm_range(f"Function containing GUID ref at 0x027CC", start, 0x200)

# Also check the function at 0x1D2E8 (caller at 0x1D310 with UNKNOWN buffer)
# This allocates a new buffer and reads into it
disasm_range("Func 0x1D2E8 (reads into allocated buffer)", 0x1D2E8, 0x100)

# Check what happens at 0x30A80 (uses buffer 0x1BE428)
disasm_range("Func 0x30A80 (uses buffer 0x1BE428)", 0x30A80, 0x80)

# Also check logfs and other partition sizes
import os
base = '/Users/xmxx/pinganhuijia/edl_backup'
print(f"\n{'='*60}")
print("Partition sizes for firmware/storage partitions:")
print(f"{'='*60}")
for fn in ['lun4/logfs.bin', 'lun4/logdump.bin', 'lun4/limits.bin',
           'lun4/apdp.bin', 'lun4/reserve1.bin']:
    fp = os.path.join(base, fn)
    if os.path.isfile(fp):
        print(f"  {fn}: {os.path.getsize(fp)}")
