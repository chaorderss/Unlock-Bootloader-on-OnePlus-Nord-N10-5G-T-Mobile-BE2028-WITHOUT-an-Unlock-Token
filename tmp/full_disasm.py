#!/usr/bin/env python3
"""Full disassembly of ReadWritePartition and its callees using capstone."""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

with open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb') as f:
    pe = f.read()

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = False

def disasm_func(name, start, max_bytes=0x200):
    print(f"\n{'='*60}")
    print(f"  {name} @ 0x{start:X}")
    print(f"{'='*60}")
    code = pe[start:start+max_bytes]
    for inst in md.disasm(code, start):
        line = f"  0x{inst.address:05X}: {inst.mnemonic:8s} {inst.op_str}"
        # Annotate ADRP+ADD targets
        if inst.mnemonic == 'adrp':
            pass
        if inst.mnemonic == 'bl':
            try:
                target = int(inst.op_str.replace('#', ''), 16)
                # Check if we know this function
                known = {
                    0x18248: "ReadWritePartition",
                    0x384D0: "init_defaults",
                    0x4FD10: "CompareMem",
                    0x280FC: "LogPrint",
                    0x28574: "DebugA",
                    0x285A0: "DebugB",
                    0x1370: "GetPartitionEntry?",
                }
                if target in known:
                    line += f"  ; {known[target]}"
            except:
                pass
        print(line)
        if inst.mnemonic == 'ret':
            break

def hexdump_at(offset, length=32, label=""):
    data = pe[offset:offset+length]
    hx = ' '.join(f'{b:02X}' for b in data)
    try:
        text = data.decode('ascii', errors='replace')
    except:
        text = ""
    print(f"  [{label}] 0x{offset:05X}: {hx}")

# 1. ReadDeviceInfo
disasm_func("ReadDeviceInfo", 0x232D8)

# 2. ReadWritePartition
disasm_func("ReadWritePartition", 0x18248, max_bytes=0x180)

# 3. Function at 0x1370 (called first by ReadWritePartition)
disasm_func("Func_0x1370 (called by ReadWritePartition)", 0x1370, max_bytes=0x100)

# 4. init_defaults
disasm_func("init_defaults", 0x384D0, max_bytes=0x200)

# 5. Check strings
print(f"\n{'='*60}")
print(f"  Key data / strings")
print(f"{'='*60}")
# GUID at 0x69BE0
guid_bytes = pe[0x69BE0:0x69BF0]
a, b, c = struct.unpack('<IHH', guid_bytes[:8])
d = guid_bytes[8:16]
print(f"  GUID at 0x69BE0: {a:08X}-{b:04X}-{c:04X}-{d[:2].hex().upper()}-{d[2:].hex().upper()}")

# GUID at 0x69C80
guid_bytes = pe[0x69C80:0x69C90]
a, b, c = struct.unpack('<IHH', guid_bytes[:8])
d = guid_bytes[8:16]
print(f"  GUID at 0x69C80: {a:08X}-{b:04X}-{c:04X}-{d[:2].hex().upper()}-{d[2:].hex().upper()}")

# Magic string location
hexdump_at(0x5BF06, 16, "magic string")

# String at 0x5AA0F (error msg from ReadDeviceInfo)
hexdump_at(0x5AA0F, 64, "error string")

# Check pointer table entry 0 (devinfo)
ptr = struct.unpack('<Q', pe[0x685E0:0x685E8])[0]
print(f"  Pointer table[0] at 0x685E0 -> 0x{ptr:X}")
hexdump_at(ptr, 20, "devinfo UCS2")

# What's at 0x6A2A8 (loaded by ReadWritePartition from x8's ADRP 0x6A000)
print(f"\n  Data around 0x6A2A8:")
for off in range(0x6A290, 0x6A2D0, 8):
    val = struct.unpack('<Q', pe[off:off+8])[0]
    print(f"    0x{off:05X}: 0x{val:016X}")

# Check what 0x1370 does - it might return a pointer that enables partition access
# Let's look at what data it references
print(f"\n  Data around 0x1BD978 (devinfo buffer):")
hexdump_at(0x1BD978, 32, "devinfo buffer (PE default)")

print(f"\n  Data at 0x1BE388 (already_read flag):")
hexdump_at(0x1BE388, 8, "already_read")
