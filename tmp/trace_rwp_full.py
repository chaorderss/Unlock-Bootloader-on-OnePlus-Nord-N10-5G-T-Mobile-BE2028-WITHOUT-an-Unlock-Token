#!/usr/bin/env python3
"""Full disassembly of ReadWritePartition (0x18248) and boot error path.
Also search for InstallProtocolInterface calls with GUID 8E5EFF91."""

import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

PE = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
with open(PE, "rb") as f:
    pe = f.read()

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

def dis(start, length, label=""):
    print(f"\n{'='*60}")
    print(f"  {label} @ 0x{start:X}")
    print(f"{'='*60}")
    code = pe[start:start+length]
    for ins in md.disasm(code, start):
        comment = ""
        mnem = ins.mnemonic
        ops = ins.op_str

        if "0x1370" in ops: comment = " ; GetStackPtr"
        elif "0x18248" in ops: comment = " ; ReadWritePartition"
        elif "0x384d0" in ops.lower(): comment = " ; init_defaults"
        elif "0x280fc" in ops.lower(): comment = " ; LogPrint"
        elif "0x28574" in ops: comment = " ; DebugA"
        elif "0x4fd10" in ops.lower(): comment = " ; CompareMem"
        elif "0x232d8" in ops.lower(): comment = " ; ReadDeviceInfo"
        elif "0xa618" in ops.lower(): comment = " ; LocatePartHandle"
        elif "#0x69000" in ops: comment = "  ; GUID page"
        elif "#0x1be000" in ops.lower(): comment = "  ; global data"
        elif "#0x1bd000" in ops.lower(): comment = "  ; devinfo page"
        elif "#0x3d0" in ops: comment = " ; BS ptr"
        elif "#0x140" in ops and "ldr" in mnem: comment = " ; BS->LocateProtocol"
        elif "#0x80" in ops and "ldr" in mnem and "x8, [x8" in ops: comment = " ; BS->InstallProtocol?"
        elif "#0xbe0" in ops: comment = " ; GUID 8E5EFF91 offset"
        elif "#0x978" in ops: comment = " ; devinfo buffer offset"
        elif "#0xa10" in ops.lower(): comment = " ; devinfo size 2576"

        print(f"  0x{ins.address:05X}: {mnem:<8} {ops}{comment}")

        if mnem == "ret":
            break

# 1) Full ReadWritePartition (0x18248)
dis(0x18248, 0x200, "ReadWritePartition FULL")

# 2) ReadDeviceInfo full (0x232D8) - both success and error paths
dis(0x232D8, 0x200, "ReadDeviceInfo FULL")

# 3) Boot sequence around ReadDeviceInfo call (0x01550-0x01650)
dis(0x01540, 0x120, "Boot sequence around ReadDeviceInfo")

# 4) Search for InstallProtocolInterface/InstallMultipleProtocolInterfaces
# BS->InstallProtocolInterface is at offset 0x80
# BS->InstallMultipleProtocolInterfaces is at offset 0x148
print(f"\n{'='*60}")
print(f"  Searching for protocol installations with GUID 8E5EFF91")
print(f"{'='*60}")

# The GUID at 0x69BE0 - search for code that loads this offset
# Pattern: ADRP xN, #0x69000 followed by ADD xN, xN, #0xBE0
text = pe[0x1000:0x6A000]
text_base = 0x1000
hits = []
for i in range(0, len(text) - 8, 4):
    addr = text_base + i
    insn1 = text[i:i+4]
    insn2 = text[i+4:i+8]

    for d1 in md.disasm(insn1, addr):
        if d1.mnemonic == "adrp" and "#0x69000" in d1.op_str:
            # Get register
            reg = d1.op_str.split(",")[0].strip()
            for d2 in md.disasm(insn2, addr + 4):
                if d2.mnemonic == "add" and "#0xbe0" in d2.op_str and reg in d2.op_str:
                    hits.append(addr)

print(f"  Found {len(hits)} references to GUID at 0x69BE0:")
for h in hits:
    # Show context (8 instructions around)
    ctx_start = max(0x1000, h - 16)
    ctx_code = pe[ctx_start:h+32]
    for ins in md.disasm(ctx_code, ctx_start):
        marker = " <--" if ins.address == h else ""
        print(f"    0x{ins.address:05X}: {ins.mnemonic:<8} {ins.op_str}{marker}")
    print()

# 5) Check what's at 0x2844 (Protocol Init) more carefully - does it INSTALL the protocol?
dis(0x2844, 0x200, "Protocol Init 0x2844 (full)")

# 6) Also look at the section before 0x2844 - the caller
dis(0x27B0, 0xA0, "Pre-Protocol Init 0x27B0")
