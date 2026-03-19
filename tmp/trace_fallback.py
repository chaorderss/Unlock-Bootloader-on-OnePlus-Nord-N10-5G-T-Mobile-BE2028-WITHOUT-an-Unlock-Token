#!/usr/bin/env python3
"""Disassemble 0x3F34 (fallback when protocol not found) and 0x18A58 (second protocol ref).
Also trace what happens around 0x027E4-0x2844."""

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
    ret_count = 0
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
        elif "0x0b114" in ops.lower(): comment = " ; PartitionOpen"
        elif "0x17c90" in ops.lower(): comment = " ; CorePartSearch"
        elif "0xa618" in ops.lower(): comment = " ; LocatePartHandle"
        elif "0x0d290" in ops.lower(): comment = " ; AllocatePool"
        elif "0x08304" in ops.lower(): comment = " ; Alloc2"
        elif "#0x69000" in ops: comment = "  ; GUID page"
        elif "#0x1be000" in ops.lower(): comment = "  ; global data"
        elif "#0x1bd000" in ops.lower(): comment = "  ; devinfo page"
        elif "#0x3d0" in ops: comment = " ; BS ptr"
        elif "#0x140" in ops and "ldr" in mnem: comment = " ; BS->LocateProtocol"
        elif "#0x80" in ops and "ldr" in mnem and "[x8" in ops: comment = " ; BS->InstallProtocol"
        elif "#0x148" in ops and "ldr" in mnem: comment = " ; BS->InstallMultipleProto"
        elif "#0xbe0" in ops: comment = " ; +0xBE0 (GUID 8E5EFF91)"
        elif "#0x978" in ops: comment = " ; +0x978 (devinfo buf)"
        elif "#0xa10" in ops.lower(): comment = " ; 0xA10=2576 (devinfo sz)"

        print(f"  0x{ins.address:05X}: {mnem:<8} {ops}{comment}")

        if mnem == "ret":
            ret_count += 1
            if ret_count >= 1:
                break

# 1) 0x3F34 - fallback when protocol not found
dis(0x3F34, 0x200, "Fallback 0x3F34 (protocol not found)")

# 2) 0x18A58 - second LocateProtocol reference
# First find the function start
dis(0x18A00, 0x150, "Second LocateProtocol ref at 0x18A58")

# 3) Function at 0x18AA8 (success path of second ref)
dis(0x18AA8, 0x200, "0x18AA8 success of second LocateProtocol")

# 4) Context around 0x027CC - the full boot init where protocol is checked
# Need more context before 0x027CC to see what function it's in
dis(0x02780, 0x100, "Boot init around protocol check")

# 5) What's at 0x3EE4, 0x3FEC, 0x30C0 (called in Protocol Init)
dis(0x30C0, 0x200, "Protocol Init continuation at 0x30C0")

# 6) Check strings referenced in fallback
for off in [0x51C05, 0x596F8]:
    raw = pe[off:off+80]
    try:
        end = raw.index(0)
        s = raw[:end].decode('ascii')
        print(f"\nString at 0x{off:05X}: \"{s}\"")
    except:
        pass
