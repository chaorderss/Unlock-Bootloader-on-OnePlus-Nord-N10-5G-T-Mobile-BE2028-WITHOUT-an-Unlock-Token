#!/usr/bin/env python3
"""Disassemble 0x17C90 (core partition search), 0xa720 (LocatePartHandle success),
and the block I/O read loop in VT[0x18]"""

import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

PE = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
with open(PE, "rb") as f:
    pe = f.read()

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

def dis(start, length=0x300, label=""):
    print(f"\n{'='*60}")
    print(f"  {label} @ 0x{start:X}")
    print(f"{'='*60}")
    code = pe[start:start+length]
    ret_count = 0
    for ins in md.disasm(code, start):
        comment = ""
        mnem = ins.mnemonic
        ops = ins.op_str
        # Annotate known addresses
        if "0x1370" in ops: comment = " ; GetStackPtr"
        elif "0x18248" in ops: comment = " ; ReadWritePartition"
        elif "0x17c90" in ops.lower(): comment = " ; CorePartSearch"
        elif "0x280fc" in ops.lower(): comment = " ; LogPrint"
        elif "0x28574" in ops: comment = " ; DebugA"
        elif "0x4fd10" in ops.lower(): comment = " ; CompareMem"
        elif "0x4debc" in ops.lower(): comment = " ; Memset/Memzero"
        elif "0xa618" in ops.lower(): comment = " ; LocatePartHandle"
        elif "0x2a108" in ops.lower(): comment = " ; StrLen"
        elif "0x2a758" in ops.lower(): comment = " ; Str2UCS2"
        elif "0x298a4" in ops.lower(): comment = " ; UCS2Len"
        elif "0x29a64" in ops.lower(): comment = " ; UCS2Copy"
        elif "#0x69000" in ops: comment = "  ; GUID/data page"
        elif "#0x1be000" in ops.lower(): comment = "  ; global data"
        elif "#0x6a000" in ops.lower(): comment = "  ; .data page"
        elif "#0x3d0" in ops: comment = " ; BS ptr"
        elif "#0x140" in ops and "ldr" in mnem: comment = " ; BS->LocateProtocol"
        elif "#0x98" in ops and "ldr" in mnem: comment = " ; BS->HandleProtocol"
        elif "#0xb0" in ops and "ldr" in mnem: comment = " ; BS->LocateHandleBuffer"
        elif "#0x118" in ops and "ldr" in mnem: comment = " ; BS->OpenProtocol"
        elif "#0x80" in ops and "ldr" in mnem: comment = " ; BS->InstallProtocol"
        elif "#0x40" in ops and "ldr" in mnem: comment = " ; BS->AllocatePool?"
        elif "#0x48" in ops and "ldr" in mnem: comment = " ; BS->FreePool?"
        elif "#0x28" in ops and "ldr" in mnem: comment = " ; BS->AllocatePages?"

        print(f"  0x{ins.address:05X}: {mnem:<8} {ops}{comment}")

        if mnem == "ret":
            ret_count += 1
            if ret_count >= 1:
                break

# 1) 0xa720 - LocatePartHandle success path (continuation of 0xa618)
dis(0xa720, 0x80, "LocatePartHandle success path 0xa720")

# 2) 0x17C90 - Core partition search function
dis(0x17C90, 0x400, "CorePartSearch 0x17C90")

# 3) VT[0x18] block read continuation at ~0xa200
dis(0xa200, 0x200, "VT[0x18] block I/O read loop 0xa200")

# 4) 0x82C0 - allocation function called in VT[0x18] success
dis(0x82C0, 0x80, "Alloc 0x82C0")

# 5) String at 0x5466E referenced by LocatePartHandle
soffsets = [
    (0x5466E, "LocatePartHandle name_too_long"),
    (0x5469B, "LocatePartHandle fail"),
    (0x541BB, "VT[0x18] offset_out_of_range"),
    (0x541FB, "VT[0x18] read_info"),
]
print(f"\n{'='*60}")
print(f"  Strings")
print(f"{'='*60}")
for off, desc in soffsets:
    raw = pe[off:off+100]
    try:
        end = raw.index(0)
        s = raw[:end].decode('ascii')
        print(f"  0x{off:05X} [{desc}]: \"{s}\"")
    except:
        chars = []
        for i in range(0, min(100, len(raw)), 2):
            ch = struct.unpack_from('<H', raw, i)[0]
            if ch == 0: break
            if 0x20 <= ch < 0x7f:
                chars.append(chr(ch))
            else:
                chars.append(f'\\u{ch:04x}')
        print(f"  0x{off:05X} [{desc}]: \"{''.join(chars)}\" (UCS-2)")
