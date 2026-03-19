#!/usr/bin/env python3
"""Disassemble key partition I/O functions: 0xa618 (handle locator),
0xa104 (VT[0x18] success path), GUID at 0x69B20, 0x23470, 0x233A8"""

import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

PE = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
with open(PE, "rb") as f:
    pe = f.read()

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

def dis(start, length=0x200, label=""):
    print(f"\n{'='*60}")
    print(f"  {label} @ 0x{start:X}")
    print(f"{'='*60}")
    code = pe[start:start+length]
    for ins in md.disasm(code, start):
        comment = ""
        mnem = ins.mnemonic
        ops = ins.op_str
        # Annotate known addresses
        if "0x1370" in ops: comment = " ; GetStackPtr"
        elif "0x18248" in ops: comment = " ; ReadWritePartition"
        elif "0x280fc" in ops or "0x280FC" in ops: comment = " ; LogPrint"
        elif "0x28574" in ops: comment = " ; DebugA"
        elif "0x4fd10" in ops: comment = " ; CompareMem"
        elif "0x22c18" in ops or "0x22C18" in ops: comment = " ; GetDevUnlocked?"
        elif "0x232d8" in ops or "0x232D8" in ops: comment = " ; ReadDeviceInfo"
        elif "0x233a8" in ops or "0x233A8" in ops: comment = " ; fn_233A8"
        elif "0x23470" in ops or "0x23470" in ops: comment = " ; fn_23470"
        elif "0xa618" in ops or "0xA618" in ops: comment = " ; LocatePartHandle"
        elif "#0x69000" in ops: comment = "  ; GUID/data page"
        elif "#0x1be000" in ops or "#0x1BE000" in ops: comment = "  ; global data page"
        elif "#0x6a000" in ops or "#0x6A000" in ops: comment = "  ; .data page"
        elif "#0x3d0" in ops: comment = " ; EFI_BOOT_SERVICES ptr"
        elif "#0x140" in ops and "ldr" in mnem: comment = " ; BS->LocateProtocol"
        elif "#0x98" in ops and "ldr" in mnem: comment = " ; BS->HandleProtocol"
        elif "#0xb0" in ops and ("ldr" in mnem or "str" in mnem): comment = " ; BS->LocateHandleBuffer"

        print(f"  0x{ins.address:05X}: {mnem:<8} {ops}{comment}")

        if mnem == "ret":
            break

# 1) Function 0xa618 - partition handle locator
dis(0xa618, 0x300, "LocatePartHandle 0xa618")

# 2) VT[0x18] success path at 0xa104
dis(0xa104, 0x100, "VT[0x18] success path 0xa104")

# 3) GUID at 0x69B20
guid_bytes = pe[0x69B20:0x69B30]
a, b, c = struct.unpack_from('<IHH', guid_bytes, 0)
d = guid_bytes[8:16]
guid_str = f"{a:08X}-{b:04X}-{c:04X}-{d[0]:02X}{d[1]:02X}-{d[2]:02X}{d[3]:02X}{d[4]:02X}{d[5]:02X}{d[6]:02X}{d[7]:02X}"
print(f"\n{'='*60}")
print(f"  GUID at 0x69B20: {guid_str}")
print(f"  Raw: {guid_bytes.hex()}")
print(f"{'='*60}")

# Also check GUIDs nearby
for off in [0x69B00, 0x69B10, 0x69B20, 0x69B30, 0x69B40, 0x69B50, 0x69B60, 0x69B70, 0x69B80, 0x69B90, 0x69BA0, 0x69BB0, 0x69BC0, 0x69BD0, 0x69BE0, 0x69BF0, 0x69C00]:
    gb = pe[off:off+16]
    a2, b2, c2 = struct.unpack_from('<IHH', gb, 0)
    d2 = gb[8:16]
    gs = f"{a2:08X}-{b2:04X}-{c2:04X}-{d2[0]:02X}{d2[1]:02X}-{d2[2]:02X}{d2[3]:02X}{d2[4]:02X}{d2[5]:02X}{d2[6]:02X}{d2[7]:02X}"
    print(f"  0x{off:05X}: {gs}")

# 4) Function 0x233A8 (called by VT[0x30])
dis(0x233A8, 0x200, "fn_233A8")

# 5) Function 0x23470 (called by VT[0x38])
dis(0x23470, 0x200, "fn_23470")

# 6) Function 0x18158 (called in VT[0x18] and others)
dis(0x18158, 0x100, "fn_18158 (called pre-locate)")

# 7) Check strings at key offsets referenced in vtable code
string_offsets = [
    (0x54186, "VT[0x18] error1"),
    (0x54170, "VT[0x18] error2/NULL"),
    (0x543A6, "VT[0x18] elapsed time"),
    (0x5450B, "VT[0x30] error"),
    (0x54529, "VT[0x30] success"),
    (0x5455A, "VT[0x38] info"),
    (0x5458C, "VT[0x38] success"),
    (0x545CE, "VT[0x48] name too long"),
    (0x545B9, "VT[0x48] handle error"),
    (0x54617, "VT[0x50] null arg"),
    (0x54497, "VT[0x58] info"),
    (0x544E2, "VT[0x58] result"),
    (0x54703, "VT[0x58] compare data"),
    (0x543C9, "VT[0x28] info"),
    (0x54411, "VT[0x28] error"),
]

print(f"\n{'='*60}")
print(f"  String references from vtable methods")
print(f"{'='*60}")
for off, desc in string_offsets:
    # Read null-terminated string (could be ASCII or UCS-2)
    raw = pe[off:off+80]
    # Try ASCII first
    try:
        end = raw.index(0)
        s = raw[:end].decode('ascii')
        print(f"  0x{off:05X} [{desc}]: \"{s}\"")
    except (ValueError, UnicodeDecodeError):
        # Try UCS-2
        chars = []
        for i in range(0, min(80, len(raw)), 2):
            ch = struct.unpack_from('<H', raw, i)[0]
            if ch == 0: break
            if 0x20 <= ch < 0x7f:
                chars.append(chr(ch))
            else:
                chars.append(f'\\u{ch:04x}')
        s = ''.join(chars)
        print(f"  0x{off:05X} [{desc}]: \"{s}\" (UCS-2)")

# 8) Read what's at 0x69B20 in context - check if it's EFI_PARTITION_INFO_PROTOCOL_GUID
# or EFI_BLOCK_IO_PROTOCOL_GUID
print(f"\n{'='*60}")
print(f"  Known UEFI GUIDs comparison")
print(f"{'='*60}")
known = {
    "EFI_BLOCK_IO_PROTOCOL": "964E5B21-6459-11D2-8E39-00A0C969723B",
    "EFI_BLOCK_IO2_PROTOCOL": "A77B2472-E282-4E9F-A245-C2C0E27BBCC1",
    "EFI_DISK_IO_PROTOCOL": "CE345171-BA0B-11D2-8E4F-00A0C969723B",
    "EFI_PARTITION_INFO_PROTOCOL": "8CF2F62C-BC9B-4821-808D-EC9EC421A1A0",
    "EFI_DEVICE_PATH_PROTOCOL": "09576E91-6D3F-11D2-8E39-00A0C969723B",
    "EFI_SIMPLE_FILE_SYSTEM": "964E5B22-6459-11D2-8E39-00A0C969723B",
}
print(f"  Our GUID at 0x69B20: {guid_str}")
for name, g in known.items():
    print(f"  {name}: {g}")
