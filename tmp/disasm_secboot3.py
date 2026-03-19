#!/usr/bin/env python3
"""Full disassembly of 0x189E8 through all paths, and the GUID at 0x69BE0."""

from capstone import *

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

with open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb') as f:
    data = f.read()

def disasm_range(start, end, title=""):
    code = data[start:end]
    print(f"\n=== {title} (0x{start:X} - 0x{end:X}) ===")
    for insn in md.disasm(code, start):
        extra = ''
        if insn.mnemonic == 'bl':
            extra = f'  ; CALL 0x{insn.operands[0].imm:X}'
        elif insn.mnemonic == 'blr':
            extra = '  ; INDIRECT CALL'
        elif insn.mnemonic == 'adrp':
            extra = f'  ; page=0x{insn.operands[1].imm:X}'
        elif insn.mnemonic in ('b', 'b.eq', 'b.ne', 'b.gt', 'b.lt', 'b.ge', 'b.le',
                               'b.hi', 'b.lo', 'b.hs', 'b.ls', 'cbz', 'cbnz', 'tbz', 'tbnz'):
            for op in insn.operands:
                if op.type == 2:
                    extra = f'  ; -> 0x{op.imm:X}'
        elif 'str' in insn.mnemonic:
            extra = '  ; *** STORE ***'
        print(f"  0x{insn.address:05X}: {insn.mnemonic:<8s} {insn.op_str}{extra}")

# Full function 0x189E8 - extend to 0x18B20
disasm_range(0x189E8, 0x18B20, "Func_0x189E8 FULL")

# Check what GUID is at 0x69BE0
import struct
guid_data = data[0x69BE0:0x69BE0+16]
d1, d2, d3 = struct.unpack_from('<IHH', guid_data, 0)
d4 = guid_data[8:16]
guid_str = f"{d1:08X}-{d2:04X}-{d3:04X}-{d4[0]:02X}{d4[1]:02X}-{d4[2]:02X}{d4[3]:02X}{d4[4]:02X}{d4[5]:02X}{d4[6]:02X}{d4[7]:02X}"
print(f"\nGUID at 0x69BE0: {guid_str}")
print(f"  Raw: {guid_data.hex()}")

# Check string at 0x51C05
s = data[0x51C05:0x51C05+80]
end_idx = s.find(0)
if end_idx > 0: s = s[:end_idx]
print(f"\nString at 0x51C05: '{s.decode('ascii', errors='replace')}'")

# Check [0x1BE3D0] - what is this pointer?
val = struct.unpack_from('<Q', data, 0x1BE3D0)[0]
print(f"\n[0x1BE3D0] = 0x{val:016X}")

# Disassemble 0x28574 and 0x285A0 (called from error paths)
disasm_range(0x28574, 0x285C0, "Func_0x28574")
disasm_range(0x285A0, 0x285E0, "Func_0x285A0")

# Also check the alternative path at 0x22F50 more fully
disasm_range(0x22F50, 0x22FEC, "Alt path 0x22F50 (SecureBoot=off unlock path)")

# Check what 0x69BE0 GUID is — is it the RPMB protocol?
# We know 0x69BE0 was used as the GUID in ReadWritePartition (LocateProtocol)
# Let's verify
print("\n=== Checking 0x69BE0 vs known at 0x69BE0 ===")
print(f"GUID at 0x69BE0: {guid_str}")
print("Previously known ReadWritePartition GUID: 8E5EFF91-21B6-47D3-AF2B-C15A01E020EC")

# Now let's understand: 0x189E8 uses [0x1BE3D0]+0x140 to call LocateProtocol
# UEFI Boot Services table: LocateProtocol is at offset 0x140
# So [0x1BE3D0] = EFI_BOOT_SERVICES_TABLE pointer
# LocateProtocol(guid=0x69BE0, registration=NULL, interface=&x20)
print("\n=== Key understanding ===")
print("0x1DAC always returns 1 (hardcoded)")
print("0x1DA4 always returns 2 (hardcoded)")
print("Since 1!=0, B.EQ not taken at 0x18A20")
print("Since 2!=3, B.NE taken at 0x18A2C → goes to 0x18A58")
print("At 0x18A58: LocateProtocol(ReadWritePartition_GUID, NULL, &interface)")
print("If protocol found (x0=0): continue at 0x18AA8")
print("If protocol NOT found: error handling, ultimately returns non-zero")
