#!/usr/bin/env python3
"""
Analyze the VB protocol: find where it's installed, what method_0x30 is,
and look for param/OEM unlock related code.
"""

from capstone import *
import struct

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

with open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb') as f:
    data = f.read()

# 1. Check error string at 0x598B9
s = data[0x598B9:0x598B9+100]
end_idx = s.find(0)
if end_idx > 0: s = s[:end_idx]
print(f"String at 0x598B9: '{s.decode('ascii', errors='replace')}'")

# 2. Find all references to the VB protocol GUID address 0x69BE0
# Search for ADRP + ADD patterns that generate address 0x69BE0
# ADRP to page 0x69000, then ADD #0xBE0
guid_page = 0x69000
guid_offset = 0xBE0

print(f"\n=== Searching for all references to GUID at 0x69BE0 ===")
code = data[0x1000:0x69000]  # .text section
refs = []
for insn in md.disasm(code, 0x1000):
    if insn.mnemonic == 'adrp':
        if len(insn.operands) >= 2 and insn.operands[1].imm == guid_page:
            refs.append((insn.address, insn.op_str))

print(f"Found {len(refs)} ADRP references to page 0x69000:")
for addr, ops in refs:
    # Check if next instruction is ADD with #0xBE0
    next_code = data[addr+4:addr+8]
    for ni in md.disasm(next_code, addr+4):
        if ni.mnemonic == 'add' and '#0xbe0' in ni.op_str:
            print(f"  0x{addr:05X}: adrp {ops}  →  0x{addr+4:05X}: {ni.mnemonic} {ni.op_str}  *** GUID REF ***")
            # Look at context (surrounding instructions)
            ctx = data[addr-16:addr+32]
            for ci in md.disasm(ctx, addr-16):
                print(f"      0x{ci.address:05X}: {ci.mnemonic:<8s} {ci.op_str}")
            print()

# 3. Find where the protocol is INSTALLED (InstallProtocolInterface uses [BS+0x80])
# Search for code that sets up function table for this protocol
print("\n=== Searching for InstallProtocolInterface calls near GUID references ===")
# InstallProtocolInterface is at BS+0x80
# InstallMultipleProtocolInterfaces is at BS+0x148

# 4. Check ReadWritePartition for the method offset it uses
print("\n=== ReadWritePartition (0x18248) method call ===")
code = data[0x18248:0x18248+200]
for insn in md.disasm(code, 0x18248):
    extra = ''
    if insn.mnemonic == 'bl':
        extra = f'  ; CALL 0x{insn.operands[0].imm:X}'
    elif insn.mnemonic == 'blr':
        extra = '  ; *** INDIRECT CALL ***'
    elif insn.mnemonic == 'adrp':
        extra = f'  ; page=0x{insn.operands[1].imm:X}'
    elif 'ldr' in insn.mnemonic and '#0x' in insn.op_str:
        extra = f'  ; LOAD'
    if insn.mnemonic == 'ret':
        print(f"  0x{insn.address:05X}: {insn.mnemonic:<8s} {insn.op_str}{extra}")
        break
    print(f"  0x{insn.address:05X}: {insn.mnemonic:<8s} {insn.op_str}{extra}")

# 5. Search for "oem" or "unlock" strings near any relevant code
print("\n=== OEM/Unlock related strings ===")
search_terms = [b'oem_unlock', b'OemUnlock', b'oem unlock', b'allow_unlock',
                b'AllowUnlock', b'ops_enable', b'frp', b'FRP', b'OEMUnlock']
for term in search_terms:
    idx = 0
    while True:
        idx = data.find(term, idx)
        if idx == -1:
            break
        context = data[max(0,idx-20):idx+len(term)+40]
        try:
            text = context.decode('ascii', errors='replace')
        except:
            text = repr(context)
        print(f"  0x{idx:05X}: {text.strip()}")
        idx += 1

# 6. Check if param partition is referenced in ABL
print("\n=== Param/config partition references ===")
for term in [b'param\x00', b'config\x00', b'oplusreserve', b'reserve']:
    idx = 0
    while True:
        idx = data.find(term, idx)
        if idx == -1:
            break
        context = data[max(0,idx-10):idx+len(term)+20]
        print(f"  0x{idx:05X}: {context}")
        idx += 1

# 7. Understand what offset 0x30 in the protocol means
# If the protocol table starts at the interface pointer, offset 0x30 is the 7th qword
# (offsets 0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30)
# In UEFI, method 0 might be the revision, so method_0x30 is the 6th actual method
print("\n=== Protocol method offset analysis ===")
print("ReadWritePartition uses method at some offset → let's check above disassembly")
print("0x189E8 uses method at offset 0x30")
print("Need to correlate these with the actual protocol structure")
