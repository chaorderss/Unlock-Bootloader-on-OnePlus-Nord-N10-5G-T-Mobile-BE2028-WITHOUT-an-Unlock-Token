#!/usr/bin/env python3
"""
Find and analyze the IsAllowUnlock function and FRP partition check.
This is the KEY to understanding if OEM unlock can work.
"""

from capstone import *
import struct

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

with open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb') as f:
    data = f.read()

# 1. Find exact address of "IsAllowUnlock" string
idx = data.find(b'IsAllowUnlock')
print(f"'IsAllowUnlock' found at: 0x{idx:05X}")

# Get the full string
end = data.find(0, idx)
full_str = data[idx:end].decode('ascii', errors='replace')
print(f"Full string: '{full_str}'")

# Also check nearby strings
for delta in range(-80, 120, 1):
    c = data[idx+delta]
    if c == 0:
        # Check if next is printable
        if idx+delta+1 < len(data) and 0x20 <= data[idx+delta+1] < 0x7f:
            s_start = idx+delta+1
            s_end = data.find(0, s_start)
            if s_end > s_start and s_end - s_start < 200:
                try:
                    s = data[s_start:s_end].decode('ascii')
                    print(f"  String at 0x{s_start:05X}: '{s}'")
                except:
                    pass

# 2. Find ADRP references to the page containing "IsAllowUnlock"
str_addr = idx
str_page = str_addr & ~0xFFF
str_offset = str_addr & 0xFFF
print(f"\nString at 0x{str_addr:05X}, page=0x{str_page:05X}, offset=0x{str_offset:03X}")

# Search for ADRP instructions pointing to this page
print(f"\n=== ADRP references to page 0x{str_page:X} with ADD #0x{str_offset:X} ===")
code = data[0x1000:0x69000]
found_refs = []
for insn in md.disasm(code, 0x1000):
    if insn.mnemonic == 'adrp':
        if len(insn.operands) >= 2 and insn.operands[1].imm == str_page:
            # Check next instruction for ADD with our offset
            next_code = data[insn.address+4:insn.address+8]
            for ni in md.disasm(next_code, insn.address+4):
                offset_hex = f'#0x{str_offset:x}'
                if ni.mnemonic == 'add' and offset_hex in ni.op_str:
                    found_refs.append(insn.address)
                    print(f"  Reference at 0x{insn.address:05X}")

# 3. Disassemble around each reference to see the full function
for ref_addr in found_refs:
    # Find function start (scan backwards for a common prologue)
    func_start = ref_addr
    for scan in range(ref_addr - 4, max(ref_addr - 800, 0x1000), -4):
        word = struct.unpack_from('<I', data, scan)[0]
        # Look for STP x29, x30 or STP xN, xN patterns at function start
        # Or look for a RET or UDF just before
        if scan > 0x1004:
            prev_word = struct.unpack_from('<I', data, scan-4)[0]
            # Check if prev instruction is RET (0xD65F03C0) or UDF
            if prev_word == 0xD65F03C0 or (prev_word & 0xFFFF0000) == 0x00000000:
                func_start = scan
                break

    print(f"\n=== Function containing IsAllowUnlock ref at 0x{ref_addr:05X} ===")
    print(f"  (estimated start: 0x{func_start:05X})")

    # Disassemble from function start
    dis_start = max(func_start, ref_addr - 200)
    dis_end = min(ref_addr + 300, 0x69000)
    code = data[dis_start:dis_end]

    for insn in md.disasm(code, dis_start):
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

        marker = ''
        if insn.address == ref_addr:
            marker = ' <<<< IsAllowUnlock string ref'
        elif insn.address == ref_addr + 4:
            marker = ' <<<< ADD for string'

        print(f"  0x{insn.address:05X}: {insn.mnemonic:<8s} {insn.op_str}{extra}{marker}")

        if insn.address > ref_addr + 250:
            break

# 4. Also find "frp" or "FRP" partition references
print("\n=== FRP partition string ===")
frp_idx = data.find(b'Error Reading FRP')
if frp_idx >= 0:
    print(f"'Error Reading FRP partition' at 0x{frp_idx:05X}")
    frp_page = frp_idx & ~0xFFF
    frp_offset = frp_idx & 0xFFF
    print(f"  page=0x{frp_page:X}, offset=0x{frp_offset:X}")

# 5. Search for "oem" related strings more precisely
print("\n=== All 'oem' strings ===")
idx = 0
while True:
    idx = data.find(b'oem', idx)
    if idx == -1:
        break
    # Get surrounding context
    start = idx
    while start > 0 and data[start-1] != 0:
        start -= 1
    end = data.find(0, idx)
    if end > start:
        try:
            s = data[start:end].decode('ascii', errors='replace')
            if len(s) < 100:
                print(f"  0x{start:05X}: '{s}'")
        except:
            pass
    idx += 1

# 6. Find "AllowUnlock" function
print("\n=== Searching for AllowUnlock function ===")
allow_idx = data.find(b'AllowUnlock')
while allow_idx >= 0:
    s_start = allow_idx
    while s_start > 0 and data[s_start-1] != 0:
        s_start -= 1
    s_end = data.find(0, allow_idx)
    try:
        s = data[s_start:s_end].decode('ascii')
        print(f"  0x{s_start:05X}: '{s}'")
    except:
        pass
    allow_idx = data.find(b'AllowUnlock', allow_idx + 1)
