#!/usr/bin/env python3
"""
Find where VB protocol is INSTALLED in ABL. Since the GUID is only in ABL,
the protocol implementation is here too. Need to find InstallProtocol calls.
"""

from capstone import *
import struct

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

with open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb') as f:
    data = f.read()

guid_bytes = bytes.fromhex('91ff5e8eb621d347af2bc15a01e020ec')

# 1. Find ALL copies of the GUID in the binary
print("=== All copies of VB protocol GUID in binary ===")
idx = 0
while True:
    idx = data.find(guid_bytes, idx)
    if idx == -1:
        break
    print(f"  GUID at offset 0x{idx:X}")
    idx += 1

# 2. Find all ADRP+ADD referencing 0x69BE0 (proven method)
guid_page = 0x69000
guid_off = 0xBE0
print(f"\n=== All references to GUID address 0x69BE0 ===")
refs_to_guid = []
for off in range(0x1000, 0x69000, 4):
    word = struct.unpack_from('<I', data, off)[0]
    if (word & 0x9F000000) == 0x90000000:  # ADRP
        immlo = (word >> 29) & 0x3
        immhi = (word >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & 0x100000:
            imm |= ~0x1FFFFF
            imm &= 0xFFFFFFFF
            imm = imm if imm < 0x80000000 else imm - 0x100000000
        page_base = off & ~0xFFF
        result_page = (page_base + (imm << 12)) & 0xFFFFFFFF
        if result_page == guid_page:
            rd = word & 0x1F
            # Check for ADD with 0xBE0
            for delta in range(4, 20, 4):
                noff = off + delta
                if noff + 4 > 0x69000:
                    break
                nword = struct.unpack_from('<I', data, noff)[0]
                # ADD Xd, Xn, #0xBE0 encoding
                # 10010001_00_IIIIIIIIIIII_NNNNN_DDDDD
                # imm = 0xBE0
                for ni in md.disasm(data[noff:noff+4], noff):
                    if ni.mnemonic == 'add' and f'#0x{guid_off:x}' in ni.op_str.lower():
                        refs_to_guid.append(off)
                        print(f"  0x{off:05X}: adrp x{rd}, #0x{guid_page:X} + 0x{noff:05X}: add {ni.op_str}")

# 3. Search for all references to 0x69BA0 (close to 0x69BE0, might be part of a struct)
# Actually, let me check what's around 0x69BE0 in the data
print(f"\n=== Data around GUID at 0x69BE0 ===")
for base in range(0x69B80, 0x69C20, 16):
    hex_str = data[base:base+16].hex()
    ascii_str = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in data[base:base+16])
    print(f"  0x{base:05X}: {hex_str}  {ascii_str}")

# 4. Search for BS function table calls that install protocols
# InstallProtocolInterface: BS+0x80
# InstallMultipleProtocolInterfaces: BS+0x148
# BS table at [0x1BE3D0]
# Pattern: ldr xN, [xM, #0x3D0]; ... ldr xN, [xN, #0x80 or #0x148]; blr xN

print(f"\n=== Searching for InstallProtocol calls ===")
# Search for LDR with offset 0x80 or 0x148 from BS table
for off in range(0x1000, 0x69000, 4):
    word = struct.unpack_from('<I', data, off)[0]
    # LDR Xt, [Xn, #0x148] for 64-bit: offset = 0x148/8 = 41
    # Encoding: 1111100101_imm12_Rn_Rt where imm12 = 41 for 0x148
    # Also check LDR Xt, [Xn, #0x80] where imm12 = 0x80/8 = 16
    for target_offset, name in [(0x80, 'InstallProtocolInterface'), (0x148, 'InstallMultipleProtocolInterfaces')]:
        imm12 = target_offset >> 3  # divide by 8 for 64-bit
        # LDR X8, [X8, #offset]: 1111100101_imm12_Rn_Rt
        expected_bits = (0b1111100101 << 22) | (imm12 << 10)
        mask = (0b1111111111 << 22) | (0x3FF << 10)
        if (word & mask) == expected_bits:
            rn = (word >> 5) & 0x1F
            rt = word & 0x1F
            # Check if next instruction is BLR Rt
            next_word = struct.unpack_from('<I', data, off+4)[0]
            expected_blr = 0xD63F0000 | (rt << 5)
            if next_word == expected_blr:
                # Check if any ADRP to 0x69000 (GUID page) is nearby
                has_guid_ref = False
                for back in range(4, 80, 4):
                    prev_off = off - back
                    if prev_off < 0x1000:
                        break
                    pword = struct.unpack_from('<I', data, prev_off)[0]
                    if (pword & 0x9F000000) == 0x90000000:
                        immlo_p = (pword >> 29) & 0x3
                        immhi_p = (pword >> 5) & 0x7FFFF
                        imm_p = (immhi_p << 2) | immlo_p
                        if imm_p & 0x100000:
                            imm_p = imm_p - 0x200000
                        page_p = (prev_off & ~0xFFF) + (imm_p << 12)
                        if (page_p & 0xFFFFFFFF) == 0x69000:
                            has_guid_ref = True
                            break

                if has_guid_ref:
                    print(f"  *** 0x{off:05X}: LDR x{rt}, [x{rn}, #0x{target_offset:X}] + BLR x{rt}")
                    print(f"    ({name} with GUID reference nearby)")
                    # Show context
                    ctx_start = max(0x1000, off-40)
                    ctx_end = min(0x69000, off+20)
                    for insn in md.disasm(data[ctx_start:ctx_end], ctx_start):
                        extra = ''
                        if insn.mnemonic == 'adrp':
                            extra = f'  ; page=0x{insn.operands[1].imm:X}' if len(insn.operands) >= 2 else ''
                        elif insn.mnemonic == 'bl':
                            extra = f'  ; CALL 0x{insn.operands[0].imm:X}'
                        print(f"      0x{insn.address:05X}: {insn.mnemonic:<8s} {insn.op_str}{extra}")
                    print()

# 5. Also search for function table construction (storing function pointers at offsets)
# If the ABL creates the protocol interface, it would build a table with function pointers
# The table would have pointers at offsets 0x08, 0x10, ..., 0x30
# Let me search for any global that has function pointers at these offsets
print(f"\n=== Search for protocol vtable in data section ===")
# The protocol interface is a struct with function pointers
# Look in data section for a group of function pointers
# at offsets 0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30
for base in range(0x6A000, len(data) - 0x38, 8):
    ptrs = []
    valid = True
    for poff in range(0, 0x38, 8):
        ptr = struct.unpack_from('<Q', data, base + poff)[0]
        if 0x1000 <= ptr < 0x69000:
            ptrs.append(ptr)
        else:
            valid = False
            break
    if valid and len(ptrs) == 7:
        print(f"  Vtable at 0x{base:05X}: {[f'0x{p:X}' for p in ptrs]}")
