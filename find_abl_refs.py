#!/usr/bin/env python3
"""
Search for code references to the AVB-related strings in tmobile_abl_decompressed.bin
Uses multiple strategies: ADRP+ADD, ADRP+LDR, and adjacent-code pattern matching.
"""
import struct, sys

with open('/Users/xmxx/pinganhuijia/tmobile_abl_decompressed.bin','rb') as f:
    d = bytearray(f.read())

size = len(d)
print(f"Decompressed ABL size: {hex(size)}")

# ===== 1. Find the strings =====
def find_str(data, s):
    b = s.encode('utf-8') + b'\x00'
    pos = data.find(b)
    return pos

STR_UNLOCKED = find_str(d, 'Unlocked, AvbSlotVerify returned')
STR_ERROR    = find_str(d, 'ERROR: Device State')
STR_VERDIS   = find_str(d, 'VERIFICATION_DISABLED bit is set')
STR_AVBSV    = find_str(d, 'AvbSlotVerify')

print(f"'Unlocked, AvbSlotVerify': {hex(STR_UNLOCKED) if STR_UNLOCKED>=0 else 'NOT FOUND'}")
print(f"'ERROR: Device State':     {hex(STR_ERROR)    if STR_ERROR>=0 else 'NOT FOUND'}")
print(f"'VERIFICATION_DISABLED':   {hex(STR_VERDIS)   if STR_VERDIS>=0 else 'NOT FOUND'}")
print(f"'AvbSlotVerify' (first):   {hex(STR_AVBSV)    if STR_AVBSV>=0 else 'NOT FOUND'}")
print()

# ===== 2. Try to understand the binary layout =====
# Check if it starts with FV or PE at 0xb8
print("Bytes at 0x00:", d[0:16].hex())
print("Bytes at 0xb8:", d[0xb8:0xb8+16].hex())

# Find PE sig
pe_off = None
if d[0xb8:0xb8+2] == b'MZ':
    e_lfanew = struct.unpack_from('<I', d, 0xb8+0x3c)[0]
    pe_sig_off = 0xb8 + e_lfanew
    if d[pe_sig_off:pe_sig_off+4] == b'PE\x00\x00':
        pe_off = pe_sig_off
        print(f"PE sig at {hex(pe_sig_off)}")
        coff_off = pe_sig_off + 4
        machine  = struct.unpack_from('<H', d, coff_off)[0]
        num_sect = struct.unpack_from('<H', d, coff_off+2)[0]
        oh_size  = struct.unpack_from('<H', d, coff_off+16)[0]
        print(f"  machine={hex(machine)}, num_sections={num_sect}, opt_hdr_sz={oh_size}")

        if oh_size > 0:
            # AArch64 PE32+ optional header
            opt_off = coff_off + 20
            image_base = struct.unpack_from('<Q', d, opt_off+24)[0]
            print(f"  image_base={hex(image_base)}")
            # Section table starts after optional header
            sect_table_off = opt_off + oh_size
            for j in range(num_sect):
                so = sect_table_off + j*40
                name = d[so:so+8].rstrip(b'\x00').decode('ascii','replace')
                vaddr = struct.unpack_from('<I', d, so+12)[0]
                vsz   = struct.unpack_from('<I', d, so+8)[0]
                raw_off = struct.unpack_from('<I', d, so+20)[0]
                raw_sz  = struct.unpack_from('<I', d, so+16)[0]
                print(f"  Section '{name}': vaddr={hex(vaddr)} vsz={hex(vsz)} raw_off={hex(0xb8+raw_off)} raw_sz={hex(raw_sz)}")

print()

# ===== 3. Determine the load address (image base) =====
# For UEFI PE32+, the image base in the PE header tells us how the linker computed VAs
# BUT the image may be loaded at a different address at runtime
# Key: the ADRP instruction uses PC-relative paging
# If the binary is loaded at address X, then a string at file offset F has VA = X + F
# (for a flat UEFI image where VAs == file offsets relative to image start)

# Let's try different load bases and see which one yields valid ADRP references
def find_adrp_add(data, target_va, base_va=0):
    """Find ADRP+ADD pairs in data that produce target_va, given code loaded at base_va"""
    results = []
    size = len(data)
    target_page = target_va & ~0xFFF
    target_off  = target_va & 0xFFF

    for i in range(0, size-8, 4):
        insn = struct.unpack_from('<I', data, i)[0]
        # Check ADRP: top bit=1, bit[28]=0, bit[27]=0, bit[26]=1, bit[25]=1, bit[24]=0
        # Actually: bits[31:29]= immlo (2 bits) and bit[28]=1 for ADRP
        # ADRP opcode: bit[31]=1 (immlo[0]), bit[30]=immlo[1], bit[28]=1, bits[27:24]=0000
        # Actually the encoding is: [31]=immlo[0] but opcode field...
        # Let me use the correct mask: (insn & 0x9F000000) == 0x90000000
        if (insn & 0x9F000000) != 0x90000000:
            continue
        # This is an ADRP
        rd = insn & 0x1f
        immlo = (insn >> 29) & 3
        immhi = (insn >> 5) & 0x7FFFF
        raw_imm = (immhi << 2) | immlo
        # Sign extend from bit 20
        if raw_imm & (1 << 20):
            raw_imm -= (1 << 21)
        imm = raw_imm << 12

        # PC as loaded at base_va
        pc_va = base_va + i
        page  = (pc_va & ~0xFFF) + imm

        if page != target_page:
            continue

        # Check next instruction: ADD xRd, xRd, #target_off
        next_insn = struct.unpack_from('<I', data, i+4)[0]
        # ADD (immediate, 64-bit): bits[31:23] = 0b100100010 0 = 0x91 0x00
        # Actually: SF=1, op=0, S=0, opc=00, then shift, imm12
        # Mask: (insn >> 23) == 0b10010001 0 = 0x122 (hmm let's be careful)
        # ADD (immediate): 0x91000000 mask 0xFF800000 -> checks top 9 bits
        # bits[31]=1(64-bit) bits[30:29]=00(ADD) bits[28:24]=10001 -> top 9 = 0b100100010 = 0x122
        if (next_insn >> 23) == 0x122:
            rn = (next_insn >> 5) & 0x1f
            rd2 = next_insn & 0x1f
            shift = (next_insn >> 22) & 1
            imm12 = (next_insn >> 10) & 0xFFF
            if shift:
                imm12 <<= 12
            if rn == rd and imm12 == target_off:
                results.append((i, rd, rd2))
    return results


# ===== Strategy A: Standard ADRP+ADD with base=0 =====
if STR_UNLOCKED >= 0:
    print(f"=== STRATEGY A: ADRP+ADD, base=0 ===")
    print(f"Searching refs to 0x{STR_UNLOCKED:x} (Unlocked string)...")
    refs = find_adrp_add(d, STR_UNLOCKED, base_va=0)
    print(f"  Found {len(refs)}: {[hex(r[0]) for r in refs[:10]]}")

    print(f"Searching refs to 0x{STR_ERROR:x} (ERROR string)...")
    refs = find_adrp_add(d, STR_ERROR, base_va=0)
    print(f"  Found {len(refs)}: {[hex(r[0]) for r in refs[:10]]}")
    print()

# ===== Strategy B: ADRP+LDR (string pointer stored in global, loaded via LDR) =====
def find_adrp_ldr(data, target_va, base_va=0):
    """Find ADRP+LDR pairs that load a pointer which equals target_va"""
    results = []
    size = len(data)
    target_page = target_va & ~0xFFF

    for i in range(0, size-8, 4):
        insn = struct.unpack_from('<I', data, i)[0]
        if (insn & 0x9F000000) != 0x90000000:
            continue
        rd = insn & 0x1f
        immlo = (insn >> 29) & 3
        immhi = (insn >> 5) & 0x7FFFF
        raw_imm = (immhi << 2) | immlo
        if raw_imm & (1 << 20):
            raw_imm -= (1 << 21)
        imm = raw_imm << 12
        pc_va = base_va + i
        page  = (pc_va & ~0xFFF) + imm

        # Check next instruction: LDR xRd, [xRd, #offset]
        next_insn = struct.unpack_from('<I', data, i+4)[0]
        # LDR (immediate, 64-bit): bits[31:22] = 1111100101 = 0x3E5
        if (next_insn >> 22) == 0x3E5:
            rn = (next_insn >> 5) & 0x1f
            rd2 = next_insn & 0x1f
            offset = ((next_insn >> 10) & 0xFFF) * 8  # scaled by 8 for 64-bit
            if rn != rd:
                continue
            # The pointer would be at file offset (page - base_va) + offset
            ptr_file_off = (page - base_va) + offset
            if 0 <= ptr_file_off < size - 8:
                ptr_val = struct.unpack_from('<Q', data, ptr_file_off)[0]
                if ptr_val == target_va or ptr_val == (target_va + base_va):
                    results.append((i, rd, rd2, ptr_file_off, ptr_val))
    return results

if STR_UNLOCKED >= 0:
    print(f"=== STRATEGY B: ADRP+LDR, base=0 ===")
    print(f"Searching LDR refs to 0x{STR_UNLOCKED:x}...")
    refs = find_adrp_ldr(d, STR_UNLOCKED, base_va=0)
    print(f"  Found {len(refs)}: {[hex(r[0]) for r in refs[:10]]}")
    print(f"Searching LDR refs to 0x{STR_ERROR:x}...")
    refs = find_adrp_ldr(d, STR_ERROR, base_va=0)
    print(f"  Found {len(refs)}: {[hex(r[0]) for r in refs[:10]]}")
    print()

# ===== Strategy C: Search for literal address value in a .got or pointer table =====
print("=== STRATEGY C: Pointer scan for string addresses in data ===")
for name, off in [('Unlocked', STR_UNLOCKED), ('ERROR', STR_ERROR), ('VERDIS', STR_VERDIS)]:
    if off < 0: continue
    # Look for the offset value stored as 8-byte LE in the binary
    target_bytes = struct.pack('<Q', off)  # 8-byte addr
    target_bytes4 = struct.pack('<I', off)  # 4-byte addr
    results = []
    pos = 0
    while True:
        pos = d.find(target_bytes, pos)
        if pos < 0: break
        results.append(hex(pos))
        pos += 1
    results4 = []
    pos = 0
    while True:
        pos = d.find(target_bytes4, pos)
        if pos < 0: break
        results4.append(hex(pos))
        pos += 1
    print(f"  '{name}' ({hex(off)}) as 8-byte ptr: {results[:5]}")
    print(f"  '{name}' ({hex(off)}) as 4-byte ptr: {results4[:5]}")

print()

# ===== Strategy D: Check if there are multiple FV files inside the decompressed blob =====
print("=== STRATEGY D: Additional FV signatures inside decompressed blob ===")
fv_sig = b'_FVH'
pos = 0
fv_list = []
while True:
    pos = d.find(fv_sig, pos)
    if pos < 0: break
    # FV header: signature is at offset 40 from FV header start
    fv_start = pos - 40
    if fv_start >= 0:
        fv_list.append(fv_start)
    pos += 1
print(f"  FV headers at: {[hex(x) for x in fv_list[:10]]}")

# Look for more MZ/PE headers
print("  MZ headers at:", end=' ')
pos = 0
mz_list = []
while True:
    pos = d.find(b'MZ', pos)
    if pos < 0: break
    mz_list.append(hex(pos))
    pos += 1
print(mz_list[:20])

print()

# ===== Strategy E: Different load base - try known UEFI ABL addresses =====
# Qualcomm UEFI ABL is typically loaded at 0x9FC00000 or similar
# Let's try load_base = 0x9FC00000 and see if ADRP hits
COMMON_BASES = [0x9FC00000, 0x9FC08000, 0x9FE00000, 0x80000000, 0x40000000, 0x60000000]
if STR_UNLOCKED >= 0:
    print("=== STRATEGY E: Non-zero load bases ===")
    for base in COMMON_BASES:
        target_va = base + STR_UNLOCKED
        refs = find_adrp_add(d, target_va, base_va=base)
        if refs:
            print(f"  base={hex(base)}: ADRP+ADD refs={[hex(r[0]) for r in refs[:5]]}")
        else:
            pass  # print(f"  base={hex(base)}: 0 refs")
    print("  Done checking common bases")
