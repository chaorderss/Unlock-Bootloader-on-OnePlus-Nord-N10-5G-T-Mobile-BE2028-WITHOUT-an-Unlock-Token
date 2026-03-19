#!/usr/bin/env python3
"""
Use capstone to find all ADRP instructions targeting page 0x591000 (where AVB strings are),
then decode the ADD/LDR following each, and show surrounding code context.
"""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

with open('/Users/xmxx/pinganhuijia/tmobile_abl_decompressed.bin','rb') as f:
    d = bytearray(f.read())

DELTA   = 0xb8  # raw_off - vaddr, so VA = file_offset - DELTA
TEXT_RAW_START = 0x10b8
TEXT_RAW_END   = 0x740b8

# String VAs (file_off - DELTA)
STR_UNLOCKED_VA = 0x592b0 - DELTA   # = 0x591f8
STR_ERROR_VA    = 0x592e4 - DELTA   # = 0x5922c
STR_VERDIS_VA   = 0x5a7b9 - DELTA   # = 0x5a701

print(f"Target string VAs: Unlocked={hex(STR_UNLOCKED_VA)}, ERROR={hex(STR_ERROR_VA)}, VERDIS={hex(STR_VERDIS_VA)}")
target_pages = {STR_UNLOCKED_VA & ~0xFFF, STR_ERROR_VA & ~0xFFF, STR_VERDIS_VA & ~0xFFF}
print(f"Target pages: {[hex(p) for p in sorted(target_pages)]}")

# Step 1: collect all ADRP targets in text section to understand distribution
page_counts = {}
for i in range(TEXT_RAW_START, TEXT_RAW_END-4, 4):
    insn = struct.unpack_from('<I', d, i)[0]
    if (insn & 0x9F000000) != 0x90000000:
        continue
    immlo = (insn >> 29) & 3
    immhi = (insn >> 5) & 0x7FFFF
    raw   = (immhi << 2) | immlo
    if raw & (1 << 20): raw -= (1 << 21)
    pc_va = i - DELTA
    page  = (pc_va & ~0xFFF) + (raw << 12)
    page_counts[page] = page_counts.get(page, 0) + 1

print(f"\nTotal distinct ADRP target pages in .text: {len(page_counts)}")

# Are our target pages in there?
for pg in sorted(target_pages):
    print(f"  Page {hex(pg)}: {page_counts.get(pg, 0)} ADRP hits")

# Show most common pages (sanity check)
top10 = sorted(page_counts.items(), key=lambda x: -x[1])[:20]
print("\nTop 20 ADRP target pages (should see data-section addresses):")
for pg, c in top10:
    print(f"  {hex(pg)}: {c} times")

print()

# Step 2: if target pages have 0 hits, let's scan ALL ADRP targets and find pages
# closest to 0x591000/0x5a000
sorted_pages = sorted(page_counts.keys())
idx591 = min(range(len(sorted_pages)), key=lambda i: abs(sorted_pages[i] - 0x591000))
print("Pages closest to 0x591000:")
for i in range(max(0,idx591-5), min(len(sorted_pages), idx591+5)):
    print(f"  {hex(sorted_pages[i])}: {page_counts[sorted_pages[i]]} refs")

idx5a = min(range(len(sorted_pages)), key=lambda i: abs(sorted_pages[i] - 0x5a000))
print("\nPages closest to 0x5a000:")
for i in range(max(0,idx5a-5), min(len(sorted_pages), idx5a+5)):
    print(f"  {hex(sorted_pages[i])}: {page_counts[sorted_pages[i]]} refs")

print()

# Step 3: Capstone disassembly - find all ADRP instructions, show decoded instruction
# The capstone base address should match what code thinks its VA is when running
# For UEFI, the image is loaded at image_base (0 in this case), but code uses the
# page-relative addressing so it works at any load address as long as we use consistent VA

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

# Disassemble entire text section and collect ADRP info
print("=== Capstone: scanning ADRP instructions near string pages ===")
code_bytes = bytes(d[TEXT_RAW_START:TEXT_RAW_END])
BASE_VA = TEXT_RAW_START - DELTA  # = 0x1000

hits = []
# Let's scan with capstone to see what target pages show up
for insn in md.disasm(code_bytes, BASE_VA):
    if insn.mnemonic.lower() != 'adrp':
        continue
    # insn.operands[1].imm is the target page address
    # (capstone computes it correctly given the pc)
    if hasattr(insn, 'operands') and len(insn.operands) >= 2:
        target_page = insn.operands[1].imm
        file_off = insn.address + DELTA
        if target_page in target_pages:
            hits.append((insn.address, file_off, insn, target_page))

print(f"Capstone ADRP hits for target pages: {len(hits)}")
for va, fo, insn, pg in hits[:20]:
    print(f"  VA {hex(va)} (file {hex(fo)}): {insn.mnemonic} {insn.op_str} [page {hex(pg)}]")
