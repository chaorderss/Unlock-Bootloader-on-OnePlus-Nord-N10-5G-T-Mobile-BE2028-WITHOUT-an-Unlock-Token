#!/usr/bin/env python3
"""Trace RPMB-related code: find functions that reference RPMB strings,
and check if devinfo data is stored/read from RPMB."""

import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

PE = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
with open(PE, "rb") as f:
    pe = f.read()

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

# Find all RPMB string locations
print("=" * 60)
print("  RPMB-related strings in PE")
print("=" * 60)
rpmb_strings = []
pos = 0
while True:
    pos = pe.find(b"RPMB", pos)
    if pos < 0:
        break
    # Get context
    start = max(0, pos - 40)
    end = min(len(pe), pos + 60)
    ctx = pe[start:end]
    # Find the start of the string (look for \x00 or non-printable before)
    str_start = pos
    while str_start > 0 and pe[str_start-1] >= 0x20 and pe[str_start-1] < 0x7f:
        str_start -= 1
    str_end = pos + 4
    while str_end < len(pe) and pe[str_end] >= 0x20 and pe[str_end] < 0x7f:
        str_end += 1
    s = pe[str_start:str_end].decode('ascii', errors='replace')
    rpmb_strings.append((str_start, s))
    print(f"  0x{str_start:05X}: \"{s}\"")
    pos += 4

# Find code that references these strings via ADRP+ADD
print("\n" + "=" * 60)
print("  Finding code references (ADRP+ADD) to RPMB strings")
print("=" * 60)

text_start = 0x1000
text_end = 0x6A000  # .text section

# We need to find ADRP instructions that point to the page containing RPMB strings
# RPMB strings are around 0x5F9D5 and 0x61425-0x6150E
# Pages: 0x5F000 and 0x61000

target_pages = set()
for addr, _ in rpmb_strings:
    page = addr & ~0xFFF
    target_pages.add(page)

print(f"  Target pages: {[hex(p) for p in sorted(target_pages)]}")

# Scan for ADRP instructions that reference these pages
refs = []
code = pe[text_start:text_end]
for ins in md.disasm(code, text_start):
    if ins.mnemonic == "adrp":
        # Extract page target
        ops = ins.op_str
        if "#0x" in ops:
            try:
                page_str = ops.split("#")[1]
                page_val = int(page_str, 16)
                if page_val in target_pages:
                    refs.append(ins.address)
            except:
                pass

print(f"  Found {len(refs)} ADRP references to RPMB string pages")
for ref in refs[:30]:
    print(f"  0x{ref:05X}")

# Now disassemble the functions around these ADRP references
# Group them into function ranges
print("\n" + "=" * 60)
print("  Disassembling RPMB-referencing functions")
print("=" * 60)

def dis_func(start, max_len=0x300, label=""):
    """Disassemble a function starting at start"""
    print(f"\n--- {label} @ 0x{start:X} ---")
    code = pe[start:start+max_len]
    for ins in md.disasm(code, start):
        comment = ""
        mnem = ins.mnemonic
        ops = ins.op_str

        # Check for string references
        if mnem == "add" and "#0x" in ops:
            try:
                parts = ops.split("#")
                if len(parts) >= 2:
                    off_val = int(parts[-1], 16)
                    # ADRP+ADD: page is set by previous ADRP
                    # Just annotate with any known string
                    for saddr, stext in rpmb_strings:
                        if off_val == (saddr & 0xFFF):
                            comment = f'  ; "{stext[:40]}"'
                            break
            except:
                pass

        if "0x18248" in ops: comment = " ; ReadWritePartition"
        elif "0x232d8" in ops.lower(): comment = " ; ReadDeviceInfo"
        elif "0x280fc" in ops.lower(): comment = " ; LogPrint"
        elif "0x28574" in ops: comment = " ; DebugA"
        elif "#0x3d0" in ops: comment = " ; BS ptr"

        print(f"  0x{ins.address:05X}: {mnem:<8} {ops}{comment}")

        if mnem == "ret":
            break

# Find function starts by scanning backward from ADRP refs
seen_funcs = set()
for ref in refs:
    # Scan backward to find function prologue (STP x29, x30 or SUB sp)
    func_start = ref
    for scan in range(ref - 0x200, ref, 4):
        if scan < text_start:
            continue
        insn_bytes = pe[scan:scan+4]
        if len(insn_bytes) < 4:
            continue
        val = struct.unpack_from('<I', insn_bytes, 0)[0]
        # Check for STP x29, x30, [sp, #-xxx]! (common function prologue)
        # Or SUB sp, sp, #xxx
        for check in md.disasm(insn_bytes, scan):
            if check.mnemonic == "sub" and "sp, sp" in check.op_str:
                func_start = scan
            elif check.mnemonic == "stp" and "x29, x30" in check.op_str:
                func_start = scan
            elif check.mnemonic == "stp" and "x19, x30" in check.op_str:
                func_start = scan

    if func_start not in seen_funcs and func_start < ref:
        seen_funcs.add(func_start)
        dis_func(func_start, min(0x400, ref - func_start + 0x200), f"RPMB-ref func")

# Also check: does ReadWritePartition (0x18248) protocol method use RPMB?
# Let me search for any cross-reference from RPMB code to devinfo buffer
print("\n" + "=" * 60)
print("  Searching for devinfo buffer refs in RPMB code")
print("=" * 60)
# devinfo buffer is at 0x1BD978 - page 0x1BD000, offset 0x978
# Check ADRP 0x1BD000 near RPMB references
for ref in refs:
    # Check nearby instructions for ADRP to devinfo page
    for off in range(-0x100, 0x100, 4):
        addr = ref + off
        if addr < text_start or addr >= text_end:
            continue
        insn_bytes = pe[addr:addr+4]
        for check in md.disasm(insn_bytes, addr):
            if check.mnemonic == "adrp" and "0x1bd000" in check.op_str.lower():
                print(f"  ADRP 0x1BD000 at 0x{addr:05X} (near RPMB ref at 0x{ref:05X})")

# Search for ReadWritePartition calls near RPMB code
print("\n  Searching for ReadWritePartition (0x18248) calls near RPMB refs...")
for ref in refs:
    for off in range(-0x200, 0x200, 4):
        addr = ref + off
        if addr < text_start or addr >= text_end:
            continue
        insn_bytes = pe[addr:addr+4]
        for check in md.disasm(insn_bytes, addr):
            if check.mnemonic == "bl" and "0x18248" in check.op_str:
                print(f"  BL 0x18248 at 0x{addr:05X} (near RPMB ref at 0x{ref:05X})")
