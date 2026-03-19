#!/usr/bin/env python3
"""
Analyze the control flow around 'Please flash unlock token first'
in the Global ABL to see if token check is mandatory or conditional.
"""
import struct

FILEPATH = "global_abl_decompressed.bin"

with open(FILEPATH, 'rb') as f:
    data = f.read()

# --- Step 1: find the token error string ---
token_str = b"Please flash unlock token first"
token_off = data.find(token_str)
print(f"[1] 'Please flash unlock token first' @ file 0x{token_off:X}")

# --- Step 2: The string pointer must appear in an ADR/ADRP+ADD or LDR sequence.
#     For AArch32 Thumb2 code: typical pattern is
#       LDR Rn, =addr    (or MOVW+MOVT)
#     Search 4 bytes before/after for the string VA reference.
#     We need to know the load VA for the string.
#     From previous analysis, VA base offset is typically 0x97c0 - file 0x0 differences.
#     Let's try to find VA from ELF segments.

# Parse ELF32 header
e_phoff = struct.unpack_from('<I', data, 0x1C)[0]
e_phnum = struct.unpack_from('<H', data, 0x2C)[0]
e_phentsize = struct.unpack_from('<H', data, 0x2A)[0]

print(f"\n[2] ELF32 program headers: phoff=0x{e_phoff:X} phnum={e_phnum}")

segments = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type   = struct.unpack_from('<I', data, off)[0]
    p_offset = struct.unpack_from('<I', data, off+4)[0]
    p_vaddr  = struct.unpack_from('<I', data, off+8)[0]
    p_filesz = struct.unpack_from('<I', data, off+16)[0]
    segments.append((p_type, p_offset, p_vaddr, p_filesz))
    print(f"   seg[{i}]: type=0x{p_type:X} file_off=0x{p_offset:X} vaddr=0x{p_vaddr:X} filesz=0x{p_filesz:X}")

# For PT_LOAD (type 1), find which segment contains our string offset
def file_to_va(file_offset):
    for p_type, p_offset, p_vaddr, p_filesz in segments:
        if p_type == 1:  # PT_LOAD
            if p_offset <= file_offset < p_offset + p_filesz:
                return p_vaddr + (file_offset - p_offset)
    return None

token_va = file_to_va(token_off)
print(f"\n[3] Token string VA = 0x{token_va:08X}" if token_va else "\n[3] Could not determine VA")

# --- Step 3: Search for references to token_va in the code ---
# In Thumb2: LDR Rn, [PC, #offset] where the pool entry = token_va
# Also MOVW+MOVT pair
if token_va:
    token_va_le = struct.pack('<I', token_va)
    print(f"\n[4] Searching for refs to token VA 0x{token_va:08X} ({token_va_le.hex()})...")
    refs = []
    pos = 0
    while True:
        idx = data.find(token_va_le, pos)
        if idx == -1:
            break
        refs.append(idx)
        pos = idx + 1
    print(f"    Found {len(refs)} references: {[hex(x) for x in refs[:10]]}")

    # For each ref, dump surrounding code (Thumb2 instructions are 2 or 4 bytes)
    for ref_off in refs[:3]:
        ref_va = file_to_va(ref_off)
        print(f"\n  === Reference @ file 0x{ref_off:X} (VA 0x{ref_va or 0:08X}) ===")
        # Dump 64 bytes before this (the caller code)
        start = max(0, ref_off - 64)
        end = ref_off + 32
        chunk = data[start:end]
        for i in range(0, len(chunk), 4):
            addr = start + i
            va = file_to_va(addr)
            raw = chunk[i:i+4]
            w32 = struct.unpack_from('<I', raw)[0] if len(raw) == 4 else 0
            marker = " <-- TOKEN VA" if addr >= ref_off and addr < ref_off + 4 else ""
            print(f"    file 0x{addr:06X} VA 0x{va or 0:08X}: {raw.hex():8s} 0x{w32:08X}{marker}")

# --- Step 4: Also look for the fastboot 'flashing unlock' handler to understand the full flow ---
fl_str = b"flashing unlock"
fl_off = data.find(fl_str)
if fl_off != -1:
    fl_va = file_to_va(fl_off)
    print(f"\n[5] 'flashing unlock' string @ file 0x{fl_off:X} VA 0x{fl_va or 0:08X}")

# --- Step 5: show all token-related strings ---
print("\n[6] All token-related strings in global ABL:")
for s in [b"token", b"unlock token", b"Token", b"CmdToken", b"op_token"]:
    pos = 0
    while True:
        idx = data.find(s, pos)
        if idx == -1:
            break
        snippet = data[idx:idx+80]
        printable = ''.join(chr(b) if 32<=b<127 else '.' for b in snippet)
        va = file_to_va(idx)
        print(f"  0x{idx:X} (VA 0x{va or 0:08X}): {printable[:60]}")
        pos = idx + len(s)
        if pos - idx > 10000:
            break
