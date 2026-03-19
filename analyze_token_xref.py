#!/usr/bin/env python3
"""
For a UEFI firmware dump (no ELF header/ptype mapping),
find xrefs to the token-required string and dump surrounding bytes
so we can understand whether the check is conditional.
"""
import struct

with open("global_abl_decompressed.bin", 'rb') as f:
    data = f.read()

print(f"=== Global ABL UEFI dump, size=0x{len(data):X} ===\n")

# Step 1: key strings and their offsets
strings = {
    "token_required_msg":   b"Please flash unlock token first",
    "oem_enable_first_msg": b"Please enable OEM unlocking in Settings first",
    "op_token_count":       b"op_token_count: %d",
    "CmdTokenFlash":        b"CmdTokenFlash",
    "flashing_unlock":      b"flashing unlock",
    "device_unlocked":      b"Device unlocked",
    "unlock_critical":      b"unlock_critical",
    "is_unlock_allowed":    b"is_unlock_allowed",
    "get_unlock_ability":   b"get_unlock_ability",
    "unlock_permitted":     b"unlock_permitted",
    "token_count":          b"token_count",
}

offsets = {}
for name, pat in strings.items():
    pos = data.find(pat)
    if pos != -1:
        offsets[name] = pos
        print(f"  {name:30s} @ 0x{pos:06X}")
    else:
        print(f"  {name:30s}   NOT FOUND")

print()

# Step 2: Search for the 4-byte LE encoding of the string offsets.
# In a UEFI binary the string is referenced by its absolute address.
# Since this is a stripped decompressed blob with no header, the "base address"
# is typically 0x0 or some load address. Let's just look for 4-byte values
# near the string offsets — they might appear as pool offsets.
# Also search for the ARM Thumb2 pattern: LDR Rn, [PC, #+offset]
# The pool will have the string VA.

token_off = offsets.get("token_required_msg")
if token_off:
    # Look for 4-byte LE encoding of the file offset (works if base=0)
    encoded = struct.pack('<I', token_off)
    print(f"\n[xref search] Token string offset as LE32 = {encoded.hex()}")
    refs = []
    p = 0
    while True:
        idx = data.find(encoded, p)
        if idx == -1:
            break
        refs.append(idx)
        p = idx + 1
    print(f"  Found {len(refs)} numeric refs: {[hex(x) for x in refs]}")

    # Dump 80 bytes before each numeric ref (likely the calling code)
    for ref in refs[:4]:
        print(f"\n  === Code dump around ref @ 0x{ref:06X} ===")
        start = max(0, ref - 96)
        end = min(len(data), ref + 48)
        chunk = data[start:end]
        for i in range(0, len(chunk), 4):
            addr = start + i
            b4 = chunk[i:i+4]
            w = struct.unpack_from('<I', b4)[0] if len(b4)==4 else 0
            marker = "  <-- XREF (token string ptr)" if addr == ref else ""
            print(f"    0x{addr:06X}  {b4.hex():8s}  0x{w:08X}{marker}")

# Step 3: Look for if the code around CmdTokenFlash shows a check on op_token_count
cmdtf_off = offsets.get("CmdTokenFlash")
if cmdtf_off:
    encoded_cmdtf = struct.pack('<I', cmdtf_off)
    refs2 = []
    p = 0
    while True:
        idx = data.find(encoded_cmdtf, p)
        if idx == -1:
            break
        refs2.append(idx)
        p = idx + 1
    print(f"\n[xref CmdTokenFlash @ 0x{cmdtf_off:X}] refs: {[hex(x) for x in refs2[:5]]}")

# Step 4: Try to find strings that appear only in no-token-required path
# On some global builds, fastboot unlock simply calls ui_print("Device will be unlocked")
# without a token branch. Look for adjacent strings.
print("\n[Step 4] Context around 'flashing unlock' string:")
fl_off = offsets.get("flashing_unlock")
if fl_off:
    start = max(0, fl_off - 16)
    end = min(len(data), fl_off + 200)
    segment = data[start:end]
    printable = ''.join(chr(b) if 32<=b<127 else '.' for b in segment)
    print(f"  Raw bytes from 0x{start:X}:")
    for i in range(0, len(segment), 80):
        print(f"    {printable[i:i+80]}")

# Step 5: Check what comes right after "Please flash unlock token first" in data
# If it's followed by other strings it's a rodata section, and we can infer
# the sequence of checks from the string table order
print("\n[Step 5] Strings near token_required_msg in rodata:")
ctx_start = max(0, token_off - 200)
ctx_end = min(len(data), token_off + 500)
ctx = data[ctx_start:ctx_end]
printable = ''.join(chr(b) if 32<=b<127 else '.' for b in ctx)
for i in range(0, len(printable), 100):
    print(f"  0x{ctx_start+i:06X}: {printable[i:i+100]}")
