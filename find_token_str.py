#!/usr/bin/env python3
import struct
import binascii

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin','rb').read()

# Search for "token" in UTF-16LE (74 00 6f 00 6b 00 65 00 6e 00)
token_utf16 = b'\x74\x00\x6f\x00\x6b\x00\x65\x00\x6e\x00'
print("=== Search for 'token' (UTF-16LE) ===")
pos = 0
while True:
    pos = data.find(token_utf16, pos)
    if pos == -1:
        break
    context = data[pos:pos+30]
    print(f"  file 0x{pos:x}: {binascii.hexlify(context)}")
    pos += 1

# Also search for "token" followed by null (as full UTF-16LE string)
print()
print("=== Search for 'token' in ASCII near strings area ===")
for match_str in [b'token', b'Token', b'TOKEN']:
    pos = 0
    while True:
        pos = data.find(match_str, pos)
        if pos == -1:
            break
        context = data[pos:pos+40]
        null_pos = context.find(b'\x00')
        if null_pos >= 0:
            ctx_str = context[:null_pos]
        else:
            ctx_str = context[:20]
        print(f"  file 0x{pos:x}: {context[:25]}")
        pos += 1

# Check function at disasm 0x4cbc8 (file 0x4dbc8) - what does it load?
print()
print("=== Disasm lines near 0x4cbc8 (function called before CmdCustUnlockFlash) ===")
import subprocess
result = subprocess.run(['grep', '-n', '^   4cb[c-f]\|^   4cc[0-3]', '/tmp/linuxloader_disasm.txt'],
                       capture_output=True, text=True)
print(result.stdout[:3000])

# Also check what's AT file 0x61854 (the string argument to CmdCustUnlockFlash)
# The ADRP goes to page 0x60000 (disasm) = page 0x61000 (file), add #0x854 = file 0x61854
# But wait: adrp x1, 0x60000 means page = 0x60000 (disasm page address)
# At runtime: page = disasm_page + 0x1000 = 0x61000
# Then add #0x854 -> 0x61854
print()
print("=== File 0x61854 (should be the display string for CmdCustUnlockFlash) ===")
chunk = data[0x61840:0x61880]
print(f"  hex: {binascii.hexlify(chunk)}")
i = 0x61840
while i < 0x61880:
    if 0x20 <= data[i] < 0x7f:
        j = i
        while j < 0x61890 and 0x20 <= data[j] < 0x7f:
            j += 1
        if j - i >= 3:
            print(f"  0x{i:x}: {data[i:j]}")
        i = j + 1
    else:
        i += 1
