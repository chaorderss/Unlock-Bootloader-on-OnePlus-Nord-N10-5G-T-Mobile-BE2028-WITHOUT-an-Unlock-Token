#!/usr/bin/env python3
import struct
import binascii

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin','rb').read()

# Known: function pointer to flash handler at file 0x68458 = 0x49bf8
# The dispatch table entry before it has string "flash:" at file 0x66b7d
# Now let's expand the table and also find what strings are near 0x681fa

print("=== Full dispatch table (16-byte entries: str_ptr, fn_ptr) ===")
offset = 0x68440  # Start from where we saw the functions
for i in range(40):
    off = offset + i * 16
    if off + 16 > len(data):
        break
    str_ptr = struct.unpack_from('<Q', data, off)[0]
    fn_ptr = struct.unpack_from('<Q', data, off+8)[0]
    if str_ptr == 0 and fn_ptr == 0:
        print(f"  0x{off:x}: [null entry - possible end]")
        break

    sval = '?'
    if 0x1000 <= str_ptr < 0x6a000:
        s = data[str_ptr:str_ptr+50]
        null_pos = s.find(b'\x00')
        if null_pos >= 0:
            s = s[:null_pos]
        if all(0x20 <= b < 0x7f for b in s) and len(s) > 0:
            sval = f'"{s.decode()}"'
        else:
            sval = f'(binary at file 0x{str_ptr:x})'
    elif str_ptr == 0:
        sval = '<null>'
    else:
        sval = f'0x{str_ptr:x}'

    fn_info = '?'
    if 0x1000 <= fn_ptr < 0x6a000:
        fn_info = f'disasm 0x{fn_ptr-0x1000:x}'
    elif fn_ptr == 0:
        fn_info = '<null>'
    else:
        fn_info = f'0x{fn_ptr:x}'

    marker = ' <<<' if fn_ptr == 0x49bf8 else ''
    print(f"  0x{off:x}: str={sval}  handler={fn_info}{marker}")

print()
print("=== Check partition names referenced in flash handler body ===")
# Look at file 0x681fa (disasm 0x671fa, the string loaded in 0x48d74-0x48d78)
# Also file 0x68218 (disasm 0x67218, the string loaded in 0x48d90)
for disasm_addr, desc in [
    (0x671fa, "string at adrp x1, 0x67000; add #0x1fa"),
    (0x67218, "string at adrp x1, 0x67000; add #0x218"),
]:
    file_off = disasm_addr + 0x1000
    chunk = data[file_off:file_off+30]
    print(f"\n  {desc}")
    print(f"  file 0x{file_off:x}: hex = {binascii.hexlify(chunk[:20]).decode()}")
    # Try ASCII
    null_pos = chunk.find(b'\x00')
    ascii_str = chunk[:null_pos] if null_pos >= 0 else chunk[:20]
    if all(0x20 <= b < 0x7f for b in ascii_str):
        print(f"  ASCII: '{ascii_str.decode()}'")
    # Try UTF-16LE
    utf_str = ''
    for j in range(0, len(chunk)-1, 2):
        c = struct.unpack_from('<H', chunk, j)[0]
        if c == 0:
            break
        if 0x20 <= c <= 0x7e:
            utf_str += chr(c)
        else:
            utf_str += '?'
    print(f"  UTF16-LE: '{utf_str}'")

print()
print("=== Search for 'token' string (ASCII) in binary ===")
for i in range(len(data) - 5):
    if data[i:i+5] == b'token':
        context = data[i:i+20]
        print(f"  file 0x{i:x}: {context}")

print()
print("=== Search for 'unlock_token' string ===")
for i in range(len(data) - 12):
    if data[i:i+12] == b'unlock_token':
        print(f"  file 0x{i:x}: {data[i:i+25]}")
