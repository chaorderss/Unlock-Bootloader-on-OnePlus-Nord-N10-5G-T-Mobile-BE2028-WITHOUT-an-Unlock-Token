#!/usr/bin/env python3
import struct
import binascii

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin','rb').read()

print("=== String at file 0x61854 (referenced by CmdCustUnlockFlash) ===")
s = data[0x61854:0x61894]
null_pos = s.find(b'\x00')
if null_pos >= 0:
    s = s[:null_pos]
print(f"  ASCII: {s}")

print("\n=== Strings near file 0x61800-0x61920 ===")
i = 0x61800
while i < 0x61920:
    if 0x20 <= data[i] < 0x7f:
        j = i
        while j < 0x61940 and 0x20 <= data[j] < 0x7f:
            j += 1
        if j - i >= 4:
            print(f"  0x{i:x}: {data[i:j]}")
        i = j + 1
    else:
        i += 1

print("\n=== Single-char entries in dispatch table (0x685a0+) ===")
for off in range(0x685a0, 0x68690, 16):
    str_ptr = struct.unpack_from('<Q', data, off)[0]
    fn_ptr = struct.unpack_from('<Q', data, off+8)[0]
    if 0x1000 <= str_ptr < 0x6a000:
        raw = data[str_ptr:str_ptr+10]
        print(f"  0x{off:x}: str_ptr=0x{str_ptr:x} raw={binascii.hexlify(raw)}")

print("\n=== First 30 bytes of function at disasm 0x289b4 (file 0x2a9b4) ===")
chunk = data[0x2a9b4:0x2a9b4+30]
print(f"  {binascii.hexlify(chunk)}")

print("\n=== Check strings in flash handler region (disasm 0x48-4a range = file 0x49-4b) ===")
# Look for strings that appear in the flash handler function at disasm 0x48bf8-0x491c8
i = 0x481f8  # file start: disasm 0x48bf8 - a bit before, but let's check the string data area
i = 0x59000  # search .text string area
while i < 0x5a000:
    if 0x20 <= data[i] < 0x7f:
        j = i
        while j < 0x5b000 and 0x20 <= data[j] < 0x7f:
            j += 1
        if j - i >= 5:
            print(f"  file 0x{i:x}: {data[i:j]}")
        i = j + 1
    else:
        i += 1
