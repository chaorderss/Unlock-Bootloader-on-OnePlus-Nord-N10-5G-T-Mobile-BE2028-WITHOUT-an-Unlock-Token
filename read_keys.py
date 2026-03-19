#!/usr/bin/env python3
import struct

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin','rb').read()

# Read raw bytes at 0x62400 as strings
print('=== Strings at 0x62400 ===')
off = 0x62400
end = 0x62480
i = off
while i < end:
    s = b''
    while i < end and data[i]:
        s += bytes([data[i]])
        i += 1
    if s:
        printable = ''.join(chr(b) if 32 <= b < 127 else f'\\x{b:02x}' for b in s)
        print(f'  0x{i - len(s):x}: {repr(printable)}')
    i += 1  # skip null

# Look at the 8-byte entries at 0x62488+
print()
print('=== 8-byte ptr entries at 0x62488 ===')
for j in range(20):
    lo = struct.unpack_from('<I', data, 0x62488 + j*8)[0]
    hi = struct.unpack_from('<I', data, 0x6248c + j*8)[0]
    ptr = (hi << 32) | lo
    if ptr:
        print(f'  0x{0x62488+j*8:x}: {ptr:#x}')
    else:
        print(f'  0x{0x62488+j*8:x}: NULL')
        if j > 2:
            break

# Now look at EFI GUID at 0x68b70 and 0x68b80
print()
print('=== EFI GUIDs (HMAC protocol) ===')
guid70 = data[0x68b70:0x68b70+16]
guid80 = data[0x68b80:0x68b80+16]
print(f'  0x68b70: {guid70.hex()}')
print(f'  0x68b80: {guid80.hex()}')

# Try GUID at 0x68b80 as HMAC key
import hmac, hashlib
key = guid80
print(f'  GUID as key: {key.hex()}')

# Print all model HMAC keys
print()
print('=== Per-model keys at 0x62213+ ===')
i = 0x62213
count = 0
while i < 0x62300 and count < 20:
    s = b''
    while data[i] and i < 0x62400:
        s += bytes([data[i]])
        i += 1
    if s:
        printable = ''.join(chr(b) if 32 <= b < 127 else f'\\x{b:02x}' for b in s)
        print(f'  0x{i - len(s):x}: {repr(printable)} ({len(s)} bytes)')
        count += 1
    i += 1

print()
print('=== Looking at 0x62200-0x62400 for model/key pairs ===')
# Read all strings in this region
i = 0x62200
while i < 0x62400:
    s = b''
    start = i
    while i < 0x62400 and data[i]:
        s += bytes([data[i]])
        i += 1
    if s and len(s) >= 3:
        printable = ''.join(chr(b) if 32 <= b < 127 else f'\\x{b:02x}' for b in s)
        print(f'  0x{start:x} [{len(s)}]: {repr(printable[:50])}')
    i += 1
