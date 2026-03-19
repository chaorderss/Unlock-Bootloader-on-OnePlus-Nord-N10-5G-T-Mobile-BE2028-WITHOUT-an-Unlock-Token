#!/usr/bin/env python3
import struct, base64

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin','rb').read()

# Decode the per-model key structure
# Each model: model_number (5 bytes) + 6 key parts (17+19+16+7+6+19 = 84 chars each)
# Let's confirm and decode

print('=== Per-model 84-char key structure ===')
# Model 18831 at 0x62213
parts_18831 = ['ZWIxYjNhNjYzZjc0M', 'MTcwOTM5MzkxZTg1OWM', 'ZDhlMjE4MDlmNWVm', 'ZjZiZmI', 'YjA2MG', 'Y2YzNDE2MzZjN2MyNDF']
key_18831 = ''.join(parts_18831)
print(f'Model 18831 key (84 chars): {key_18831}')
try:
    # Add padding
    padded = key_18831 + '=' * (-len(key_18831) % 4)
    decoded = base64.b64decode(padded)
    print(f'  Base64 decoded: {decoded.hex()}')
    print(f'  As ASCII: {decoded}')
except Exception as e:
    print(f'  Base64 error: {e}')

# Model 20809 at 0x62393
parts_20809 = ['EGhei1thee2ohquai', 'quoof5peo2laedequai', 'quee6Eis8eigenoo', 'Oang4ah', 'Siech3', 'chah8hah9ahm1Ditie5']
key_20809 = ''.join(parts_20809)
print(f'Model 20809 key (84 chars): {key_20809}')

# Check the string at 0x62200 (before model entries)
print(f'\nPre-model string at 0x62200: d48r4e5Td4fGTSAdf4')

# Look at ALL strings from 0x62480 to 0x62e5c
print()
print('=== All strings from 0x62480 to 0x62e5c ===')
i = 0x62480
while i < 0x62e5c:
    s = b''
    start = i
    while i < 0x62e5c and data[i]:
        s += bytes([data[i]])
        i += 1
    if s and len(s) >= 2:
        printable = ''.join(chr(b) if 32 <= b < 127 else f'\\x{b:02x}' for b in s)
        print(f'  0x{start:x} [{len(s)}]: {repr(printable[:60])}')
    i += 1  # skip null

# Also print EFI area around 0x68b00 to truly find the HMAC GUIDs
print()
print('=== Data at 0x68b00 - 0x68c00 (GUID area) ===')
i = 0x68b00
while i < 0x68c00:
    s = b''
    start = i
    while i < 0x68c00 and data[i]:
        s += bytes([data[i]])
        i += 1
    if s and len(s) >= 3:
        printable = ''.join(chr(b) if 32 <= b < 127 else f'\\x{b:02x}' for b in s)
        print(f'  0x{start:x} [{len(s)}]: {repr(printable[:60])}')
    i += 1

# Print raw hex of 0x68b60 to 0x68bc0
print()
print('=== Raw hex 0x68b60 - 0x68bc0 ===')
for j in range(0, 0x60, 16):
    row = data[0x68b60+j:0x68b60+j+16]
    hex_str = ' '.join(f'{b:02x}' for b in row)
    ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row)
    print(f'  {0x68b60+j:x}: {hex_str}  {ascii_str}')
