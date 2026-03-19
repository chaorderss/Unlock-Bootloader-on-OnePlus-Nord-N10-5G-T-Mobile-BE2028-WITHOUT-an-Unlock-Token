#!/usr/bin/env python3
data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb').read()

# Dump raw bytes at 0x68340-0x68370
print('Raw bytes at 0x68340:')
for off in range(0x68340, 0x68370, 16):
    hex_str = data[off:off+16].hex()
    ascii_str = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in data[off:off+16])
    print(f'  0x{off:05X}: {hex_str}  {ascii_str}')

# UTF-16 decode
s16 = data[0x68342:0x68360]
try:
    decoded = s16.decode('utf-16-le')
    end = decoded.find(chr(0))
    if end > 0: decoded = decoded[:end]
    print(f'UTF-16LE at 0x68342: "{decoded}"')
except:
    print('Not valid UTF-16')

# Search for frp in various encodings
for term, label in [(b'f\x00r\x00p\x00', 'UTF-16 frp'), (b'frp\x00', 'ASCII frp')]:
    idx = 0
    count = 0
    while count < 20:
        idx = data.find(term, idx)
        if idx < 0: break
        print(f'{label} at 0x{idx:05X}')
        count += 1
        idx += 1

# Search for "FRP" uppercase too
for term, label in [(b'F\x00R\x00P\x00', 'UTF-16 FRP'), (b'FRP\x00', 'ASCII FRP')]:
    idx = 0
    count = 0
    while count < 20:
        idx = data.find(term, idx)
        if idx < 0: break
        print(f'{label} at 0x{idx:05X}')
        count += 1
        idx += 1

# Check what string the ABL log references
# "Error Reading FRP partition" was at 0x66DE7
s = data[0x66DD2:0x66E20]
print(f'\nStrings near FRP error:')
pos = 0
while pos < len(s):
    if s[pos] == 0:
        pos += 1
        continue
    end = s.find(0, pos)
    if end < 0: break
    try:
        print(f'  +{pos}: "{s[pos:end].decode("ascii")}"')
    except:
        pass
    pos = end + 1
