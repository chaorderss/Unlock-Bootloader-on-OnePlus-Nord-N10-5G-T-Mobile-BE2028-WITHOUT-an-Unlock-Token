import struct
data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin','rb').read()

# Search for the address 0x61f12 as a little-endian 4-byte or 8-byte value
target_4 = struct.pack('<I', 0x61f12)
target_8 = struct.pack('<Q', 0x61f12)

print("Searching for refs to 0x61f12 in .data section (0x6a000+)...")
for off in range(0x6a000, min(len(data)-8, 0x1c8000)):
    if data[off:off+4] == target_4:
        print(f'  4-byte ref at file offset 0x{off:x}')
    if data[off:off+8] == target_8:
        print(f'  8-byte ref at file offset 0x{off:x}')

print("Searching for refs to 0x61f12 in .text section...")
for off in range(0x1000, 0x6a000-8):
    if data[off:off+4] == target_4:
        print(f'  4-byte in .text at 0x{off:x}: {data[off-4:off+8].hex()}')
    if data[off:off+8] == target_8:
        print(f'  8-byte in .text at 0x{off:x}: {data[off-4:off+8].hex()}')

# Also check: maybe oem get_unlock_code is at a different location
# because the binary was compiled with different section layout
# Let's find ALL occurrences of "oem get_unlock"
needle = b'oem get_unlock'
pos = 0
while True:
    pos = data.find(needle, pos)
    if pos == -1:
        break
    s = data[pos:pos+30]
    printable = ''.join(chr(b) if 32<=b<127 else '.' for b in s)
    print(f'String "oem get_unlock*" at 0x{pos:x}: {repr(printable)}')
    pos += 1
