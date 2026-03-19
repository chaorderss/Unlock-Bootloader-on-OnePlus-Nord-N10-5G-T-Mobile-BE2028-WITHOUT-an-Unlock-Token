import struct

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb').read()

print('=== Encoded strings at 0x62e4c+ ===')
off = 0x62e4c
while off < 0x63100:
    s = b''
    i = off
    while i < off + 80 and data[i]:
        s += bytes([data[i]])
        i += 1
    if s:
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in s)
        print(f'0x{off:x}: {repr(printable[:60])}')
    off = i + 1

print()
print('=== Trying XOR decode with various single-byte keys ===')
encoded = data[0x62e5c:0x62e5c+11]  # jqtxsth%xut
for key in range(256):
    decoded = bytes(b ^ key for b in encoded)
    printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in decoded)
    if all(32 <= b < 128 for b in decoded):
        words = ['flash', 'oem', 'unlock', 'token', 'boot', 'test', 'download', 'erase']
        if any(w in printable.lower() for w in words):
            print(f'  XOR 0x{key:02x}: {repr(printable)}')

# Also try the string "oem get_unlock_code" encoded in the same way
# If we know one plaintext (the unlock code command), we can figure out the cipher
print()
print('=== If 0x62e5c encodes "oem get_unlock" variants ===')
# oem get_unlock_code = 0x6f 0x65 0x6d 0x20 0x67 0x65 0x74 0x5f 0x75 0x6e 0x6c
target = b'oem get_un'  # 10 chars
enc = data[0x62e5c:0x62e5c+10]
xor_keys = [a ^ b for a, b in zip(enc, target)]
print(f'  XOR keys if plaintext="oem get_un": {[hex(k) for k in xor_keys]}')

# Try with "flash token"
target2 = b'flash token'  # 11 chars
xor_keys2 = [a ^ b for a, b in zip(enc[:10], target2[:10])]
print(f'  XOR keys if plaintext="flash token": {[hex(k) for k in xor_keys2]}')

# Check: does the "xut" suffix decode to something standard?
# If "xut" ends the command, what are common command endings?
# "oken" = "flash token"
# "de" = "oem get_unlock_code"
suffix_enc = data[0x62e68:0x62e68+4]  # sz%x from jqtxsthsz%xut
print(f'\nThe "sz" insertion bytes: {[hex(b) for b in suffix_enc[:2]]}')
# This inserts "sz" before "%xut" - in clear text this might be "_raw" before some suffix
