#!/usr/bin/env python3
import struct
import binascii

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin','rb').read()

# Model 20888 (billie8t) key entry at file 0x626f0
# Structure (88 bytes, 8-byte fields):
#   offset 0:  model number (0x5198 = 20888)
#   offset 8:  pointer to string1 (key segment 1)
#   offset 16: pointer to string2
#   offset 24: pointer to string3
#   offset 32: pointer to string4
#   offset 40: pointer to string5
#   offset 48: pointer to string6
#   offset 56: pointer to SMEM/data-section value
#   offset 64: model index (7 for 20888, checked != 9)
#   offset 72: pointer to another string
#   offset 80: pointer to model+codename string

print("=== Key entry for model 20888 (index 7) at file 0x626f0 ===")
entry_off = 0x626f0
entry = data[entry_off:entry_off+88]
print(f"Full hex: {binascii.hexlify(entry)}")

# Parse all 8-byte fields
for i in range(11):
    val = struct.unpack_from('<Q', entry, i*8)[0]
    if i == 0:
        print(f"  [0]: model_num = {val} (0x{val:x})")
    elif i == 7:
        print(f"  [56]: data_ptr = 0x{val:x} (SMEM or .data section address)")
    elif i == 8:
        val32 = struct.unpack_from('<I', entry, i*8)[0]
        print(f"  [64]: model_index = {val32}")
    elif i == 9:
        if 0x1000 <= val < len(data):
            s = data[val:val+50]
            null_pos = s.find(b'\x00')
            if null_pos >= 0: s = s[:null_pos]
            print(f"  [72]: string_ptr = 0x{val:x} -> '{s.decode('ascii', errors='replace')}'")
    elif i == 10:
        if 0x1000 <= val < len(data):
            s = data[val:val+30]
            null_pos = s.find(b'\x00')
            if null_pos >= 0: s = s[:null_pos]
            print(f"  [80]: model_str_ptr = 0x{val:x} -> '{s.decode('ascii', errors='replace')}'")
    else:
        ptr = val
        if 0x1000 <= ptr < len(data):
            s = data[ptr:ptr+50]
            null_pos = s.find(b'\x00')
            if null_pos >= 0: s = s[:null_pos]
            if all(0x20 <= b < 0x7f for b in s) and len(s) > 0:
                print(f"  [{i*8}]: str_ptr = 0x{ptr:x} -> '{s.decode()}'")
            else:
                print(f"  [{i*8}]: str_ptr = 0x{ptr:x} -> HEX:{binascii.hexlify(data[ptr:ptr+20])}")
        else:
            print(f"  [{i*8}]: unknown ptr = 0x{ptr:x}")

print()
print("=== Key strings comparison across models ===")
for model_idx in range(9):
    eo = 0x62488 + model_idx * 88
    m_num = struct.unpack_from('<Q', data, eo)[0]
    ptrs = [struct.unpack_from('<Q', data, eo + 8 + i*8)[0] for i in range(6)]
    strings = []
    for ptr in ptrs:
        if 0x1000 <= ptr < len(data):
            s = data[ptr:ptr+30]
            null_pos = s.find(b'\x00')
            if null_pos >= 0: s = s[:null_pos]
            strings.append(s.decode('ascii', errors='replace') if all(0x20 <= b < 0x7f for b in s) else f'HEX:{binascii.hexlify(s[:8]).decode()}')
        else:
            strings.append(f'ptr=0x{ptr:x}')
    print(f"  Model {m_num}: [{', '.join(repr(s) for s in strings)}]")

print()
print("=== String at file 0x061904 (from entry byte 72) ===")
s = data[0x61904:0x61904+50]
null_pos = s.find(b'\x00')
if null_pos >= 0: s = s[:null_pos]
print(f"  '{s.decode('ascii', errors='replace')}'")
print(f"  hex: {binascii.hexlify(data[0x61904:0x61920])}")
