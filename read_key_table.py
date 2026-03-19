#!/usr/bin/env python3
import struct
import binascii

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin','rb').read()

# Per-model key table at file 0x62488, stride=88 bytes per entry
KEY_TABLE_BASE = 0x62488
STRIDE = 88  # 0x58

# Model mapping:
model_check_addrs = [
    (0x62213, "18831"),   # x8=0 (from per-model table at 0x62213)
    (0x62273, "19861"),   # x8=1
    (0x622d3, "19863"),   # x8=2
    (0x62333, "19855"),   # x8=3
    (0x62393, "20809"),   # x8=4
    (0x5f53b, "billie8"), # x8=5 (adrp 0x5e000+0xb26=0x5eb26? NO: 0x5e000+0x53b)
    (0x5fb26, "?"),       # x8=6 (adrp 0x5e000+0xb26)
    (0x5f524, "20888"),   # x8=7 (adrp 0x5e000+0x524)
    (0x5fb2c, "?"),       # x8=8 (adrp 0x5e000+0xb2c)
]

print("=== Per-model key table entries (88 bytes each at file 0x62488) ===")
for i, (check_addr, model) in enumerate(model_check_addrs):
    entry_off = KEY_TABLE_BASE + i * STRIDE
    entry = data[entry_off:entry_off+STRIDE]
    # Read the check_addr string to confirm model
    s = data[check_addr:check_addr+20]
    null_pos = s.find(b'\x00')
    if null_pos >= 0: s = s[:null_pos]

    # Key entry field at offset 64 (compared to 9)
    field_64 = struct.unpack_from('<I', entry, 64)[0]

    print(f"\n  Model index {i} = '{s.decode('ascii', errors='replace')}' (check at file 0x{check_addr:x})")
    print(f"  Key entry at file 0x{entry_off:x}, field[64]=0x{field_64:x}")
    print(f"  Entry hex: {binascii.hexlify(entry)}")
    # Try to find ASCII strings in entry
    j = 0
    while j < STRIDE:
        if 0x20 <= entry[j] < 0x7f:
            k = j
            while k < STRIDE and 0x20 <= entry[k] < 0x7f:
                k += 1
            if k - j >= 4:
                print(f"  ASCII[{j}:{k}]: {entry[j:k]}")
            j = k + 1
        else:
            j += 1

print()
print("=== Strings used in token HMAC input (from 0x36d38 function) ===")
# adrp x1, 0x61000; add +0x7ba → runtime 0x62000 + 0x7ba = file 0x627ba
# adrp x1, 0x61000; add +0x7a0 → runtime 0x62000 + 0x7a0 = file 0x627a0
for disasm_base, offset, desc in [
    (0x61000, 0x7ba, "9-byte string for HMAC input (at 36da0)"),
    (0x61000, 0x7a0, "26-byte string for HMAC input (at 36dbc)"),
]:
    runtime_addr = (disasm_base + 0x1000) + offset
    file_off = runtime_addr  # since all delta=0 for sections
    chunk = data[file_off:file_off+30]
    null_pos = chunk.find(b'\x00')
    if null_pos >= 0: display = chunk[:null_pos]
    else: display = chunk[:20]
    print(f"\n  {desc}")
    print(f"  file 0x{file_off:x}: {binascii.hexlify(chunk[:20])}")
    if all(0x20 <= b < 0x7f for b in display):
        print(f"  ASCII: '{display.decode()}'")

print()
print("=== String at file 0x61862 (partition name for cust-unlock in 0x36d38) ===")
chunk = data[0x61862:0x61882]
print(f"  hex: {binascii.hexlify(chunk)}")
# Try UTF-16LE
utf_str = ''
for j in range(0, len(chunk)-1, 2):
    c = struct.unpack_from('<H', chunk, j)[0]
    if c == 0: break
    if 0x20 <= c <= 0x7e: utf_str += chr(c)
    else: utf_str += '?'
print(f"  UTF-16LE: '{utf_str}'")
