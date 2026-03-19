#!/usr/bin/env python3
import struct, re

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin','rb').read()

print('=== Search for 5-digit model numbers (18xxx to 22xxx range) ===')
model_re = re.compile(rb'(?:^|(?<=\x00))(1[89]\d{3}|2[012]\d{3})(?=\x00)', re.MULTILINE)
for m in model_re.finditer(data):
    pos = m.start()
    model_str = m.group(1).decode()
    print(f'  0x{pos:x}: {model_str}')

print()
print('=== Also search for "20888" specifically ===')
idx = 0
while True:
    idx = data.find(b'20888', idx)
    if idx < 0:
        break
    print(f'  Found at 0x{idx:x}: {data[idx:idx+10]}')
    idx += 1

print()
print('=== Strings at 0x622f0-0x62415 (model key continuation) ===')
i = 0x622f0
while i < 0x62415:
    s = b''
    start = i
    while i < 0x62500 and data[i]:
        s += bytes([data[i]])
        i += 1
    if s and len(s) >= 4:
        printable = ''.join(chr(b) if 32 <= b < 127 else f'\\x{b:02x}' for b in s)
        print(f'  0x{start:x} [{len(s)}]: {repr(printable[:80])}')
    i += 1

print()
print('=== Check if oem get_unlock_code handler is at 0x361c0 ===')
# Look for dispatch table entry pointing to 0x361c0
for addr in range(0x633b8, 0x636c0, 16):
    func_ptr = struct.unpack_from('<Q', data, addr+8)[0] if addr+8 < len(data) else 0
    str_ptr = struct.unpack_from('<Q', data, addr)[0]
    if func_ptr == 0x361c0:
        s = b''
        j = str_ptr
        while j < str_ptr+60 and data[j]:
            s += bytes([data[j]])
            j += 1
        print(f'  dispatch[0x{addr:x}]: str={repr(s[:40])}, func=0x361c0')
    if func_ptr == 0x35fb8:
        s = b''
        j = str_ptr
        while j < str_ptr+60 and data[j]:
            s += bytes([data[j]])
            j += 1
        print(f'  dispatch[0x{addr:x}]: str={repr(s[:40])}, func=0x35fb8')

# Also look for handler entries that call 0x35fb8 or 0x361c0
print()
print('=== Handlers that call 0x35fb8 ===')
for off in range(0x1000, 0x69000, 4):
    insn = struct.unpack_from('<I', data, off)[0]
    if (insn & 0xfc000000) == 0x94000000:  # BL
        imm = (insn & 0x3ffffff)
        if imm & (1<<25): imm -= (1<<26)
        target = (off + imm*4) & 0xffffffff
        if target == 0x35fb8:
            print(f'  0x{off:x}: bl 0x35fb8')
        if target == 0x361c0:
            print(f'  0x{off:x}: bl 0x361c0')
