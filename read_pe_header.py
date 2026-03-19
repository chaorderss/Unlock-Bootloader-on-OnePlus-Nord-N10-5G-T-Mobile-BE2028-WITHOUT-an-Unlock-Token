#!/usr/bin/env python3
import struct

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin','rb').read()

# Read PE header
e_lfanew = struct.unpack_from('<I', data, 0x3c)[0]
print(f'PE offset: 0x{e_lfanew:x}')
assert data[e_lfanew:e_lfanew+4] == b'PE\x00\x00', "Not a PE file"

opt_start = e_lfanew + 24
magic = struct.unpack_from('<H', data, opt_start)[0]
print(f'Magic: 0x{magic:x}')  # 0x20B = PE32+

image_base = struct.unpack_from('<Q', data, opt_start+24)[0]
print(f'ImageBase: 0x{image_base:x}')

num_sections = struct.unpack_from('<H', data, e_lfanew+6)[0]
opt_size = struct.unpack_from('<H', data, e_lfanew+20)[0]
sect_start = e_lfanew + 24 + opt_size
print(f'Sections: {num_sections}')
for i in range(num_sections):
    s = sect_start + i*40
    name = data[s:s+8].rstrip(b'\x00').decode('ascii','replace')
    vsize = struct.unpack_from('<I', data, s+8)[0]
    vaddr = struct.unpack_from('<I', data, s+12)[0]
    rawsize = struct.unpack_from('<I', data, s+16)[0]
    rawoff = struct.unpack_from('<I', data, s+20)[0]
    print(f'  [{name}] VAddr=0x{vaddr:x} VSize=0x{vsize:x} RawOff=0x{rawoff:x} RawSize=0x{rawsize:x}')

# if ImageBase != 0, then runtime addresses in dispatch table = ImageBase + RVA
# The dispatch table stores absolute addresses after relocation
# At rest (before loading), the pointers in the file are RELATIVE to ImageBase
# After relocation at runtime: absolute_addr = ImageBase + RVA

print()
print('=== Checking dispatch table pointer interpretation ===')
# Read 8-byte pointer at 0x633c0
raw_ptr = struct.unpack_from('<Q', data, 0x633c0)[0]
print(f'Raw pointer at 0x633c0: 0x{raw_ptr:x}')
# If ImageBase = 0, ptr = RVA = 0x3bcc0
# If ImageBase = X, ptr at rest = RVA = raw_ptr - X
rva = raw_ptr - image_base
print(f'RVA (if ImageBase applies): 0x{rva:x}')
# The disassembly has address = RVA (disassembled from base 0x0)
print(f'Expected function address in disassembly: 0x{rva:x}')

# Verify: is there a function at 0x3acc0 in data?
data_at_3acc0 = struct.unpack_from('<I', data, 0x3acc0)[0]
data_at_3bcc0 = struct.unpack_from('<I', data, 0x3bcc0)[0]
print(f'Data at file offset 0x3acc0: 0x{data_at_3acc0:08x}')  # Should be 0x90000c21 for ADRP
print(f'Data at file offset 0x3bcc0: 0x{data_at_3bcc0:08x}')
