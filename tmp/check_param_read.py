#!/usr/bin/env python3
"""Check if any param read flows back to devinfo writes."""

import struct

pe = open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb').read()

# Find ALL calls in the param accessor range
print('=== Param accessor functions and their callers ===')
targets = {}
for pc in range(0, 0x6A000, 4):
    insn = struct.unpack_from('<I', pe, pc)[0]
    if (insn & 0xFC000000) != 0x94000000:
        continue
    offset = insn & 0x3FFFFFF
    if offset & (1 << 25):
        offset -= (1 << 26)
    target = pc + offset * 4
    if 0x32500 <= target <= 0x33500:
        if target not in targets:
            targets[target] = []
        targets[target].append(pc)

for t in sorted(targets.keys()):
    callers = targets[t]
    devinfo_callers = [c for c in callers if 0x22000 <= c <= 0x24000]
    oem_callers = [c for c in callers if 0x36000 <= c <= 0x37000]
    extra = ''
    if devinfo_callers:
        extra += f' DEVINFO_AREA:{[hex(c) for c in devinfo_callers]}'
    if oem_callers:
        extra += f' OEMCHECK:{[hex(c) for c in oem_callers]}'
    print(f'  0x{t:05x}: {len(callers)} callers{extra}')

# All BL calls within OemCheckResetDevInfo function (0x36400-0x36800)
print('\n=== All BL calls in OemCheckResetDevInfo (0x36400-0x36800) ===')
for pc in range(0x36400, 0x36800, 4):
    insn = struct.unpack_from('<I', pe, pc)[0]
    if (insn & 0xFC000000) == 0x94000000:
        offset = insn & 0x3FFFFFF
        if offset & (1 << 25):
            offset -= (1 << 26)
        target = pc + offset * 4
        print(f'  0x{pc:05x}: bl 0x{target:05x}')

# Check if 0x32540 (read_param_block) is called from OemCheckResetDevInfo
# 0x32540 was found as a callee from 0x366c0
print('\n=== Callers of 0x32540 (read_param_block?) ===')
for pc in range(0, 0x6A000, 4):
    insn = struct.unpack_from('<I', pe, pc)[0]
    if (insn & 0xFC000000) != 0x94000000:
        continue
    offset = insn & 0x3FFFFFF
    if offset & (1 << 25):
        offset -= (1 << 26)
    target = pc + offset * 4
    if target == 0x32540:
        print(f'  0x{pc:05x}: bl 0x32540')

print('\n[done]')
