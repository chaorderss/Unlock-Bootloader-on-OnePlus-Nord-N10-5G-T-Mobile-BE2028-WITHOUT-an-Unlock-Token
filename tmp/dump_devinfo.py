#!/usr/bin/env python3
"""Dump devinfo.bin non-zero bytes and structure."""

d = open('/Users/xmxx/pinganhuijia/edl_backup/lun4/devinfo.bin', 'rb').read()
print(f'Size: {len(d)} bytes')
print('Non-zero bytes:')
for i in range(len(d)):
    if d[i] != 0:
        ch = chr(d[i]) if 32 <= d[i] < 127 else '.'
        print(f'  0x{i:04x} ({i:4d}): 0x{d[i]:02x} ({d[i]:3d}) {ch!r}')

print()
print('First 32 bytes:')
for i in range(0, 32, 16):
    row = d[i:i+16]
    hexs = ' '.join(f'{b:02x}' for b in row)
    ascs = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row)
    print(f'  {i:04x}: {hexs}  {ascs}')

# Based on ABL code analysis:
print()
print('=== DevInfo Structure Map (from ABL code) ===')
print(f'  [0x00-0x0C] magic:             {d[0:13]!r}')
print(f'  [0x0D]      is_unlocked:       {d[0x0D]} ({"UNLOCKED" if d[0x0D] else "LOCKED"})')
print(f'  [0x0E]      is_unlock_critical: {d[0x0E]}')
print(f'  [0x0F]      charger_screen?:   {d[0x0F]}')
print(f'  [0x90]      (offset 144):      {d[0x90]}')
print(f'  [0x94]      (offset 148):      {d[0x94]}')
