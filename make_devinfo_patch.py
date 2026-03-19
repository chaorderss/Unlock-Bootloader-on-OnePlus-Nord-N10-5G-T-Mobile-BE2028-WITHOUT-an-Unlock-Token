#!/usr/bin/env python3
"""Patch devinfo: set is_unlocked=1 for both VBOOT_MOTA and non-VBOOT_MOTA formats"""

DEVINFO = '/Users/xmxx/pinganhuijia/edl_backup/devinfo.bin.original'
OUT     = '/Users/xmxx/pinganhuijia/edl_backup/devinfo_unlocked.bin'

with open(DEVINFO, 'rb') as f:
    data = bytearray(f.read())

print('Before patch:')
print(f'  magic: {bytes(data[0:13])}')
print(f'  0x0D (VBOOT_MOTA is_unlocked):   {hex(data[0x0D])}')
print(f'  0x0E (VBOOT_MOTA is_tampered):   {hex(data[0x0E])}')
print(f'  0x0F (VBOOT_MOTA is_verified):   {hex(data[0x0F])}')
print(f'  0x10 (non-VBOOT is_unlocked):    {hex(data[0x10])}')
print(f'  0x14 (non-VBOOT is_tampered):    {hex(data[0x14])}')
print(f'  0x18 (non-VBOOT is_unlock_crit): {hex(data[0x18])}')

# Patch both struct formats
data[0x0D] = 0x01  # VBOOT_MOTA: is_unlocked = true
data[0x0E] = 0x00  # VBOOT_MOTA: is_tampered = false (keep)
# 0x0F stays 0x01 (is_verified = true, keep)
data[0x10] = 0x01  # non-VBOOT_MOTA: is_unlocked = true (also VBOOT_MOTA: charger_screen_enabled)
data[0x18] = 0x01  # non-VBOOT_MOTA: is_unlock_critical = true
data[0xD1] = 0x01  # VBOOT_MOTA: is_unlock_critical = true

print()
print('After patch:')
print(f'  0x0D (VBOOT_MOTA is_unlocked):   {hex(data[0x0D])}')
print(f'  0x0E (VBOOT_MOTA is_tampered):   {hex(data[0x0E])}')
print(f'  0x10 (non-VBOOT is_unlocked):    {hex(data[0x10])}')
print(f'  0x18 (non-VBOOT is_unlock_crit): {hex(data[0x18])}')
print(f'  0xD1 (VBOOT_MOTA is_unlock_crit):{hex(data[0xD1])}')

with open(OUT, 'wb') as f:
    f.write(data)
print(f'\nWritten: {OUT}  ({len(data)} bytes)')
