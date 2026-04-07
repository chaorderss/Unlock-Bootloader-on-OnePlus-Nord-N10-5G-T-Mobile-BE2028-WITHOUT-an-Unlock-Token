#!/usr/bin/env python3
import struct

# Check boot_a header
boot = open('tmp/boot_a_curr_hdr.bin','rb').read()
magic = boot[:8]
print('=== boot_a (current on device) ===')
print('magic:', magic)
if magic == b'ANDROID!':
    kernel_size = struct.unpack_from('<I', boot, 8)[0]
    os_version_raw = struct.unpack_from('<I', boot, 48)[0]
    os_ver = (os_version_raw >> 11)
    os_major = (os_ver >> 14) & 0x7f
    os_minor = (os_ver >> 7) & 0x7f
    os_patch = os_ver & 0x7f
    header_version = struct.unpack_from('<I', boot, 60)[0]
    print(f'OS version: {os_major}.{os_minor}-{os_patch}')
    print(f'kernel_size: {kernel_size}')
    print(f'header_version: {header_version}')

# Compare with backup
backup_boot = open('edl_backup/lun4/boot_a.bin','rb').read(4096)
if boot[:64] == backup_boot[:64]:
    print('boot_a = SAME AS BACKUP (Android 10) - UBports did not flash new boot.img')
else:
    print('boot_a = DIFFERENT from backup - UBports flashed a new image!')
    backup_magic = backup_boot[:8]
    print(f'  backup magic: {backup_magic}')
    if magic == b'ANDROID!':
        bos_raw = struct.unpack_from('<I', backup_boot, 48)[0]
        bos = (bos_raw >> 11)
        print(f'  backup OS: {(bos >> 14) & 0x7f}.{(bos >> 7) & 0x7f}-{bos & 0x7f}')

print()
print('=== vbmeta_a (current on device) ===')
vbmeta = open('tmp/vbmeta_a_curr.bin','rb').read()
idx = vbmeta.find(b'AVB0')
if idx >= 0:
    ri = struct.unpack_from('>Q', vbmeta, idx+112)[0]
    flags = struct.unpack_from('>I', vbmeta, idx+120)[0]
    algo = struct.unpack_from('>I', vbmeta, idx+28)[0]
    auth_size = struct.unpack_from('>Q', vbmeta, idx+12)[0]
    print(f'rollback_index = {ri}')
    print(f'flags = 0x{flags:08x}  (3=verification disabled)')
    print(f'algo = {algo}  (0=NONE/disabled, 2=SHA256_RSA4096)')
    print(f'auth_block_size = {auth_size}  (0=signature stripped)')
else:
    print('No AVB0 magic found')

# Also compare vbmeta with backup
print()
backup_vbmeta = open('edl_backup/lun4/vbmeta_a.bin','rb').read()
if vbmeta[:256] == backup_vbmeta[:256]:
    print('vbmeta_a = SAME AS BACKUP (our disabled version)')
else:
    print('vbmeta_a = DIFFERENT from backup')
    bidx = backup_vbmeta.find(b'AVB0')
    if bidx >= 0:
        bri = struct.unpack_from('>Q', backup_vbmeta, bidx+112)[0]
        bflags = struct.unpack_from('>I', backup_vbmeta, bidx+120)[0]
        print(f'  backup rollback_index = {bri}, flags = 0x{bflags:08x}')
