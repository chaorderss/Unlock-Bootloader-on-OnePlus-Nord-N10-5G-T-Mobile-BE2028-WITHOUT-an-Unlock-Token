#!/usr/bin/env python3
with open('edl_backup/abl_b.img','rb') as f:
    f.seek(0x3000)
    payload = f.read(0x212000)

nz = next((i for i,b in enumerate(payload) if b != 0), None)
print(f'First non-zero byte at PT_LOAD offset: 0x{nz:X}')
print(f'Bytes there: {payload[nz:nz+16].hex()}')

fv_off   = payload.find(b'_FVH')
gzip_off = payload.find(b'\x1f\x8b')
print(f'UEFI FV (_FVH): 0x{fv_off:X}' if fv_off!=-1 else 'No _FVH')
print(f'GZIP: 0x{gzip_off:X}' if gzip_off!=-1 else 'No GZIP')

tok = payload.find(b'Please flash unlock token')
skip = payload.find(b'unlocked, Skipping boot')
print(f'Token string: 0x{tok:X}' if tok!=-1 else 'Token string NOT FOUND')
print(f'Skip boot verify string: 0x{skip:X}' if skip!=-1 else 'Skip-boot-verify NOT FOUND')

print()
start = nz
for i in range(0, 64, 16):
    chunk = payload[start+i:start+i+16]
    hexs = ' '.join(f'{b:02x}' for b in chunk)
    asc = ''.join(chr(b) if 32<=b<127 else '.' for b in chunk)
    print(f'  0x{nz+i:06X}: {hexs}  {asc}')
