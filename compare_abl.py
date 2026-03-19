import struct

def analyze_abl(filename):
    with open(filename,'rb') as f:
        data = f.read()
    print(f'{filename}: {len(data)} bytes, non-zero: {len(data.rstrip(bytes([0])))} bytes')
    e_phoff = struct.unpack_from('<I', data, 0x1c)[0]
    e_phnum = struct.unpack_from('<H', data, 0x2c)[0]
    e_phentsize = struct.unpack_from('<H', data, 0x2a)[0]
    print(f'  phoff=0x{e_phoff:x}, phnum={e_phnum}')
    hash_offset = None
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from('<I', data, off)[0]
        p_offset = struct.unpack_from('<I', data, off+4)[0]
        p_filesz = struct.unpack_from('<I', data, off+16)[0]
        p_flags = struct.unpack_from('<I', data, off+24)[0]
        print(f'  PH[{i}]: type=0x{p_type:x} offset=0x{p_offset:x} filesz=0x{p_filesz:x} flags=0x{p_flags:x}')
        if p_flags == 0x2200000:
            hash_offset = p_offset
    if hash_offset:
        hs = data[hash_offset:hash_offset+0x50]
        print(f'  Hash segment at 0x{hash_offset:x}:')
        for i in range(0, 80, 16):
            hex_str = ' '.join(f'{b:02x}' for b in hs[i:i+16])
            print(f'    {i:04x}: {hex_str}')
        header_vsn = struct.unpack_from('<I', hs, 4)[0]
        sig_size = struct.unpack_from('<I', hs, 0x1c)[0]
        cert_chain_size = struct.unpack_from('<I', hs, 0x24)[0]
        sw_at_38 = struct.unpack_from('<I', hs, 0x38)[0]
        sw_at_3c = struct.unpack_from('<I', hs, 0x3c)[0]
        sw_at_40 = struct.unpack_from('<I', hs, 0x40)[0]
        print(f'  header_vsn={header_vsn}, sig_size={sig_size}, cert_size={cert_chain_size}')
        print(f'  Values at 0x38=0x{sw_at_38:x}({sw_at_38}), 0x3c=0x{sw_at_3c:x}, 0x40=0x{sw_at_40:x}')

import os
os.chdir('/Users/xmxx/pinganhuijia')
analyze_abl('edl_backup/abl_b.img')
print()
analyze_abl('global_abl_raw.img')
