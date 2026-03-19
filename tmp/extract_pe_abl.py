#!/usr/bin/env python3
"""Extract PE sections from ABL's EFI Firmware Volume and search for keys."""
import struct, re
from binascii import hexlify

with open('/tmp/abl_a.bin', 'rb') as f:
    abl = f.read()

abl = abl[:0x215000]

# Find all PE (MZ) headers
print("=== PE sections in ABL ===")
pe_sections = []
pos = 0
while True:
    idx = abl.find(b'MZ', pos)
    if idx == -1:
        break
    # Verify it looks like a real PE
    if idx + 64 < len(abl):
        pe_offset = struct.unpack('<I', abl[idx+0x3C:idx+0x40])[0]
        if pe_offset < 0x1000:
            pe_sig_pos = idx + pe_offset
            if pe_sig_pos + 4 < len(abl):
                pe_sig = abl[pe_sig_pos:pe_sig_pos+4]
                if pe_sig == b'PE\x00\x00':
                    # Get size info
                    machine = struct.unpack('<H', abl[pe_sig_pos+4:pe_sig_pos+6])[0]
                    num_secs = struct.unpack('<H', abl[pe_sig_pos+6:pe_sig_pos+8])[0]
                    opt_hdr_size = struct.unpack('<H', abl[pe_sig_pos+20:pe_sig_pos+22])[0]

                    # Determine end by looking at sections
                    sec_table = pe_sig_pos + 24 + opt_hdr_size
                    max_end = idx
                    for s in range(num_secs):
                        sec_off = sec_table + s * 40
                        if sec_off + 40 <= len(abl):
                            raw_size = struct.unpack('<I', abl[sec_off+16:sec_off+20])[0]
                            raw_ptr = struct.unpack('<I', abl[sec_off+20:sec_off+24])[0]
                            end = idx + raw_ptr + raw_size
                            if end > max_end:
                                max_end = end

                    size = max_end - idx
                    pe_data = abl[idx:max_end]
                    pe_sections.append((idx, size, pe_data))

                    machine_str = {0x14c: "i386", 0x8664: "x64", 0xAA64: "AArch64"}.get(machine, hex(machine))
                    print(f"  PE at 0x{idx:X}, size ~{size//1024}KB, machine={machine_str}, sections={num_secs}")
    pos = idx + 2

# Also look for TE (Terse Executable) headers
print("\n=== TE sections ===")
te_sections = []
pos = 0
while True:
    idx = abl.find(b'VZ', pos)
    if idx == -1:
        break
    if idx + 40 < len(abl):
        machine = struct.unpack('<H', abl[idx+2:idx+4])[0]
        num_secs = abl[idx+4]
        if machine in [0x14c, 0x8664, 0xAA64] and 0 < num_secs <= 20:
            print(f"  TE at 0x{idx:X}, machine={hex(machine)}, sections={num_secs}")
            te_sections.append(idx)
    pos = idx + 2

# Search all PE sections for our strings
print("\n=== Searching PE sections for param strings ===")
search_patterns = [
    b'Encrypted block',
    b'verified success',
    b'sw_proj_id',
    b'GetParam',
    b'get_param_by_index',
    b'Software',
    b'carrier',
    b'decrypt',
    b'OnePlus',
    b'000OnePlus818000',
    b'init_param',
]

for pe_idx, pe_size, pe_data in pe_sections:
    found_any = False
    for pattern in search_patterns:
        idx = pe_data.find(pattern)
        if idx >= 0:
            if not found_any:
                print(f"\n  PE at 0x{pe_idx:X} ({pe_size//1024}KB):")
                found_any = True
            # Get null-terminated string
            start = idx
            while start > 0 and pe_data[start-1] != 0:
                start -= 1
            end = idx
            while end < len(pe_data) and pe_data[end] != 0:
                end += 1
            s = pe_data[start:end].decode('utf-8', errors='replace')
            abs_off = pe_idx + start
            print(f"    0x{abs_off:06X}: '{s[:100]}'")

# Also search the ENTIRE binary for strings regardless of PE boundaries
print("\n=== Full binary string search ===")
for pattern in [b'Encrypted block', b'get_param_by_index', b'sw_proj_id', b'OnePlus818',
                b'000OnePlus', b'init_param_sw', b'check and restore']:
    idx = abl.find(pattern)
    if idx >= 0:
        start = idx
        while start > 0 and abl[start-1] != 0:
            start -= 1
        end = idx
        while end < len(abl) and abl[end] != 0:
            end += 1
        s = abl[start:end].decode('utf-8', errors='replace')
        print(f"  0x{start:06X}: '{s[:120]}'")
    else:
        print(f"  '{pattern.decode()}': NOT FOUND")
