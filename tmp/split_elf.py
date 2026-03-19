#!/usr/bin/env python3
"""
Split Qualcomm TZ ELF (uefisecapp) into .mdt + .bXX files
for loading via QSEECom_start_app.

.mdt = ELF header + program headers + hash segment
.b00-.bNN = individual ELF segments
"""
import struct
import sys
import os

def split_elf(in_path, out_dir, app_name="uefisecapp"):
    with open(in_path, 'rb') as f:
        data = f.read()

    # Parse ELF header (32-bit)
    assert data[:4] == b'\x7fELF', "Not an ELF file"
    ei_class = data[4]
    assert ei_class == 1, f"Expected 32-bit ELF, got class={ei_class}"

    e_phoff = struct.unpack_from('<I', data, 28)[0]
    e_phentsize = struct.unpack_from('<H', data, 42)[0]
    e_phnum = struct.unpack_from('<H', data, 44)[0]

    print(f"ELF: phoff=0x{e_phoff:x}, phentsize={e_phentsize}, phnum={e_phnum}")

    # Parse program headers
    segments = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
            struct.unpack_from('<IIIIIIII', data, off)
        segments.append({
            'type': p_type, 'offset': p_offset, 'vaddr': p_vaddr,
            'paddr': p_paddr, 'filesz': p_filesz, 'memsz': p_memsz,
            'flags': p_flags, 'align': p_align
        })
        print(f"  PH[{i}]: type={p_type:#x} offset={p_offset:#x} "
              f"filesz={p_filesz:#x} memsz={p_memsz:#x} flags={p_flags:#x}")

    os.makedirs(out_dir, exist_ok=True)

    # .mdt = ELF header + all program headers + segment 0 data (hash segment)
    mdt_size = e_phoff + e_phnum * e_phentsize
    # Include hash segment (first program header's data)
    if segments[0]['filesz'] > 0:
        hash_end = max(mdt_size, segments[0]['offset'] + segments[0]['filesz'])
    else:
        hash_end = mdt_size

    mdt_data = data[:hash_end]
    mdt_path = os.path.join(out_dir, f"{app_name}.mdt")
    with open(mdt_path, 'wb') as f:
        f.write(mdt_data)
    print(f"\nWrote {mdt_path} ({len(mdt_data)} bytes)")

    # .bXX = individual segment data
    for i, seg in enumerate(segments):
        seg_data = data[seg['offset']:seg['offset'] + seg['filesz']] if seg['filesz'] > 0 else b''
        bxx_path = os.path.join(out_dir, f"{app_name}.b{i:02d}")
        with open(bxx_path, 'wb') as f:
            f.write(seg_data)
        print(f"Wrote {bxx_path} ({len(seg_data)} bytes)")

    print(f"\nDone. Files in {out_dir}/")
    print(f"Total segments: {e_phnum}")

if __name__ == '__main__':
    in_path = sys.argv[1] if len(sys.argv) > 1 else '/Users/xmxx/pinganhuijia/edl_backup/lun4/uefisecapp_a.bin'
    out_dir = sys.argv[2] if len(sys.argv) > 2 else '/Users/xmxx/pinganhuijia/tmp/uefisecapp_split'
    app_name = sys.argv[3] if len(sys.argv) > 3 else 'uefisecapp'
    split_elf(in_path, out_dir, app_name)
