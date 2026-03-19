#!/usr/bin/env python3
"""
Fix uefisecapp .mdt + .bXX split for QSEECOM loading.

The .mdt must contain: ELF header + PHDRs + hash segment data
(concatenated, not at original file offsets).

Format matches working egista.mdt on device:
  .mdt = data[0:hdr_end] + data[hash_off:hash_off+hash_sz]
  .bXX = data[seg_off:seg_off+seg_sz] for each program header
"""
import struct
import sys
import os

def split_elf_fixed(in_path, out_dir, app_name="uefisecapp"):
    with open(in_path, 'rb') as f:
        data = f.read()

    assert data[:4] == b'\x7fELF', "Not an ELF"
    ei_class = data[4]
    assert ei_class == 1, f"Expected 32-bit ELF, got class={ei_class}"

    e_phoff = struct.unpack_from('<I', data, 28)[0]
    e_phentsize = struct.unpack_from('<H', data, 42)[0]
    e_phnum = struct.unpack_from('<H', data, 44)[0]
    hdr_end = e_phoff + e_phnum * e_phentsize

    print(f"ELF: {len(data)} bytes, phoff=0x{e_phoff:x}, phnum={e_phnum}")
    print(f"Headers end at 0x{hdr_end:x} ({hdr_end} bytes)")

    segments = []
    hash_seg = None
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
            struct.unpack_from('<IIIIIIII', data, off)
        seg = {
            'idx': i, 'type': p_type, 'offset': p_offset,
            'filesz': p_filesz, 'memsz': p_memsz, 'flags': p_flags
        }
        segments.append(seg)
        marker = ""
        if p_flags & 0x2200000:
            hash_seg = seg
            marker = " <-- HASH"
        elif i == 0 and p_type == 0:
            marker = " <-- META"
        print(f"  PH[{i}]: type={p_type:#x} off={p_offset:#x} "
              f"filesz={p_filesz:#x} flags={p_flags:#x}{marker}")

    if not hash_seg:
        print("ERROR: No hash segment found (flags & 0x2200000)")
        sys.exit(1)

    os.makedirs(out_dir, exist_ok=True)

    # .mdt = ELF header + PHDRs + hash segment data (concatenated)
    mdt_data = data[0:hdr_end] + data[hash_seg['offset']:hash_seg['offset'] + hash_seg['filesz']]
    mdt_path = os.path.join(out_dir, f"{app_name}.mdt")
    with open(mdt_path, 'wb') as f:
        f.write(mdt_data)
    print(f"\n.mdt: {len(mdt_data)} bytes ({hdr_end} hdr + {hash_seg['filesz']} hash)")

    # .bXX = individual segment data
    for seg in segments:
        if seg['filesz'] > 0:
            seg_data = data[seg['offset']:seg['offset'] + seg['filesz']]
        else:
            seg_data = b''
        bxx_path = os.path.join(out_dir, f"{app_name}.b{seg['idx']:02d}")
        with open(bxx_path, 'wb') as f:
            f.write(seg_data)
        print(f".b{seg['idx']:02d}: {len(seg_data)} bytes")

    print(f"\nDone. {len(segments) + 1} files in {out_dir}/")

    # Verify against egista format
    egista_mdt = os.path.join(os.path.dirname(out_dir), 'egista.mdt')
    if os.path.exists(egista_mdt):
        esize = os.path.getsize(egista_mdt)
        print(f"\nReference: egista.mdt = {esize} bytes")
        print(f"Our .mdt  = {len(mdt_data)} bytes")
        if esize == len(mdt_data):
            print("SIZE MATCH!")

if __name__ == '__main__':
    in_path = sys.argv[1] if len(sys.argv) > 1 else \
        '/Users/xmxx/pinganhuijia/edl_backup/lun4/uefisecapp_a.bin'
    out_dir = sys.argv[2] if len(sys.argv) > 2 else \
        '/Users/xmxx/pinganhuijia/tmp/uefisecapp_split'
    app_name = sys.argv[3] if len(sys.argv) > 3 else 'uefisecapp'
    split_elf_fixed(in_path, out_dir, app_name)
