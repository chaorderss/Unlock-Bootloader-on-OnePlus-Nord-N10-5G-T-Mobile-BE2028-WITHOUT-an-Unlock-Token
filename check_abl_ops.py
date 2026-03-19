import struct

hits = [0x2a02c6c, 0x2a10c6c, 0x2ae1c6c, 0x2ae8c6c, 0x2d9eb4c, 0x2dd9c6c]
ops = 'global-oos-10-5-7/extracted/billie8_14_O.01_201121.ops'

with open(ops, 'rb') as f:
    for h in hits:
        f.seek(h)
        hdr = f.read(52)
        if len(hdr) < 52:
            continue
        e_type    = struct.unpack_from('<H', hdr, 16)[0]
        e_machine = struct.unpack_from('<H', hdr, 18)[0]
        e_entry   = struct.unpack_from('<I', hdr, 24)[0]
        e_phnum   = struct.unpack_from('<H', hdr, 44)[0]
        e_shnum   = struct.unpack_from('<H', hdr, 48)[0]
        tag = '*** ARM EXEC - possible ABL! ***' if (e_type == 2 and e_machine == 0x28 and e_phnum >= 2) else ''
        print(f'@0x{h:08X}: type={e_type} mach=0x{e_machine:04x} entry=0x{e_entry:08x} phnum={e_phnum} shnum={e_shnum} {tag}')

# Also check the first hit from the 64-bit scan for comparison
print()
print('--- Checking 64-bit ELF hit for reference ---')
with open(ops, 'rb') as f:
    f.seek(0x29cac6c)
    hdr = f.read(64)
    e_type    = struct.unpack_from('<H', hdr, 16)[0]
    e_machine = struct.unpack_from('<H', hdr, 18)[0]
    print(f'@0x29cac6c: class={hdr[4]} type={e_type} mach=0x{e_machine:04x}')
