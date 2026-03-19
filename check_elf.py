#!/usr/bin/env python3
import struct

with open('/Users/xmxx/pinganhuijia/edl_backup/abl_b.img','rb') as f:
    d = f.read()

e_ident = d[:16]
ei_class    = e_ident[4]   # 1=32bit, 2=64bit
e_type      = struct.unpack_from('<H', d, 16)[0]
e_machine   = struct.unpack_from('<H', d, 18)[0]

print(f"ELF magic: {e_ident[:4]}, class={'32-bit' if ei_class==1 else '64-bit'}")
print(f"ELF type={hex(e_type)} machine={hex(e_machine)} ({'ARM' if e_machine==0x28 else 'AArch64' if e_machine==0xaa64 else hex(e_machine)})")

if ei_class == 1:  # 32-bit ELF
    e_phoff     = struct.unpack_from('<I', d, 28)[0]
    e_phentsize = struct.unpack_from('<H', d, 42)[0]
    e_phnum     = struct.unpack_from('<H', d, 44)[0]
    PH_FMT = '<IIIIIIII'  # 32-bit: type,off,vaddr,paddr,filesz,memsz,flags,align
    def ph_fields(buf):
        t,off,va,pa,fsz,msz,fl,_ = struct.unpack_from(PH_FMT, buf)
        return t, off, fsz
else:  # 64-bit ELF
    e_phoff     = struct.unpack_from('<Q', d, 32)[0]
    e_phentsize = struct.unpack_from('<H', d, 54)[0]
    e_phnum     = struct.unpack_from('<H', d, 56)[0]
    def ph_fields(buf):
        t  = struct.unpack_from('<I', buf, 0)[0]
        off= struct.unpack_from('<Q', buf, 8)[0]
        fsz= struct.unpack_from('<Q', buf, 32)[0]
        return t, off, fsz

print(f"Program headers: {e_phnum} @ offset {hex(e_phoff)}, entry_size={e_phentsize}")
print()

SIGNING_TYPES = {
    0x65002712: "HASH_SEGMENT",
    0x65000001: "CERT_OR_SIG",
    0x60000000: "CERT_CHAIN",
    0x65002714: "HASH_SEGMENT_v2",
    1: "PT_LOAD",
    0: "PT_NULL",
    6: "PT_PHDR",
}

print("Program headers:")
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    buf = d[off:off+e_phentsize]
    p_type, p_offset, p_filesz = ph_fields(buf)
    label = SIGNING_TYPES.get(p_type, f"UNKNOWN_{hex(p_type)}")
    preview = d[p_offset:p_offset+16].hex() if p_filesz > 0 and p_offset+16 <= len(d) else ""
    print(f"  [{i}] type={hex(p_type):<12} ({label:<20}) offset={hex(p_offset)} filesz={hex(p_filesz)}")
    if preview:
        print(f"       bytes: {preview}")

# Also scan for Qualcomm hash/signature magic bytes
print()
print("Scanning for Qualcomm signing signatures...")
# Magic: 0xD3510100 or similar hash header
for magic, name in [(b'\x00\x01\x51\xD3', 'QC_MBN_HDR'), (b'\x01\x84\xBE\x10', 'HASH_HDR')]:
    pos = d.find(magic)
    if pos >= 0:
        print(f"  Found {name} @ {hex(pos)}: {d[pos:pos+32].hex()}")
