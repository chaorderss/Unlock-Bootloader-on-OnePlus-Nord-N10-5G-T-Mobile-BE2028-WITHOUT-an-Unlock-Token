import re, struct, sys, os, zlib

# ===== UEFI FV parser for Global ABL =====
# ELF wraps a UEFI Firmware Volume at LOAD segment offset 0x3000

def parse_guid(raw):
    d1 = struct.unpack_from('<I', raw)[0]
    d2 = struct.unpack_from('<H', raw, 4)[0]
    d3 = struct.unpack_from('<H', raw, 6)[0]
    d4 = raw[8:16].hex().upper()
    return f"{d1:08X}-{d2:04X}-{d3:04X}-{d4[:4]}-{d4[4:]}"

def search_strings(data, patterns):
    found = []
    for pat in patterns:
        for m in re.finditer(re.escape(pat), data, re.I):
            ctx = data[max(0,m.start()-40):m.start()+80]
            found.append((m.start(), pat, ctx))
    return found

def decompress_efi(data):
    """Try EFI standard decompression (Tiano variant uses zlib with modifications)"""
    # Some ABLs use raw zlib within EFI_SECTION_COMPRESSION
    try:
        orig_size = struct.unpack_from('<I', data)[0]
        scratch_size = struct.unpack_from('<I', data, 4)[0]
        return zlib.decompress(data[8:], -15)
    except:
        pass
    # Try plain zlib
    try:
        return zlib.decompress(data)
    except:
        pass
    return None

def parse_fv(fv_data, label="FV"):
    """Parse UEFI Firmware Volume and return all strings found"""
    if len(fv_data) < 0x50:
        return
    fv_sig = fv_data[0x28:0x2C]
    if fv_sig != b'_FVH':
        print(f"{label}: No _FVH signature found (got {fv_sig.hex()})")
        return

    fv_len = struct.unpack_from('<Q', fv_data, 0x20)[0]
    fv_hdr_len = struct.unpack_from('<H', fv_data, 0x30)[0]
    print(f"\n{label}: len={hex(fv_len)}, hdrlen={fv_hdr_len}")

    FFS_HDR = 24
    pos = (fv_hdr_len + 7) & ~7
    file_count = 0
    all_strings = []

    while pos + FFS_HDR <= min(fv_len, len(fv_data)):
        raw_guid = fv_data[pos:pos+16]
        if all(b == 0xFF for b in raw_guid):
            break
        if all(b == 0x00 for b in raw_guid):
            pos += 8
            continue

        guid = parse_guid(raw_guid)
        ftype = fv_data[pos+18]
        size_b = fv_data[pos+20:pos+23]
        size = size_b[0] | (size_b[1]<<8) | (size_b[2]<<16)

        if size < FFS_HDR or pos + size > len(fv_data):
            break

        file_payload = fv_data[pos+FFS_HDR:pos+size]
        file_count += 1

        # Search for interesting strings directly in raw data
        pats = [b'Please flash', b'unlock token', b'fastboot', b'devinfo',
                b'OEMUnlock', b'is_unlock', b'unlock_allowed', b'token',
                b'UNLOCK', b'oem_unlock', b'cust', b'carrier']
        raw_hits = search_strings(file_payload, pats)

        # Parse sections within this FFS file
        spat = re.findall(b'[\x20-\x7e]{5,}', file_payload)
        interesting_strs = [s for s in spat if len(s) >= 5]

        if raw_hits or (ftype == 0xA):  # 0xA = EFI_FV_FILETYPE_APPLICATION
            print(f"\n  FFS[{file_count}] GUID={guid} type={hex(ftype)} size={hex(size)}")
            for offset, pat, ctx in raw_hits:
                printable = bytes(b if 32<=b<127 else ord('.') for b in ctx)
                print(f"    HIT '{pat.decode()}' at file+{hex(offset)}: {printable.decode()}")

        # Parse sections
        spos = 0
        while spos + 4 <= len(file_payload):
            sz_b = file_payload[spos:spos+3]
            if len(sz_b) < 3: break
            sec_size = sz_b[0] | (sz_b[1]<<8) | (sz_b[2]<<16)
            if sec_size < 4 or spos + sec_size > len(file_payload): break
            sec_type = file_payload[spos+3]
            sec_data = file_payload[spos+4:spos+sec_size]

            # Type 0x15 = USER_INTERFACE (name in UTF-16LE)
            if sec_type == 0x15 and len(sec_data) >= 2:
                try:
                    name = sec_data.decode('utf-16-le', errors='replace').rstrip('\x00')
                    print(f"  FFS[{file_count}] Name='{name}' type={hex(ftype)} size={hex(size)}")
                except:
                    pass

            # Type 0x01 = EFI_SECTION_COMPRESSION
            if sec_type == 0x01 and len(sec_data) > 8:
                decomp_size = struct.unpack_from('<I', sec_data)[0]
                comp_type = sec_data[4]
                compressed_data = sec_data[5:]
                dec = decompress_efi(compressed_data)
                if dec:
                    hits = search_strings(dec, pats)
                    if hits:
                        print(f"  FFS[{file_count}] Compressed section decompressed {len(dec)} bytes")
                        for offset, pat, ctx in hits:
                            printable = bytes(b if 32<=b<127 else ord('.') for b in ctx)
                            print(f"    DECOMP HIT '{pat.decode()}' at +{hex(offset)}: {printable.decode()}")
                    all_strings.extend(dec)

            spos += (sec_size + 3) & ~3

        pos += (size + 7) & ~7

    print(f"\n{label}: parsed {file_count} FFS files")
    return all_strings

# Main
fname = '/Users/xmxx/pinganhuijia/global_abl.img'
with open(fname, 'rb') as f:
    data = f.read()

print(f"File: {fname}, size: {len(data)}")

# FV starts at ELF LOAD segment offset 0x3000
fv_data = data[0x3000:]
parse_fv(fv_data, "Global ABL FV")

# Also search raw data for strings
print("\n=== Direct raw strings in global_abl.img ===")
raw_strs = re.findall(b'[\x20-\x7e]{8,}', data)
interesting = [s for s in raw_strs if any(k in s.lower() for k in [b'unlock', b'token', b'fastboot', b'devinfo', b'oem', b'flash'])]
for s in interesting[:20]:
    print(f"  {s.decode()}")

print("\nDone.")

def parse_guid(raw):
    d1 = struct.unpack_from('<I', raw)[0]
    d2 = struct.unpack_from('<H', raw, 4)[0]
    d3 = struct.unpack_from('<H', raw, 6)[0]
    d4 = raw[8:16].hex().upper()
    return f"{d1:08X}-{d2:04X}-{d3:04X}-{d4[:4]}-{d4[4:]}"

def extract_sections(file_data, indent=2):
    """Extract UEFI FFS sections from a FFS file payload"""
    pos = 0
    results = []
    while pos < len(file_data) - 4:
        sz_b = file_data[pos:pos+3]
        if len(sz_b) < 3:
            break
        section_size = sz_b[0] | (sz_b[1]<<8) | (sz_b[2]<<16)
        if section_size < 4 or section_size > len(file_data) - pos:
            break
        section_type = file_data[pos+3]
        section_data = file_data[pos+4:pos+section_size]
        results.append((section_type, section_data))
        # Section types: 0x10=EFI_SECTION_PE32, 0x15=0x15 FREEFORM, 0x02=COMPRESS, 0x11=PIC
        pos += (section_size + 3) & ~3
    return results

fname = '/Users/xmxx/pinganhuijia/global_abl.img'
with open(fname,'rb') as f:
    data = f.read()

print(f"=== Global ABL Analysis ===")
print(f"File size: {len(data)} bytes")

# UTF-16LE string search
for s in ['unlock', 'token', 'Please', 'fastboot', 'devinfo', 'OEM', 'cust']:
    pat = s.encode('utf-16-le')
    hits = [m.start() for m in re.finditer(re.escape(pat), data, re.I)]
    if hits:
        h = hits[0]
        ctx = data[max(0,h-20):h+80]
        try:
            dec = ctx.decode('utf-16-le', errors='replace')
        except:
            dec = repr(ctx)
        print(f"UTF16 '{s}' at {[hex(x) for x in hits[:3]]}: ...{dec}...")
    else:
        print(f"UTF16 '{s}': not found")

# Compression detection
for magic, name in [
    (bytes([0xFD,0x37,0x7A,0x58,0x5A,0x00]), 'XZ'),
    (bytes([0x28,0xB5,0x2F,0xFD]), 'ZSTD'),
    (bytes([0x5D,0x00,0x00,0x80,0x00]), 'LZMA'),
    (bytes([0x1F,0x8B]), 'GZIP'),
    (bytes([0x02,0x21,0x4C,0x18]), 'LZ4'),
    (bytes([0x04,0x22,0x4D,0x18]), 'LZ4'),
]:
    hits = [m.start() for m in re.finditer(re.escape(magic), data)]
    if hits:
        print(f"{name} at {[hex(h) for h in hits[:5]]}")

# ELF header analysis
print("\n=== ELF ===")
ei_class = data[4]
e_type, e_machine = struct.unpack_from('<HH', data, 0x10)
e_entry = struct.unpack_from('<I' if ei_class==1 else '<Q', data, 0x18)[0]
e_phoff = struct.unpack_from('<I' if ei_class==1 else '<Q', data, 0x1c if ei_class==1 else 0x20)[0]
e_phnum = struct.unpack_from('<H', data, 0x2c if ei_class==1 else 0x38)[0]
e_phentsize = struct.unpack_from('<H', data, 0x2a if ei_class==1 else 0x36)[0]
print(f"Class={ei_class}(32b=1) machine={hex(e_machine)} entry={hex(e_entry)}")
print(f"phoff={hex(e_phoff)} phnum={e_phnum} phentsize={e_phentsize}")

for i in range(min(e_phnum, 10)):
    off = e_phoff + i * e_phentsize
    if ei_class == 1:
        p_type,p_offset,p_vaddr,p_paddr,p_filesz,p_memsz,p_flags,p_align = struct.unpack_from('<IIIIIIII', data, off)
    else:
        p_type,p_flags,p_offset,p_vaddr,p_paddr,p_filesz,p_memsz,p_align = struct.unpack_from('<IIQQQQQQ', data, off)
    if p_filesz > 0:
        fb = data[p_offset:p_offset+16]
        print(f"  PH[{i}] t={hex(p_type)} off={hex(p_offset)} filesz={hex(p_filesz)} memsz={hex(p_memsz)} first={fb.hex()}")
        # Check for compression magic in this segment
        for magic, name in [(bytes([0xFD,0x37,0x7A,0x58,0x5A,0x00]),'XZ'),(bytes([0x5D,0x00,0x00,0x80]),'LZMA'),(bytes([0x28,0xB5,0x2F,0xFD]),'ZSTD')]:
            if fb[:len(magic)] == magic:
                print(f"    -> Segment data starts with {name}!")

print("\n=== Decompressing GZIP blocks in Global ABL ===")
import gzip, io

with open('/Users/xmxx/pinganhuijia/global_abl.img', 'rb') as f:
    data = f.read()

gzip_offsets = [m.start() for m in re.finditer(re.escape(bytes([0x1F,0x8B])), data)]
print(f"All GZIP offsets: {[hex(h) for h in gzip_offsets]}")

total_decompressed = b''
for goff in gzip_offsets:
    try:
        import zlib
        # Try decompressing from this offset
        chunk = data[goff:]
        dec = zlib.decompress(chunk, 47)  # 47 = zlib.MAX_WBITS|16 for gzip
        print(f"  GZIP at {hex(goff)}: decompressed {len(dec)} bytes")
        total_decompressed += dec
        # Show some strings from this chunk
        strings = re.findall(b'[\x20-\x7e]{6,}', dec)
        for s in strings[:10]:
            print(f"    string: {s.decode()}")
    except Exception as e:
        print(f"  GZIP at {hex(goff)}: FAILED ({e})")

print(f"\nTotal decompressed: {len(total_decompressed)} bytes")
for pat in [b'unlock token', b'flash unlock', b'fastboot', b'devinfo', b'Please flash']:
    hits = [m.start() for m in re.finditer(re.escape(pat), total_decompressed, re.I)]
    print(f"  '{pat.decode()}': {len(hits)} hits at {[hex(h) for h in hits[:5]]}")

print(f"Total size: {len(data)} bytes")
print(f"Non-zero: {len(data.rstrip(bytes([0])))} bytes")

# Look for version/build strings
for pattern in [b'BE88CB', b'BE88', b'billie8', b'11.0.', b'20888']:
    positions = [m.start() for m in re.finditer(re.escape(pattern), data)]
    if positions:
        for pos in positions[:3]:
            ctx = data[max(0,pos-20):pos+50]
            printable = ''.join(chr(b) if 32<=b<127 else '.' for b in ctx)
            print(f"'{pattern.decode()}' at 0x{pos:x}: {printable}")

# Look for the "unlock" related strings
for pattern in [b'unlock', b'token', b'cust-unlock', b'carrier', b'oem_unlock']:
    positions = [m.start() for m in re.finditer(re.escape(pattern), data, re.IGNORECASE)]
    if positions:
        print(f"\n'{pattern.decode()}' found at {len(positions)} locations:")
        for pos in positions[:5]:
            ctx = data[max(0,pos-30):pos+60]
            printable = ''.join(chr(b) if 32<=b<127 else '.' for b in ctx)
            print(f"  0x{pos:x}: {printable}")

# ELF program headers to find code segments
e_type = struct.unpack_from('<H', data, 0x10)[0]
e_machine = struct.unpack_from('<H', data, 0x12)[0]
e_phoff = struct.unpack_from('<I', data, 0x1c)[0]
e_phnum = struct.unpack_from('<H', data, 0x2c)[0]
e_phentsize = struct.unpack_from('<H', data, 0x2a)[0]
print(f"\nELF: type={e_type} machine={e_machine} phoff=0x{e_phoff:x} phnum={e_phnum}")

# Read program headers
for i in range(min(e_phnum, 20)):
    offset = e_phoff + i * e_phentsize
    p_type = struct.unpack_from('<I', data, offset)[0]
    p_offset = struct.unpack_from('<I', data, offset+4)[0]
    p_vaddr = struct.unpack_from('<I', data, offset+8)[0]
    p_paddr = struct.unpack_from('<I', data, offset+12)[0]
    p_filesz = struct.unpack_from('<I', data, offset+16)[0]
    p_memsz = struct.unpack_from('<I', data, offset+20)[0]
    p_flags = struct.unpack_from('<I', data, offset+24)[0]
    print(f"  PH[{i}]: type=0x{p_type:x} off=0x{p_offset:x} vaddr=0x{p_vaddr:x} filesz=0x{p_filesz:x} flags=0x{p_flags:x}")
