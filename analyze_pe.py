#!/usr/bin/env python3
"""
Parse PE sections, find data section layout, analyze Unlocked-related code,
and check devinfo for possible CRC fields.
"""
import struct

DECOMP = '/Users/xmxx/pinganhuijia/global_abl_decompressed.bin'
PE_OFFSET = 0xB8

with open(DECOMP, 'rb') as f:
    data = bytearray(f.read())

# ─── 1. Parse PE section table ───────────────────────────────────────────────
print("="*65)
print("1. PE Section Table")
print("="*65)

pe_off = PE_OFFSET
assert data[pe_off:pe_off+4] == b'PE\x00\x00', "PE signature not found"
coff = pe_off + 4
num_sections, = struct.unpack_from('<H', data, coff + 2)
opt_size, = struct.unpack_from('<H', data, coff + 16)
opt_off = coff + 20

# Optional header magic
opt_magic, = struct.unpack_from('<H', data, opt_off)
print(f"  OptHdr magic: {opt_magic:#x} ({'PE32+' if opt_magic == 0x20b else 'PE32'})")
image_base, = struct.unpack_from('<Q' if opt_magic == 0x20b else '<I', data, opt_off + (24))
print(f"  ImageBase: {image_base:#x}")

sections_off = opt_off + opt_size
sections = []
print(f"\n  {'Name':<12} {'VirtAddr':>12} {'VirtSize':>12} {'RawOff':>12} {'RawSize':>12}")
print(f"  {'-'*64}")
for i in range(num_sections):
    s = sections_off + i*40
    name = data[s:s+8].rstrip(b'\x00').decode('latin1')
    vsize, vaddr, raw_size, raw_off = struct.unpack_from('<IIII', data, s+8)
    sections.append((name, vaddr, vsize, raw_off, raw_size))
    print(f"  {name:<12} {vaddr:>12x} {vsize:>12x} {raw_off:>12x} {raw_size:>12x}")

def raw_to_va(raw_off):
    for name, vaddr, vsize, sect_raw, sect_rawsize in sections:
        if sect_raw <= raw_off < sect_raw + sect_rawsize:
            return image_base + vaddr + (raw_off - sect_raw)
    return None

def va_to_raw(va):
    for name, vaddr, vsize, sect_raw, sect_rawsize in sections:
        if image_base + vaddr <= va < image_base + vaddr + vsize:
            return sect_raw + (va - (image_base + vaddr))
    return None

def va_to_file(va):
    raw = va_to_raw(va)
    return (PE_OFFSET + raw) if raw is not None else None

def file_to_va(foff):
    raw = foff - PE_OFFSET
    return raw_to_va(raw)

# ─── 2. Find "Device unlocked" string VA ──────────────────────────────────────
print("\n" + "="*65)
print("2. String VAs")
print("="*65)
for s in [b'Device unlocked', b'unlocked: ', b'ANDROID-BOOT!', b'Unlocked']:
    p = 0
    while True:
        idx = data.find(s, p)
        if idx < 0: break
        va = file_to_va(idx + PE_OFFSET)
        raw = idx - PE_OFFSET if idx >= PE_OFFSET else None
        print(f"  {s.decode()!r:25s} file={idx:#x}  raw={raw:#x if raw else 'N/A'}  VA={va:#x if va else 'N/A'}")
        p = idx + 1

# ─── 3. Find ADRP refs to "Unlocked" strings ─────────────────────────────────
print("\n" + "="*65)
print("3. Code refs to 'Unlocked' strings via ADRP+ADD")
print("="*65)

def find_code_refs_to_file_offset(data, target_file_offset):
    """Find ADRP+ADD sequences that reference the given file offset"""
    target_va = file_to_va(target_file_offset)
    if target_va is None:
        print(f"  Cannot find VA for file offset {target_file_offset:#x}")
        return []
    target_page = target_va & ~0xFFF
    target_off  = target_va & 0xFFF

    # find .text section
    text_sect = None
    for s in sections:
        if s[0] in ('.text', 'text', '.TEXT', 'TEXT', ''):
            text_sect = s
            break
    if text_sect is None:
        text_sect = sections[0]

    name, vaddr, vsize, raw_off_sect, rawsize = text_sect
    refs = []
    for i in range(0, rawsize - 4, 4):
        foff = PE_OFFSET + raw_off_sect + i
        if foff + 4 > len(data): break
        insn = struct.unpack_from('<I', data, foff)[0]
        va = image_base + vaddr + i

        # ADRP check
        if (insn & 0x9F000000) != 0x90000000:
            continue
        rd = insn & 0x1F
        immlo = (insn >> 29) & 0x3
        immhi = (insn >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20): imm -= (1 << 21)
        page = (va & ~0xFFF) + (imm << 12)
        if page != target_page:
            continue

        # Check next instruction ADD
        if foff + 4 < len(data):
            insn2 = struct.unpack_from('<I', data, foff + 4)[0]
            if (insn2 & 0xFF800000) == 0x91000000:
                rd2 = insn2 & 0x1F
                rn2 = (insn2 >> 5) & 0x1F
                imm12 = (insn2 >> 10) & 0xFFF
                if rn2 == rd and imm12 == target_off:
                    refs.append(foff)
    return refs

def decode_simple(data, foff):
    insn = struct.unpack_from('<I', data, foff)[0]
    va = file_to_va(foff)
    pc = va if va else foff

    if (insn & 0x9F000000) == 0x90000000:
        rd = insn & 0x1F
        immlo = (insn >> 29) & 0x3; immhi = (insn >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1<<20): imm -= (1<<21)
        page = (pc & ~0xFFF) + (imm << 12)
        return f"ADRP X{rd}, {page:#x}"
    if (insn & 0xFF800000) == 0x91000000:
        rd = insn&0x1F; rn=(insn>>5)&0x1F; imm=(insn>>10)&0xFFF
        return f"ADD  X{rd}, X{rn}, #{imm:#x}"
    if (insn & 0xFFC00000) == 0x39400000:
        rt=insn&0x1F; rn=(insn>>5)&0x1F; imm=(insn>>10)&0xFFF
        return f"LDRB W{rt}, [X{rn}, #{imm:#x}]"
    if (insn & 0xFFC00000) == 0x39000000:
        rt=insn&0x1F; rn=(insn>>5)&0x1F; imm=(insn>>10)&0xFFF
        return f"STRB W{rt}, [X{rn}, #{imm:#x}]"
    if (insn & 0xFFC00000) == 0xB9400000:
        rt=insn&0x1F; rn=(insn>>5)&0x1F; imm=((insn>>10)&0xFFF)*4
        return f"LDR  W{rt}, [X{rn}, #{imm:#x}]"
    if (insn & 0xFFC00000) == 0xF9400000:
        rt=insn&0x1F; rn=(insn>>5)&0x1F; imm=((insn>>10)&0xFFF)*8
        return f"LDR  X{rt}, [X{rn}, #{imm:#x}]"
    if (insn & 0xFFC00000) == 0xF9000000:
        rt=insn&0x1F; rn=(insn>>5)&0x1F; imm=((insn>>10)&0xFFF)*8
        return f"STR  X{rt}, [X{rn}, #{imm:#x}]"
    if insn == 0xD65F03C0: return "RET"
    if insn == 0xD503201F: return "NOP"
    if (insn & 0xFC000000) == 0x94000000:
        imm26 = insn&0x3FFFFFF;
        if imm26&(1<<25): imm26-=(1<<26)
        return f"BL   {pc+imm26*4:#x}"
    if (insn & 0xFC000000) == 0x14000000:
        imm26 = insn&0x3FFFFFF
        if imm26&(1<<25): imm26-=(1<<26)
        return f"B    {pc+imm26*4:#x}"
    if (insn & 0xFF000010) == 0x54000000:
        imm19=(insn>>5)&0x7FFFF
        if imm19&(1<<18): imm19-=(1<<19)
        cond=insn&0xF
        nn=['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
        return f"B.{nn[cond]:<2}  {pc+imm19*4:#x}"
    if (insn & 0x7E000000) == 0x34000000:
        op=(insn>>24)&1; sf=(insn>>31)&1
        imm19=(insn>>5)&0x7FFFF
        if imm19&(1<<18): imm19-=(1<<19)
        rt=insn&0x1F
        reg='X' if sf else 'W'
        return f"{'CBNZ' if op else 'CBZ '} {reg}{rt}, {pc+imm19*4:#x}"
    if (insn & 0xFFC0001F) == 0x7100001F:
        rn=(insn>>5)&0x1F; imm=(insn>>10)&0xFFF; sh=(insn>>22)&1
        if sh: imm<<=12
        return f"CMP  W{rn}, #{imm:#x}"
    if (insn & 0x7F800000) == 0x52800000:
        rd=insn&0x1F; imm=(insn>>5)&0xFFFF
        return f"MOV  W{rd}, #{imm:#x}"
    if (insn & 0xFFE0FFE0) == 0xAA0003E0:
        return f"MOV  X{insn&0x1F}, X{(insn>>16)&0x1F}"
    if (insn & 0xFFE0FFE0) == 0x2A0003E0:
        return f"MOV  W{insn&0x1F}, W{(insn>>16)&0x1F}"
    if (insn & 0xFFC0001F) == 0x7200001F:
        return f"TST  W{(insn>>5)&0x1F}, ..."
    return f"0x{insn:08x}"

def dump_code(data, start_va=None, start_foff=None, count=40, mark_va=None):
    if start_va is not None:
        foff = va_to_file(start_va)
        if foff is None:
            print(f"  Cannot resolve VA {start_va:#x}")
            return
    else:
        foff = start_foff
    for i in range(count):
        off = foff + i*4
        if off + 4 > len(data): break
        va = file_to_va(off)
        insn = struct.unpack_from('<I', data, off)[0]
        desc = decode_simple(data, off)
        marker = " >>>" if (va is not None and va == mark_va) else "    "
        vastr = f"VA {va:#010x}" if va else f"raw {off:#010x}"
        print(f"  {marker}  {off:#010x} ({vastr}): {insn:08x}  {desc}")

# Find "Unlocked" string refs
for sstr in [b'Unlocked', b'unlocked: ']:
    p = 0
    while True:
        idx = data.find(sstr, p)
        if idx < 0: break
        refs = find_code_refs_to_file_offset(data, idx)
        va = file_to_va(idx)
        print(f"\n  String {sstr.decode()!r} at file {idx:#x} (VA {va:#x if va else 'N/A'}), code refs: {len(refs)}")
        for r in refs[:3]:
            rva = file_to_va(r)
            print(f"\n    Ref at file {r:#x} (VA {rva:#x}):")
            dump_code(data, start_foff=r - 30*4, count=70, mark_va=rva)
        p = idx + 1

# ─── 4. Show devinfo_unlocked.bin contents ────────────────────────────────────
print("\n" + "="*65)
print("4. devinfo_unlocked.bin contents (first 64 bytes)")
print("="*65)
with open('/Users/xmxx/pinganhuijia/edl_backup/devinfo_unlocked.bin', 'rb') as f:
    dv = f.read(64)
print("  " + dv[:16].hex(' '))
print("  " + dv[16:32].hex(' '))
print("  " + dv[32:48].hex(' '))
print("  " + dv[48:64].hex(' '))
print(f"  byte[0x0D]={dv[0x0D]:#04x}  byte[0x0E]={dv[0x0E]:#04x}  byte[0x0F]={dv[0x0F]:#04x}  byte[0x10]={dv[0x10]:#04x}")
# check last 16 bytes for possible CRC
with open('/Users/xmxx/pinganhuijia/edl_backup/devinfo_unlocked.bin', 'rb') as f:
    dv_all = f.read()
print(f"  Last 16 bytes: {dv_all[-16:].hex(' ')}")
print(f"  Total size: {len(dv_all)} bytes")
import zlib
crc32 = zlib.crc32(dv_all[:-4]) & 0xFFFFFFFF
crc32_full = zlib.crc32(dv_all[:]) & 0xFFFFFFFF
print(f"  CRC32 of all-but-last-4: {crc32:#010x}")
print(f"  Last 4 bytes as LE uint32: {struct.unpack_from('<I', dv_all, len(dv_all)-4)[0]:#010x}")
