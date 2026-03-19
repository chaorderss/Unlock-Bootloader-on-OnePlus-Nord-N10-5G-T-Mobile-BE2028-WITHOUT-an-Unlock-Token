#!/usr/bin/env python3
"""
Targeted devinfo analysis:
1. Parse PE sections correctly (MZ at 0xB8)
2. Find all LDR (literal pool) and ADR refs to "ANDROID-BOOT!" string
3. Find refs to "Unlocked" / "Device unlocked" / "unlocked: " strings
4. Check devinfo binary for CRC pattern
5. Dump "Unlocked" string context: trace what byte is read before printing
"""
import struct, zlib

DECOMP = '/Users/xmxx/pinganhuijia/global_abl_decompressed.bin'
DEVINFO = '/Users/xmxx/pinganhuijia/edl_backup/devinfo_unlocked.bin'
MZ_OFF = 0xB8

with open(DECOMP, 'rb') as fh:
    data = bytearray(fh.read())

# ── Parse PE ──────────────────────────────────────────────────────────────────
e_lfanew = struct.unpack_from('<I', data, MZ_OFF + 0x3C)[0]
PE_SIG = MZ_OFF + e_lfanew
assert data[PE_SIG:PE_SIG+4] == b'PE\x00\x00'
coff_off = PE_SIG + 4
num_sections, = struct.unpack_from('H', data, coff_off + 2)
opt_size, = struct.unpack_from('H', data, coff_off + 16)
opt_off = coff_off + 20
image_base = struct.unpack_from('<Q', data, opt_off + 24)[0]  # PE32+
sect_off = opt_off + opt_size
sections = []
for i in range(num_sections):
    s = sect_off + i*40
    name = data[s:s+8].rstrip(b'\x00').decode('latin1')
    vsize, vaddr, raw_size, raw_off = struct.unpack_from('<IIII', data, s+8)
    fstart = MZ_OFF + raw_off
    sections.append((name, image_base + vaddr, vsize, fstart, raw_size))

def file_to_va(foff):
    for nm, va, vsz, fs, rsz in sections:
        if fs <= foff < fs + rsz:
            return va + (foff - fs)
    return None

def va_to_file(va):
    for nm, vva, vsz, fs, rsz in sections:
        if vva <= va < vva + vsz:
            return fs + (va - vva)
    return None

TEXT_FS   = sections[0][3]
TEXT_SIZE = sections[0][4]
TEXT_VA   = sections[0][1]

print("  Sections:")
for nm, va, vsz, fs, rsz in sections:
    print(f"    {nm:<10} VA={va:#x}  file={fs:#x}..{fs+rsz:#x}")

# ── String VAs ────────────────────────────────────────────────────────────────
print()
strings = {}
for s in [b'ANDROID-BOOT!', b'Device unlocked', b'unlocked: ', b'Unlocked']:
    p = 0
    while True:
        idx = data.find(s, p)
        if idx < 0: break
        va = file_to_va(idx)
        key = (idx, s.decode('latin1'))
        strings[key] = va
        va_str2 = f"{va:#x}" if va else "N/A"
        print(f"  {s!r:25s} file={idx:#x}  VA={va_str2}")
        p = idx + 1

# ── Disassembler ──────────────────────────────────────────────────────────────
def dis(data, foff):
    """Returns (insn_bytes, mnemonic_string)"""
    if foff + 4 > len(data): return None, "??"
    insn = struct.unpack_from('<I', data, foff)[0]
    va = file_to_va(foff)
    pc = va if va else foff

    if insn == 0xD65F03C0: return insn, "RET"
    if insn == 0xD503201F: return insn, "NOP"
    if (insn & 0x9F000000) == 0x90000000:
        rd = insn & 0x1F
        immlo=(insn>>29)&3; immhi=(insn>>5)&0x7FFFF
        imm=(immhi<<2)|immlo
        if imm&(1<<20): imm-=(1<<21)
        return insn, f"ADRP X{rd}, {(pc&~0xFFF)+(imm<<12):#x}"
    if (insn & 0xFF800000) == 0x91000000:
        rd=insn&0x1F; rn=(insn>>5)&0x1F; imm=(insn>>10)&0xFFF; sh=(insn>>22)&1
        if sh: imm<<=12
        return insn, f"ADD  X{rd}, X{rn}, #{imm:#x}"
    if (insn & 0xFFC00000) == 0x39400000:
        rt=insn&0x1F; rn=(insn>>5)&0x1F; imm=(insn>>10)&0xFFF
        return insn, f"LDRB W{rt}, [X{rn}, #{imm:#x}]"
    if (insn & 0xFFC00000) == 0x39000000:
        rt=insn&0x1F; rn=(insn>>5)&0x1F; imm=(insn>>10)&0xFFF
        return insn, f"STRB W{rt}, [X{rn}, #{imm:#x}]"
    if (insn & 0xFFC00000) == 0xB9400000:
        rt=insn&0x1F; rn=(insn>>5)&0x1F; imm=((insn>>10)&0xFFF)*4
        return insn, f"LDR  W{rt}, [X{rn}, #{imm:#x}]"
    if (insn & 0xFFC00000) == 0xF9400000:
        rt=insn&0x1F; rn=(insn>>5)&0x1F; imm=((insn>>10)&0xFFF)*8
        return insn, f"LDR  X{rt}, [X{rn}, #{imm:#x}]"
    if (insn & 0xBF000000) == 0x18000000:  # LDR (literal) 32/64-bit
        rt=insn&0x1F; imm19=(insn>>5)&0x7FFFF
        if imm19&(1<<18): imm19-=(1<<19)
        return insn, f"LDR  W{rt}, [PC, #{imm19*4:+d}]  ; ={pc+imm19*4:#x}"
    if (insn & 0xFF000000) == 0x58000000:  # LDR (literal) 64-bit
        rt=insn&0x1F; imm19=(insn>>5)&0x7FFFF
        if imm19&(1<<18): imm19-=(1<<19)
        return insn, f"LDR  X{rt}, [PC, #{imm19*4:+d}]  ; ={pc+imm19*4:#x}"
    if (insn & 0x9F000000) == 0x10000000:  # ADR
        rd=insn&0x1F; immlo=(insn>>29)&3; immhi=(insn>>5)&0x7FFFF
        imm=(immhi<<2)|immlo
        if imm&(1<<20): imm-=(1<<21)
        return insn, f"ADR  X{rd}, {pc+imm:#x}"
    if (insn & 0xFC000000) == 0x94000000:
        imm26=insn&0x3FFFFFF
        if imm26&(1<<25): imm26-=(1<<26)
        return insn, f"BL   {pc+imm26*4:#x}"
    if (insn & 0xFC000000) == 0x14000000:
        imm26=insn&0x3FFFFFF
        if imm26&(1<<25): imm26-=(1<<26)
        return insn, f"B    {pc+imm26*4:#x}"
    if (insn & 0xFF000010) == 0x54000000:
        imm19=(insn>>5)&0x7FFFF
        if imm19&(1<<18): imm19-=(1<<19)
        cond=insn&0xF
        nm=['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
        return insn, f"B.{nm[cond]:<2} {pc+imm19*4:#x}"
    if (insn & 0x7E000000) == 0x34000000:
        op=(insn>>24)&1; sf=(insn>>31)&1
        imm19=(insn>>5)&0x7FFFF
        if imm19&(1<<18): imm19-=(1<<19)
        rt=insn&0x1F
        return insn, f"{'CBNZ' if op else 'CBZ '} {'X' if sf else 'W'}{rt}, {pc+imm19*4:#x}"
    if (insn & 0xFFC0001F) == 0x7100001F:
        imm=(insn>>10)&0xFFF; sh=(insn>>22)&1
        if sh: imm<<=12
        return insn, f"CMP  W{(insn>>5)&0x1F}, #{imm:#x}"
    if (insn & 0x7F800000) == 0x52800000:
        return insn, f"MOV  W{insn&0x1F}, #{(insn>>5)&0xFFFF:#x}"
    if (insn & 0xFFC0001F) == 0x7200001F:
        return insn, f"TST  W{(insn>>5)&0x1F}, ..."
    if (insn & 0xFFE0FFE0) == 0xAA0003E0:
        return insn, f"MOV  X{insn&0x1F}, X{(insn>>16)&0x1F}"
    return insn, f"0x{insn:08x}"

def dump(foff_start, count, mark_foff=None):
    for i in range(count):
        foff = foff_start + i*4
        insn, d = dis(data, foff)
        va = file_to_va(foff)
        m = ">>>" if foff == mark_foff else "   "
        print(f"  {m} {foff:#010x} VA={va:#010x if va else 0:010x}: {(insn or 0):08x}  {d}")

# ── Find code refs to target strings ─────────────────────────────────────────
# Method 1: ADRP+ADD
# Method 2: ADR (PC-relative, range ±1MB for 21-bit imm)
# Method 3: LDR literal (range ±1MB)

def find_all_refs_to_va(target_va):
    refs = []
    target_page = target_va & ~0xFFF
    target_off12 = target_va & 0xFFF
    for i in range(0, TEXT_SIZE - 4, 4):
        foff = TEXT_FS + i
        insn = struct.unpack_from('<I', data, foff)[0]
        va = TEXT_VA + i
        # ADRP + ADD
        if (insn & 0x9F000000) == 0x90000000:
            rd = insn & 0x1F
            immlo=(insn>>29)&3; immhi=(insn>>5)&0x7FFFF
            imm=(immhi<<2)|immlo
            if imm&(1<<20): imm-=(1<<21)
            pg = (va & ~0xFFF) + (imm<<12)
            if pg == target_page and foff+4 < len(data):
                insn2 = struct.unpack_from('<I', data, foff+4)[0]
                if (insn2 & 0xFF800000) == 0x91000000:
                    rd2=insn2&0x1F; rn2=(insn2>>5)&0x1F; imm2=(insn2>>10)&0xFFF
                    if rn2==rd and imm2==target_off12:
                        refs.append(('ADRP+ADD', foff))
        # ADR
        if (insn & 0x9F000000) == 0x10000000:
            rd=insn&0x1F; immlo=(insn>>29)&3; immhi=(insn>>5)&0x7FFFF
            imm=(immhi<<2)|immlo
            if imm&(1<<20): imm-=(1<<21)
            if va + imm == target_va:
                refs.append(('ADR', foff))
        # LDR literal (loads address from a PC-relative pool entry containing the VA)
        # Check 32-bit and 64-bit literal load
        if (insn & 0xFF000000) == 0x58000000:  # LDR Xt (64-bit literal)
            imm19=(insn>>5)&0x7FFFF
            if imm19&(1<<18): imm19-=(1<<19)
            pool_va = va + imm19*4
            pool_foff = va_to_file(pool_va)
            if pool_foff and pool_foff+8 <= len(data):
                val = struct.unpack_from('<Q', data, pool_foff)[0]
                if val == target_va:
                    refs.append(('LDR-lit', foff))
    return refs

print("\n" + "="*60)
print("Code refs to key strings:")
print("="*60)
for (foff_str, sname), va_str in strings.items():
    if va_str is None: continue
    refs = find_all_refs_to_va(va_str)
    print(f"\n  {sname!r} at file={foff_str:#x} VA={va_str:#x}:")
    if not refs:
        print("    No refs found via ADRP+ADD/ADR/LDR-literal")
        # Last resort: scan for VA as literal 32-bit or 64-bit value in code
        iva = struct.pack('<I', va_str & 0xFFFFFFFF)
        qva = struct.pack('<Q', va_str)
        for pattern, pname in [(qva, '64-bit'), (iva, '32-bit')]:
            p = 0
            while True:
                idx = data.find(pattern, TEXT_FS, TEXT_FS+TEXT_SIZE)
                if idx < 0: break
                print(f"    Literal {pname} match at file {idx:#x} (VA {file_to_va(idx):#x})")
                p = idx + 1
    for kind, ref_foff in refs[:5]:
        ref_va = file_to_va(ref_foff)
        print(f"    [{kind}] file={ref_foff:#x} VA={ref_va:#x}")
        dump(ref_foff - 15*4, 45, ref_foff)

# ── devinfo CRC analysis ──────────────────────────────────────────────────────
print("\n" + "="*60)
print("devinfo CRC analysis")
print("="*60)
with open(DEVINFO, 'rb') as fh:
    dv = bytearray(fh.read())
print(f"Size: {len(dv)} bytes  ({len(dv):#x})")
print("First 32 bytes:")
for i in range(0, min(64, len(dv)), 16):
    hexs = ' '.join(f'{b:02x}' for b in dv[i:i+16])
    ascs = ''.join(chr(b) if 32 <= b < 127 else '.' for b in dv[i:i+16])
    print(f"  {i:04x}: {hexs:<48}  {ascs}")

last4 = struct.unpack_from('<I', dv, len(dv)-4)[0]
last4_be = struct.unpack_from('>I', dv, len(dv)-4)[0]
crc_body = zlib.crc32(bytes(dv[:-4])) & 0xFFFFFFFF
crc_all  = zlib.crc32(bytes(dv)) & 0xFFFFFFFF
crc_16   = zlib.crc32(bytes(dv[:16])) & 0xFFFFFFFF
print(f"\nLast 4 bytes LE={last4:#010x}  BE={last4_be:#010x}")
print(f"CRC32(all-but-last-4): {crc_body:#010x}  {'MATCH!' if last4==crc_body else 'no match'}")
print(f"CRC32(first-16-bytes): {crc_16:#010x}")

# count non-zero bytes
nonzero = [(i, dv[i]) for i in range(min(64, len(dv))) if dv[i]]
print(f"\nNon-zero bytes (first 64): {[(hex(i), hex(v)) for i,v in nonzero]}")

# What we'd write for various is_unlocked candidates:
print("\nRequired values to set is_unlocked=1 at various offsets:")
for off in [0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13]:
    cur_val = dv[off] if off < len(dv) else '?'
    print(f"  dv[0x{off:02x}] = currently {cur_val:#04x}")
