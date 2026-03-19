#!/usr/bin/env python3
import struct

MZ_OFF = 0xB8
f = open('/Users/xmxx/pinganhuijia/global_abl_decompressed.bin','rb').read()

e_lfanew = struct.unpack_from('<I', f, MZ_OFF + 0x3C)[0]
PE_SIG = MZ_OFF + e_lfanew
assert f[PE_SIG:PE_SIG+4] == b'PE\x00\x00', f"PE not at {PE_SIG:#x}: {f[PE_SIG:PE_SIG+4].hex()}"

coff_off = PE_SIG + 4
machine, num_sections = struct.unpack_from('<HH', f, coff_off)
opt_size, = struct.unpack_from('<H', f, coff_off + 16)
opt_off = coff_off + 20
opt_magic, = struct.unpack_from('<H', f, opt_off)
image_base = struct.unpack_from('<Q', f, opt_off+24)[0] if opt_magic==0x20b else struct.unpack_from('<I', f, opt_off+28)[0]

print(f"PE sig at: {PE_SIG:#x}  ImageBase: {image_base:#x}  Sections: {num_sections}")

sect_off = opt_off + opt_size
sections = []
print(f"\n{'Name':<10} {'VA':>10} {'VSize':>10} {'RawOff':>10} {'RawSize':>10}  FileStart  FileEnd")
for i in range(num_sections):
    s = sect_off + i*40
    name = f[s:s+8].rstrip(b'\x00').decode('latin1')
    vsize, vaddr, raw_size, raw_off = struct.unpack_from('<IIII', f, s+8)
    fs = MZ_OFF + raw_off
    fe = fs + raw_size
    sections.append((name, image_base+vaddr, vsize, MZ_OFF+raw_off, raw_size))
    print(f"{name:<10} {image_base+vaddr:>10x} {vsize:>10x} {raw_off:>10x} {raw_size:>10x}  {fs:#x}  {fe:#x}")

def file_to_va(foff):
    for nm,va,vsz,fs,rsz in sections:
        if fs <= foff < fs+rsz:
            return va + (foff-fs)
    return None

def va_to_file(va):
    for nm,vva,vsz,fs,rsz in sections:
        if vva <= va < vva+vsz:
            return fs + (va-vva)
    return None

# Find key strings and their VAs
print("\nString locations:")
for s in [b'ANDROID-BOOT!', b'Device unlocked', b'Unlocked', b'unlocked: ', b'is_unlocked']:
    idx = 0
    while True:
        idx = f.find(s, idx)
        if idx < 0: break
        va = file_to_va(idx)
        print(f"  {s!r:28s} file={idx:#x}  VA={va:#x if va else 'N/A'}")
        idx += 1

# Find ADRP refs to "Device unlocked" string
print("\nFinding code refs to 'Device unlocked' and 'Unlocked'...")
text_sec = sections[0]  # First section is .text
nm, text_va, text_vsz, text_fs, text_rsz = text_sec
print(f"Searching in section '{nm}' file={text_fs:#x} size={text_rsz:#x}")

targets = {}
for s in [b'Device unlocked', b'Unlocked']:
    idx = 0
    while True:
        idx = f.find(s, idx)
        if idx < 0: break
        va = file_to_va(idx)
        if va:
            targets[idx] = (s.decode(), va)
        idx += 1

for foff_str, (name, str_va) in targets.items():
    page = str_va & ~0xFFF
    off12 = str_va & 0xFFF
    refs = []
    for i in range(0, text_rsz-4, 4):
        foff = text_fs + i
        insn = struct.unpack_from('<I', f, foff)[0]
        pc = text_va + i
        if (insn & 0x9F000000) != 0x90000000: continue
        rd = insn & 0x1F
        immlo = (insn>>29)&0x3; immhi = (insn>>5)&0x7FFFF
        imm = (immhi<<2)|immlo
        if imm & (1<<20): imm -= (1<<21)
        pg = (pc & ~0xFFF) + (imm<<12)
        if pg != page: continue
        if foff+4 < len(f):
            insn2 = struct.unpack_from('<I', f, foff+4)[0]
            if (insn2&0xFF800000)==0x91000000:
                rd2=insn2&0x1F; rn2=(insn2>>5)&0x1F; imm12=(insn2>>10)&0xFFF
                if rn2==rd and imm12==off12:
                    refs.append((foff, pc))
    print(f"\n  String '{name}' at file {foff_str:#x} VA {str_va:#x}: {len(refs)} code refs")
    for rf_foff, rf_va in refs[:5]:
        print(f"    Ref at file {rf_foff:#x} (VA {rf_va:#x})")
        # Dump context
        for j in range(-25, 40):
            off = rf_foff + j*4
            if off < 0 or off+4 > len(f): continue
            insn = struct.unpack_from('<I', f, off)[0]
            va2 = file_to_va(off)
            pc2 = va2 if va2 else off
            marker = ">>>" if off == rf_foff else "   "
            # quick decode
            d = f"0x{insn:08x}"
            if insn == 0xD65F03C0: d = "RET"
            elif insn == 0xD503201F: d = "NOP"
            elif (insn&0x9F000000)==0x90000000:
                rd=insn&0x1F; immlo=(insn>>29)&0x3; immhi=(insn>>5)&0x7FFFF
                imm=(immhi<<2)|immlo
                if imm&(1<<20): imm-=(1<<21)
                d=f"ADRP X{rd}, {(pc2&~0xFFF)+(imm<<12):#x}"
            elif (insn&0xFF800000)==0x91000000:
                rd=insn&0x1F; rn=(insn>>5)&0x1F; imm=(insn>>10)&0xFFF
                d=f"ADD  X{rd}, X{rn}, #{imm:#x}"
            elif (insn&0xFFC00000)==0x39400000:
                d=f"LDRB W{insn&0x1F}, [X{(insn>>5)&0x1F}, #{(insn>>10)&0xFFF:#x}]"
            elif (insn&0xFFC00000)==0x39000000:
                d=f"STRB W{insn&0x1F}, [X{(insn>>5)&0x1F}, #{(insn>>10)&0xFFF:#x}]"
            elif (insn&0xFFC00000)==0xB9400000:
                d=f"LDR  W{insn&0x1F}, [X{(insn>>5)&0x1F}, #{((insn>>10)&0xFFF)*4:#x}]"
            elif (insn&0xFFC00000)==0xF9400000:
                d=f"LDR  X{insn&0x1F}, [X{(insn>>5)&0x1F}, #{((insn>>10)&0xFFF)*8:#x}]"
            elif (insn&0xFC000000)==0x94000000:
                imm26=insn&0x3FFFFFF
                if imm26&(1<<25): imm26-=(1<<26)
                d=f"BL   {pc2+imm26*4:#x}"
            elif (insn&0xFC000000)==0x14000000:
                imm26=insn&0x3FFFFFF
                if imm26&(1<<25): imm26-=(1<<26)
                d=f"B    {pc2+imm26*4:#x}"
            elif (insn&0xFF000010)==0x54000000:
                imm19=(insn>>5)&0x7FFFF
                if imm19&(1<<18): imm19-=(1<<19)
                cond=insn&0xF
                nn=['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
                d=f"B.{nn[cond]:<2} {pc2+imm19*4:#x}"
            elif (insn&0x7E000000)==0x34000000:
                op=(insn>>24)&1; imm19=(insn>>5)&0x7FFFF
                if imm19&(1<<18): imm19-=(1<<19)
                rt=insn&0x1F
                d=f"{'CBNZ' if op else 'CBZ '} W{rt}, {pc2+imm19*4:#x}"
            elif (insn&0xFFC0001F)==0x7100001F:
                imm=(insn>>10)&0xFFF
                d=f"CMP  W{(insn>>5)&0x1F}, #{imm:#x}"
            print(f"    {marker} {off:#010x} (VA {va2:#010x if va2 else 0:010x}): {insn:08x}  {d}")
        print()

# Check devinfo for CRC/checksum
print("="*65)
print("devinfo_unlocked.bin analysis")
print("="*65)
with open('/Users/xmxx/pinganhuijia/edl_backup/devinfo_unlocked.bin', 'rb') as fh:
    dv = bytearray(fh.read())
print(f"Size: {len(dv)} bytes")
print("First 32 bytes:", dv[:32].hex(' '))
print(f"  [0x0D]={dv[0xD]:#04x}  [0x0E]={dv[0xE]:#04x}  [0x0F]={dv[0xF]:#04x}  [0x10]={dv[0x10]:#04x}")
import zlib
last4 = struct.unpack_from('<I', dv, len(dv)-4)[0]
crc32_body = zlib.crc32(bytes(dv[:-4])) & 0xFFFFFFFF
print(f"Last 4 bytes: {last4:#010x}")
print(f"CRC32 of all-but-last-4: {crc32_body:#010x}")
print(f"Match: {last4 == crc32_body}")
# check nonzero regions in devinfo
nonzero = [(i, dv[i]) for i in range(len(dv)) if dv[i] != 0]
print(f"Non-zero bytes: {[(hex(i), hex(v)) for i,v in nonzero[:20]]}")
