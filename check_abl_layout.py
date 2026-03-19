#!/usr/bin/env python3
import struct

with open('/Users/xmxx/pinganhuijia/tmobile_abl_decompressed.bin','rb') as f:
    d = bytearray(f.read())

DELTA = 0xb8

def disasm_one(insn, i, delta=DELTA):
    top8 = insn >> 24
    cnames=['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
    if (insn & 0x9F000000) == 0x90000000:
        rd=insn&0x1f; immlo=(insn>>29)&3; immhi=(insn>>5)&0x7FFFF
        raw=(immhi<<2)|immlo
        if raw & (1<<20): raw -= (1<<21)
        page = ((i-delta)&~0xFFF) + (raw<<12)
        return f"ADRP x{rd}, #{hex(page)}"
    elif top8 in (0x94, 0x97):
        imm26 = insn & 0x3FFFFFF
        if imm26&(1<<25): imm26 -= (1<<26)
        target = (i-delta) + imm26*4
        return f"BL #{hex(target)} (file {hex(target+delta)})"
    elif top8 in (0x14, 0x17):
        imm26 = insn & 0x3FFFFFF
        if imm26&(1<<25): imm26 -= (1<<26)
        target = (i-delta) + imm26*4
        return f"B #{hex(target)} (file {hex(target+delta)})"
    elif top8 == 0x54:
        cond=insn&0xF
        imm19=(insn>>5)&0x7FFFF
        if imm19&(1<<18): imm19 -= (1<<19)
        target = (i-delta) + imm19*4
        return f"B.{cnames[cond]} #{hex(target)} (file {hex(target+delta)})"
    elif (insn>>23)==0x122:
        imm12=(insn>>10)&0xFFF; shift=(insn>>22)&1
        if shift: imm12<<=12
        return f"ADD x{insn&0x1f}, x{(insn>>5)&0x1f}, #{hex(imm12)}"
    elif top8 == 0x35:
        imm19=(insn>>5)&0x7FFFF
        if imm19&(1<<18): imm19-=(1<<19)
        t=(i-delta)+imm19*4
        return f"CBNZ x{insn&0x1f}, #{hex(t)} (file {hex(t+delta)})"
    elif top8 == 0x34:
        imm19=(insn>>5)&0x7FFFF
        if imm19&(1<<18): imm19-=(1<<19)
        t=(i-delta)+imm19*4
        return f"CBZ x{insn&0x1f}, #{hex(t)} (file {hex(t+delta)})"
    elif (insn>>22) == 0x3E5:
        # LDR 64-bit
        rn=(insn>>5)&0x1f; rt=insn&0x1f
        off12=((insn>>10)&0xFFF)*8
        return f"LDR x{rt}, [x{rn}, #{hex(off12)}]"
    elif (insn>>22) == 0x1C5:
        # LDR 32-bit
        rn=(insn>>5)&0x1f; rt=insn&0x1f
        off12=((insn>>10)&0xFFF)*4
        return f"LDR w{rt}, [x{rn}, #{hex(off12)}]"
    return f"?? {hex(insn)}"

# Hexdump around ERROR string
off = 0x592e4
print(f"=== Hexdump around ERROR string @ file {hex(off)} ===")
for i in range(off - 0x80, off + 0x80, 16):
    chunk = d[i:i+16]
    hex_str = ' '.join(f'{b:02x}' for b in chunk)
    asc_str = ''.join(chr(b) if 0x20<=b<0x7f else '.' for b in chunk)
    print(f"  {hex(i)}:  {hex_str:<47}  {asc_str}")

print()
print("=== 'Instructions' before ERROR string ===")
for i in range(off - 0x80, off, 4):
    insn = struct.unpack_from('<I', d, i)[0]
    print(f"  {hex(i)}: {insn:08x}  {disasm_one(insn, i)}")

print()
print("=== Check code density ===")
def looks_like_insn(v):
    t = v>>24
    return t in {0x94,0x97,0x14,0x17,0x54,0x91,0xB9,0xF9,0xA9,0xAA,0xEB,0xCA,0x52,
                 0xD2,0xF4,0xA8,0xD1,0xCB,0xD5,0x72,0x32,0xF8,0xB8,0xA8} or (v&0x9F000000)==0x90000000

r1 = sum(1 for i in range(0x10b8, 0x592b0, 4) if looks_like_insn(struct.unpack_from('<I',d,i)[0]))
t1 = (0x592b0 - 0x10b8) // 4
print(f".text before strings: {r1}/{t1} ({100*r1//max(1,t1)}%) look like instructions")

r2 = sum(1 for i in range(0x592b0-0x100, 0x592b0, 4) if looks_like_insn(struct.unpack_from('<I',d,i)[0]))
print(f"256 bytes before 'Unlocked': {r2}/64 ({100*r2//64}%) look like instructions")

r3 = sum(1 for i in range(0x592b0, 0x592b0+0x100, 4) if looks_like_insn(struct.unpack_from('<I',d,i)[0]))
print(f"256 bytes after 'Unlocked': {r3}/64 ({100*r3//64}%) look like instructions")

# Check some known-good code region around offset 0x20000
r4 = sum(1 for i in range(0x20000, 0x20200, 4) if looks_like_insn(struct.unpack_from('<I',d,i)[0]))
print(f"Region 0x20000-0x20200 (should be code): {r4}/128 ({100*r4//128}%)")
