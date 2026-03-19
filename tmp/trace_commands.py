#!/usr/bin/env python3
"""
1. 读取命令表字符串 — 找出 0x3C328 对应的 OEM 命令名
2. 解码 0x34E50（在 OemCheckResetDevInfo 前调用的关键函数）
3. 检查 0x22CA8 WriteDeviceInfo 与 0x18248 的区别
4. 搜索 devinfo 缓冲区是否被 memset/memcpy 清零
5. 0x1F8F0 和 0x1EA00 — boot中的两个函数
"""
import struct

PE32 = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
TEXT_SIZE = 0x6A000

with open(PE32, "rb") as f:
    pe = f.read()
code = pe[:TEXT_SIZE]

def read_string(addr, maxlen=100):
    if addr >= len(pe): return "(out of range)"
    end = addr
    while end < min(addr + maxlen, len(pe)) and pe[end] != 0:
        end += 1
    return pe[addr:end].decode('utf-8', errors='replace')

def decode_simple(addr):
    if addr < 0 or addr + 4 > TEXT_SIZE:
        return "OUT"
    insn = struct.unpack_from('<I', code, addr)[0]
    if insn == 0xD65F03C0: return "ret"
    if insn == 0xD503201F: return "nop"
    if insn == 0: return ".word 0"
    if (insn & 0xFC000000) == 0x94000000:
        off = insn & 0x03FFFFFF
        if off & (1<<25): off -= (1<<26)
        return f"bl 0x{addr+off*4:05X}"
    if (insn & 0xFC000000) == 0x14000000:
        off = insn & 0x03FFFFFF
        if off & (1<<25): off -= (1<<26)
        return f"b 0x{addr+off*4:05X}"
    if (insn & 0xFF000010) == 0x54000000:
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1<<18): imm19 -= (1<<19)
        conds = {0:'EQ',1:'NE',2:'CS',3:'CC',4:'MI',5:'PL',6:'VS',7:'VC',8:'HI',9:'LS',10:'GE',11:'LT',12:'GT',13:'LE'}
        return f"b.{conds.get(insn&0xf,'?')} 0x{addr+imm19*4:05X}"
    if (insn & 0x7E000000) == 0x34000000:
        sf="x" if (insn>>31) else "w"
        op="cbnz" if (insn>>24)&1 else "cbz"
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1<<18): imm19 -= (1<<19)
        return f"{op} {sf}{insn&0x1f}, 0x{addr+imm19*4:05X}"
    if (insn & 0x7E000000) == 0x36000000:
        op="tbnz" if (insn>>24)&1 else "tbz"
        bit = ((insn>>31)<<5)|((insn>>19)&0x1f)
        imm14 = (insn >> 5) & 0x3FFF
        if imm14 & (1<<13): imm14 -= (1<<14)
        return f"{op} x{insn&0x1f}, #{bit}, 0x{addr+imm14*4:05X}"
    if (insn & 0x9F000000) == 0x90000000:
        rd = insn & 0x1f
        immlo = (insn>>29)&3; immhi = (insn>>5)&0x7ffff
        imm = (immhi<<2)|immlo
        if imm & (1<<20): imm -= (1<<21)
        pg = (addr & ~0xFFF) + (imm << 12)
        return f"adrp x{rd}, 0x{pg:X}"
    if (insn & 0xFF000000) == 0x91000000:
        return f"add x{insn&0x1f}, x{(insn>>5)&0x1f}, #0x{(insn>>10)&0xFFF:X}"
    if (insn & 0xFF000000) == 0xD1000000:
        return f"sub x{insn&0x1f}, x{(insn>>5)&0x1f}, #0x{(insn>>10)&0xFFF:X}"
    if (insn & 0xFF800000) == 0x52800000:
        return f"mov w{insn&0x1f}, #0x{((insn>>5)&0xFFFF):X}"
    if (insn & 0xFFE0FFE0) == 0xAA0003E0:
        return f"mov x{insn&0x1f}, x{(insn>>16)&0x1f}"
    if (insn & 0xFFE0FFE0) == 0x2A0003E0:
        return f"mov w{insn&0x1f}, w{(insn>>16)&0x1f}"
    if (insn & 0xFFC00000) == 0x39000000:
        return f"strb w{insn&0x1f}, [x{(insn>>5)&0x1f}, #{(insn>>10)&0xFFF}]"
    if (insn & 0xFFC00000) == 0x39400000:
        return f"ldrb w{insn&0x1f}, [x{(insn>>5)&0x1f}, #{(insn>>10)&0xFFF}]"
    if (insn & 0xFFC00000) == 0xF9400000:
        return f"ldr x{insn&0x1f}, [x{(insn>>5)&0x1f}, #{((insn>>10)&0xFFF)*8}]"
    if (insn & 0xFFC00000) == 0xF9000000:
        return f"str x{insn&0x1f}, [x{(insn>>5)&0x1f}, #{((insn>>10)&0xFFF)*8}]"
    if (insn & 0xFFC00000) == 0xB9400000:
        return f"ldr w{insn&0x1f}, [x{(insn>>5)&0x1f}, #{((insn>>10)&0xFFF)*4}]"
    if (insn & 0xFFC00000) == 0xB9000000:
        return f"str w{insn&0x1f}, [x{(insn>>5)&0x1f}, #{((insn>>10)&0xFFF)*4}]"
    if (insn & 0xFF80001F) == 0x7100001F:
        return f"cmp w{(insn>>5)&0x1f}, #{(insn>>10)&0xFFF}"
    if (insn & 0xFF80001F) == 0xF100001F:
        return f"cmp x{(insn>>5)&0x1f}, #{(insn>>10)&0xFFF}"
    if (insn & 0xFFFFFC1F) == 0xD63F0000:
        return f"blr x{(insn>>5)&0x1f}"
    if (insn & 0xFFFFFC1F) == 0xD61F0000:
        return f"br x{(insn>>5)&0x1f}"
    return f"0x{insn:08X}"

# ==========================================
print("=" * 60)
print("=== 1. 命令调度表 — 命令名 ===")
print("=" * 60)
for off in range(0x63400, min(0x635D0, len(pe)), 16):
    func = struct.unpack_from('<Q', pe, off)[0]
    str_addr = struct.unpack_from('<Q', pe, off+8)[0]
    s = read_string(str_addr) if 0 < str_addr < len(pe) else "???"
    mark = " <<<" if off == 0x63498 else ""
    print(f"  0x{off:05X}: func=0x{func:05X}  cmd=\"{s}\"{mark}")

# ==========================================
print(f"\n{'='*60}")
print("=== 2. 0x3C328 相关命令字符串 ===")
print("=" * 60)
# Entry at 0x63498 (string for 0x3C328 at 0x634A0)
# Actually let me re-check: the table is {func, string} pairs at 16-byte stride
# So for 0x634A0 (func=0x3C328), the string is at 0x634A8
str_3c328 = struct.unpack_from('<Q', pe, 0x634A8)[0]
print(f"  0x3C328 command string at 0x{str_3c328:05X}: \"{read_string(str_3c328)}\"")

# Also check the previous entry - string at 0x63498
str_prev = struct.unpack_from('<Q', pe, 0x63498)[0]
print(f"  Previous cmd at 0x{str_prev:05X}: \"{read_string(str_prev)}\"")

# ==========================================
print(f"\n{'='*60}")
print("=== 3. 解码 0x22CA8 WriteDeviceInfo ===")
print("=" * 60)
for a in range(0x22CA8, min(0x22D40, TEXT_SIZE), 4):
    d = decode_simple(a)
    mark = ""
    if "0x18248" in d: mark = " ← calls ReadWritePartition!"
    print(f"  0x{a:05X}: {d}{mark}")
    if d == "ret":
        break

# ==========================================
print(f"\n{'='*60}")
print("=== 4. 解码 0x34E50（OemCheckResetDevInfo前调用）===")
print("=" * 60)
for a in range(0x34E50, min(0x34E50 + 0x400, TEXT_SIZE), 4):
    d = decode_simple(a)
    mark = ""
    if "0x362D" in d: mark = " ← OemCheckResetDevInfo!"
    elif "0x384D0" in d: mark = " ← init_defaults!"
    elif "0x22C18" in d: mark = " ← IsDeviceUnlocked!"
    elif "0x18248" in d: mark = " ← ReadWriteDevInfo!"
    elif "0x232D8" in d: mark = " ← ReadDeviceInfo!"
    elif "0x384B0" in d: mark = " ← SetIsUnlocked!"
    elif "0x22CA8" in d: mark = " ← WriteDeviceInfo!"
    elif "0x1BD" in d: mark = " ← devinfo buffer page!"
    elif "0x38" in d and d.startswith("bl "):
        target = int(d.split("0x")[1], 16)
        if 0x38400 <= target <= 0x38700: mark = " ← devinfo area!"
    print(f"  0x{a:05X}: {d}{mark}")
    if d == "ret" and a > 0x34E60:
        break

# ==========================================
print(f"\n{'='*60}")
print("=== 5. IsSecureBootEnabled 0x189E0 分析 ===")
print("=" * 60)
for a in range(0x189E0, min(0x189E0 + 0x60, TEXT_SIZE), 4):
    d = decode_simple(a)
    print(f"  0x{a:05X}: {d}")
    if d == "ret":
        break

# ==========================================
print(f"\n{'='*60}")
print("=== 6. 检查 init_defaults 的 TST 指令 ===")
print("=" * 60)
# At 0x38524: tst w0, #bitmask — what bitmask?
insn = struct.unpack_from('<I', code, 0x38524)[0]
print(f"  0x38524: raw=0x{insn:08X}")
# TST (ANDS wzr): 0111 0010 Noorrrrr mmssssss nnnnn 11111
# Actually TST is: 0111001000Nrrrrrrssssss nnnnn 11111
if (insn & 0x7F80001F) == 0x7200001F:
    N = (insn >> 22) & 1
    immr = (insn >> 16) & 0x3f
    imms = (insn >> 10) & 0x3f
    rn = (insn >> 5) & 0x1f
    print(f"  TST w{rn}: N={N}, immr={immr}, imms={imms}")
    # For 32-bit, bitmask immediate:
    # If N=0, element size determined by highest bit of ~imms
    # Simple case: if imms = 0, immr determines rotation
    # Let's compute
    len_val = 32
    levels = (imms & 0x1f) if N == 0 else 63
    s = imms & 0x3f
    r = immr & 0x3f
    welem = (1 << ((s & 0x1f) + 1)) - 1
    welem = ((welem >> r) | (welem << (32 - r))) & 0xFFFFFFFF
    print(f"  Computed bitmask (approx): 0x{welem:X}")
    # Simpler: for tst w0, #0xFF → N=0, immr=0, imms=7
    # For tst w0, #1 → N=0, immr=0, imms=0
    if imms == 0 and immr == 0 and N == 0:
        print(f"  → TST w{rn}, #0x1")
    elif imms <= 31 and immr == 0 and N == 0:
        mask = (1 << (imms + 1)) - 1
        print(f"  → TST w{rn}, #0x{mask:X}")

# Also check 0x3852C cset
insn2 = struct.unpack_from('<I', code, 0x3852C)[0]
print(f"\n  0x3852C: raw=0x{insn2:08X}")
# CSINC: 0 sf 0 11010100 Rm cond o2 Rn Rd
# For 32-bit: 0 0 0 11010100 Rm cond 0 1 Rn Rd
# 1A9F17E9: 0001 1010 1001 1111 0001 0111 1110 1001
sf = (insn2 >> 31) & 1
rm = (insn2 >> 16) & 0x1f
cond = (insn2 >> 12) & 0xf
o2 = (insn2 >> 10) & 1
rn = (insn2 >> 5) & 0x1f
rd = insn2 & 0x1f
conds = {0:'EQ',1:'NE',2:'CS',3:'CC',4:'MI',5:'PL',6:'VS',7:'VC',8:'HI',9:'LS',10:'GE',11:'LT',12:'GT',13:'LE'}
print(f"  CSINC: sf={sf}, rm=w{rm}, cond={conds.get(cond,'?')}({cond}), rn=w{rn}, rd=w{rd}")
if rm == 31 and rn == 31:
    inv_cond = cond ^ 1  # invert condition
    print(f"  → CSET w{rd}, {conds.get(inv_cond, '?')} (inverted from {conds.get(cond,'?')})")
    print(f"  Meaning: w{rd} = ({conds.get(inv_cond,'?')} ? 1 : 0)")
    print(f"  After TST w0, #bitmask:")
    print(f"    If SecureBoot returns 0: TST sets Z→EQ, w{rd} = ({'1 (unlocked)' if inv_cond==0 else '0 (locked)'})")
    print(f"    If SecureBoot returns 1: TST clears Z→NE, w{rd} = ({'0 (locked)' if inv_cond==0 else '1 (unlocked)'})")

# ==========================================
print(f"\n{'='*60}")
print("=== 7. GUID at 0x69BE0 (devinfo partition protocol) ===")
print("=" * 60)
if 0x69BE0 + 16 <= len(pe):
    guid = pe[0x69BE0:0x69BE0+16]
    d1 = struct.unpack_from('<I', guid, 0)[0]
    d2 = struct.unpack_from('<H', guid, 4)[0]
    d3 = struct.unpack_from('<H', guid, 6)[0]
    d4 = guid[8:16].hex().upper()
    print(f"  GUID: {d1:08X}-{d2:04X}-{d3:04X}-{d4[:4]}-{d4[4:]}")

# ==========================================
print(f"\n{'='*60}")
print("=== 8. 0x30890 函数（OemCheckResetDevInfo后调用） ===")
print("=" * 60)
for a in range(0x30890, min(0x30890 + 0x200, TEXT_SIZE), 4):
    d = decode_simple(a)
    mark = ""
    if "0x384D0" in d: mark = " ← init_defaults!"
    elif "0x22C18" in d: mark = " ← IsDeviceUnlocked!"
    elif "0x18248" in d: mark = " ← ReadWriteDevInfo!"
    elif "0x232D8" in d: mark = " ← ReadDeviceInfo!"
    elif "0x384B0" in d: mark = " ← SetIsUnlocked!"
    elif "0x22CA8" in d: mark = " ← WriteDeviceInfo!"
    elif d.startswith("bl "):
        target = int(d.split("0x")[1], 16)
        if 0x384B0 <= target <= 0x386FF: mark = " ← devinfo func area!"
    print(f"  0x{a:05X}: {d}{mark}")
    if d == "ret" and a > 0x30900:
        break
