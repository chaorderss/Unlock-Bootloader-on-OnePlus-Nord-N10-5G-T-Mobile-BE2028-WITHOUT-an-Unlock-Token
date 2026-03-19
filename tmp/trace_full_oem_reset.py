#!/usr/bin/env python3
"""
完整反汇编 OemCheckResetDevInfo (0x362D8 - 0x36700)
逐条指令，追踪所有分支
"""
import struct

PE = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
with open(PE, "rb") as f:
    pe = f.read()

def decode(off, inst):
    s = f"0x{off:05X}: 0x{inst:08X}"
    if inst == 0xD65F03C0: return s + "  ret"
    if inst == 0x00000000: return s + "  nop"

    # BL
    if (inst >> 26) == 0x25:
        imm = inst & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        t = off + (imm << 2)
        return s + f"  bl 0x{t & 0xFFFFFFFF:05X}"
    # B
    if (inst >> 26) == 0x05:
        imm = inst & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        t = off + (imm << 2)
        return s + f"  b 0x{t & 0xFFFFFFFF:05X}"
    # ADRP
    if (inst & 0x9F000000) == 0x90000000:
        rd = inst & 0x1F
        immhi = (inst >> 5) & 0x7FFFF; immlo = (inst >> 29) & 0x3
        iv = (immhi << 2) | immlo
        if iv & 0x100000: iv |= ~0x1FFFFF
        pg = ((off & ~0xFFF) + (iv << 12)) & 0xFFFFFFFF
        return s + f"  adrp x{rd}, 0x{pg:X}"
    # ADD Xd, Xn, #imm
    if (inst & 0xFF800000) == 0x91000000:
        rd = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm12 = (inst >> 10) & 0xFFF
        sh = (inst >> 22) & 1
        if sh: imm12 <<= 12
        return s + f"  add x{rd}, x{rn}, #0x{imm12:X}"
    # SUB Xd, Xn, #imm
    if (inst & 0xFF800000) == 0xD1000000:
        rd = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm12 = (inst >> 10) & 0xFFF
        return s + f"  sub x{rd}, x{rn}, #0x{imm12:X}"
    # STRB
    if (inst & 0xFFC00000) == 0x39000000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = (inst >> 10) & 0xFFF
        return s + f"  strb w{rt}, [x{rn}, #{imm}]"
    # LDRB
    if (inst & 0xFFC00000) == 0x39400000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = (inst >> 10) & 0xFFF
        return s + f"  ldrb w{rt}, [x{rn}, #{imm}]"
    # LDR Xt (unsigned offset)
    if (inst & 0xFFC00000) == 0xF9400000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = ((inst >> 10) & 0xFFF) * 8
        return s + f"  ldr x{rt}, [x{rn}, #{imm}]"
    # STR Xt (unsigned offset)
    if (inst & 0xFFC00000) == 0xF9000000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = ((inst >> 10) & 0xFFF) * 8
        return s + f"  str x{rt}, [x{rn}, #{imm}]"
    # LDR Wt
    if (inst & 0xFFC00000) == 0xB9400000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = ((inst >> 10) & 0xFFF) * 4
        return s + f"  ldr w{rt}, [x{rn}, #{imm}]"
    # STR Wt
    if (inst & 0xFFC00000) == 0xB9000000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F; imm = ((inst >> 10) & 0xFFF) * 4
        return s + f"  str w{rt}, [x{rn}, #{imm}]"
    # LDUR
    if (inst & 0xFFE00C00) == 0xB8400000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F
        imm9 = (inst >> 12) & 0x1FF
        if imm9 & 0x100: imm9 -= 0x200
        return s + f"  ldur w{rt}, [x{rn}, #{imm9}]"
    # LDUR X
    if (inst & 0xFFE00C00) == 0xF8400000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F
        imm9 = (inst >> 12) & 0x1FF
        if imm9 & 0x100: imm9 -= 0x200
        return s + f"  ldur x{rt}, [x{rn}, #{imm9}]"
    # STUR
    if (inst & 0xFFE00C00) == 0xB8000000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F
        imm9 = (inst >> 12) & 0x1FF
        if imm9 & 0x100: imm9 -= 0x200
        return s + f"  stur w{rt}, [x{rn}, #{imm9}]"
    if (inst & 0xFFE00C00) == 0xF8000000:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F
        imm9 = (inst >> 12) & 0x1FF
        if imm9 & 0x100: imm9 -= 0x200
        return s + f"  stur x{rt}, [x{rn}, #{imm9}]"
    # B.cond
    if (inst & 0xFF000000) == 0x54000000:
        imm19 = (inst >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 |= ~0x7FFFF
        t = off + (imm19 << 2)
        c = inst & 0xF
        cn = {0:'EQ',1:'NE',2:'CS',3:'CC',4:'MI',5:'PL',6:'VS',7:'VC',
              8:'HI',9:'LS',10:'GE',11:'LT',12:'GT',13:'LE',14:'AL'}
        return s + f"  b.{cn.get(c,'?')} 0x{t & 0xFFFFFFFF:05X}"
    # CBZ/CBNZ
    for pfx, mn in [(0xB4,'cbz x'),(0xB5,'cbnz x'),(0x34,'cbz w'),(0x35,'cbnz w')]:
        if inst >> 24 == pfx:
            rt = inst & 0x1F; imm19 = (inst >> 5) & 0x7FFFF
            if imm19 & 0x40000: imm19 |= ~0x7FFFF
            t = off + (imm19 << 2)
            return s + f"  {mn}{rt}, 0x{t & 0xFFFFFFFF:05X}"
    # TBZ/TBNZ
    if (inst & 0x7E000000) == 0x36000000:
        b5 = (inst >> 31) & 1; op = (inst >> 24) & 1
        b40 = (inst >> 19) & 0x1F; bp = (b5 << 5) | b40
        imm14 = (inst >> 5) & 0x3FFF
        if imm14 & 0x2000: imm14 |= ~0x3FFF
        t = off + (imm14 << 2)
        mn = "tbnz" if op else "tbz"
        return s + f"  {mn} w{inst&0x1F}, #{bp}, 0x{t & 0xFFFFFFFF:05X}"
    # MOV Wd, #imm16
    if (inst & 0xFF800000) == 0x52800000:
        rd = inst & 0x1F; imm16 = (inst >> 5) & 0xFFFF
        return s + f"  mov w{rd}, #{imm16}"
    # MOVZ Xd, #imm16
    if (inst & 0xFF800000) == 0xD2800000:
        rd = inst & 0x1F; imm16 = (inst >> 5) & 0xFFFF
        hw = (inst >> 21) & 3
        return s + f"  movz x{rd}, #0x{imm16:X}" + (f", lsl #{hw*16}" if hw else "")
    # MOVK
    if (inst & 0xFF800000) == 0xF2800000:
        rd = inst & 0x1F; imm16 = (inst >> 5) & 0xFFFF
        hw = (inst >> 21) & 3
        return s + f"  movk x{rd}, #0x{imm16:X}, lsl #{hw*16}"
    # MOV Xd, Xm
    if (inst & 0xFFE0FFE0) == 0xAA0003E0:
        rd = inst & 0x1F; rm = (inst >> 16) & 0x1F
        return s + f"  mov x{rd}, x{rm}"
    # MOV Wd, Wm
    if (inst & 0xFFE0FFE0) == 0x2A0003E0:
        rd = inst & 0x1F; rm = (inst >> 16) & 0x1F
        return s + f"  mov w{rd}, w{rm}"
    # CMP Wn, #imm
    if (inst & 0xFFC0001F) == 0x7100001F:
        rn = (inst >> 5) & 0x1F; imm = (inst >> 10) & 0xFFF
        return s + f"  cmp w{rn}, #{imm}"
    # CMP Xn, Xm
    if (inst & 0xFFE0FC1F) == 0xEB00001F:
        rn = (inst >> 5) & 0x1F; rm = (inst >> 16) & 0x1F
        return s + f"  cmp x{rn}, x{rm}"
    # ORR (bitmask imm) - includes MOV from bitmask
    if (inst & 0xFFC00000) == 0x32000000:
        rd = inst & 0x1F; rn = (inst >> 5) & 0x1F
        immr = (inst >> 16) & 0x3F; imms = (inst >> 10) & 0x3F
        # Simplified: just show raw
        return s + f"  orr w{rd}, w{rn}, #bitmask(immr={immr},imms={imms})"
    if (inst & 0xFFC00000) == 0xB2000000:
        rd = inst & 0x1F; rn = (inst >> 5) & 0x1F
        return s + f"  orr x{rd}, x{rn}, #bitmask"
    # TST
    if (inst & 0xFFC0001F) == 0x72000000 | 0x1F:
        # TST Wn, #bitmask = ANDS WZR, Wn, #bitmask
        pass
    # BLR/BR/RET
    if (inst & 0xFFFFFC00) == 0xD63F0000:
        rn = (inst >> 5) & 0x1F
        return s + f"  blr x{rn}"
    if (inst & 0xFFFFFC00) == 0xD61F0000:
        rn = (inst >> 5) & 0x1F
        return s + f"  br x{rn}"
    # STP
    if (inst & 0x7FC00000) == 0xA9000000:
        rt = inst & 0x1F; rt2 = (inst >> 10) & 0x1F; rn = (inst >> 5) & 0x1F
        imm7 = (inst >> 15) & 0x7F
        if imm7 & 0x40: imm7 -= 0x80
        sf = inst >> 31
        sz = 8 if sf else 4
        rp = 'x' if sf else 'w'
        return s + f"  stp {rp}{rt}, {rp}{rt2}, [x{rn}, #{imm7*sz}]"
    # LDP
    if (inst & 0x7FC00000) == 0xA9400000:
        rt = inst & 0x1F; rt2 = (inst >> 10) & 0x1F; rn = (inst >> 5) & 0x1F
        imm7 = (inst >> 15) & 0x7F
        if imm7 & 0x40: imm7 -= 0x80
        sf = inst >> 31
        sz = 8 if sf else 4
        rp = 'x' if sf else 'w'
        return s + f"  ldp {rp}{rt}, {rp}{rt2}, [x{rn}, #{imm7*sz}]"
    # STP pre-index
    if (inst & 0x7FC00000) == 0xA9800000:
        rt = inst & 0x1F; rt2 = (inst >> 10) & 0x1F; rn = (inst >> 5) & 0x1F
        imm7 = (inst >> 15) & 0x7F
        if imm7 & 0x40: imm7 -= 0x80
        sf = inst >> 31
        sz = 8 if sf else 4
        rp = 'x' if sf else 'w'
        return s + f"  stp {rp}{rt}, {rp}{rt2}, [x{rn}, #{imm7*sz}]!"
    # LDP post-index (A8C...)
    if (inst & 0x7FC00000) == 0xA8C00000:
        rt = inst & 0x1F; rt2 = (inst >> 10) & 0x1F; rn = (inst >> 5) & 0x1F
        imm7 = (inst >> 15) & 0x7F
        if imm7 & 0x40: imm7 -= 0x80
        sf = inst >> 31
        sz = 8 if sf else 4
        rp = 'x' if sf else 'w'
        return s + f"  ldp {rp}{rt}, {rp}{rt2}, [x{rn}], #{imm7*sz}"
    # STR pre-index (F81...)
    if (inst & 0xFFE00C00) == 0xF8000C00:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F
        imm9 = (inst >> 12) & 0x1FF
        if imm9 & 0x100: imm9 -= 0x200
        return s + f"  str x{rt}, [x{rn}, #{imm9}]!"
    # LDR pre-index
    if (inst & 0xFFE00C00) == 0xF8400C00:
        rt = inst & 0x1F; rn = (inst >> 5) & 0x1F
        imm9 = (inst >> 12) & 0x1FF
        if imm9 & 0x100: imm9 -= 0x200
        return s + f"  ldr x{rt}, [x{rn}, #{imm9}]!"
    # CSINC / CSEL / etc
    if (inst & 0xFFE00C00) == 0x1A800400:  # CSINC (32-bit)
        rd = inst & 0x1F; rn = (inst >> 5) & 0x1F; rm = (inst >> 16) & 0x1F
        cond = (inst >> 12) & 0xF
        cn = {0:'EQ',1:'NE',2:'CS',3:'CC',4:'MI',5:'PL',6:'VS',7:'VC',
              8:'HI',9:'LS',10:'GE',11:'LT',12:'GT',13:'LE',14:'AL'}
        return s + f"  csinc w{rd}, w{rn}, w{rm}, {cn.get(cond,'?')}"
    if (inst & 0xFFE00C00) == 0x9A800400:  # CSINC (64-bit)
        rd = inst & 0x1F; rn = (inst >> 5) & 0x1F; rm = (inst >> 16) & 0x1F
        cond = (inst >> 12) & 0xF
        cn = {0:'EQ',1:'NE',2:'CS',3:'CC',4:'MI',5:'PL',6:'VS',7:'VC',
              8:'HI',9:'LS',10:'GE',11:'LT',12:'GT',13:'LE',14:'AL'}
        return s + f"  csinc x{rd}, x{rn}, x{rm}, {cn.get(cond,'?')}"
    # CSEL
    if (inst & 0xFFE00C00) == 0x1A800000:
        rd = inst & 0x1F; rn = (inst >> 5) & 0x1F; rm = (inst >> 16) & 0x1F
        cond = (inst >> 12) & 0xF
        cn = {0:'EQ',1:'NE',2:'CS',3:'CC',4:'MI',5:'PL',6:'VS',7:'VC',8:'HI',9:'LS',10:'GE',11:'LT',12:'GT',13:'LE'}
        return s + f"  csel w{rd}, w{rn}, w{rm}, {cn.get(cond,'?')}"
    # TST Wn, #bitmask  (ANDS WZR, Wn, #bitmask)
    if (inst & 0xFFC0001F) == 0x7200001F:
        rn = (inst >> 5) & 0x1F
        return s + f"  tst w{rn}, #bitmask"
    # ADD shifted reg
    if (inst & 0xFF200000) == 0x8B000000:
        rd = inst & 0x1F; rn = (inst >> 5) & 0x1F; rm = (inst >> 16) & 0x1F
        shift = (inst >> 22) & 3; imm6 = (inst >> 10) & 0x3F
        shifts = ['LSL','LSR','ASR','ROR']
        return s + f"  add x{rd}, x{rn}, x{rm}, {shifts[shift]} #{imm6}"

    return s

# Full disassembly of OemCheckResetDevInfo
print("=" * 80)
print("=== OemCheckResetDevInfo 完整反汇编 (0x362D8 - 0x36690) ===")
print("=" * 80)
for off in range(0x362D8, 0x36690, 4):
    inst = struct.unpack_from("<I", pe, off)[0]
    line = decode(off, inst)
    # Annotate known functions
    if "bl 0x384D0" in line: line += "  ← init_defaults!"
    if "bl 0x384B0" in line: line += "  ← SetIsUnlocked!"
    if "bl 0x189E0" in line: line += "  ← IsSecureBootEnabled!"
    if "bl 0x22CA8" in line: line += "  ← WriteDeviceInfo!"
    if "bl 0x38490" in line: line += "  ← GetCalRebootCount"
    if "bl 0x38430" in line: line += "  ← SetCalRebootCount"
    if "bl 0x29FE8" in line: line += "  ← ReadBytes"
    if "bl 0x28574" in line: line += "  ← DebugCheck"
    if "bl 0x285A0" in line: line += "  ← DebugCheck2"
    if "bl 0x280FC" in line: line += "  ← DebugPrint"
    if "bl 0x30A80" in line: line += "  ← PostProcess"
    print(line)
    if inst == 0xD65F03C0 and off > 0x36300:
        break

# Also check what's at the table 0x5AAB0
print("\n" + "=" * 80)
print("=== 表格 0x5AAB0 数据 (SetDeviceUnlocked 参数表) ===")
print("=" * 80)
for i in range(8):  # check 8 entries (16 bytes each)
    base = 0x5AAB0 + i * 16
    if base + 16 > len(pe): break
    w0 = struct.unpack_from("<I", pe, base)[0]
    w1_byte = pe[base + 8]
    print(f"  Entry[{i}]: mode=0x{w0:08X}={w0}, value=0x{w1_byte:02X}={w1_byte}, raw={pe[base:base+16].hex()}")

# Check what function contains 0x1D38C (SetDeviceUnlocked caller)
print("\n" + "=" * 80)
print("=== 反汇编 0x1D280-0x1D310 (查找 SetDeviceUnlocked 调用者的函数入口) ===")
print("=" * 80)
for off in range(0x1D280, 0x1D310, 4):
    inst = struct.unpack_from("<I", pe, off)[0]
    print(decode(off, inst))

# Find callers of this function (try 0x1D2F0)
print("\n" + "=" * 80)
print("=== 搜索 BL 0x1D2D0/0x1D2E0/0x1D2F0/0x1D290 调用者 ===")
print("=" * 80)
for try_addr in [0x1D290, 0x1D2A0, 0x1D2B0, 0x1D2C0, 0x1D2D0, 0x1D2E0, 0x1D2F0]:
    for off in range(0, 0x6A000, 4):
        inst = struct.unpack_from("<I", pe, off)[0]
        if (inst >> 26) == 0x25:
            imm = inst & 0x3FFFFFF
            if imm & 0x2000000: imm |= ~0x3FFFFFF
            t = off + (imm << 2)
            if (t & 0xFFFFFFFF) == try_addr:
                print(f"  BL at 0x{off:05X} → 0x{try_addr:05X}")
