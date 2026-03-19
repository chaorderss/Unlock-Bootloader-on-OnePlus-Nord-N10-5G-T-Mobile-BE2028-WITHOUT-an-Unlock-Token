#!/usr/bin/env python3
"""
找所有写入 devinfo[0x0D] (is_unlocked) 的代码路径。
STRB Wt, [Xn, #13] — 如果 Xn 指向 devinfo buffer (0x1BD978)
"""
import struct

PE32 = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
TEXT_SIZE = 0x6A000

with open(PE32, "rb") as f:
    pe = f.read()

code = pe[:TEXT_SIZE]

# 1. Find all STRB Wt, [Xn, #13] instructions
print("=== 所有 STRB Wt, [Xn, #13] ===")
strb_refs = []
for i in range(0, TEXT_SIZE, 4):
    insn = struct.unpack_from('<I', code, i)[0]
    # STRB (unsigned offset): 0011 1001 00 imm12 Rn Rt
    if (insn & 0xFFC00000) == 0x39000000:
        imm12 = (insn >> 10) & 0xFFF
        rn = (insn >> 5) & 0x1f
        rt = insn & 0x1f
        if imm12 == 13:
            strb_refs.append((i, rn, rt))
            print(f"  0x{i:05X}: strb w{rt}, [x{rn}, #13]")

# 2. For each STRB, check if base reg was loaded from devinfo (0x1BD978)
print(f"\n=== 追踪哪些 STRB #13 写入 devinfo buffer ===")
for addr, rn, rt in strb_refs:
    for back in range(addr - 4, max(addr - 100, 0), -4):
        insn = struct.unpack_from('<I', code, back)[0]
        if (insn & 0x9F000000) == 0x90000000:  # ADRP
            rd = insn & 0x1f
            if rd == rn or True:  # check all ADRP to see what they load
                immlo = (insn >> 29) & 3
                immhi = (insn >> 5) & 0x7ffff
                imm = (immhi << 2) | immlo
                if imm & (1 << 20): imm -= (1 << 21)
                page = (back & ~0xFFF) + (imm << 12)

                if page == 0x1BD000 and back + 4 < TEXT_SIZE:
                    next_insn = struct.unpack_from('<I', code, back + 4)[0]
                    if (next_insn & 0xFFC00000) == 0x91000000:
                        add_imm = (next_insn >> 10) & 0xFFF
                        add_rn = (next_insn >> 5) & 0x1f
                        add_rd = next_insn & 0x1f
                        if add_rn == rd and add_imm == 0x978:
                            target = 0x1BD978
                            if add_rd == rn:
                                print(f"  ✅ 0x{addr:05X}: strb w{rt}, [x{rn}, #13] ← devinfo (ADRP at 0x{back:05X})")
                                # Show context
                                for ctx in range(max(back - 20, 0), min(addr + 20, TEXT_SIZE), 4):
                                    insn2 = struct.unpack_from('<I', code, ctx)[0]
                                    # Quick decode
                                    desc = ""
                                    if (insn2 & 0xFFC00000) == 0x39000000:
                                        desc = f"strb w{insn2&0x1f}, [x{(insn2>>5)&0x1f}, #{(insn2>>10)&0xFFF}]"
                                    elif (insn2 & 0xFFC00000) == 0x39400000:
                                        desc = f"ldrb w{insn2&0x1f}, [x{(insn2>>5)&0x1f}, #{(insn2>>10)&0xFFF}]"
                                    elif insn2 == 0xD65F03C0:
                                        desc = "ret"
                                    elif (insn2 & 0xFC000000) == 0x94000000:
                                        off26 = insn2 & 0x03FFFFFF
                                        if off26 & (1<<25): off26 -= (1<<26)
                                        desc = f"bl 0x{ctx + off26*4:05X}"
                                    elif (insn2 & 0xFF800000) == 0x52800000:
                                        desc = f"mov w{insn2&0x1f}, #{(insn2>>5)&0xFFFF}"
                                    elif (insn2 & 0x9F000000) == 0x90000000:
                                        rd2 = insn2 & 0x1f
                                        immlo2 = (insn2 >> 29) & 3; immhi2 = (insn2 >> 5) & 0x7ffff
                                        imm2 = (immhi2 << 2) | immlo2
                                        if imm2 & (1<<20): imm2 -= (1<<21)
                                        pg = (ctx & ~0xFFF) + (imm2 << 12)
                                        desc = f"adrp x{rd2}, 0x{pg:X}"
                                    elif (insn2 & 0xFFC00000) == 0x91000000:
                                        desc = f"add x{insn2&0x1f}, x{(insn2>>5)&0x1f}, #0x{(insn2>>10)&0xFFF:X}"
                                    elif (insn2 & 0xFF200C00) == 0x1A800000 or (insn2 & 0xFF200C00) == 0x9A800000:
                                        sf="x" if (insn2>>31) else "w"
                                        ops={0:'csel',1:'csinc',2:'csinv',3:'csneg'}
                                        conds={0:'EQ',1:'NE',2:'CS',3:'CC',4:'MI',5:'PL',10:'GE',11:'LT',12:'GT',13:'LE'}
                                        desc = f"{ops.get((insn2>>10)&3,'?')} {sf}{insn2&0x1f}, {sf}{(insn2>>5)&0x1f}, {sf}{(insn2>>16)&0x1f}, {conds.get((insn2>>12)&0xf,'?')}"
                                    elif (insn2 & 0xFF800000) == 0x72000000:
                                        desc = f"tst w{(insn2>>5)&0x1f}, #imm"
                                    else:
                                        desc = f"0x{insn2:08X}"
                                    m = " <<<" if ctx == addr else (" [ADRP]" if ctx == back else "")
                                    print(f"      0x{ctx:05X}: {desc}{m}")
                                break
                    # Also check if LDR indirect
                    elif (next_insn & 0xFFC00000) == 0xF9400000:
                        ldr_imm = (next_insn >> 10) & 0xFFF
                        ldr_rd = next_insn & 0x1f
                        target = page + ldr_imm * 8
                        if ldr_rd == rn and target < len(pe):
                            ptr = struct.unpack_from('<Q', pe, target)[0]
                            if ptr == 0x1BD978 or (ptr & 0xFFFFFF) == 0x1BD978:
                                print(f"  ✅ 0x{addr:05X}: strb w{rt}, [x{rn}, #13] ← devinfo (LDR indirect at 0x{back:05X})")

# 3. Also look for init defaults (0x384d0) which sets devinfo[13] based on SecureBoot
# The key instruction is CSINC or similar that sets 0 when SecureBoot is on
print(f"\n=== Init defaults 相关代码 (0x384d0-0x38580) ===")
for i in range(0x384D0, 0x38580, 4):
    insn = struct.unpack_from('<I', code, i)[0]
    desc = ""
    if (insn & 0xFFC00000) == 0x39000000:
        imm12 = (insn >> 10) & 0xFFF
        desc = f"strb w{insn&0x1f}, [x{(insn>>5)&0x1f}, #{imm12}]"
    elif (insn & 0xFFC00000) == 0x39400000:
        desc = f"ldrb w{insn&0x1f}, [x{(insn>>5)&0x1f}, #{(insn>>10)&0xFFF}]"
    elif (insn & 0xFC000000) == 0x94000000:
        off26 = insn & 0x03FFFFFF
        if off26 & (1<<25): off26 -= (1<<26)
        desc = f"bl 0x{i + off26*4:05X}"
    elif insn == 0xD65F03C0:
        desc = "ret"
    elif (insn & 0xFF200C00) in (0x1A800000, 0x9A800000):
        ops = {0:'csel',1:'csinc',2:'csinv',3:'csneg'}
        sf = "x" if (insn>>31) else "w"
        desc = f"{ops.get((insn>>10)&3,'?')} {sf}{insn&0x1f}, {sf}{(insn>>5)&0x1f}, {sf}{(insn>>16)&0x1f}, cond{(insn>>12)&0xf}"
    elif (insn & 0x9F000000) == 0x90000000:
        desc = f"adrp x{insn&0x1f}"
    elif (insn & 0xFFC00000) == 0x91000000:
        desc = f"add x{insn&0x1f}, x{(insn>>5)&0x1f}, #0x{(insn>>10)&0xFFF:X}"
    elif (insn & 0xFF800000) == 0x52800000:
        desc = f"mov w{insn&0x1f}, #{(insn>>5)&0xFFFF}"
    elif (insn & 0xFE000000) == 0x54000000:
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1<<18): imm19 -= (1<<19)
        conds = {0:'EQ',1:'NE',2:'CS',3:'CC'}
        desc = f"b.{conds.get(insn&0xf, '?')} 0x{i + imm19*4:05X}"
    else:
        desc = f"0x{insn:08X}"
    print(f"  0x{i:05X}: {desc}")

# 4. Also look at OemCheckResetDevInfo (0x36400-0x36700) for strb #13
print(f"\n=== OemCheckResetDevInfo STRB 指令 ===")
for i in range(0x36400, 0x36800, 4):
    insn = struct.unpack_from('<I', code, i)[0]
    if (insn & 0xFFC00000) == 0x39000000:
        imm12 = (insn >> 10) & 0xFFF
        rn = (insn >> 5) & 0x1f
        rt = insn & 0x1f
        print(f"  0x{i:05X}: strb w{rt}, [x{rn}, #{imm12}]")
