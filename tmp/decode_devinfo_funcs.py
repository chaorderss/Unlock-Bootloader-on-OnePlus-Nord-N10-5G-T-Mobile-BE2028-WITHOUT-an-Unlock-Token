#!/usr/bin/env python3
"""Decode functions at 0x23350 and 0x384f0 (ANDROID-BOOT! magic references)"""
import struct

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin','rb').read()

def decode_adrp(insn, pc):
    if (insn & 0x9F000000) != 0x90000000:
        return None
    rd = insn & 0x1F
    immlo = (insn >> 29) & 0x3
    immhi = (insn >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    return rd, (pc & ~0xFFF) + (imm << 12)

def decode_add_imm(insn):
    if (insn & 0xFF800000) == 0x91000000:
        rd = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm12 = (insn >> 10) & 0xFFF
        sh = (insn >> 22) & 1
        if sh: imm12 <<= 12
        return rd, rn, imm12
    return None

def get_str(off, maxlen=120):
    if off < 0 or off >= len(data):
        return None
    end = off
    while end < len(data) and end < off + maxlen and data[end] != 0:
        end += 1
    try:
        return data[off:end].decode('ascii')
    except:
        return data[off:min(off+40,end)].hex()

def scan_func(start, end_addr, label):
    print(f"\n=== {label}: {start:#x} - {end_addr:#x} ===")
    adrp_regs = {}
    for pc in range(start, end_addr, 4):
        if pc + 4 > len(data):
            break
        insn = struct.unpack_from('<I', data, pc)[0]

        a = decode_adrp(insn, pc)
        if a:
            adrp_regs[a[0]] = (pc, a[1])

        add = decode_add_imm(insn)
        if add:
            rd, rn, imm12 = add
            if rn in adrp_regs:
                apc, page = adrp_regs[rn]
                if 0 < (pc - apc) <= 64:
                    final = page + imm12
                    s = get_str(final)
                    if s and len(s) > 0:
                        print(f"  {pc:#07x}: x{rd} = {final:#x}  \"{s[:80]}\"")

        if (insn & 0xFC000000) == 0x94000000:
            imm26 = insn & 0x3FFFFFF
            if imm26 & (1 << 25): imm26 -= (1 << 26)
            target = pc + (imm26 << 2)
            print(f"  {pc:#07x}: bl {target:#x}")

        if (insn & 0xFFFFFC1F) == 0xD63F0100:
            reg = (insn >> 5) & 0x1F
            print(f"  {pc:#07x}: blr x{reg}")

        if insn == 0xD65F03C0:
            print(f"  {pc:#07x}: RET")

        if (insn & 0x7E000000) == 0x34000000:
            op = (insn >> 24) & 1
            imm19 = (insn >> 5) & 0x7FFFF
            if imm19 & (1 << 18): imm19 -= (1 << 19)
            rt = insn & 0x1F
            target = pc + (imm19 << 2)
            name = 'cbnz' if op else 'cbz'
            print(f"  {pc:#07x}: {name} x{rt}, {target:#x}")

        if (insn & 0xFF000010) == 0x54000000:
            imm19 = (insn >> 5) & 0x7FFFF
            if imm19 & (1 << 18): imm19 -= (1 << 19)
            cond = insn & 0xF
            conds = ['eq','ne','cs','cc','mi','pl','vs','vc','hi','ls','ge','lt','gt','le','al','nv']
            target = pc + (imm19 << 2)
            print(f"  {pc:#07x}: b.{conds[cond]} {target:#x}")

# Find function boundaries for 0x23350 region
# Look backward for prologue
for pc in range(0x2334c, 0x22000, -4):
    insn = struct.unpack_from('<I', data, pc)[0]
    if insn == 0xD65F03C0:
        print(f"Function containing 0x23350: starts after RET at {pc:#x}")
        scan_func(pc + 4, 0x23500, "ReadDeviceInfo candidate 1")
        break

# Function 2: 0x384f0
for pc in range(0x384ec, 0x38000, -4):
    insn = struct.unpack_from('<I', data, pc)[0]
    if insn == 0xD65F03C0:
        print(f"\nFunction containing 0x384f0: starts after RET at {pc:#x}")
        scan_func(pc + 4, 0x38700, "ReadDeviceInfo candidate 2")
        break

# Also look at the "DeviceInfo not initalized" references at 0x5bf43
# to find which function checks the magic
print("\n=== Scanning for 'DeviceInfo not initalized' refs ===")
targets = {0x05bf43, 0x05bfb0, 0x05c018, 0x05c067, 0x05c08e, 0x05c0ba}
target_pages = {a & ~0xFFF for a in targets}
adrp_log = {}
for pc in range(0x1000, 0x89000, 4):
    if pc + 4 > len(data): break
    insn = struct.unpack_from('<I', data, pc)[0]
    a = decode_adrp(insn, pc)
    if a:
        rd, page = a
        if page in target_pages:
            adrp_log[rd] = (pc, page)
    add = decode_add_imm(insn)
    if add:
        rd, rn, imm12 = add
        if rn in adrp_log:
            apc, page = adrp_log[rn]
            if 0 < (pc - apc) <= 64:
                final = page + imm12
                if final in targets:
                    print(f"  {pc:#07x}: x{rd} -> {final:#x}")
