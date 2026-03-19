#!/usr/bin/env python3
"""
Find devinfo structure layout in Global ABL:
1. Find "ANDROID-BOOT!" magic string refs in code
2. Find "Device unlocked" / unlock-related print strings
3. Trace what byte offset is compared for is_unlocked
4. Find AVB lock check code to see what triggers red screen
"""
import struct

DECOMP = '/Users/xmxx/pinganhuijia/global_abl_decompressed.bin'
PE_OFFSET = 0xB8
IMAGE_BASE = 0x0
TEXT_VA = 0x1000
TEXT_RAW = 0x1000
TEXT_SIZE = 0x69000

def va_to_file(va):
    if TEXT_VA <= va < TEXT_VA + TEXT_SIZE:
        return PE_OFFSET + TEXT_RAW + (va - TEXT_VA)
    return None

def file_to_va(off):
    raw = off - PE_OFFSET
    if TEXT_RAW <= raw < TEXT_RAW + TEXT_SIZE:
        return TEXT_VA + (raw - TEXT_RAW)
    return None

def read32le(data, off):
    return struct.unpack_from('<I', data, off)[0]

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

def decode_ldrb(insn):
    """LDRB Wt, [Xn, #imm12] → returns (rt, rn, imm) or None"""
    if (insn & 0xFFC00000) == 0x39400000:
        rt = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm12 = (insn >> 10) & 0xFFF
        return rt, rn, imm12
    return None

def decode_ldr_imm(insn):
    """LDR Wt, [Xn, #imm12] (32-bit) → returns (rt, rn, imm*4) or None"""
    if (insn & 0xFFC00000) == 0xB9400000:
        rt = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm12 = ((insn >> 10) & 0xFFF) * 4
        return rt, rn, imm12
    return None

def find_strings(data, targets):
    """Find all occurrences of target strings (bytes or str)"""
    results = {}
    for t in targets:
        if isinstance(t, str):
            tb = t.encode()
        else:
            tb = t
        pos = 0
        positions = []
        while True:
            idx = data.find(tb, pos)
            if idx < 0:
                break
            positions.append(idx)
            pos = idx + 1
        results[t if isinstance(t, str) else t.decode('latin1')] = positions
    return results

def find_code_refs_to_va(data, target_va):
    """Find ADRP+ADD pairs that load target_va"""
    target_page = target_va & ~0xFFF
    target_off  = target_va & 0xFFF
    refs = []
    for i in range(0, TEXT_SIZE - 4, 4):
        foff = PE_OFFSET + TEXT_RAW + i
        insn = read32le(data, foff)
        pc   = TEXT_VA + i
        adrp = decode_adrp(insn, pc)
        if adrp is None:
            continue
        rd, page = adrp
        if page != target_page:
            continue
        if foff + 4 >= len(data):
            continue
        insn2 = read32le(data, foff + 4)
        add = decode_add_imm(insn2)
        if add and add[1] == rd and add[2] == target_off:
            refs.append((foff, pc, rd, add[0]))
    return refs

def show_context(data, foff, n_before=20, n_after=15, mark_off=None):
    start = max(PE_OFFSET + TEXT_RAW, foff - n_before*4)
    end   = min(PE_OFFSET + TEXT_RAW + TEXT_SIZE, foff + n_after*4)
    for off in range(start, end, 4):
        insn = read32le(data, off)
        va   = file_to_va(off)
        marker = " >>>" if off == foff or off == mark_off else "    "
        # quick decode
        desc = hex(insn)
        pc = va if va else off
        adrp = decode_adrp(insn, pc) if va else None
        if adrp: desc = f"ADRP X{adrp[0]}, {adrp[1]:#x}"
        add = decode_add_imm(insn)
        if add: desc = f"ADD  X{add[0]}, X{add[1]}, #{add[2]:#x}"
        ldrb = decode_ldrb(insn)
        if ldrb: desc = f"LDRB W{ldrb[0]}, [X{ldrb[1]}, #{ldrb[2]:#x}]"
        ldr = decode_ldr_imm(insn)
        if ldr: desc = f"LDR  W{ldr[0]}, [X{ldr[1]}, #{ldr[2]:#x}]"
        if insn == 0xD65F03C0: desc = "RET"
        if (insn & 0xFC000000) == 0x94000000:
            imm26 = insn & 0x3FFFFFF
            if imm26 & (1<<25): imm26 -= (1<<26)
            target = pc + imm26*4
            desc = f"BL   {target:#x}"
        if (insn & 0xFF000010) == 0x54000000:
            imm19 = (insn >> 5) & 0x7FFFF
            if imm19 & (1<<18): imm19 -= (1<<19)
            cond = insn & 0xF
            names = ['eq','ne','cs','cc','mi','pl','vs','vc','hi','ls','ge','lt','gt','le','al','nv']
            desc = f"B.{names[cond].upper()} {pc + imm19*4:#x}"
        if (insn & 0x7E000000) == 0x34000000:
            op = (insn >> 24) & 1
            imm19 = (insn >> 5) & 0x7FFFF
            if imm19 & (1<<18): imm19 -= (1<<19)
            rt = insn & 0x1F
            dest = pc + imm19*4
            desc = f"{'CBNZ' if op else 'CBZ '} X{rt}, {dest:#x}"
        print(f"  {marker} {off:#010x} (VA {va:#010x}): {insn:08x}  {desc}")

with open(DECOMP, 'rb') as f:
    data = bytearray(f.read())

print(f"=== ABL Devinfo Structure Analyzer ===")
print(f"Loaded {len(data)} bytes\n")

# ── Step 1: Find ANDROID-BOOT! string references
print("─"*60)
print("Step 1: Finding ANDROID-BOOT! magic string in code\n")
magic = b'ANDROID-BOOT!'
magic_positions = []
pos = 0
while True:
    idx = data.find(magic, pos)
    if idx < 0: break
    magic_positions.append(idx)
    pos = idx + 1
print(f"  'ANDROID-BOOT!' at file offsets: {[hex(p) for p in magic_positions]}")

for mp in magic_positions:
    va = IMAGE_BASE + (mp - PE_OFFSET)
    print(f"\n  String at file offset {mp:#x} → VA {va:#x}")
    refs = find_code_refs_to_va(data, va)
    for ref in refs:
        print(f"    Code ref at file {ref[0]:#x} (VA {ref[1]:#x})")
        # Show context + look for LDRB near the reference
        print(f"    Context:")
        show_context(data, ref[0], n_before=5, n_after=25)
        print()

# ── Step 2: Find "Device unlocked" equivalent string
print("\n" + "─"*60)
print("Step 2: Finding unlock-related strings\n")
strings_to_find = [
    b'Device unlocked',
    b'unlocked: ',
    b'is_unlocked',
    b'Unlocked',
    b'unlock_critical',
    b'charger_screen',
    b'verity_mode',
    b'device-info',
    b'oem_unlock',
]
for s in strings_to_find:
    positions = []
    p = 0
    while True:
        idx = data.find(s, p)
        if idx < 0: break
        positions.append(idx)
        p = idx + 1
    if positions:
        print(f"  {s.decode()!r:30s}: {[hex(x) for x in positions[:5]]}")

# ── Step 3: Search for LDRB/LDR patterns that load offset 0xD or 0xE from devinfo ptr
# After finding ANDROID-BOOT! refs, look for LDRB Wt, [Xn, #13] or #14 near them
print("\n" + "─"*60)
print("Step 3: Searching for LDRB [Xn, #0xD] and LDRB [Xn, #0xE] patterns\n")
for i in range(0, TEXT_SIZE - 4, 4):
    foff = PE_OFFSET + TEXT_RAW + i
    insn = read32le(data, foff)
    ldrb = decode_ldrb(insn)
    if ldrb and ldrb[2] in (0xD, 0xE, 0xF, 0x10, 0x11):
        va = TEXT_VA + i
        print(f"  LDRB W{ldrb[0]}, [X{ldrb[1]}, #{ldrb[2]:#x}] at file {foff:#x} (VA {va:#x})")
        # Show what's around it
        show_context(data, foff, n_before=8, n_after=12)
        print()
