#!/usr/bin/env python3
"""Analyze qtmir ApplicationManager::onSessionStarting and related functions"""
import struct, sys, re

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def disasm_aarch64(data, base_off, count=100):
    """Simple AArch64 disassembler for key instructions"""
    results = []
    for i in range(count):
        off = base_off + i * 4
        if off + 4 > len(data):
            break
        insn = read_u32(data, off)
        addr = off

        # RET
        if insn == 0xd65f03c0:
            results.append((addr, insn, "RET"))
        # BL imm
        elif (insn >> 26) == 0x25:
            imm26 = insn & 0x3ffffff
            if imm26 & 0x2000000:
                imm26 -= 0x4000000
            target = addr + imm26 * 4
            results.append((addr, insn, f"BL 0x{target:x}"))
        # B imm
        elif (insn >> 26) == 0x05:
            imm26 = insn & 0x3ffffff
            if imm26 & 0x2000000:
                imm26 -= 0x4000000
            target = addr + imm26 * 4
            results.append((addr, insn, f"B 0x{target:x}"))
        # B.cond
        elif (insn & 0xff000010) == 0x54000000:
            cond = insn & 0xf
            imm19 = (insn >> 5) & 0x7ffff
            if imm19 & 0x40000:
                imm19 -= 0x80000
            target = addr + imm19 * 4
            conds = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
            results.append((addr, insn, f"B.{conds[cond]} 0x{target:x}"))
        # CBZ/CBNZ
        elif (insn & 0x7e000000) == 0x34000000:
            sf = (insn >> 31) & 1
            op = (insn >> 24) & 1
            imm19 = (insn >> 5) & 0x7ffff
            if imm19 & 0x40000:
                imm19 -= 0x80000
            target = addr + imm19 * 4
            rt = insn & 0x1f
            reg = f"X{rt}" if sf else f"W{rt}"
            mnem = "CBNZ" if op else "CBZ"
            results.append((addr, insn, f"{mnem} {reg}, 0x{target:x}"))
        # TBZ/TBNZ
        elif (insn & 0x7e000000) == 0x36000000:
            op = (insn >> 24) & 1
            b5 = (insn >> 31) & 1
            b40 = (insn >> 19) & 0x1f
            bit = (b5 << 5) | b40
            imm14 = (insn >> 5) & 0x3fff
            if imm14 & 0x2000:
                imm14 -= 0x4000
            target = addr + imm14 * 4
            rt = insn & 0x1f
            mnem = "TBNZ" if op else "TBZ"
            results.append((addr, insn, f"{mnem} X{rt}, #{bit}, 0x{target:x}"))
        # ADRP
        elif (insn & 0x9f000000) == 0x90000000:
            rd = insn & 0x1f
            immhi = (insn >> 5) & 0x7ffff
            immlo = (insn >> 29) & 0x3
            imm = (immhi << 2) | immlo
            if imm & 0x100000:
                imm -= 0x200000
            page = ((addr) & ~0xfff) + (imm << 12)
            results.append((addr, insn, f"ADRP X{rd}, 0x{page:x}"))
        # ADD imm
        elif (insn & 0x7f800000) == 0x11000000:
            sf = (insn >> 31) & 1
            sh = (insn >> 22) & 1
            imm12 = (insn >> 10) & 0xfff
            rn = (insn >> 5) & 0x1f
            rd = insn & 0x1f
            if sh:
                imm12 <<= 12
            rp = "X" if sf else "W"
            results.append((addr, insn, f"ADD {rp}{rd}, {rp}{rn}, #0x{imm12:x}"))
        # LDR/STR imm unsigned offset
        elif (insn & 0x3b200c00) == 0x39000000:
            size = (insn >> 30) & 3
            v = (insn >> 26) & 1
            opc = (insn >> 22) & 3
            imm12 = (insn >> 10) & 0xfff
            rn = (insn >> 5) & 0x1f
            rt = insn & 0x1f
            scale = size
            offset = imm12 << scale
            if opc == 0:
                mnem = "STRB" if size == 0 else ("STRH" if size == 1 else ("STR" if size == 2 else "STR"))
            elif opc == 1:
                mnem = "LDRB" if size == 0 else ("LDRH" if size == 1 else ("LDR" if size == 2 else "LDR"))
            else:
                mnem = f"LDR/STR(opc={opc})"
            rp = "X" if size == 3 else "W"
            if size == 0:
                rp = "W"
            results.append((addr, insn, f"{mnem} {rp}{rt}, [X{rn}, #0x{offset:x}]"))
        # MOV immediate (MOVZ/MOVK/MOVN)
        elif (insn & 0x1f800000) == 0x12800000:
            opc = (insn >> 29) & 3
            sf = (insn >> 31) & 1
            hw = (insn >> 21) & 3
            imm16 = (insn >> 5) & 0xffff
            rd = insn & 0x1f
            rp = "X" if sf else "W"
            if opc == 0:
                results.append((addr, insn, f"MOVN {rp}{rd}, #0x{imm16:x}, LSL #{hw*16}"))
            elif opc == 2:
                results.append((addr, insn, f"MOVZ {rp}{rd}, #0x{imm16:x}, LSL #{hw*16}"))
            elif opc == 3:
                results.append((addr, insn, f"MOVK {rp}{rd}, #0x{imm16:x}, LSL #{hw*16}"))
            else:
                results.append((addr, insn, f"MOV? {rp}{rd}, #0x{imm16:x}"))
        # STP/LDP
        elif (insn & 0x3e000000) == 0x28000000:
            opc = (insn >> 30) & 3
            p = (insn >> 24) & 1
            w = (insn >> 23) & 1
            l = (insn >> 22) & 1
            imm7 = (insn >> 15) & 0x7f
            if imm7 & 0x40:
                imm7 -= 0x80
            rt2 = (insn >> 10) & 0x1f
            rn = (insn >> 5) & 0x1f
            rt = insn & 0x1f
            scale = 2 + (opc >> 1)
            off_val = imm7 << scale
            rp = "X" if opc >= 2 else "W"
            mnem = "LDP" if l else "STP"
            results.append((addr, insn, f"{mnem} {rp}{rt}, {rp}{rt2}, [X{rn}, #{off_val}]"))
        else:
            results.append((addr, insn, f"??? 0x{insn:08x}"))
    return results

# Find functions by symbol name pattern
def find_symbols(data):
    """Find function symbols from .dynsym"""
    symbols = {}
    # Search for known symbol strings
    patterns = [
        b'onSessionStarting',
        b'onSessionStopping',
        b'authorizeSession',
        b'onProcessStarting',
        b'onProcessStopped',
        b'startApplication',
        b'findApplication',
        b'appIdHasProcessId',
        b'setApplication',
    ]
    for pat in patterns:
        idx = 0
        while True:
            idx = data.find(pat, idx)
            if idx == -1:
                break
            # Read surrounding context
            start = max(0, idx - 100)
            end = min(len(data), idx + 200)
            context = data[start:end]
            # Find the full symbol name
            sym_start = idx
            while sym_start > 0 and data[sym_start-1:sym_start] not in (b'\0', b'\n'):
                sym_start -= 1
            sym_end = data.find(b'\0', idx)
            if sym_end == -1:
                sym_end = idx + len(pat)
            sym_name = data[sym_start:sym_end].decode('ascii', errors='replace')
            symbols[sym_name] = sym_start
            idx += 1
    return symbols

def find_func_offset(data, mangled_prefix):
    """Find function offset from PLT/GOT or direct references"""
    idx = data.find(mangled_prefix.encode())
    if idx == -1:
        return None
    # The actual function offset needs to be found from relocations
    return idx

with open('/Users/xmxx/pinganhuijia/tmp/qtmir_orig.so', 'rb') as f:
    orig = f.read()

print(f"Binary size: {len(orig)} bytes")

# Find key function addresses by searching for known log strings
# The log string "TaskController::onSessionStarting" should be near the function
strings_to_find = [
    b'TaskController::onSessionStarting',
    b'TaskController::onSessionStopping',
    b'ApplicationManager::onSessionStarting',
    b'ApplicationManager::onProcessStarting',
    b'ApplicationManager::startApplication',
    b'ApplicationManager REJECTED',
    b'appIdHasProcessId',
    b'setApplication',
    b'findApplication',
    b'No such running application',
    b'application already found',
    b'Unable to instantiate application',
]

print("\n=== String locations ===")
for s in strings_to_find:
    idx = orig.find(s)
    if idx >= 0:
        # Read more context
        end = orig.find(b'\0', idx)
        full = orig[idx:end].decode('ascii', errors='replace') if end > idx else s.decode()
        print(f"  0x{idx:06x}: {full[:100]}")
    else:
        print(f"  NOT FOUND: {s.decode()}")

# Find the onSessionStarting function by looking at ADRP+ADD references to the log string
print("\n=== Looking for onSessionStarting code references ===")
target_str = b'ApplicationManager::onSessionStarting'
str_idx = orig.find(target_str)
if str_idx >= 0:
    # Look for ADRP that could reference this address
    str_page = str_idx & ~0xfff
    for off in range(0, min(len(orig), 0xb0000), 4):
        insn = read_u32(orig, off)
        # Check for ADRP
        if (insn & 0x9f000000) == 0x90000000:
            rd = insn & 0x1f
            immhi = (insn >> 5) & 0x7ffff
            immlo = (insn >> 29) & 0x3
            imm = (immhi << 2) | immlo
            if imm & 0x100000:
                imm -= 0x200000
            page = (off & ~0xfff) + (imm << 12)
            if page == str_page:
                # Check next instruction for ADD with matching offset
                if off + 4 < len(orig):
                    next_insn = read_u32(orig, off + 4)
                    if (next_insn & 0x7f800000) == 0x11000000:
                        add_rd = next_insn & 0x1f
                        add_rn = (next_insn >> 5) & 0x1f
                        imm12 = (next_insn >> 10) & 0xfff
                        sh = (next_insn >> 22) & 1
                        if sh:
                            imm12 <<= 12
                        full_addr = page + imm12
                        if abs(full_addr - str_idx) < 16:
                            print(f"  Found ADRP+ADD at 0x{off:06x} -> 0x{full_addr:06x} (string at 0x{str_idx:06x})")
                            # Now scan backwards to find function prologue
                            for scan_off in range(off, max(off - 200, 0), -4):
                                scan_insn = read_u32(orig, scan_off)
                                # Look for STP X29, X30 or PACIASP
                                if scan_insn == 0xd503233f:  # PACIASP
                                    print(f"  Function prologue (PACIASP) at 0x{scan_off:06x}")
                                    break
                                # STP X29, X30, [SP, #xxx]!
                                if (scan_insn & 0xffe07fff) == 0xa9007bfd or \
                                   (scan_insn & 0xffc003e0) == 0xa98003e0:
                                    # Check if prev instruction is SUB SP
                                    if scan_off >= 4:
                                        prev = read_u32(orig, scan_off - 4)
                                        if (prev & 0xff0003ff) == 0xd10003ff:  # SUB SP, SP, #imm
                                            print(f"  Function prologue (SUB SP + STP) at 0x{scan_off-4:06x}")
                                            break

# Now let's look at the key function: ApplicationManager::onSessionStarting
# It's called from TaskController and processes new sessions
print("\n=== Looking for _ZN5qtmir18ApplicationManager17onSessionStartingEPNS_16SessionInterfaceE ===")
sym = b'_ZN5qtmir18ApplicationManager17onSessionStartingE'
idx = orig.find(sym)
if idx >= 0:
    print(f"  Symbol string at 0x{idx:06x}")

# Find all function symbols
print("\n=== Key demangled symbols ===")
key_syms = [
    b'_ZN5qtmir18ApplicationManager17onSessionStarting',
    b'_ZN5qtmir18ApplicationManager16authorizeSession',
    b'_ZN5qtmir14TaskController17onSessionStarting',
    b'_ZN5qtmir18ApplicationManager18onProcessStarting',
    b'_ZN5qtmir7Session14setApplication',
]
for sym in key_syms:
    idx = orig.find(sym)
    if idx >= 0:
        end = orig.find(b'\0', idx)
        full = orig[idx:end].decode('ascii', errors='replace')
        print(f"  0x{idx:06x}: {full}")

# Now let's parse ELF to find actual function addresses
print("\n=== Parsing ELF for function offsets ===")
# ELF header
e_shoff = struct.unpack_from('<Q', orig, 40)[0]
e_shentsize = struct.unpack_from('<H', orig, 58)[0]
e_shnum = struct.unpack_from('<H', orig, 60)[0]
e_shstrndx = struct.unpack_from('<H', orig, 62)[0]

# Read section headers
sections = []
for i in range(e_shnum):
    sh_off = e_shoff + i * e_shentsize
    sh_name = struct.unpack_from('<I', orig, sh_off)[0]
    sh_type = struct.unpack_from('<I', orig, sh_off + 4)[0]
    sh_flags = struct.unpack_from('<Q', orig, sh_off + 8)[0]
    sh_addr = struct.unpack_from('<Q', orig, sh_off + 16)[0]
    sh_offset = struct.unpack_from('<Q', orig, sh_off + 24)[0]
    sh_size = struct.unpack_from('<Q', orig, sh_off + 32)[0]
    sh_link = struct.unpack_from('<I', orig, sh_off + 40)[0]
    sh_info = struct.unpack_from('<I', orig, sh_off + 44)[0]
    sh_entsize = struct.unpack_from('<Q', orig, sh_off + 56)[0]
    sections.append({
        'name_off': sh_name, 'type': sh_type, 'flags': sh_flags,
        'addr': sh_addr, 'offset': sh_offset, 'size': sh_size,
        'link': sh_link, 'info': sh_info, 'entsize': sh_entsize
    })

# Get section name string table
shstrtab = sections[e_shstrndx]
shstrtab_data = orig[shstrtab['offset']:shstrtab['offset']+shstrtab['size']]

def get_section_name(off):
    end = shstrtab_data.find(b'\0', off)
    return shstrtab_data[off:end].decode('ascii', errors='replace')

# Find .dynsym and .dynstr
dynsym_sec = None
dynstr_sec = None
for s in sections:
    name = get_section_name(s['name_off'])
    if name == '.dynsym':
        dynsym_sec = s
    elif name == '.dynstr':
        dynstr_sec = s

if dynsym_sec and dynstr_sec:
    dynstr_data = orig[dynstr_sec['offset']:dynstr_sec['offset']+dynstr_sec['size']]

    def get_dynstr(off):
        end = dynstr_data.find(b'\0', off)
        return dynstr_data[off:end].decode('ascii', errors='replace')

    # Parse dynsym
    entsize = dynsym_sec['entsize'] or 24
    num_syms = dynsym_sec['size'] // entsize

    target_funcs = [
        'onSessionStarting',
        'authorizeSession',
        'onProcessStarting',
        'startApplication',
        'setApplication',
        'appIdHasProcessId',
    ]

    for i in range(num_syms):
        sym_off = dynsym_sec['offset'] + i * entsize
        st_name = struct.unpack_from('<I', orig, sym_off)[0]
        st_info = orig[sym_off + 4]
        st_other = orig[sym_off + 5]
        st_shndx = struct.unpack_from('<H', orig, sym_off + 6)[0]
        st_value = struct.unpack_from('<Q', orig, sym_off + 8)[0]
        st_size = struct.unpack_from('<Q', orig, sym_off + 16)[0]

        name = get_dynstr(st_name)
        for tf in target_funcs:
            if tf in name and st_value > 0:
                print(f"  0x{st_value:06x} [{st_size:4d}] {name}")

# Now disassemble onSessionStarting
print("\n=== Disassembly of key functions ===")
# Search for the function by finding references to its log string
for target_name, target_str_bytes in [
    ("ApplicationManager::onSessionStarting", b'ApplicationManager::onSessionStarting'),
]:
    str_offset = orig.find(target_str_bytes)
    if str_offset < 0:
        continue

    # We need to find code that references this string
    # The function might be at a specific offset from the ELF
    # Let's search for ADRP instructions that could point to this string
    str_page = str_offset & ~0xfff
    str_lo = str_offset & 0xfff

    candidates = []
    for off in range(0, min(len(orig), 0xb3000), 4):
        insn = read_u32(orig, off)
        if (insn & 0x9f000000) == 0x90000000:
            rd = insn & 0x1f
            immhi = (insn >> 5) & 0x7ffff
            immlo = (insn >> 29) & 0x3
            imm = (immhi << 2) | immlo
            if imm & 0x100000:
                imm -= 0x200000
            page = (off & ~0xfff) + (imm << 12)
            if page == str_page and off + 4 < len(orig):
                next_insn = read_u32(orig, off + 4)
                if (next_insn & 0x7f800000) == 0x11000000:
                    imm12 = (next_insn >> 10) & 0xfff
                    sh = (next_insn >> 22) & 1
                    if sh:
                        imm12 <<= 12
                    if imm12 == str_lo:
                        candidates.append(off)

    for c in candidates:
        print(f"\n--- Reference to '{target_name}' string at code offset 0x{c:06x} ---")
        # Scan backwards for function prologue
        func_start = c
        for scan in range(c, max(c - 400, 0), -4):
            insn = read_u32(orig, scan)
            if insn == 0xd503233f:  # PACIASP
                func_start = scan
                break
            # SUB SP, SP, #imm
            if (insn & 0xff0003ff) == 0xd10003ff:
                func_start = scan
                break

        print(f"  Estimated function start: 0x{func_start:06x}")
        print(f"  Disassembly from 0x{func_start:06x}:")
        instrs = disasm_aarch64(orig, func_start, 200)
        for addr, raw, asm in instrs:
            marker = " <<<<" if addr == c else ""
            print(f"    0x{addr:06x}: {raw:08x}  {asm}{marker}")
            if asm == "RET" and addr > c:
                break
