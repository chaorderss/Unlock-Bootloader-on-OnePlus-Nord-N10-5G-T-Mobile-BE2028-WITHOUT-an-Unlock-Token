#!/usr/bin/env python3
"""Analyze hwcomposer binary to find where to inject xdg_toplevel_set_app_id call"""
import struct

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def disasm_one(data, addr, insn):
    if insn == 0xd65f03c0: return "RET"
    if insn == 0xd503201f: return "NOP"
    if (insn >> 26) == 0x25:
        imm26 = insn & 0x3ffffff
        if imm26 & 0x2000000: imm26 -= 0x4000000
        return f"BL 0x{addr + imm26*4:x}"
    if (insn >> 26) == 0x05:
        imm26 = insn & 0x3ffffff
        if imm26 & 0x2000000: imm26 -= 0x4000000
        return f"B 0x{addr + imm26*4:x}"
    if (insn & 0xff000010) == 0x54000000:
        cond = insn & 0xf
        imm19 = (insn >> 5) & 0x7ffff
        if imm19 & 0x40000: imm19 -= 0x80000
        conds = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
        return f"B.{conds[cond]} 0x{addr + imm19*4:x}"
    if (insn & 0x7e000000) == 0x34000000:
        sf = (insn >> 31) & 1
        op = (insn >> 24) & 1
        imm19 = (insn >> 5) & 0x7ffff
        if imm19 & 0x40000: imm19 -= 0x80000
        rt = insn & 0x1f
        reg = f"{'X' if sf else 'W'}{rt}"
        return f"{'CBNZ' if op else 'CBZ'} {reg}, 0x{addr + imm19*4:x}"
    if (insn & 0x9f000000) == 0x90000000:
        rd = insn & 0x1f
        immhi = (insn >> 5) & 0x7ffff
        immlo = (insn >> 29) & 0x3
        imm = (immhi << 2) | immlo
        if imm & 0x100000: imm -= 0x200000
        page = (addr & ~0xfff) + (imm << 12)
        return f"ADRP X{rd}, 0x{page:x}"
    if (insn & 0x7f800000) == 0x11000000:
        sf = (insn >> 31) & 1
        sh = (insn >> 22) & 1
        imm12 = (insn >> 10) & 0xfff
        rn = (insn >> 5) & 0x1f
        rd = insn & 0x1f
        if sh: imm12 <<= 12
        rp = "X" if sf else "W"
        return f"ADD {rp}{rd}, {rp}{rn}, #0x{imm12:x}"
    if (insn & 0x7f800000) == 0x52800000:
        sf = (insn >> 31) & 1
        hw = (insn >> 21) & 3
        imm16 = (insn >> 5) & 0xffff
        rd = insn & 0x1f
        rp = "X" if sf else "W"
        val = imm16 << (hw * 16)
        return f"MOV {rp}{rd}, #{val}"
    if (insn & 0x7fe0ffe0) == 0x2a0003e0:
        sf = (insn >> 31) & 1
        rm = (insn >> 16) & 0x1f
        rd = insn & 0x1f
        rp = "X" if sf else "W"
        return f"MOV {rp}{rd}, {rp}{rm}"
    if (insn & 0xfffffc1f) == 0xd63f0000:
        rn = (insn >> 5) & 0x1f
        return f"BLR X{rn}"
    if (insn & 0x3b200c00) == 0x39000000:
        size = (insn >> 30) & 3
        opc = (insn >> 22) & 3
        imm12 = (insn >> 10) & 0xfff
        rn = (insn >> 5) & 0x1f
        rt = insn & 0x1f
        offset = imm12 << size
        mnems = {(0,0):"STRB",(0,1):"LDRB",(1,0):"STRH",(1,1):"LDRH",
                 (2,0):"STR W",(2,1):"LDR W",(3,0):"STR X",(3,1):"LDR X"}
        mnem = mnems.get((size,opc), f"MEM{size}_{opc}")
        return f"{mnem}{rt}, [X{rn}, #0x{offset:x}]"
    if (insn & 0xffc00000) == 0xf9400000:
        imm12 = (insn >> 10) & 0xfff
        rn = (insn >> 5) & 0x1f
        rt = insn & 0x1f
        return f"LDR X{rt}, [X{rn}, #0x{imm12*8:x}]"
    if (insn & 0xffc00000) == 0xf9000000:
        imm12 = (insn >> 10) & 0xfff
        rn = (insn >> 5) & 0x1f
        rt = insn & 0x1f
        return f"STR X{rt}, [X{rn}, #0x{imm12*8:x}]"
    if (insn & 0x3e000000) == 0x28000000:
        opc = (insn >> 30) & 3
        l = (insn >> 22) & 1
        imm7 = (insn >> 15) & 0x7f
        if imm7 & 0x40: imm7 -= 0x80
        rt2 = (insn >> 10) & 0x1f
        rn = (insn >> 5) & 0x1f
        rt = insn & 0x1f
        scale = 2 + (opc >> 1)
        off_val = imm7 << scale
        rp = "X" if opc >= 2 else "W"
        mnem = "LDP" if l else "STP"
        return f"{mnem} {rp}{rt}, {rp}{rt2}, [X{rn}, #{off_val}]"
    if (insn & 0x7f800000) == 0x51000000:
        sf = (insn >> 31) & 1
        imm12 = (insn >> 10) & 0xfff
        rn = (insn >> 5) & 0x1f
        rd = insn & 0x1f
        rp = "X" if sf else "W"
        return f"SUB {rp}{rd}, {rp}{rn}, #0x{imm12:x}"
    return f"??? 0x{insn:08x}"

with open('/Users/xmxx/pinganhuijia/tmp/hwc.so', 'rb') as f:
    data = f.read()

print(f"Binary size: {len(data)} bytes")

# Find key strings
print("\n=== Key strings ===")
strings_to_find = [
    b'xdg_wm_base',
    b'xdg_surface',
    b'xdg_toplevel',
    b'wl_shell',
    b'wl_compositor',
    b'desktop_file_hint',
    b'Waydroid',
    b'waydroid',
    b'set_maximized',
    b'set_app_id',
    b'wl_proxy_marshal',
]
for s in strings_to_find:
    idx = data.find(s)
    if idx >= 0:
        end = data.find(b'\0', idx)
        full = data[idx:end].decode('ascii', errors='replace') if end > idx else s.decode()
        print(f"  0x{idx:06x}: {full[:80]}")
    else:
        print(f"  NOT FOUND: {s.decode()}")

# Find PLT/GOT entries for wl_proxy_marshal
print("\n=== PLT/GOT for wl_proxy_marshal ===")
# Look for wl_proxy_marshal in dynamic symbols
idx = 0
while True:
    idx = data.find(b'wl_proxy_marshal', idx)
    if idx < 0:
        break
    end = data.find(b'\0', idx)
    name = data[idx:end].decode('ascii', errors='replace')
    print(f"  0x{idx:06x}: {name}")
    idx += 1

# Parse ELF to find PLT stubs for wl_proxy_marshal
# ELF header
e_shoff = struct.unpack_from('<Q', data, 40)[0]
e_shentsize = struct.unpack_from('<H', data, 58)[0]
e_shnum = struct.unpack_from('<H', data, 60)[0]
e_shstrndx = struct.unpack_from('<H', data, 62)[0]

sections = []
for i in range(e_shnum):
    off = e_shoff + i * e_shentsize
    sh = {
        'name_off': struct.unpack_from('<I', data, off)[0],
        'type': struct.unpack_from('<I', data, off+4)[0],
        'flags': struct.unpack_from('<Q', data, off+8)[0],
        'addr': struct.unpack_from('<Q', data, off+16)[0],
        'offset': struct.unpack_from('<Q', data, off+24)[0],
        'size': struct.unpack_from('<Q', data, off+32)[0],
        'link': struct.unpack_from('<I', data, off+40)[0],
        'entsize': struct.unpack_from('<Q', data, off+56)[0],
    }
    sections.append(sh)

shstrtab = sections[e_shstrndx]
shstrtab_data = data[shstrtab['offset']:shstrtab['offset']+shstrtab['size']]
def get_sh_name(off):
    end = shstrtab_data.find(b'\0', off)
    return shstrtab_data[off:end].decode()

# Find .dynsym, .dynstr, .rela.plt, .plt
dynsym = dynstr = rela_plt = plt = None
for s in sections:
    name = get_sh_name(s['name_off'])
    if name == '.dynsym': dynsym = s
    elif name == '.dynstr': dynstr = s
    elif name == '.rela.plt': rela_plt = s
    elif name == '.plt': plt = s
    # print(f"  Section: {name:20s} offset=0x{s['offset']:06x} size=0x{s['size']:06x} addr=0x{s['addr']:06x}")

if dynsym and dynstr:
    dynstr_data = data[dynstr['offset']:dynstr['offset']+dynstr['size']]
    def get_dynstr(off):
        end = dynstr_data.find(b'\0', off)
        return dynstr_data[off:end].decode('ascii', errors='replace')

    # Find wl_proxy_marshal* symbols
    print("\n=== Dynamic symbols (wl_proxy_*) ===")
    entsize = dynsym['entsize'] or 24
    num_syms = dynsym['size'] // entsize
    wl_sym_indices = {}
    for i in range(num_syms):
        sym_off = dynsym['offset'] + i * entsize
        st_name = struct.unpack_from('<I', data, sym_off)[0]
        st_value = struct.unpack_from('<Q', data, sym_off + 8)[0]
        name = get_dynstr(st_name)
        if 'wl_proxy' in name:
            print(f"  sym[{i}] value=0x{st_value:06x} {name}")
            wl_sym_indices[name] = i

# Find all BL instructions and their targets to identify wl_proxy_marshal calls
print("\n=== Finding wl_proxy_marshal PLT entry ===")
# The PLT entry will be a BL target. Let me find PLT section
for s in sections:
    name = get_sh_name(s['name_off'])
    if 'plt' in name.lower():
        print(f"  {name}: offset=0x{s['offset']:06x} addr=0x{s['addr']:06x} size=0x{s['size']:06x}")

# Find all BL targets and which ones are in PLT range
if plt:
    plt_start = plt['offset']
    plt_end = plt_start + plt['size']
    print(f"  PLT range: 0x{plt_start:06x} - 0x{plt_end:06x}")

# Now let's search for the code that creates xdg_toplevel and calls set_maximized
# set_maximized is opcode 4 on xdg_toplevel
# The call would be: wl_proxy_marshal(proxy, 4) - with W1=4
print("\n=== Searching for MOV W1, #4 (set_maximized opcode) followed by BL ===")
for off in range(0, len(data) - 8, 4):
    insn = read_u32(data, off)
    # MOV W1, #4  = MOVZ W1, #4 = 0x52800081
    if insn == 0x52800081:
        # Check nearby for BL
        for delta in range(4, 20, 4):
            if off + delta + 4 <= len(data):
                next_insn = read_u32(data, off + delta)
                if (next_insn >> 26) == 0x25:  # BL
                    imm26 = next_insn & 0x3ffffff
                    if imm26 & 0x2000000: imm26 -= 0x4000000
                    target = (off + delta) + imm26 * 4
                    # Print context
                    print(f"\n  MOV W1, #4 at 0x{off:06x}, BL at 0x{off+delta:06x} -> 0x{target:06x}")
                    # Print surrounding context
                    start = max(0, off - 20)
                    end_ctx = min(len(data), off + delta + 20)
                    for a in range(start, end_ctx, 4):
                        i = read_u32(data, a)
                        d = disasm_one(data, a, i)
                        marker = " <<<<" if a == off else (" <<<BL" if a == off + delta else "")
                        print(f"    0x{a:06x}: {i:08x}  {d}{marker}")
                    break

# Also search for MOV W1, #3 (set_app_id opcode) to see if it's already there
print("\n=== Searching for MOV W1, #3 (set_app_id opcode) near BL ===")
for off in range(0, len(data) - 8, 4):
    insn = read_u32(data, off)
    # MOV W1, #3  = MOVZ W1, #3 = 0x52800061
    if insn == 0x52800061:
        for delta in range(4, 20, 4):
            if off + delta + 4 <= len(data):
                next_insn = read_u32(data, off + delta)
                if (next_insn >> 26) == 0x25:  # BL
                    imm26 = next_insn & 0x3ffffff
                    if imm26 & 0x2000000: imm26 -= 0x4000000
                    target = (off + delta) + imm26 * 4
                    print(f"  MOV W1, #3 at 0x{off:06x}, BL at 0x{off+delta:06x} -> 0x{target:06x}")

# Find xdg_wm_base_get_xdg_surface and xdg_surface_get_toplevel calls
# These use wl_proxy_marshal_constructor with specific opcodes
print("\n=== Searching for xdg-shell related opcodes ===")
# xdg_wm_base_get_xdg_surface = opcode 2
# xdg_surface_get_toplevel = opcode 1
# These use wl_proxy_marshal_constructor
for opc_val, opc_name in [(1, "get_toplevel"), (2, "get_xdg_surface")]:
    insn_val = 0x52800001 | (opc_val << 5)  # MOV W1, #opc_val
    for off in range(0, len(data) - 8, 4):
        insn = read_u32(data, off)
        if insn == insn_val:
            # Check nearby for BL (within 6 instructions)
            for delta in range(4, 28, 4):
                if off + delta + 4 <= len(data):
                    next_insn = read_u32(data, off + delta)
                    if (next_insn >> 26) == 0x25:  # BL
                        imm26 = next_insn & 0x3ffffff
                        if imm26 & 0x2000000: imm26 -= 0x4000000
                        target = (off + delta) + imm26 * 4
                        print(f"  MOV W1, #{opc_val} ({opc_name}) at 0x{off:06x}, BL at 0x{off+delta:06x} -> 0x{target:06x}")
                        # Print context
                        start = max(0, off - 16)
                        end_ctx = min(len(data), off + delta + 16)
                        for a in range(start, end_ctx, 4):
                            i = read_u32(data, a)
                            d = disasm_one(data, a, i)
                            marker = " <<<<" if a == off or a == off + delta else ""
                            print(f"      0x{a:06x}: {i:08x}  {d}{marker}")
                        break

# Find wl_proxy_marshal_constructor* PLT entries
print("\n=== All BL targets (looking for PLT) ===")
bl_targets = {}
for off in range(0, min(len(data), 0x60000), 4):
    insn = read_u32(data, off)
    if (insn >> 26) == 0x25:
        imm26 = insn & 0x3ffffff
        if imm26 & 0x2000000: imm26 -= 0x4000000
        target = off + imm26 * 4
        if target not in bl_targets:
            bl_targets[target] = []
        bl_targets[target].append(off)

# Show most common BL targets (likely PLT entries)
common = sorted(bl_targets.items(), key=lambda x: -len(x[1]))[:20]
for target, callers in common:
    print(f"  Target 0x{target:06x} called {len(callers)} times")

# Now find unused space (zero bytes) for code injection
print("\n=== Finding code caves (>= 64 bytes of zeros) ===")
zero_runs = []
i = 0
while i < len(data):
    if data[i] == 0:
        start = i
        while i < len(data) and data[i] == 0:
            i += 1
        length = i - start
        if length >= 64:
            zero_runs.append((start, length))
    else:
        i += 1

for start, length in zero_runs[:10]:
    print(f"  0x{start:06x}: {length} bytes of zeros")
