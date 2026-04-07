#!/usr/bin/env python3
"""Find xdg_toplevel set_maximized and set_app_id call sites in hwcomposer"""
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
    if (insn & 0x7f800000) == 0x51000000:
        sf = (insn >> 31) & 1
        imm12 = (insn >> 10) & 0xfff
        rn = (insn >> 5) & 0x1f
        rd = insn & 0x1f
        rp = "X" if sf else "W"
        return f"SUB {rp}{rd}, {rp}{rn}, #0x{imm12:x}"
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
    return f"??? 0x{insn:08x}"

with open('/Users/xmxx/pinganhuijia/tmp/hwc.so', 'rb') as f:
    data = f.read()

# xdg_toplevel opcodes from stable xdg-shell:
# 0=destroy, 1=set_parent, 2=set_title, 3=set_app_id, 4=show_window_menu
# 5=move, 6=resize, 7=set_max_size, 8=set_min_size, 9=set_maximized
print("=== Search for MOV W1, #N (various opcodes) near BL ===")
for opc_val, opc_name in [(9, "set_maximized"), (3, "set_app_id"), (7, "set_max_size"), (8, "set_min_size")]:
    expected_insn = 0x52800001 | (opc_val << 5)
    for off in range(0, len(data) - 8, 4):
        insn = read_u32(data, off)
        if insn == expected_insn:
            for delta in range(4, 28, 4):
                if off + delta + 4 <= len(data):
                    next_insn = read_u32(data, off + delta)
                    if (next_insn >> 26) == 0x25:  # BL
                        imm26 = next_insn & 0x3ffffff
                        if imm26 & 0x2000000: imm26 -= 0x4000000
                        target = (off + delta) + imm26 * 4
                        print(f"\n  MOV W1, #{opc_val} ({opc_name}) at 0x{off:06x}, BL at 0x{off+delta:06x} -> 0x{target:06x}")
                        start = max(0, off - 24)
                        end_ctx = min(len(data), off + delta + 16)
                        for a in range(start, end_ctx, 4):
                            i = read_u32(data, a)
                            d = disasm_one(data, a, i)
                            marker = " <<<<" if a == off or a == off + delta else ""
                            print(f"    0x{a:06x}: {i:08x}  {d}{marker}")
                        break

# Also check if opcodes are passed via W2 (second arg) instead of W1
print("\n=== Search for MOV W2, #9 near BL (alternate param passing) ===")
expected_insn = 0x52800002 | (9 << 5)  # MOV W2, #9
for off in range(0, len(data) - 8, 4):
    insn = read_u32(data, off)
    if insn == expected_insn:
        for delta in range(4, 28, 4):
            if off + delta + 4 <= len(data):
                next_insn = read_u32(data, off + delta)
                if (next_insn >> 26) == 0x25:  # BL
                    imm26 = next_insn & 0x3ffffff
                    if imm26 & 0x2000000: imm26 -= 0x4000000
                    target = (off + delta) + imm26 * 4
                    print(f"  MOV W2, #9 at 0x{off:06x}, BL at 0x{off+delta:06x} -> 0x{target:06x}")

# Search for PLT stubs - wl_proxy_marshal should be at some PLT offset
# wl_proxy_marshal's GOT entry value was 0x049ad4
# Let's find which PLT entry targets it
print("\n=== Identifying wl_proxy_marshal PLT entry ===")
# PLT entries on aarch64 typically look like:
# ADRP Xn, got_page
# LDR Xn, [Xn, got_offset]
# ADD Xn, Xn, ...
# BR Xn

# Or they could use a different pattern. Let me scan PLT range
plt_start = 0x065fc0
plt_end = 0x067bf0

# First, let me search for BL targets that match known wl_proxy_marshal-like behavior
# wl_proxy_marshal is variadic: wl_proxy_marshal(proxy, opcode, ...)
# Look for calls where X0 = some proxy, W1 = small constant (opcode)

# Let me check the xdg_toplevel_requests table near "set_maximized" string
print("\n=== Data around 'set_maximized' string at 0x018a38 ===")
sm_idx = data.find(b'set_maximized')
if sm_idx >= 0:
    # Dump context
    start = max(0, sm_idx - 64)
    end = min(len(data), sm_idx + 128)
    # Look for this as part of a wl_message array
    # wl_message is: { const char *name, const char *signature, const struct wl_interface **types }
    # So the address of "set_maximized" should appear as a pointer in the data

    print(f"  String 'set_maximized' at 0x{sm_idx:06x}")
    # Also find other toplevel request names nearby
    for name in [b'destroy', b'set_parent', b'set_title', b'set_app_id',
                 b'show_window_menu', b'move\x00', b'resize', b'set_max_size', b'set_min_size',
                 b'set_maximized', b'unset_maximized', b'set_fullscreen', b'set_minimized']:
        idx = data.find(name)
        if idx >= 0 and idx < 0x20000:  # Only in read-only data sections
            print(f"    0x{idx:06x}: {name.decode('ascii', errors='replace').rstrip(chr(0))}")

# Now let's find where wl_proxy_marshal PLT entry is
# The GOT entry offset for wl_proxy_marshal sym value 0x049ad4
# Search in .rela.plt for the relocation
print("\n=== Parsing .rela.plt to find wl_proxy_marshal GOT/PLT entries ===")
# .rela.plt at offset 0x0124a8, size 0x2a18
# Each entry is 24 bytes: r_offset(8), r_info(8), r_addend(8)
rela_start = 0x0124a8
rela_size = 0x2a18
rela_end = rela_start + rela_size

# We need .dynsym and .dynstr to resolve
# Parse ELF sections
e_shoff = struct.unpack_from('<Q', data, 40)[0]
e_shentsize = struct.unpack_from('<H', data, 58)[0]
e_shnum = struct.unpack_from('<H', data, 60)[0]
e_shstrndx = struct.unpack_from('<H', data, 62)[0]

sections = {}
for i in range(e_shnum):
    off = e_shoff + i * e_shentsize
    sh = {
        'type': struct.unpack_from('<I', data, off+4)[0],
        'addr': struct.unpack_from('<Q', data, off+16)[0],
        'offset': struct.unpack_from('<Q', data, off+24)[0],
        'size': struct.unpack_from('<Q', data, off+32)[0],
        'link': struct.unpack_from('<I', data, off+40)[0],
        'entsize': struct.unpack_from('<Q', data, off+56)[0],
    }
    shstrtab_off = e_shoff + e_shstrndx * e_shentsize
    shstrtab_data_off = struct.unpack_from('<Q', data, shstrtab_off+24)[0]
    shstrtab_size = struct.unpack_from('<Q', data, shstrtab_off+32)[0]
    name_off = struct.unpack_from('<I', data, off)[0]
    name_end = data.find(b'\0', shstrtab_data_off + name_off)
    name = data[shstrtab_data_off + name_off:name_end].decode()
    sections[name] = sh

dynsym = sections.get('.dynsym')
dynstr = sections.get('.dynstr')

if dynsym and dynstr:
    dynstr_data = data[dynstr['offset']:dynstr['offset']+dynstr['size']]

    for off in range(rela_start, rela_end, 24):
        r_offset = struct.unpack_from('<Q', data, off)[0]
        r_info = struct.unpack_from('<Q', data, off + 8)[0]
        r_type = r_info & 0xffffffff
        r_sym = r_info >> 32

        # Get symbol name
        sym_off = dynsym['offset'] + r_sym * (dynsym['entsize'] or 24)
        st_name = struct.unpack_from('<I', data, sym_off)[0]
        sym_name_end = dynstr_data.find(b'\0', st_name)
        sym_name = dynstr_data[st_name:sym_name_end].decode('ascii', errors='replace')

        if 'wl_proxy_marshal' in sym_name and 'array' not in sym_name:
            # This is a PLT entry for wl_proxy_marshal!
            # r_offset is the GOT entry address
            # The PLT stub index can be computed from the GOT entry
            got_plt_start = 0x06e680  # .got.plt start
            idx = (r_offset - got_plt_start) // 8
            plt_entry = plt_start + idx * 16  # Each PLT entry is 16 bytes
            print(f"  {sym_name}: GOT@0x{r_offset:06x}, PLT index={idx}, PLT@~0x{plt_entry:06x}")
            # Show PLT stub
            for a in range(plt_entry - 16, plt_entry + 32, 4):
                if 0 <= a < len(data):
                    i = read_u32(data, a)
                    d = disasm_one(data, a, i)
                    marker = " <<<<" if a == plt_entry else ""
                    print(f"    0x{a:06x}: {i:08x}  {d}{marker}")

# Now find all calls TO the wl_proxy_marshal PLT entry
# wl_proxy_marshal PLT entry should be around 0x067xxx based on the previous analysis
# Let me check which of the common BL targets is wl_proxy_marshal
print("\n=== Calls to wl_proxy_marshal (matching PLT target) ===")
# From the rela.plt analysis above, we'll find the exact PLT address
# For now, let's check each BL target and see if it matches
# wl_proxy_marshal signature: wl_proxy_marshal(struct wl_proxy *p, uint32_t opcode, ...)
# The caller typically: MOV W1, #opcode before the BL

# Let me collect ALL BL calls and check what's in W1 before them
bl_calls = []
for off in range(0, min(len(data), 0x60000), 4):
    insn = read_u32(data, off)
    if (insn >> 26) == 0x25:
        imm26 = insn & 0x3ffffff
        if imm26 & 0x2000000: imm26 -= 0x4000000
        target = off + imm26 * 4
        # Check instructions before for MOV W1, #N
        for lookback in range(4, 20, 4):
            prev_off = off - lookback
            if prev_off >= 0:
                prev = read_u32(data, prev_off)
                if (prev & 0xffe0001f) == 0x52800001:  # MOVZ W1, #imm16
                    imm16 = (prev >> 5) & 0xffff
                    if imm16 < 20:  # Wayland opcodes are small
                        bl_calls.append((off, target, prev_off, imm16))
                        break

# Group by target
from collections import defaultdict
by_target = defaultdict(list)
for bl_off, target, mov_off, opc in bl_calls:
    by_target[target].append((bl_off, mov_off, opc))

for target, calls in sorted(by_target.items()):
    if len(calls) >= 2:  # Only show targets called multiple times with small opcodes
        opcodes = [c[2] for c in calls]
        print(f"  Target 0x{target:06x}: {len(calls)} calls with opcodes {opcodes}")
        if any(opc == 9 for opc in opcodes):
            print(f"    ^^^ HAS OPCODE 9 (set_maximized) ^^^")
            for bl_off, mov_off, opc in calls:
                if opc == 9:
                    print(f"    BL at 0x{bl_off:06x}, MOV W1,#9 at 0x{mov_off:06x}")
                    # Print context
                    start = max(0, mov_off - 32)
                    end_ctx = min(len(data), bl_off + 16)
                    for a in range(start, end_ctx, 4):
                        i = read_u32(data, a)
                        d = disasm_one(data, a, i)
                        marker = ""
                        if a == mov_off: marker = " <<<< MOV W1,#9"
                        elif a == bl_off: marker = " <<<< BL wl_proxy_marshal"
                        print(f"      0x{a:06x}: {i:08x}  {d}{marker}")
