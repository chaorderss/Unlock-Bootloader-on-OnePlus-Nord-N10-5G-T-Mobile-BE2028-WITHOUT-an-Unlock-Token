#!/usr/bin/env python3
"""Find code referencing devinfo strings, especially the magic check and Read/Write paths"""
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

# Key target addresses to find references to
targets = {
    0x05bf06: "ANDROID-BOOT!",
    0x05bf43: "DeviceInfo not initalized",
    0x05bfb0: "DeviceInfo not initalized (2)",
    0x05c018: "DeviceInfo not initalized (3)",
    0x060ba0: "DevInfo] reset_devinfo",
    0x060be2: "DevInfo] set_param_by_index_and_offset failed",
    0x066ba3: "unlock_ability",
    0x067aa5: "unlock_ability: %d",
}

target_pages = {}
for addr in targets:
    page = addr & ~0xFFF
    if page not in target_pages:
        target_pages[page] = set()
    target_pages[page].add(addr)

print("=== Code references to devinfo strings ===")
adrp_log = {}
for pc in range(0x1000, 0x89000, 4):
    if pc + 4 > len(data):
        break
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
                    print(f"  {pc:#07x}: x{rd} -> {final:#x} \"{targets[final][:60]}\"")

# Now find ReadDeviceInfo / WriteDeviceInfo by searching for "devinfo" partition name
print()
print("=== 'devinfo' partition name string ===")
for needle in [b'devinfo\x00', b'DeviceInfo\x00']:
    idx = 0
    while True:
        idx = data.find(needle, idx)
        if idx < 0:
            break
        # Show context around it
        start = max(0, idx - 16)
        print(f"  Found at {idx:#x}, context: {data[start:idx+len(needle)+16].hex()}")
        idx += 1

# Search for the function that reads/writes devinfo partition
# It likely uses a string "devinfo" as partition name passed to ReadWritePartition
print()
print("=== Searching for partition read/write with 'devinfo' string ===")
# The string "devinfo" at 0x60baf is inside a longer string. Let me find standalone "devinfo"
for i in range(len(data) - 8):
    if data[i:i+7] == b'devinfo' and (i == 0 or data[i-1] == 0) and data[i+7] == 0:
        print(f"  Standalone 'devinfo\\0' at {i:#x}")
