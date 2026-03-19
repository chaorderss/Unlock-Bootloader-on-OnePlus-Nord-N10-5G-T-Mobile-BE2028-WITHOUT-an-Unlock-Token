#!/usr/bin/env python3
import struct

pe = open('/tmp/ffs_modules/pe32_59d536f5_1.bin','rb').read()

addrs = {
    'x24 value (when unlocked)': 0x5FDC8,
    'x25 value (when locked)': 0x51B65,
    'var1 name (bl 0x22C38)': 0x067D1F,
    'var2 name (bl 0x22C18=IsUnlocked)': 0x067D2F,
    'var3 name (bl 0x22C28=IsUnlockCrit)': 0x067D43,
    'var4 name (bl 0x22C48)': 0x067D60,
}

print("=== fastboot 变量注册的字符串 ===")
for label, addr in addrs.items():
    end = pe.index(0, addr, addr + 60)
    s = pe[addr:end].decode('ascii', errors='replace')
    print(f'  {label}: 0x{addr:06X} = "{s}"')

# Decode devinfo getter functions
code = pe[:0x6A000]
print("\n=== devinfo getter 函数列表 (0x22C18-0x22C60) ===")
for i in range(0x22C18, 0x22C60, 4):
    insn = struct.unpack_from('<I', code, i)[0]
    if (insn & 0xFFC00000) == 0x39400000:
        rt = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm12 = (insn >> 10) & 0xFFF
        print(f'  0x{i:05X}: ldrb w{rt}, [x{rn}, #{imm12}]  (devinfo offset 0x{imm12:02X})')
    elif insn == 0xD65F03C0:
        print(f'  0x{i:05X}: ret')
    elif (insn & 0x9F000000) == 0x90000000:
        rd = insn & 0x1f
        immlo = (insn >> 29) & 3
        immhi = (insn >> 5) & 0x7ffff
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= (1 << 21)
        page = (i & ~0xFFF) + (imm << 12)
        print(f'  0x{i:05X}: adrp x{rd}, 0x{page:X}')
    elif (insn & 0xFFC00000) == 0x91000000:
        rd = insn & 0x1f
        rn2 = (insn >> 5) & 0x1f
        imm12 = (insn >> 10) & 0xFFF
        print(f'  0x{i:05X}: add x{rd}, x{rn2}, #0x{imm12:X}')
    else:
        print(f'  0x{i:05X}: .word 0x{insn:08X}')

# Show what function is at 0x22C48 (the 4th getter)
print("\n=== 0x22C48 getter function ===")
for i in range(0x22C48, 0x22C60, 4):
    insn = struct.unpack_from('<I', code, i)[0]
    if (insn & 0xFFC00000) == 0x39400000:
        rt = insn & 0x1f
        rn = (insn >> 5) & 0x1f
        imm12 = (insn >> 10) & 0xFFF
        print(f'  0x{i:05X}: ldrb w{rt}, [x{rn}, #{imm12}]  → devinfo[0x{imm12:02X}]')
    elif insn == 0xD65F03C0:
        print(f'  0x{i:05X}: ret')
    elif (insn & 0x9F000000) == 0x90000000:
        rd = insn & 0x1f
        immlo = (insn >> 29) & 3
        immhi = (insn >> 5) & 0x7ffff
        imm = (immhi << 2) | immlo
        if imm & (1 << 20): imm -= (1 << 21)
        page = (i & ~0xFFF) + (imm << 12)
        print(f'  0x{i:05X}: adrp x{rd}, 0x{page:X}')
    elif (insn & 0xFFC00000) == 0x91000000:
        rd = insn & 0x1f
        rn2 = (insn >> 5) & 0x1f
        imm12 = (insn >> 10) & 0xFFF
        print(f'  0x{i:05X}: add x{rd}, x{rn2}, #0x{imm12:X}')
