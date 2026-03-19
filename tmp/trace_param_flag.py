#!/usr/bin/env python3
"""
检查 param 中的 "reset_devinfo" 标志。
代码通过 0x29FE8 函数读取4字节，如果值==1则触发 init_defaults。
需要找出哪个偏移量被读取。

Also trace: *(0x1AD048) 指向哪里？
"""
import struct

PE32 = "/tmp/ffs_modules/pe32_59d536f5_1.bin"
TEXT_SIZE = 0x6A000

with open(PE32, "rb") as f:
    pe = f.read()

code = pe[:TEXT_SIZE]

# === 1. Check what 0x1AD048 contains ===
# 0x1AD000 page, offset +72 = +0x48 → 0x1AD048
if 0x1AD048 < len(pe):
    val = struct.unpack_from('<Q', pe, 0x1AD048)[0]
    print(f"*(0x1AD048) = 0x{val:016X}")
    if val == 0:
        print("  → Zero (runtime pointer, not initialized in binary)")
    else:
        print(f"  → Points to 0x{val:X}")

# === 2. Analyze function 0x29FE8 ===
print(f"\n=== Function 0x29FE8 (memcpy/param reader) ===")
for addr in range(0x29FE8, min(0x2A100, TEXT_SIZE), 4):
    insn = struct.unpack_from('<I', code, addr)[0]
    if insn == 0xD65F03C0:
        print(f"  0x{addr:05X}: ret")
        break
    # Quick decode
    if (insn & 0xFC000000) == 0x94000000:
        off26 = insn & 0x03FFFFFF
        if off26 & (1<<25): off26 -= (1<<26)
        print(f"  0x{addr:05X}: bl 0x{addr + off26*4:05X}")
    elif (insn & 0x9F000000) == 0x90000000:
        rd = insn & 0x1f
        immlo = (insn >> 29) & 3; immhi = (insn >> 5) & 0x7ffff
        imm = (immhi << 2) | immlo
        if imm & (1<<20): imm -= (1<<21)
        page = (addr & ~0xFFF) + (imm << 12)
        print(f"  0x{addr:05X}: adrp x{rd}, 0x{page:X}")
    elif (insn & 0xFFC00000) == 0x91000000:
        rd = insn & 0x1f; rn = (insn >> 5) & 0x1f; imm12 = (insn >> 10) & 0xFFF
        print(f"  0x{addr:05X}: add x{rd}, x{rn}, #0x{imm12:X}")
    elif (insn & 0xFFC00000) == 0xF9400000:
        imm12 = (insn >> 10) & 0xFFF
        rd = insn & 0x1f; rn = (insn >> 5) & 0x1f
        print(f"  0x{addr:05X}: ldr x{rd}, [x{rn}, #{imm12*8}]")
    else:
        print(f"  0x{addr:05X}: 0x{insn:08X}")

# === 3. Check param files at various offsets ===
print(f"\n=== 检查 param 文件中的关键偏移量 ===")
import os

param_files = {
    'original': '/Users/xmxx/pinganhuijia/edl_backup/param.bin',
    'patched': '/Users/xmxx/pinganhuijia/edl_backup/param_global_patched.bin',
    'readback': '/Users/xmxx/pinganhuijia/tmp/param_readback_after_reboot.bin',
}

param_data = {}
for name, path in param_files.items():
    if os.path.exists(path):
        with open(path, 'rb') as f:
            param_data[name] = f.read()
        print(f"  {name}: {len(param_data[name])} bytes")
    else:
        print(f"  {name}: NOT FOUND")

# Check at various offsets for the "reset_devinfo" flag
# The code uses: *(global_ptr) + 12704  and  *(global_ptr) + 10376
# global_ptr at 0x1AD048 is zero (runtime), so we don't know the base
# But let's check common offsets: 0x31A0, 0x2888, and also search for bytes
# that differ between versions

print(f"\n=== 在 param 中搜索值为 1 的 4字节 word ===")
# Check specific offsets
offsets_to_check = [0x31A0, 0x2888, 0x3400, 0x3404, 0x3408,
                    0x4B000, 0x4B004, 0x4B008, 0x4B00C, 0x4B010, 0x4B014,
                    0x0, 0x4, 0x8, 0xC, 0x10, 0x14, 0x18, 0x1C, 0x20]

for off in offsets_to_check:
    values = {}
    for name, data in param_data.items():
        if off + 4 <= len(data):
            val = struct.unpack_from('<I', data, off)[0]
            values[name] = val
    if values:
        vals_str = ", ".join(f"{name}=0x{v:08X}" for name, v in values.items())
        changed = len(set(values.values())) > 1
        flag = " ***" if changed else ""
        print(f"  0x{off:05X}: {vals_str}{flag}")

# Search for uint32 with value 1 that changes between versions
print(f"\n=== 搜索 param 中 original→readback 变化的 word==1 的位置 ===")
if 'original' in param_data and 'readback' in param_data:
    orig = param_data['original']
    rb = param_data['readback']
    patched = param_data.get('patched', None)

    for off in range(0, min(len(orig), len(rb)) - 4, 4):
        orig_val = struct.unpack_from('<I', orig, off)[0]
        rb_val = struct.unpack_from('<I', rb, off)[0]
        pat_val = struct.unpack_from('<I', patched, off)[0] if patched and off + 4 <= len(patched) else None

        if rb_val == 1 and orig_val != 1:
            pat_str = f", patched=0x{pat_val:08X}" if pat_val is not None else ""
            print(f"  0x{off:05X}: orig=0x{orig_val:08X}, readback=0x{rb_val:08X}{pat_str}")

print(f"\n=== 搜索 param 中所有 readback==1 但 original!=1 的字节 ===")
if 'original' in param_data and 'readback' in param_data:
    orig = param_data['original']
    rb = param_data['readback']
    count = 0
    for off in range(len(orig)):
        if off < len(rb) and rb[off] == 1 and orig[off] != 1:
            pat_val = param_data['patched'][off] if 'patched' in param_data and off < len(param_data['patched']) else None
            pat_str = f", patched=0x{pat_val:02X}" if pat_val is not None else ""
            print(f"  0x{off:05X}: orig=0x{orig[off]:02X}, readback=0x01{pat_str}")
            count += 1
            if count > 50:
                print("  ... (truncated)")
                break

# === 4. Also check which function sets 0x1C757C ===
print(f"\n=== 搜索写入 0x1C757C (unlock token flag) 的代码 ===")
# 0x1C7000 + 0x57C = 0x1C757C
for i in range(0, TEXT_SIZE, 4):
    insn = struct.unpack_from('<I', code, i)[0]
    # STRB Wt, [Xn, #1404]
    if (insn & 0xFFC00000) == 0x39000000:
        imm12 = (insn >> 10) & 0xFFF
        if imm12 == 1404:  # 0x57C
            rn = (insn >> 5) & 0x1f
            rt = insn & 0x1f
            # Check if base reg points to 0x1C7000
            for back in range(i-4, max(i-80, 0), -4):
                binsn = struct.unpack_from('<I', code, back)[0]
                if (binsn & 0x9F000000) == 0x90000000:
                    rd = binsn & 0x1f
                    if rd == rn:
                        immlo = (binsn >> 29) & 3; immhi = (binsn >> 5) & 0x7ffff
                        imm = (immhi << 2) | immlo
                        if imm & (1<<20): imm -= (1<<21)
                        page = (back & ~0xFFF) + (imm << 12)
                        if page == 0x1C7000:
                            print(f"  0x{i:05X}: strb w{rt}, [x{rn}, #1404]  (0x1C757C)")
                            # Show context
                            for ctx in range(max(i-20, 0), min(i+8, TEXT_SIZE), 4):
                                cinsn = struct.unpack_from('<I', code, ctx)[0]
                                if (cinsn & 0xFC000000) == 0x94000000:
                                    off26 = cinsn & 0x03FFFFFF
                                    if off26 & (1<<25): off26 -= (1<<26)
                                    print(f"      0x{ctx:05X}: bl 0x{ctx+off26*4:05X}")
                                elif (cinsn & 0xFF800000) == 0x52800000:
                                    print(f"      0x{ctx:05X}: mov w{cinsn&0x1f}, #{(cinsn>>5)&0xFFFF}")
                                else:
                                    print(f"      0x{ctx:05X}: 0x{cinsn:08X}")
                        break

# === 5. Also check 0x29FE8 callers to understand what offsets are used ===
print(f"\n=== 0x29FE8 的所有调用者和参数 ===")
for i in range(0, TEXT_SIZE, 4):
    insn = struct.unpack_from('<I', code, i)[0]
    if (insn & 0xFC000000) == 0x94000000:
        off26 = insn & 0x03FFFFFF
        if off26 & (1<<25): off26 -= (1<<26)
        if i + off26*4 == 0x29FE8:
            # Show context to find w9 (the offset)
            for back in range(max(i-40, 0), i, 4):
                binsn = struct.unpack_from('<I', code, back)[0]
                if (binsn & 0xFF800000) == 0x52800000:
                    rd = binsn & 0x1f
                    imm = (binsn >> 5) & 0xFFFF
                    print(f"  caller 0x{i:05X}: mov w{rd}, #{imm} (0x{imm:X})")
