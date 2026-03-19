#!/usr/bin/env python3
"""
Check key string references and understand the broader IsAllowUnlock context.
Then check the param partition in EDL backup.
"""

from capstone import *
import struct

with open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb') as f:
    data = f.read()

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

# 1. String at 0x681E4 (compared in third caller of 0x189E8)
s = data[0x681E4:0x681E4+80]
end = s.find(0)
if end > 0: s = s[:end]
print(f"String at 0x681E4: '{s.decode('ascii', errors='replace')}'")

# 2. String at 0x512BC (error in early boot path)
s = data[0x512BC:0x512BC+80]
end = s.find(0)
if end > 0: s = s[:end]
print(f"String at 0x512BC: '{s.decode('ascii', errors='replace')}'")

# 3. String at 0x512DD (error in early boot path)
s = data[0x512DD:0x512DD+80]
end = s.find(0)
if end > 0: s = s[:end]
print(f"String at 0x512DD: '{s.decode('ascii', errors='replace')}'")

# 4. Context before 0x48534 to see where x8 comes from for IsAllowUnlock
# Need to see what happens before the ADRP at 0x48534
print("\n=== Context before IsAllowUnlock print (0x484C0-0x48538) ===")
code = data[0x484C0:0x48540]
for insn in md.disasm(code, 0x484C0):
    extra = ''
    if insn.mnemonic == 'bl':
        extra = f'  ; CALL 0x{insn.operands[0].imm:X}'
    elif insn.mnemonic == 'blr':
        extra = '  ; INDIRECT CALL'
    elif insn.mnemonic == 'adrp':
        extra = f'  ; page=0x{insn.operands[1].imm:X}'
    elif insn.mnemonic in ('b', 'b.eq', 'b.ne', 'b.gt', 'b.lt', 'b.ge', 'b.le',
                           'b.hi', 'b.lo', 'b.hs', 'b.ls', 'cbz', 'cbnz', 'tbz', 'tbnz'):
        for op in insn.operands:
            if op.type == 2:
                extra = f'  ; -> 0x{op.imm:X}'
    elif 'str' in insn.mnemonic:
        extra = '  ; *** STORE ***'
    print(f"  0x{insn.address:05X}: {insn.mnemonic:<8s} {insn.op_str}{extra}")

# 5. Let's look harder at the function start of the IsAllowUnlock context
# Search backwards further
print("\n=== Wider search for function containing 0x48534 ===")
for scan in range(0x48530, 0x48200, -4):
    word = struct.unpack_from('<I', data, scan)[0]
    if word == 0xD65F03C0:  # RET
        print(f"  Found RET at 0x{scan:05X}, function starts at 0x{scan+4:05X}")
        break
    elif word == 0x00000000:  # UDF
        prev_word = struct.unpack_from('<I', data, scan - 4)[0]
        if prev_word == 0xD65F03C0 or (prev_word & 0xFFFF0000) == 0x00000000:
            print(f"  Found boundary at 0x{scan:05X}, function starts at ~0x{scan+4:05X}")
            break

# 6. Let's find where the devinfo struct with IsAllowUnlock field is populated
# devinfo buffer is at 0x1BD978
# Check if offset 0x10 from some base contains IsAllowUnlock
# From 0x4853C: ldr w2, [x8, #0x10] - x8 points to something
# Let's trace x8 back through the code

# 7. Actually, IsAllowUnlock might be stored in devinfo_buf at a certain offset
# devinfo_buf is at 0x1BD978
# devinfo[0x0D] = is_unlocked
# What's at devinfo[0x10]? Let's check
devinfo_base = 0x1BD978
for off in [0x00, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x90]:
    val = data[devinfo_base + off]
    print(f"  devinfo[0x{off:02X}] = 0x{val:02X}")

# 8. Search for "IsAllowUnlock" in the devinfo structure comments
# The actual IsAllowUnlock might be a separate variable, not in devinfo
# Let's search for any store/load at known offsets

# 9. Check if the param partition exists in EDL backup
import os
edl_base = '/Users/xmxx/pinganhuijia/edl_backup'
print("\n=== Checking for param partition in EDL backup ===")
for lun in range(6):
    param_path = os.path.join(edl_base, f'lun{lun}', 'param.bin')
    if os.path.exists(param_path):
        size = os.path.getsize(param_path)
        print(f"  FOUND: {param_path} ({size} bytes)")
        # Read header
        with open(param_path, 'rb') as f:
            header = f.read(64)
        print(f"  Header: {header[:32].hex()}")
        print(f"  Header: {header[32:64].hex()}")

# Also check for oplusreserve or similar
for lun in range(6):
    lun_dir = os.path.join(edl_base, f'lun{lun}')
    if os.path.exists(lun_dir):
        files = os.listdir(lun_dir)
        for f in sorted(files):
            if 'param' in f.lower() or 'reserve' in f.lower() or 'config' in f.lower() or 'ops' in f.lower():
                path = os.path.join(lun_dir, f)
                size = os.path.getsize(path)
                print(f"  {path} ({size} bytes)")
