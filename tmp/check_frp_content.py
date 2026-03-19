import struct

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb').read()

# Check strings in .text near 0x69xxx that 0x4FD10 references
print('=== Strings used in 0x4FD10 ===')
for addr in [0x6928F, 0x6932A, 0x6934C, 0x69369, 0x693AC, 0x693EA]:
    try:
        end = data.index(b'\x00', addr)
        s = data[addr:min(end, addr+100)]
        print(f'  0x{addr:X}: {s}')
    except:
        print(f'  0x{addr:X}: (error reading)')

# Check the 0x6A0A8 global (referenced by 0x4FD1C + 0xA8)
print(f'\n[0x6A0A8] value: 0x{struct.unpack_from("<Q", data, 0x6A0A8)[0]:X}')

# Check caller of the init function containing 0x383A0
# First find function in 0x38300-0x383A0 prologue
print('\n=== Looking for function boundary near 0x38300 ===')
import struct as st
for off in range(0x37800, 0x38300, 4):
    instr = st.unpack_from('<I', data, off)[0]
    # STP with writeback to SP (function prologue)
    # STP Xn, Xm, [SP, #-N]! = A9Bx xxxx where bits29-27=110, bit23=1
    if off == 0x37F88 or off == 0x3811C:
        print(f'  Branch target at 0x{off:X}: 0x{instr:08X}')

# Find callers of ~0x38300 area
def decode_bl(instr, pc):
    imm26 = instr & 0x03FFFFFF
    if imm26 & 0x02000000:
        imm26 -= 0x04000000
    return pc + imm26 * 4

print('\n=== Callers of functions in 0x38300-0x383A0 range ===')
for i in range(0, 0x69000-4, 4):
    instr = st.unpack_from('<I', data, i)[0]
    if (instr & 0xFC000000) == 0x94000000:
        target = decode_bl(instr, i)
        if 0x38300 <= target <= 0x383A0:
            print(f'  BL 0x{target:X} from 0x{i:X}')

# Check what's in backup FRP vs our file
import os
frp_orig = open('edl_backup/lun0/frp.bin', 'rb').read()
frp_new = open('tmp/frp_unlocked.bin', 'rb').read()
print(f'\n=== FRP comparison ===')
print(f'Original FRP size: {len(frp_orig)}')
diffs = [(i, frp_orig[i], frp_new[i]) for i in range(min(len(frp_orig), len(frp_new))) if frp_orig[i] != frp_new[i]]
print(f'Differences: {len(diffs)}')
for i, old, new in diffs[:10]:
    print(f'  offset 0x{i:X}: 0x{old:02X} -> 0x{new:02X}')

# Non-zero data in original FRP
nonzero = [(i, frp_orig[i]) for i in range(len(frp_orig)) if frp_orig[i] != 0]
print(f'Non-zero bytes in original FRP: {len(nonzero)}')
for i, v in nonzero[:20]:
    print(f'  0x{i:X}: 0x{v:02X}')
