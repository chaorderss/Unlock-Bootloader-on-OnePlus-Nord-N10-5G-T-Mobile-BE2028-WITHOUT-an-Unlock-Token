import struct

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb').read()

# The init function at 0x37D38:
# 0x37DA4: MOV W29, #0x9   ← initial carrier ID = 9
# 0x37E14: STR W29, [X8, #0x64]  ← store to [0x1AD064]
#
# For model 20888 (match at 0x37EA8):
# 0x37F30: MOV W8, #0x5   ← model index = 5
#
# 0x37F4C: MOV W9, #0x58   ← struct size = 0x58
# 0x37F54: ADD X10, X10, #0x488  ← table base at 0x62488
# 0x37F58: MADD X8, X8, X9, X10  ← X8 = 5 * 0x58 + 0x62488 = 0x62640
# 0x37F60: LDR W8, [X8, #0x40]  ← load carrier ID from 0x62640 + 0x40 = 0x62680
# 0x37F64: STR W8, [X29, #0x64]  ← store carrier ID
# 0x37F68: CMP W8, #0x9
# 0x37F6C: B.EQ 0x37F84 → EARLY RETURN if carrier == 9
# 0x37F70: ... continue to carrier unlock flow (eventually sets [0x1BF518])

# Check the carrier ID for model 20888
table_base = 0x62488
struct_size = 0x58
model_index = 5  # for 20888

entry_addr = model_index * struct_size + table_base
carrier_id_addr = entry_addr + 0x40

carrier_id = struct.unpack_from('<I', data, carrier_id_addr)[0]
print(f'Table base: 0x{table_base:X}')
print(f'Entry for index 5 (20888): 0x{entry_addr:X}')
print(f'Carrier ID address: 0x{carrier_id_addr:X}')
print(f'Carrier ID value: {carrier_id} (0x{carrier_id:X})')
print(f'Is T-Mobile (==9)? {carrier_id == 9}')
print()

# Dump the ENTIRE table entry for model 20888
print(f'=== Table entry for 20888 at 0x{entry_addr:X} (0x58 bytes) ===')
for i in range(0, struct_size, 8):
    vals = struct.unpack_from('<Q', data, entry_addr + i)[0]
    print(f'  +0x{i:02X}: 0x{vals:016X}  [{data[entry_addr+i:entry_addr+i+8].hex()}]')

# Dump ALL carrier entries in the table to see all models
print('\n=== All model entries in carrier table ===')
model_strings = {
    0x62213: 'model_0',
    0x62273: 'model_1',
    0x622D3: 'model_2',
    0x62333: 'model_3',
    0x62393: 'model_4',
}

for idx in range(10):  # Check 10 entries
    addr = idx * struct_size + table_base
    if addr + struct_size > len(data):
        break
    cid = struct.unpack_from('<I', data, addr + 0x40)[0]
    # Try to read the model name string from the entry
    # Check what the string refs are
    print(f'  Index {idx}: entry at 0x{addr:X}, carrier_id at 0x{addr+0x40:X} = {cid}')

# Now let's verify the model strings used in the comparison
print('\n=== Model strings in comparison ===')
# From carrier check 0x3BB48:
strings = [
    (0x5F53B, '20888'),
    (0x5F524, '20882'),
    (0x5FB26, '20880'),
    (0x5FB2C, '20885'),
]
for addr, expected in strings:
    actual = data[addr:addr+20]
    # find null terminator
    null_pos = actual.find(b'\x00')
    if null_pos >= 0:
        actual = actual[:null_pos]
    print(f'  0x{addr:X}: "{actual.decode("ascii", errors="replace")}" (expected: {expected})')

# From init function 0x37D38, the model comparisons:
print('\n=== Model strings in init (0x37D38) ===')
init_strings = [
    (0x62213, 'model_0'),
    (0x62273, 'model_1'),
    (0x622D3, 'model_2'),
    (0x62333, 'model_3'),
    (0x62393, 'model_4'),
    (0x5F53B, 'model_5 (20888)'),
    (0x5FB26, 'model_6'),
    (0x5F524, 'model_7'),
    (0x5FB2C, 'model_8'),
]
for addr, label in init_strings:
    actual = data[addr:addr+20]
    null_pos = actual.find(b'\x00')
    if null_pos >= 0:
        actual = actual[:null_pos]
    print(f'  {label}: 0x{addr:X}: "{actual.decode("ascii", errors="replace")}"')

# Check what's at 0x37F84 (early return for carrier 9)
# 0x37F84: 0xB2410BF4
instr = struct.unpack_from('<I', data, 0x37F84)[0]
# ORR X20, XZR, #imm
# Decode the immediate
print(f'\n=== Decode 0x37F84: 0x{instr:08X} ===')
# This is ORR Xd, Xn, #imm  (sf=1, opc=01, 100100)
N = (instr >> 22) & 1
immr = (instr >> 16) & 0x3F
imms = (instr >> 10) & 0x3F
rn = (instr >> 5) & 0x1F
rd = instr & 0x1F
print(f'  ORR X{rd}, X{rn}, N={N}, immr={immr}, imms={imms}')

# Decode the bitmask for ORR immediate
# For 64-bit N=0: element size determined by highest bit in ~imms[5:0]
def decode_bitmask_64(N, imms, immr):
    if N == 1:
        # 64-bit element
        len_val = 6
        levels = 0x3F
    else:
        # Find highest set bit of ~imms (6 bits)
        not_imms = (~imms) & 0x3F
        # Find position of highest bit
        for bit in range(5, -1, -1):
            if not_imms & (1 << bit):
                len_val = bit + 1
                break
        else:
            return None  # Reserved
        levels = (1 << len_val) - 1

    S = imms & levels
    R = immr & levels
    esize = 1 << len_val

    # Create the element
    welem = (1 << (S + 1)) - 1
    # Rotate right by R within element
    welem = ((welem >> R) | (welem << (esize - R))) & ((1 << esize) - 1)

    # Replicate to fill 64 bits
    result = 0
    for i in range(64 // esize):
        result |= welem << (i * esize)
    return result

bitmask = decode_bitmask_64(N, imms, immr)
if bitmask is not None:
    if rn == 31:  # XZR
        val = bitmask  # ORR with XZR = MOV
        print(f'  → MOV X{rd}, #0x{val:016X}')
    else:
        print(f'  Bitmask: 0x{bitmask:016X}')

# Check the critical path:
# If carrier_id == 9 at 0x37F6C, it branches to 0x37F84 → sets X20 → returns at 0x37FBC
# The function NEVER reaches 0x383B8 (FRP read) or 0x383F8 ([0x1BF518] write)
print('\n=== CRITICAL CONCLUSION ===')
if carrier_id == 9:
    print('*** CONFIRMED: Model 20888 has carrier_id = 9 (T-Mobile) ***')
    print('*** The init function returns EARLY at 0x37F84 when carrier == 9 ***')
    print('*** It NEVER reaches 0x383F8 which sets [0x1BF518] = 1 ***')
    print('*** Therefore [0x1BF518] stays 0, carrier check always fails ***')
    print('*** T-Mobile devices REQUIRE an actual unlock token ***')
    print('')
    print('Options to bypass:')
    print('1. Modify the carrier table to change model 20888 carrier from 9 to something else')
    print('   → But ABL is signed, cannot modify')
    print('2. Find the actual unlock token protocol')
    print('3. Find alternate paths that skip the carrier check entirely')
    print('4. Modify another partition to trick the carrier check')
else:
    print(f'Carrier ID for 20888 is {carrier_id}, NOT 9')
    print('The early return does NOT apply - need to investigate other paths')
