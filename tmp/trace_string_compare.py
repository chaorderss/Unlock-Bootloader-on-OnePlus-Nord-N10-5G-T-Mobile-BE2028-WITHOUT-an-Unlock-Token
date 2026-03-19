import struct

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb').read()

# Check what's at 0x61862 in various encodings
print('=== Raw bytes at 0x61860-0x61880 ===')
raw = data[0x61860:0x61880]
print(f'  Hex: {raw.hex()}')
print(f'  ASCII: {raw.decode("ascii", errors="replace")}')

# Check as UTF-16LE
try:
    utf16 = raw.decode('utf-16-le', errors='replace')
    print(f'  UTF-16LE: "{utf16}"')
except:
    pass

# More context
print('\n=== Wider context 0x61840-0x618A0 ===')
raw2 = data[0x61840:0x618A0]
print(f'  Hex: {raw2.hex()}')
print(f'  ASCII: {raw2.decode("ascii", errors="replace")}')

# Check specifically: is "c" (0x63) at 0x61862?
print(f'\n  Byte at 0x61862: 0x{data[0x61862]:02X}')
print(f'  Byte at 0x61863: 0x{data[0x61863]:02X}')
print(f'  Byte at 0x61864: 0x{data[0x61864]:02X}')
print(f'  Byte at 0x61865: 0x{data[0x61865]:02X}')

# Actually the string compare function 0x299B4 uses LDRH (UTF-16)
# For OnePlus, "c" might stand for something related to Carrier
# Or this might be a longer string - let me read from the exact offset as UTF-16
print('\n=== UTF-16LE string starting at 0x61862 ===')
i = 0x61862
chars = []
while i < 0x618F0:
    ch = struct.unpack_from('<H', data, i)[0]
    if ch == 0:
        break
    chars.append(chr(ch))
    i += 2
print(f'  "{("".join(chars))}"')

# Also check: what is X28 (1st param of 0x37D38)?
# Called from 0x49D0C with: X0 = X21
# Let's trace X21 in the caller function (around 0x49BF8-0x49D0C)
print('\n\n=== Tracing X21 (=X0=X28 in init) in caller function ===')

def decode_bl(instr, pc):
    imm26 = instr & 0x03FFFFFF
    if imm26 & 0x02000000:
        imm26 -= 0x04000000
    return pc + imm26 * 4

def decode_adrp(instr, pc):
    immhi = (instr >> 5) & 0x7FFFF
    immlo = (instr >> 29) & 0x3
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    return (pc & ~0xFFF) + (imm << 12)

# Disassemble from 0x49BF8 (function entry) to 0x49D20
for off in range(0x49BF8, 0x49D20, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    desc = f'raw 0x{instr:08X}'

    if (instr & 0xFC000000) == 0x94000000:
        desc = f'BL 0x{decode_bl(instr, off):X}'
    elif (instr & 0xFC000000) == 0x14000000:
        desc = f'B 0x{decode_bl(instr, off):X}'
    elif (instr & 0xFF000010) == 0x54000000:
        imm19 = (instr >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 -= 0x80000
        cond = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV'][instr & 0xF]
        desc = f'B.{cond} 0x{off + imm19*4:X}'
    elif (instr & 0x7E000000) == 0x34000000:
        imm19 = (instr >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 -= 0x80000
        op = 'CBNZ' if (instr >> 24) & 1 else 'CBZ'
        reg = instr & 0x1F
        size = 'W' if (instr >> 31) == 0 else 'X'
        desc = f'{op} {size}{reg} -> 0x{off + imm19*4:X}'
    elif (instr & 0x9F000000) == 0x90000000:
        desc = f'ADRP X{instr&0x1F}, 0x{decode_adrp(instr, off):X}'
    elif (instr & 0xFF800000) == 0x91000000:
        imm12 = (instr >> 10) & 0xFFF
        rd = instr & 0x1F
        rn = (instr >> 5) & 0x1F
        sh = (instr >> 22) & 1
        if sh: imm12 <<= 12
        desc = f'ADD X{rd}, X{rn}, #0x{imm12:X}'
    elif instr == 0xD65F03C0:
        desc = 'RET'
    elif (instr & 0xFFE00000) == 0xAA000000:
        rm = (instr >> 16) & 0x1F
        rn = (instr >> 5) & 0x1F
        rd = instr & 0x1F
        if rn == 31: desc = f'MOV X{rd}, X{rm}'
        else: desc = f'ORR X{rd}, X{rn}, X{rm}'
    elif (instr & 0xFFC00000) == 0xF9400000:
        imm12 = (instr >> 10) & 0xFFF
        rn = (instr >> 5) & 0x1F
        rt = instr & 0x1F
        desc = f'LDR X{rt}, [X{rn}, #0x{imm12*8:X}]'
    elif (instr & 0xFFC00000) == 0xF9000000:
        imm12 = (instr >> 10) & 0xFFF
        rn = (instr >> 5) & 0x1F
        rt = instr & 0x1F
        desc = f'STR X{rt}, [X{rn}, #0x{imm12*8:X}]'
    elif (instr & 0xFF800000) == 0x52800000:
        hw = (instr >> 21) & 0x3
        imm16 = (instr >> 5) & 0xFFFF
        rd = instr & 0x1F
        desc = f'MOV W{rd}, #0x{imm16 << (hw*16):X}'
    elif (instr & 0xFFE00000) == 0x2A000000:
        rm = (instr >> 16) & 0x1F
        rn = (instr >> 5) & 0x1F
        rd = instr & 0x1F
        if rn == 31: desc = f'MOV W{rd}, W{rm}'
        else: desc = f'ORR W{rd}, W{rn}, W{rm}'
    elif (instr & 0xFF800000) == 0xD1000000:
        imm12 = (instr >> 10) & 0xFFF
        rd = instr & 0x1F
        rn = (instr >> 5) & 0x1F
        desc = f'SUB X{rd}, X{rn}, #0x{imm12:X}'
    elif (instr & 0xFFC00000) == 0x39000000:
        imm12 = (instr >> 10) & 0xFFF
        rn = (instr >> 5) & 0x1F
        rt = instr & 0x1F
        desc = f'STRB W{rt}, [X{rn}, #0x{imm12:X}]'
    elif (instr & 0xFFC00000) == 0xB9000000:
        imm12 = (instr >> 10) & 0xFFF
        rn = (instr >> 5) & 0x1F
        rt = instr & 0x1F
        desc = f'STR W{rt}, [X{rn}, #0x{imm12*4:X}]'
    elif (instr & 0xFF000000) == 0xA9000000:
        desc = f'STP 0x{instr:08X}'
    elif (instr & 0xFF000000) == 0xA8000000:
        desc = f'LDP 0x{instr:08X}'

    print(f'  0x{off:05X}: {desc}')

# Also check: 0x36CA8 called just before 0x37D38
print('\n\n=== Function 0x36CA8 (called at 0x49CF0 before init) ===')
for off in range(0x36CA8, 0x36D20, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    desc = f'raw 0x{instr:08X}'
    if (instr & 0xFC000000) == 0x94000000:
        desc = f'BL 0x{decode_bl(instr, off):X}'
    elif instr == 0xD65F03C0:
        desc = 'RET'
    elif (instr & 0x9F000000) == 0x90000000:
        desc = f'ADRP X{instr&0x1F}, 0x{decode_adrp(instr, off):X}'
    elif (instr & 0xFF800000) == 0x91000000:
        imm12 = (instr >> 10) & 0xFFF
        rd = instr & 0x1F
        rn = (instr >> 5) & 0x1F
        desc = f'ADD X{rd}, X{rn}, #0x{imm12:X}'
    elif (instr & 0xFFC00000) == 0xF9400000:
        imm12 = (instr >> 10) & 0xFFF
        rn = (instr >> 5) & 0x1F
        rt = instr & 0x1F
        desc = f'LDR X{rt}, [X{rn}, #0x{imm12*8:X}]'
    print(f'  0x{off:05X}: {desc}')
    if desc == 'RET':
        break

# Now the critical question: the string at 0x61862 is compared with
# the first param to init (X28=X0). If they don't match → early return.
# X0 comes from the caller's X21, which is set via a SUB from X27.
# X27 was set at 0x49C28-0x49C30 to ADRP 0x1C7000 + ADD 0x118 = 0x1C7118

# Check what's at 0x1C7118
print('\n\n=== Data at 0x1C7118 (X27 value in caller) ===')
raw = data[0x1C7118:0x1C7150]
print(f'  Hex: {raw.hex()}')
# This is likely a structure. X21 = X27 - something
# 0x49CDC: SUB X21, X27, #0x98 → X21 = 0x1C7118 - 0x98 = 0x1C7080
# Wait: 0x49CDC: raw 0xD10263B5 → SUB X21, X29, #0x98? Let me decode

instr_49cdc = struct.unpack_from('<I', data, 0x49CDC)[0]
print(f'\n  0x49CDC: 0x{instr_49cdc:08X}')
rd = instr_49cdc & 0x1F
rn = (instr_49cdc >> 5) & 0x1F
imm12 = (instr_49cdc >> 10) & 0xFFF
print(f'  SUB X{rd}, X{rn}, #0x{imm12:X}')

# X21 = X29 - 0x98
# But we need to know what X29 is... this is getting complex
# Let me try another approach: look at what BL 0x4DBC8 at 0x49CE0 does
# (called just before the init) and what's at 0x49CEC's LDR

# Check X21 more carefully
# 0x49CDC: SUB X21, X29, #0x98
# 0x49CE0: BL 0x4DBC8
# 0x49CE4: LDR X1, [...]
# 0x49CE8: MOV X0, X21
# 0x49CEC: LDR X2, [...]
# 0x49CF0: BL 0x36CA8

# Then later:
# 0x49D00: LDR X1, [...]
# 0x49D04: MOV X0, X21  ← X0 = X21 = X29 - 0x98
# 0x49D08: LDR X2, [...]
# 0x49D0C: BL 0x37D38   ← this is our init function

# So X0 (which becomes X28 in init) = X21 = stack-based pointer
# It's pointing into the stack frame (X29 - 0x98)
# This is a local buffer, not a global string
# The question is: what does 0x36CA8 write into this buffer?

# More importantly: what does the string comparison at 0x37F80 expect?
# If it compares against the UTF-16 string at 0x61862
# And 0x61862 is just "c" (one char), what would match that?

# Let me look at the broader init function to understand 0x37F70-0x37F80
# Actually, the string compare 0x299B4 is a WIDE string compare (UTF-16)
# What if 0x61862 is not a standalone string but middle of another?

# Let me check what string starts BEFORE 0x61862
# Scan backward for null terminator (0x0000 in UTF-16)
print('\n=== Finding UTF-16 string boundary before 0x61862 ===')
pos = 0x61862
while pos > 0x61800:
    ch = struct.unpack_from('<H', data, pos-2)[0]
    if ch == 0:
        break
    pos -= 2

print(f'  String starts at 0x{pos:X}')
full_str = []
p = pos
while p < 0x618A0:
    ch = struct.unpack_from('<H', data, p)[0]
    if ch == 0:
        break
    full_str.append(chr(ch))
    p += 2
print(f'  UTF-16 string: "{"".join(full_str)}"')
print(f'  String ends at 0x{p:X}')

# So the FULL UTF-16 context around 0x61862
print('\n=== UTF-16LE strings around 0x61800-0x618A0 ===')
p = 0x61800
while p < 0x618A0:
    ch = struct.unpack_from('<H', data, p)[0]
    if ch == 0:
        # Found null terminator, check if next is a string start
        p += 2
        continue
    # Start of a string
    chars = []
    start = p
    while p < 0x618A0:
        ch = struct.unpack_from('<H', data, p)[0]
        if ch == 0:
            break
        chars.append(chr(ch) if 0x20 <= ch < 0x7F else f'[{ch:04X}]')
        p += 2
    if chars:
        print(f'  0x{start:X}: "{"".join(chars)}"')
    p += 2  # skip null
