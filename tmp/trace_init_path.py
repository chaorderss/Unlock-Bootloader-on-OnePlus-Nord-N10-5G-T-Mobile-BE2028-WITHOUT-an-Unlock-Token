import struct

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb').read()

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

# The init function 0x37D38 has the following critical path to reach [0x1BF518] write:
# 0x37FC0 → 0x37FD4 → 0x37FE0 → ... → 0x382A4 → ... → 0x383B8 → 0x383E8 → 0x383F8

# Let's check ALL branch targets that could redirect execution AWAY from 0x383F8
# and decode the error strings at those targets

print('=== Error/redirect paths in init function ===')
error_paths = [
    # (address, description)
    (0x38128, 'error from ops override fail'),
    (0x38040, 'error from protocol path 1'),
    (0x38080, 'error from protocol path 2 (X28/X20 null)'),
    (0x38190, 'error from BL 0x1DB4 fail'),
    (0x381F0, 'error from BL 0x2048 fail'),
    (0x3823C, 'error from BL 0x34A18 fail'),
    (0x3828C, 'error from BL 0xEE50 fail'),
]

for addr, desc in error_paths:
    # Check if there's an ADRP+ADD to a string
    instr = struct.unpack_from('<I', data, addr)[0]
    if (instr & 0x9F000000) == 0x90000000:
        page = decode_adrp(instr, addr)
        next_instr = struct.unpack_from('<I', data, addr+4)[0]
        if (next_instr & 0xFF800000) == 0x91000000:
            imm12 = (next_instr >> 10) & 0xFFF
            sh = (next_instr >> 22) & 1
            if sh: imm12 <<= 12
            str_addr = page + imm12
            s = data[str_addr:str_addr+80]
            null = s.find(b'\x00')
            if null >= 0: s = s[:null]
            print(f'\n  0x{addr:X} ({desc}):')
            print(f'    String at 0x{str_addr:X}: "{s.decode("ascii", errors="replace")}"')

# Let's specifically look at the UEFI protocol calls and branches
# The path from 0x37FD4:
print('\n\n=== Critical path analysis from 0x37FC0 to 0x383F8 ===')

# 0x37FC0: Check IsAllowUnlock
print('\n--- Step 1: IsAllowUnlock check (0x37FC0) ---')
print('  LDR W8, [0x1C0010] (IsAllowUnlock)')
print('  CBNZ W8, 0x37FD4 → skip ops override if allowed')
print('  Else: BL 0x3A258 → ops override, CBZ → 0x38128 (error)')

# 0x37FD4: Load parameters
print('\n--- Step 2: Parameter check (0x37FD4-0x37FE4) ---')
print('  LDR X8, [SP, #0x8] → 3rd parameter')
print('  SUB X27, X27, #0x100')
print('  X28 must be non-null (first param), else → 0x3804C')
print('  X20 must be non-null (from BL 0xD214), else → 0x3804C')

# 0x37FE8: UEFI Protocol call
print('\n--- Step 3: UEFI Protocol call #1 (0x37FE8-0x38008) ---')
# LDR X8, [0x1BE000+0x3D0] = protocol pointer at 0x1BE3D0
instr = struct.unpack_from('<I', data, 0x37FE8)[0]
page = decode_adrp(instr, 0x37FE8)
next_instr = struct.unpack_from('<I', data, 0x37FEC)[0]
if (next_instr & 0x9F000000) == 0x90000000:
    page2 = decode_adrp(next_instr, 0x37FEC)

# Actually trace the protocol call more carefully
print('  0x37FE8: ADRP X8, page → LDR X8 → protocol interface')
print('  0x37FF0: ADRP X0, 0x69000 + ADD → GUID at 0x69B90')
# Check GUID at 0x69B90
guid = data[0x69B90:0x69BA0]
print(f'  GUID at 0x69B90: {guid.hex()}')
# Parse as GUID: 4 bytes LE, 2 bytes LE, 2 bytes LE, 8 bytes
a = struct.unpack_from('<IHH', guid, 0)
b = guid[8:16]
guid_str = f'{a[0]:08X}-{a[1]:04X}-{a[2]:04X}-{b[0]:02X}{b[1]:02X}-{b[2]:02X}{b[3]:02X}{b[4]:02X}{b[5]:02X}{b[6]:02X}{b[7]:02X}'
print(f'  GUID = {guid_str}')

print('  0x38004: BLR X8 → indirect call through protocol')
print('  0x38008: CBZ X0 → 0x3808C if returns NULL')

# 0x3808C: Second protocol path
print('\n--- Step 4: After Protocol #1 returns NULL (0x3808C) ---')
# This loads carrier_id and uses table to find a function pointer
# 0x3808C: LDR W8, [X29, #0x64] → carrier_id
# 0x38090: MOV W9, #0x58
# 0x38098: LDR X0, [X24, #0x0] → boot services?
# 0x380A0: MOV W2, #0x3F1 → allocation size
# 0x380A4: MADD → table lookup
# 0x380AC: LDR X9, [X0, #0x30] → indirect call setup
# 0x380B0: LDR X1, [X8, #0x38] → function pointer from table+0x38
# 0x380B4: BLR X9 → allocate memory?
# 0x380B8: CBZ X0 → 0x38134

print('  Uses carrier_id to lookup table, allocates memory')
print('  0x380B8: CBZ X0 → 0x38134 if allocation fails')

# 0x38134: Third path
print('\n--- Step 5: Memory allocation path (0x38134) ---')
print('  0x38134: LDR X0, [X24] → boot services')
print('  0x38154: BL 0x1DB4 → some function')
print('  0x38158: CBZ X0 → 0x3819C if returns NULL')

# 0x3819C: Fourth path
print('\n--- Step 6: Path after 0x1DB4 fails (0x3819C) ---')
print('  0x3819C: LDR X0, [X24]')
print('  0x381B4: BL 0x2048 → another function')
print('  0x381B8: CBZ X0 → 0x381FC if returns NULL')

# 0x381FC path
print('\n--- Step 7: Path after 0x2048 fails (0x381FC) ---')
print('  0x381FC: MOV X0, X23 → carrier name string')
print('  0x38200: BL 0x34A18 → parse carrier info?')
print('  0x38204: CBZ W0 → 0x38248 if returns 0')

# 0x38248 path
print('\n--- Step 8: Carrier UUID lookup (0x38248) ---')
print('  0x38248: MOV W1, #0x9 → length')
print('  0x3824C: MOV X0, X22 → carrier name')
print('  0x38250: BL 0xEE50 → locate UUID?')
print('  0x38254: CBZ X0 → 0x382A4 if returns NULL')

# 0x382A4: The path that leads to FRP check!
print('\n--- Step 9: MAIN PATH to FRP check (0x382A4) ---')
print('  0x382A4: ADRP X28, 0x1AD000')
print('  0x382A8: MOV W20, #0x58')
print('  0x382AC: LDR W8, [X28, #0x64] → carrier_id')
print('  ... table lookups, data preparation ...')
print('  0x383B8: BL 0x4FD10 → READ FRP TOKEN')
print('  0x383BC: CBZ X0 → 0x383E8 → if NULL (no token)')
print('  0x383E8: set [0x1BF518] = 1 ← TARGET!')

# So the path is:
# 0x37FC0 → 0x37FD4 → 0x37FE0 → 0x37FE4 → 0x37FE8 (protocol call)
# Protocol returns NULL → 0x3808C
# Table lookup + AllocatePool → 0x380B4 (BLR)
# If alloc fails → 0x38134
# BL 0x1DB4 → if fails → 0x3819C
# BL 0x2048 → if fails → 0x381FC
# BL 0x34A18 → if returns 0 → 0x38248
# BL 0xEE50 → if returns NULL → 0x382A4 ← MAIN PATH TO FRP!

print('\n\n=== KEY QUESTION: What makes us NOT reach 0x382A4? ===')

# The critical branches are:
# 1. 0x37FE0: CBZ X28 → 0x3804C (if 1st param NULL)
# 2. 0x37FE4: CBZ X20 → 0x3804C (if X20 NULL)
# 3. 0x38008: CBZ X0 → 0x3808C (if protocol returns NULL)
# 4. 0x380B8: CBZ X0 → 0x38134 (if alloc fails)
# 5. 0x38158: CBZ X0 → 0x3819C (if 0x1DB4 fails)
# 6. 0x381B8: CBZ X0 → 0x381FC (if 0x2048 fails)
# 7. 0x38204: CBZ W0 → 0x38248 (if 0x34A18 returns 0)
# 8. 0x38254: CBZ X0 → 0x382A4 (if 0xEE50 returns NULL)

# Actually, ALL of these NULL/fail paths lead eventually to 0x382A4!
# The function has:
# 0x38040/80/128/190/1F0/23C/28C → all B to 0x38294
# 0x38294: MOV X20, #special, BL 0x46634 (print), B 0x37F88
# 0x37F88: STP/LDP... B 0x37F94: B.NE 0x38418 → error
# Or 0x37F98: STR → 0x37FA0 → epilogue → RET!

# Wait - 0x37F88 is a RETURN point, not continuation!
# 0x38294 prints an error and then loops back to 0x37F88 which RETURNS.
# So if any of these paths fail, we go to 0x38294 → 0x37F88 → RETURN
# and NEVER reach 0x382A4!

print('\n  ERROR PATHS 0x38040,0x38080,0x38128,0x38190,0x381F0,0x3823C,0x3828C')
print('  ALL → B 0x38294 → BL 0x46634 (print error) → B 0x37F88 → RETURN')
print('')
print('  0x382A4 (FRP check) is only reached from 0x38254!')
print('  0x38254: CBZ X0 → 0x382A4 (when 0xEE50 returns NULL)')
print('')
print('  So the FULL success path to reach FRP check requires:')
print('  1. IsAllowUnlock ≠ 0 OR ops override passes')
print('  2. X28 ≠ NULL (1st param)')
print('  3. X20 ≠ NULL (from 0xD214)')
print('  4. Protocol call at 0x38004 MUST return non-NULL')
print('     OR the allocation at 0x380B4 MUST succeed')
print('     → both can redirect to error paths')

# Actually WAIT - let me re-read the paths more carefully
# 0x38008: CBZ X0 → 0x3808C → this goes to allocation path
# 0x38008 is "if protocol returns NULL, try alternative (allocate)"
# If that also fails (0x380B8 CBZ → 0x38134), it tries yet another path
# The cascading try/catch pattern suggests:
# Try protocol → if fail → try allocate → if fail → try 0x1DB4 →
# if fail → try 0x2048 → if fail → try 0x34A18 → if fail → try 0xEE50 →
# if fail → 0x382A4 (FRP check)

# But the ERROR paths go to 0x38294 which goes back to 0x37F88 (RETURN)
# So which paths go to 0x38294 vs which cascade to next try?

print('\n=== Re-analyzing branching: cascade vs error ===')
# Let me check what the SUCCESSFUL return of each function does

# After protocol call succeeds (0x38008 not taken):
# 0x3800C: BL 0x28574 (debug)
# ...prints...
# 0x38040: ADRP X0 → ADD → string
# 0x38048: B 0x38294 → this is SUCCESS path printing and returning!

# After alloc succeeds (0x380B8 not taken):
# 0x380BC: MOV X29, X0
# ... debug ...
# 0x380F4: SUB X21
# ... preparing data ...
# 0x38118: BL 0x4E9E0 (print formatted)
# 0x3811C: MOV X0, X21
# 0x38120: BL 0x46634
# 0x38124: B 0x37F88 → RETURN!

print('  Protocol SUCCESS → 0x38040 → B 0x38294 → RETURN')
print('  Alloc SUCCESS → 0x38118 → 0x38124 → B 0x37F88 → RETURN')
print('')
print('  *** BOTH SUCCESS AND FAILURE paths return before reaching 0x382A4! ***')
print('')

# Let me re-read: after protocol call fails (0x38008 CBZ → 0x3808C):
# 0x3808C uses carrier table to get info → 0x380B4 call → 0x380B8 CBZ → 0x38134
# At 0x38134: tries 0x1DB4 → 0x38158 CBZ → 0x3819C
# At 0x3819C: tries 0x2048 → 0x381B8 CBZ → 0x381FC

# But what about when protocol SUCCEEDS?
# 0x38008: CBZ X0 → 0x3808C (taken if NULL) — if NOT taken (success):
# 0x3800C-0x38040: print stuff then B 0x38294 → return

# Hmm so: if protocol succeeds → we RETURN EARLY with a message but [0x1BF518] NOT set
# If protocol fails → we fall through to allocation path

# So the ONLY way to reach 0x382A4 (FRP check) is through the cascading failure path:
# protocol fails → alloc fails → 0x1DB4 fails → 0x2048 fails →
# 0x34A18 returns 0 → 0xEE50 returns NULL → 0x382A4!

print('  *** The FRP check at 0x382A4 is ONLY reached when ALL protocol/alloc attempts FAIL ***')
print('  *** This is the "fallback" path when no carrier token infrastructure exists ***')
print('')

# Now the question: which of these might be NOT failing on our device?
# If any of 0x1DB4, 0x2048, 0x34A18, 0xEE50 SUCCEEDS, it goes to 0x38294 → RETURN
# without ever reaching 0x382A4 and the [0x1BF518] write

# Let me check what 0x34A18 and 0xEE50 do
print('=== Function 0x34A18 ===')
for off in range(0x34A18, 0x34A80, 4):
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
        desc = f'ADD X{instr&0x1F}, X{(instr>>5)&0x1F}, #0x{imm12:X}'
    print(f'  0x{off:05X}: {desc}')
    if desc == 'RET':
        break

print('\n=== Function 0xEE50 ===')
for off in range(0xEE50, 0xEF00, 4):
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
        desc = f'ADD X{instr&0x1F}, X{(instr>>5)&0x1F}, #0x{imm12:X}'
    elif (instr & 0x7E000000) == 0x34000000:
        imm19 = (instr >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 -= 0x80000
        op = 'CBNZ' if (instr >> 24) & 1 else 'CBZ'
        reg = instr & 0x1F
        size = 'W' if (instr >> 31) == 0 else 'X'
        desc = f'{op} {size}{reg} -> 0x{off + imm19*4:X}'
    print(f'  0x{off:05X}: {desc}')
    if desc == 'RET':
        break

# Also: what are the error strings at each path?
print('\n=== Strings at error/success path destinations ===')
string_refs = [
    (0x62074, '0x38040 success after protocol'),
    (0x62068, '0x38080 success after X28/X20 null'),
    (0x62018, '0x38128 error: ops override fail'),
    (0x61F91, '0x38190 error from 0x1DB4 fail'),
    (0x62091, '0x381F0 error from 0x2048 fail'),
    (0x620C6, '0x38244 error from 0x34A18'),
    (0x620F8, '0x38290 error from 0xEE50'),
]
for addr, desc in string_refs:
    s = data[addr:addr+100]
    null = s.find(b'\x00')
    if null >= 0: s = s[:null]
    print(f'  {desc}:')
    print(f'    0x{addr:X}: "{s.decode("ascii", errors="replace")}"')
