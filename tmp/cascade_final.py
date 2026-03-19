import struct

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb').read()

def decode_adrp(instr, pc):
    immhi = (instr >> 5) & 0x7FFFF
    immlo = (instr >> 29) & 0x3
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    return (pc & ~0xFFF) + (imm << 12)

def decode_bl(instr, pc):
    imm26 = instr & 0x03FFFFFF
    if imm26 & 0x02000000:
        imm26 -= 0x04000000
    return pc + imm26 * 4

# ============================================================
# THE CASCADE PATH (0x37FC0-0x382A4) — determine WHICH step
# would succeed on our device and terminate the cascade early
# ============================================================

print("=" * 70)
print("CASCADE ANALYSIS: Which step prevents reaching 0x382A4?")
print("=" * 70)

# Step 4: Protocol call at 0x38004
# Uses GUID 408EC123-134E-4B80-9142-B89A0E08F8B3
# Called via [0x1BE3D0]+0x140 protocol function pointer
# X0 = GUID ptr, X1 = NULL, X2 = X24 (output buffer)
# CBZ X0 -> 0x3808C (continue if FAIL=0)
# If returns NON-ZERO → "failed (-2)" at 0x38074 → RETURN EARLY
print("""
Step 4 (0x38004): Protocol LocateProtocol(GUID=408EC123)
  - GUID: 408EC123-134E-4B80-9142-B89A0E08F8B3
  - If protocol NOT installed → returns 0 (EFI_NOT_FOUND) → CONTINUE ✓
  - If protocol IS installed → returns non-0 → "failed (-2)" → RETURN ✗
  - Question: Is this protocol installed on T-Mobile device?
""")

# Step 6: Table lookup + AllocatePool at 0x3808C-0x380B4
# Loads carrier_id from [X29+0x64] (= [0x1AD064])
# Multiplies by 0x58 to index carrier table at 0x62488
# Gets X1 = carrier_table[idx]+0x38 (certificate pointer)
#   For our device (idx=7): X1 = 0x1AE781 (X.509 cert)
# Calls BLR X9 = [X0+0x30] (AllocatePool/LocateProtocol)
#   X0 = [X24] (protocol output from step 4)
#   W2 = 0x3F1 (size)
#   X3 = X25 (buffer)
# CBZ X0 -> 0x38134 (continue if FAIL=0)
# If SUCCESS → prints → RETURN EARLY ✗
print("""
Step 6 (0x380B4): Protocol call via [X24]+0x30 function pointer
  - Uses return from Step 4 (X24 = output buffer)
  - W2 = 0x3F1 (cert size?) - matches our cert at 0x1AE781 (0x3ED + header?)
  - X1 = carrier_table[7]+0x38 = 0x1AE781 (T-Mobile carrier cert!)
  - X3 = stack buffer
  - THIS STEP LIKELY USES THE CARRIER CERTIFICATE
  - If Step 4 returned NULL, then [X24] would be NULL too → crash or skip
""")

# Wait, if step 4 fails (returns 0), X24 is still the original stack buffer
# Let me re-read step 4 more carefully

# At 0x37FF8: MOV X1, X31 (X1 = NULL/zero register)
# At 0x37FFC: MOV X2, X24 (X2 = output buffer)
# At 0x38004: BLR X8 (call protocol)
# At 0x38008: CBZ X0 -> 0x3808C (if return == 0, continue)

# But X24 was set at: 0x37D78: SUB X24, X26, #0x1D0
# X24 is a stack buffer. The protocol call writes result INTO X24.
# After the protocol FAILS, X24 still points to the stack buffer (maybe zeroed)

# Step 6 does: LDR X0, [X24, #0x0] — reads from function output buffer
# If step 4 failed, [X24] is likely NULL or garbage
# Then LDR X9, [X0+0x30] would try to dereference NULL → crash?

# Or maybe X24 was zeroed by SetMem earlier?
# At 0x37D88: MOV X0, X21; ... BL 0x4DEBC (SetMem X21)
# X24 ≠ X21, so X24 might not be zeroed

# Let me check more carefully what happens:
print("""
KEY INSIGHT: If Step 4 fails (protocol not found), the protocol call
at 0x38004 returns EFI_NOT_FOUND. The LocateProtocol API writes NULL
to the Interface pointer (*X2 = NULL). So [X24] = NULL after failure.

In Step 6: LDR X0, [X24, #0x0] → loads NULL (from failed step 4)
           LDR X9, [X0, #0x30] → would dereference NULL → crash!

Unless... Step 6 only runs when step 4 SUCCEEDED (CBZ goes to 0x3808C
on FAILURE, which IS step 6's entry). So step 6 runs AFTER step 4 FAILS!

Wait, re-reading the flow:
  0x38004: BLR X8       → protocol call
  0x38008: CBZ X0 → 0x3808C   → if RETURN=0 (SUCCESS in EFI), go to step 6

In EFI, 0 = EFI_SUCCESS. So CBZ means "if SUCCESS, continue to 0x3808C"
Non-zero = error, goes to 0x3800C → "failed (-2)" → return

So the logic is INVERTED from what I initially thought:
  Protocol SUCCESS → continue
  Protocol FAIL → exit with error!

This means: for the cascade to progress, EACH step must SUCCEED!
""")

# Let me re-analyze the entire cascade with correct EFI error semantics
# EFI_SUCCESS = 0, all errors are non-zero
# CBZ = "if success, branch" is actually the CONTINUE path

print("=" * 70)
print("RE-ANALYSIS with correct EFI semantics (0 = SUCCESS)")
print("=" * 70)

print("""
Corrected cascade analysis:

Step 4 (0x38004): LocateProtocol(GUID=408EC123)
  0x38008: CBZ X0 → 0x3808C   ← SUCCESS → continue to Step 6
           (non-zero = error → "failed (-2)" → RETURN EARLY)
  ★ Protocol MUST be found for cascade to continue

Step 6 (0x380B4): [X24+0x30] protocol function call (cert verification?)
  0x380B8: CBZ X0 → 0x38134   ← SUCCESS → continue to Step 7
           (non-zero = error → print cert info → RETURN EARLY)
  ★ Cert processing MUST succeed for cascade to continue

Step 7 (0x38154): BL 0x1DB4
  0x38158: CBZ X0 → 0x3819C   ← SUCCESS → continue to Step 8
           (non-zero → "related info (-1)" → RETURN EARLY)
  ★ Must succeed

Step 8 (0x381B4): BL 0x2048
  0x381B8: CBZ X0 → 0x381FC   ← SUCCESS → continue to Step 9
           (non-zero → "Verify Failed" → RETURN EARLY)
  ★ Must succeed

Step 9 (0x38200): BL 0x34A18
  0x38204: CBZ W0 → 0x38248   ← SUCCESS → continue to Step 10
           (non-zero → "related info (-2)" → RETURN EARLY)
  ★ Must succeed

Step 10 (0x38250): BL 0xEE50
  0x38254: CBZ X0 → 0x382A4   ← SUCCESS → REACH FRP CHECK! 🎯
           (non-zero → "related info (-3)" → RETURN EARLY)
  ★ Must succeed to reach FRP check

★★★ ALL steps must return SUCCESS (0) to reach the FRP check!
One failure at ANY step → cascade exits early!

Since we see "Please flash unlock token first" (at 0x3BBD4),
the cascade IS reaching the carrier check at 0x3BB48.
This means the init function DID set [0x1BF518]...

WAIT! Or the cascade FAILS and [0x1BF518] stays 0, and then
the carrier check at 0x48828 reads [0x1BF518]=0 and fails.

Let me check: does the CALLER check the return value?
""")

# Check the calling context more carefully
# At 0x49D0C: BL 0x37D38
# At 0x49D10: CMP X0, X26 (X26 = 0x8000000000000000)
# At 0x49D14: B.NE 0x49CA8 (if not equal, exit)
# So the caller expects 0x37D38 to return 0x8000000000000000

# What does 0x37D38 return?
# The return path at 0x37F88-0x37FBC:
# 0x37F88: [stack operations]
# 0x37F9C: MOV X0, X20 ← returns X20
# 0x37FBC: RET

# X20 was set at 0x37E10: MOV X20, X0 (return value of 0xD214)
# 0xD214 is called at 0x37E08

# But also: on ERROR paths, the function branches to 0x38294:
# 0x38294: MOV X20, #0x15
# 0x38298: TST ...
# 0x3829C: BL 0x46634 (print)
# 0x382A0: B 0x37F88 (go to return with X20=0x15)

# And on SUCCESS path (reaching FRP check):
# 0x383F8: STRB W9=1, [X8+0x518] → [0x1BF518] = 1
# 0x383FC: BL 0x46700
# 0x38400: BL 0x48708
# 0x38404-0x38410: print + cleanup
# 0x38414: B 0x37F88 (return with original X20)

# So: if cascade FAILS at any step → X20 = 0x15 → returned to caller
# If cascade SUCCEEDS → X20 = original value from 0xD214 → returned

print("""
RETURN VALUE ANALYSIS:
  - Error path: X20 = 0x15 → return 0x15 (EFI_NOT_FOUND or similar)
  - The FRP-success path at 0x383E8: X20 stays as original (from 0xD214)
  - The FRP-token-found path at 0x383C0: also branches back with a print
    then jumps to 0x3811C → 0x37F88 → return

The caller at 0x49D10 checks: CMP X0, 0x8000000000000000
  0x8000000000000000 = probably a success marker from 0xD214 OR
  it could be ORR X26, XZR, #0x8000000000000000 (seen at 0x49CF4)

If the return is 0x15 (error), caller exits.
But this is about the INIT — it runs once during boot.
The [0x1BF518] flag persists in memory regardless of return value.
""")

# ============================================================
# FINAL CHECK: Does the FRP-NULL path actually set [0x1BF518]=1?
# Or does the cascade need to FULLY succeed?
# ============================================================
print("=" * 70)
print("FRP CHECK PATH (0x382A4-0x38414)")
print("=" * 70)

print("""
At 0x382A4 (reached when ALL steps succeed AND EE50 returns 0):
  0x382A4-0x383A4: Build verification data from carrier table
    - Reads entries at +0x18, +0x20, +0x28, +0x30 from carrier table
    - Calls 0x29464 (string/data formatter) multiple times
    - Calls 0x4AA8/0x4B90/0x4C2C (SHA-256 hash computation)

  0x383B0: LDR X1, [SP, #0x8]     ← second original param
  0x383B4: MOV X2, X27             ← processed data
  0x383B8: BL 0x4FD10              ← FRP READER / TOKEN CHECK
  0x383BC: CBZ X0 → 0x383E8        ← if NO TOKEN (NULL) → set flag!

  0x383C0-0x383E4: Token found path → print & return (X20 stays)

  0x383E8: Print "Device is unlocked." (at 0x6214A)
  0x383EC: ADRP X8, 0x1BF000
  0x383F0: ORR W9, WZR, #1         ← W9 = 1
  0x383F8: STRB W9, [X8, #0x518]   ← [0x1BF518] = 1 !!! 🎯
  0x383FC: BL 0x46700              ← some display function
  0x38400: BL 0x48708              ← calls back to carrier check??
  0x38404-0x38414: cleanup → return
""")

# Check what 0x48708 does (called right after setting flag)
print("\n--- 0x48708 (called after setting [0x1BF518]=1) ---")
for off in range(0x48708, 0x48760, 4):
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
    elif (instr & 0xFFC00000) == 0xB9400000:
        imm12 = (instr >> 10) & 0xFFF
        rn = (instr >> 5) & 0x1F
        rt = instr & 0x1F
        desc = f'LDR W{rt}, [X{rn}, #0x{imm12*4:X}]'
    elif (instr & 0x7E000000) == 0x34000000:
        imm19 = (instr >> 5) & 0x7FFFF
        if imm19 & 0x40000: imm19 -= 0x80000
        op = 'CBNZ' if (instr >> 24) & 1 else 'CBZ'
        reg = instr & 0x1F
        size = 'W' if (instr >> 31) == 0 else 'X'
        desc = f'{op} {size}{reg} -> 0x{off + imm19*4:X}'
    print(f'  0x{off:05X}: {desc}')

# ============================================================
# Now the REAL KEY QUESTION:
# Which step fails in the cascade on our device?
# The error messages tell us! If we could see boot logs...
#
# But from static analysis, the MOST LIKELY failure point is:
# Step 4 (0x38004): LocateProtocol with GUID 408EC123
# This protocol might not be installed on T-Mobile devices,
# OR it could be a carrier-specific protocol that IS installed.
#
# If it's NOT installed: returns EFI_NOT_FOUND (non-zero)
#   → "failed (-2)" → cascade exits
#   → [0x1BF518] NEVER set to 1
#   → carrier check FAILS
#
# This would explain everything!
# ============================================================

print("\n" + "=" * 70)
print("HYPOTHESIS: Why cascade fails")
print("=" * 70)
print("""
If Protocol 408EC123-134E-4B80-9142-B89A0E08F8B3 is NOT INSTALLED:
  Step 4 returns non-zero (EFI_NOT_FOUND)
  → jumps to 0x3800C → prints "failed (-2)" → RETURNS EARLY
  → [0x1BF518] never set to 1
  → carrier check at 0x3BB48 fails
  → "Please flash unlock token first."

This protocol is likely the OnePlus Carrier Unlock Protocol.
It would be installed by a separate UEFI driver in the ABL firmware volume.
If the driver is present but its LocateProtocol succeeds, the cascade
continues. If NOT present, the cascade fails at the very first step.

ALTERNATIVELY: If the protocol IS installed but Step 6's cert verification
fails, we'd get stuck at step 6. Each subsequent step has its own
verification that depends on the previous step's output.
""")

# Let's check: what other UEFI modules are in the ABL firmware volume?
# The GUID 408EC123-134E-4B80-9142-B89A0E08F8B3 might be from another module
# Let's search for this GUID in the broader ABL binary
guid_bytes = struct.pack('<IHH', 0x408EC123, 0x134E, 0x4B80) + bytes([0x91,0x42,0xB8,0x9A,0x0E,0x08,0xF8,0xB3])
print(f"\nSearching for GUID 408EC123 in ABL binary...")
print(f"GUID bytes: {guid_bytes.hex()}")

# Also search in the FFS extraction directory
import os, glob
ffs_dir = '/tmp/ffs_modules/'
if os.path.exists(ffs_dir):
    print(f"\nFFS modules in {ffs_dir}:")
    for f in sorted(os.listdir(ffs_dir)):
        fpath = os.path.join(ffs_dir, f)
        if os.path.isfile(fpath):
            fdata = open(fpath, 'rb').read()
            size = len(fdata)
            has_guid = guid_bytes in fdata
            marker = " <<<< HAS TARGET GUID!" if has_guid else ""
            print(f'  {f}: {size} bytes{marker}')

# Check 0xEE50 more carefully - it uses GUID 85C1F7D2
guid2_bytes = struct.pack('<IHH', 0x85C1F7D2, 0xBCE6, 0x4F31) + bytes([0x8F,0x4D,0xD3,0x7E,0x03,0xD0,0x5E,0xAA])
print(f"\nAlso searching for GUID 85C1F7D2 (used in 0xEE50)...")
if os.path.exists(ffs_dir):
    for f in sorted(os.listdir(ffs_dir)):
        fpath = os.path.join(ffs_dir, f)
        if os.path.isfile(fpath):
            fdata = open(fpath, 'rb').read()
            if guid2_bytes in fdata:
                print(f'  {f}: HAS GUID 85C1F7D2!')
