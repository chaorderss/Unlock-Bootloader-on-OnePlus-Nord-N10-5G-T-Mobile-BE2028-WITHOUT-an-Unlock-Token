#!/usr/bin/env python3
import struct, zlib

MZ_OFF  = 0xB8
DEVINFO = 'edl_backup/devinfo_unlocked.bin'
DECOMP  = 'global_abl_decompressed.bin'

with open(DECOMP, 'rb') as f:
    abl = f.read()

# PE parse
e_lfanew = struct.unpack_from('<I', abl, MZ_OFF+0x3C)[0]
PE_SIG   = MZ_OFF + e_lfanew
coff     = PE_SIG + 4
num_sec, = struct.unpack_from('H', abl, coff+2)
opt_sz,  = struct.unpack_from('H', abl, coff+16)
opt_off  = coff + 20
image_base = struct.unpack_from('<Q', abl, opt_off+24)[0]
sect_off = opt_off + opt_sz
sections = []
for i in range(num_sec):
    s = sect_off + i*40
    nm = abl[s:s+8].rstrip(b'\x00').decode('latin1')
    vsize, vaddr, rsz, roff = struct.unpack_from('<IIII', abl, s+8)
    sections.append((nm, image_base+vaddr, vsize, MZ_OFF+roff, rsz))

def file_to_va(fo):
    for nm,va,vsz,fs,rsz in sections:
        if fs<=fo<fs+rsz: return va+(fo-fs)
    return None

TEXT_FS  = sections[0][3]
TEXT_RSZ = sections[0][4]
TEXT_VA  = sections[0][1]
DATA_FS  = sections[1][3]
DATA_RSZ = sections[1][4]
DATA_VA  = sections[1][1]

# 1. Raw bytes around strings
print("=== Raw bytes at key string locations ===")
for name, foff in [
    ("Device unlocked", 0x67de7),
    ("Unlocked (1)",    0x51e00),
    ("ANDROID-BOOT!",  0x5bfbe),
]:
    start = foff - 4
    end   = foff + 48
    raw = abl[start:end]
    print(f"\n  {name} file={foff:#x}:")
    for i in range(0, len(raw), 16):
        chunk = raw[i:i+16]
        hexs = ' '.join(f'{b:02x}' for b in chunk)
        ascs = ''.join(chr(b) if 32<=b<127 else '.' for b in chunk)
        print(f"    {start+i:#010x}: {hexs:<48}  {ascs}")

# 2. Search .data for pointers to string VAs (64-bit LE)
print("\n=== .data pointer table hits ===")
for name, foff_s in [
    ("Device unlocked", 0x67de7),
    ("Unlocked (1)",    0x51e00),
    ("Unlocked (2)",    0x51e66),
    ("ANDROID-BOOT!",  0x5bfbe),
]:
    va_s = file_to_va(foff_s)
    if va_s is None:
        print(f"  {name}: cannot resolve VA")
        continue
    target = struct.pack('<Q', va_s)
    found = []
    p = DATA_FS
    while True:
        idx = abl.find(target, p, DATA_FS+DATA_RSZ)
        if idx < 0: break
        dv = DATA_VA + (idx - DATA_FS)
        found.append((idx, dv))
        p = idx + 1
    vs = hex(va_s)
    if found:
        for (idx, dv) in found:
            print(f"  {name} VA={vs} -> .data file={idx:#x} VA={dv:#x}")
    else:
        print(f"  {name} VA={vs} -> NOT found in .data")

# 3. LDRB [Xn, #0x10] (potential is_unlocked at struct+0x10)
print("\n=== LDRB [Xn, #0x10] instructions in .text ===")
count = 0
for i in range(0, TEXT_RSZ-4, 4):
    foff = TEXT_FS + i
    insn = struct.unpack_from('<I', abl, foff)[0]
    if (insn & 0xFFC00000) == 0x39400000:
        rt  = insn & 0x1F
        rn  = (insn >> 5) & 0x1F
        imm = (insn >> 10) & 0xFFF
        if imm == 0x10:
            va = TEXT_VA + i
            print(f"  LDRB W{rt}, [X{rn}, #0x10] at file={foff:#x} VA={va:#x}")
            count += 1
            if count >= 20: print("  ... (more)"); break

# 4. Devinfo hex dump
print("\n=== devinfo_unlocked.bin ===")
with open(DEVINFO, 'rb') as f:
    dv = bytearray(f.read())
print(f"  Size: {len(dv)}")
for i in range(0, 48, 16):
    chunk = dv[i:i+16]
    hexs = ' '.join(f'{b:02x}' for b in chunk)
    ascs = ''.join(chr(b) if 32<=b<127 else '.' for b in chunk)
    print(f"  {i:04x}: {hexs:<48}  {ascs}")
print(f"  Last 4 bytes: {dv[-4:].hex()}")
crc = zlib.crc32(bytes(dv[:-4])) & 0xFFFFFFFF
print(f"  CRC32(body): {crc:#010x}  last4={struct.unpack_from('<I',dv,len(dv)-4)[0]:#010x}")

# 5. Create variants
print("\n=== Creating devinfo variants ===")
magic = b'ANDROID-BOOT!'

# Variant A: DEVICE_MAGIC_SIZE=16 (padded), is_unlocked at 0x10, oem at 0x10+5=0x15?
# Standard QTI ordering: [0x10]=is_unlocked [0x11]=is_tampered [0x12]=is_unlock_critical
# [0x13]=charger_screen_enabled [0x14]=verity_mode [0x15]=oem_unlock_allowed
dv_A = bytearray(4096)
dv_A[:len(magic)] = magic
# 16-byte magic (3 zeros padding after "ANDROID-BOOT!")
dv_A[0x10] = 1  # is_unlocked
dv_A[0x15] = 1  # oem_unlock_allowed (standard QTI position)

# Variant B: brute force - set EVERYTHING 0x0D..0x1F to 1
dv_B = bytearray(4096)
dv_B[:len(magic)] = magic
for off in range(0x0D, 0x20):
    dv_B[off] = 1

# Variant C: 13-byte magic, [0x0E] and friends
dv_C = bytearray(4096)
dv_C[:len(magic)] = magic
dv_C[0x0D] = 1  # oem_unlock_allowed (previously confirmed)
dv_C[0x0E] = 1  # is_unlocked (our previous attempt)
dv_C[0x10] = 1  # try this too (in case DEVICE_MAGIC_SIZE was meant to be 16)
dv_C[0x15] = 1  # extra

for nm, dv_v in [("variantA", dv_A), ("variantB", dv_B), ("variantC", dv_C)]:
    with open(f'edl_backup/devinfo_{nm}.bin', 'wb') as f:
        f.write(dv_v)
    first = dv_v[:24].hex(' ')
    print(f"  {nm}: {first}")
    print(f"         Written to edl_backup/devinfo_{nm}.bin")
