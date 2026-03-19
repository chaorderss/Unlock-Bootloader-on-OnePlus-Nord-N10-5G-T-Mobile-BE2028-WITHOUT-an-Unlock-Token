#!/usr/bin/env python3
"""Analyze CmdCustUnlockFlash token verification paths"""

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin','rb').read()

print("=== String references from CmdCustUnlockFlash ===")
# Key strings referenced via ADRP+ADD in the function
# We need to decode ADRP+ADD pairs properly
# ADRP uses PC-relative page addressing

def get_str(data, off, maxlen=120):
    end = off
    while end < len(data) and end < off + maxlen and data[end] != 0:
        end += 1
    return data[off:end].decode('ascii', errors='replace')

# The error we got: pe32+[0x61f31]
print(f"Error string: '{get_str(data, 0x61f31)}'")
print()

# Now trace the ADRP+ADD references in CmdCustUnlockFlash
# 0x35cd4: adrp x8, 0x69000 -> page 0x69000
# 0x35cd8: adrp x1, 0x60000 -> page 0x60000
# 0x35ce0: add x1, x1, #0x854 -> x1 = 0x60854
print(f"0x60854: '{get_str(data, 0x60854)}'")

# 0x35d60: adrp x0, 0x68000
# 0x35d64: add x0, x0, #0xb90 -> x0 = 0x68b90
print(f"0x68b90: '{get_str(data, 0x68b90)}'")

# 0x35d9c: adrp x1, 0x60000 + add x1, x1, #0xca3
print(f"0x60ca3: '{get_str(data, 0x60ca3)}'")

# 0x35dc4/35dc8: adrp+add x1=0x60c77, x2=0x60c95
print(f"0x60c77: '{get_str(data, 0x60c77)}'")
print(f"0x60c95: '{get_str(data, 0x60c95)}'")

# 0x35ddc/35de0: adrp x0, 0x55000 + add x0, x0, #0x4eb
print(f"0x554eb: '{get_str(data, 0x554eb)}'")

# 0x35e24/35e28: adrp x1, 0x60000 + add x1, #0x916
print(f"0x60916: '{get_str(data, 0x60916)}'")

# 0x35e5c/35e60: adrp+add x1=0x60cda
print(f"0x60cda: '{get_str(data, 0x60cda)}'")

# 0x35ea4-35eb0: x1=0x60d09, x2=0x60c95
print(f"0x60d09: '{get_str(data, 0x60d09)}'")

# 0x35ebc/35ec0: adrp+add x0=0x60d2a
print(f"0x60d2a: '{get_str(data, 0x60d2a)}'")

# 0x35f04-35f10: x1=0x60d46, x2=0x60c95
print(f"0x60d46: '{get_str(data, 0x60d46)}'")

# 0x35f1c/35f20: x0=0x60d74
print(f"0x60d74: '{get_str(data, 0x60d74)}'")

# 0x35f70/35f74: x1=0x58e5d (0x58000+0xe5d)
print(f"0x58e5d: '{get_str(data, 0x58e5d)}'")

# 0x35f84/35f88: x0=0x60d9c
print(f"0x60d9c: '{get_str(data, 0x60d9c)}'")

# 0x35f90+35f98: x0=0x60dbe
print(f"0x60dbe: '{get_str(data, 0x60dbe)}'")

# 0x35fbc/35fc0: x2=0x60dbe (same)
# 0x35fec/35ff0: x0=0x60dcf
print(f"0x60dcf: '{get_str(data, 0x60dcf)}'")

# 0x36044/36048: x0=0x60de5
print(f"0x60de5: '{get_str(data, 0x60de5)}'")

# 0x360b4/360b8: x0=0x60e5f
print(f"0x60e5f: '{get_str(data, 0x60e5f)}'")

# 0x360c0/360c4: x0=0x60e78
print(f"0x60e78: '{get_str(data, 0x60e78)}'")

print()
print("=== CRITICAL ANALYSIS ===")
print()
print("CmdCustUnlockFlash (0x35ca8) verification flow:")
print()
print("1. bl 0x289b4 (validate fastboot cmd args)")
print("   if fail -> return error 0x8000000000000003")
print()
print("2. bl 0xc214 (allocate 0x20=32 bytes) -> x24")
print("   x20+x21 (token data, token_size-0x100) added together -> x25")
print()
print("3. blr x8 (EFI protocol call via [x8+320])")
print("   x0=proto, x1=0, x2=x22(stack area)")
print("   -> loads something from EFI into x22 area")
print()
print("PATH A: bl 0xdb4 at 0x35e80")
print("   Args: x0=[x22](proto), x1=2, x2=x20(token), x3=x21(signed_part), x4=x24(buf), x5=0x20")
print("   This is: OPVerify(proto, hash_algo=2, data, data_len, out_hash, hash_len=32)")
print("   -> Extracts/verifies a SIGNED ENVELOPE from the token data")
print("   if cbz x0 -> try PATH B")
print()
print("PATH B: bl 0x1048 at 0x35ee0")
print("   Args: x0=[x22](proto), x1=x24(hash from A), x2=2, x3=x23, x4=x25, x5=0x100")
print("   Another verify call")
print("   if cbz x0 -> fall through to HMAC path")
print()
print("PATH C (HMAC FALLBACK): 0x35f28-0x360ac")
print("   1. memset 73-byte buffer")
print("   2. ReadDeviceID -> 9 bytes device serial")
print("   3. strlcat: key_strings + device_id (build 72-byte HMAC input)")
print("   4. HmacInit / HmacUpdate(72B) / HmacFinal")
print("   5. memcmp(hmac_output, token_data)")
print("   if match -> UNLOCK SUCCESS")
print()
print("KEY INSIGHT:")
print("  PATH A/B use EFI crypto protocol (RSA/ECDSA signature verification)")
print("  PATH C is a SOFTWARE HMAC fallback")
print("  The HMAC key is HARDWARE-BACKED (via EFI LocateProtocol)")
print("  So even the fallback HMAC cannot be computed without the hardware key")
