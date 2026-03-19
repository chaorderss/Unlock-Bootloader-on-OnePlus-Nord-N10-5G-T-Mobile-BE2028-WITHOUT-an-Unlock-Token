#!/usr/bin/env python3
"""
Create the cust-unlock binary token from the unlock code returned by
fastboot oem get_unlock_code
"""
import binascii
import os
import sys

# The unlock code returned by the device
UNLOCK_CODE = '709417F3BD269DE909ACA59342EC3BE64E122B5DF9287DC65EC2B521B1E41482'

# Verify correct length
if len(UNLOCK_CODE) != 64:
    print(f'ERROR: expected 64 hex chars, got {len(UNLOCK_CODE)}')
    sys.exit(1)

# Convert to binary
try:
    token_bytes = binascii.unhexlify(UNLOCK_CODE)
except Exception as e:
    print(f'ERROR: {e}')
    sys.exit(1)

assert len(token_bytes) == 32, f'Expected 32 bytes, got {len(token_bytes)}'

# Write to file
outpath = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       'tmp', 'cust_unlock_token.bin')
os.makedirs(os.path.dirname(outpath), exist_ok=True)
with open(outpath, 'wb') as f:
    f.write(token_bytes)

print(f'Token written to: {outpath}')
print(f'Size: {len(token_bytes)} bytes')
print(f'Contents: {token_bytes.hex()}')
print()
print('To flash:')
print(f'  fastboot flash cust-unlock {outpath}')
print('Then:')
print('  fastboot oem unlock')
