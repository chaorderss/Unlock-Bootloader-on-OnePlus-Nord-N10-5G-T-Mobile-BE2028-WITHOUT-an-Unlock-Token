#!/usr/bin/env python3
"""
Directly test paramtools with exact same call as standalone tool
"""
import sys
sys.path.insert(0, '/Library/Frameworks/Python.framework/Versions/3.14/lib/python3.14/site-packages')

import struct, hashlib

# Exact same imports as oneplus_param.py
from edlclient.Library.Modules.oneplus_param import paramtools

PARAM_BIN = '/Users/xmxx/pinganhuijia/edl_backup/param.bin'

with open(PARAM_BIN, 'rb') as f:
    data = f.read()

print("=== Testing with string mode='1' string serial='0xdb0c1e4b' (standalone tool call) ===")
p1 = paramtools("1", "0xdb0c1e4b")
print(f"Key used: {p1.aes_key.hex()}")
print(f"expected default key: 3030304f6e65506c7573383138303030")
print(f"expected serial key:  62833ed9de4dfa73ae63d951f2fe188b")

print("\n=== Testing with int mode=1 int serial=1969577307 (EDL runtime call) ===")
p2 = paramtools(1, 1969577307)
print(f"Key used: {p2.aes_key.hex()}")

print("\n=== Testing with int mode=1 int serial=3674081355 (androidboot.serialno) ===")
p3 = paramtools(1, 3674081355)
print(f"Key used: {p3.aes_key.hex()}")

print("\n=== Directly calling parse_encrypted_fields with mode=1 serial=1969577307 ===")
p4 = paramtools(1, 1969577307)
p4.parse_encrypted_fields(data)

print("\n=== Directly calling parse_encrypted_fields with default key ===")
p5 = paramtools(0, 0)
p5.parse_encrypted_fields(data)

print("\n=== Checking iv ===")
print(f"IV: {p2.aes_iv.hex()}")
