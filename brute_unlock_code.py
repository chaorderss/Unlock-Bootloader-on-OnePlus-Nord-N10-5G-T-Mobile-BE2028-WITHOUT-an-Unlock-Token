import hmac
import hashlib
import itertools

# Known device values
serial = 'db0c1e4b'
imei = '990016800470419'
pcba = '002088880B28132410AA0KP0'
target = '709417F3BD269DE909ACA59342EC3BE64E122B5DF9287DC65EC2B521B1E41482'
target_bytes = bytes.fromhex(target)

# Known global HMAC keys
global_keys = [
    b'9sLeM7jAuFKcXoxr',
    b'C6PMgHLaVydsUGiMP7vYd',
    b'07ltETGOgDs33FkTQOA',
]

# Per-model keys (from binary analysis)
# These are base64 strings that may decode to key material for other models
per_model_keys_b64 = [
    b'ZWIxYjNhNjYzZjc0MDc4NjkxZTg1OWM5ZDhlMjE4MDlmNWVmZjZiZmI5YjA2MG==',  # 18831
    b'AWNjY2RhMGQxMDNjODYzYjA5ZTllOTg4ZTJjYjQ1N2UzYjJmNjkzNWJmOGJjEA==',  # 19861
]

# Components to combine
components = {
    'serial': serial,
    'imei': imei,
    'pcba': pcba,
}

# Try various combinations
print(f"Target: {target}")
print()

algos = ['sha256', 'sha1', 'md5']
separators = ['', ',', '|', ';', ':', '\n', ' ']

found = False

# Test 1: HMAC with global keys, various input combos
print("=== Testing HMAC with global keys ===")
for key in global_keys:
    for sep in separators:
        for order in itertools.permutations([serial, imei, pcba]):
            data = sep.join(order).encode('ascii')
            for algo in algos:
                result = hmac.new(key, data, algo).digest()
                result_hex = result.hex().upper()
                if result_hex == target:
                    print(f"FOUND! key={key}, sep={repr(sep)}, order={order}, algo={algo}")
                    found = True

# Test 2: Pure hash (not HMAC) - SHA256 of concatenated data
print("=== Testing pure hash ===")
for sep in separators:
    for order in itertools.permutations([serial, imei, pcba]):
        data = sep.join(order).encode('ascii')
        for algo in algos:
            result = hashlib.new(algo, data).digest()
            result_hex = result.hex().upper()
            if result_hex == target:
                print(f"FOUND! pure {algo}, sep={repr(sep)}, order={order}")
                found = True

# Test 3: CmdCustUnlockFlash uses 72-byte input: check that structure
# From analysis: 72 bytes = some combination
# The CmdCustUnlockFlash uses 0x48=72 byte HMAC update
print("=== Testing with 72-byte formatted input ===")
# Various formatted combinations that might be 72 bytes
test_inputs = [
    serial + imei + pcba,  # 8 + 15 + 24 = 47 bytes - not 72
    serial.upper() + imei + pcba,
    # Maybe there's padding?
]
for key in global_keys:
    for inp in test_inputs:
        data = inp.encode('ascii')
        result = hmac.new(key, data, hashlib.sha256).digest()
        result_hex = result.hex().upper()
        if result_hex == target:
            print(f"FOUND! key={key}, input={repr(inp)}")
            found = True

# Test 4: The CmdCustUnlockFlash function builds input at sp+buffer
# It does: "Serial Number:" + serial + ", IMEI:" + imei + ", PCBA:" + pcba
print("=== Testing formatted string inputs ===")
formatted_inputs = [
    f"Serial Number:{serial}, IMEI:{imei}, PCBA:{pcba}",
    f"Serial Number:{serial},IMEI:{imei},PCBA:{pcba}",
    f"{serial},{imei},{pcba}",
    f"Serial Number: {serial}, IMEI: {imei}, PCBA: {pcba}",
    f"sn={serial}&imei={imei}&pcba={pcba}",
    f"Serial Number:\n{serial}\nIMEI:\n{imei}\nPCBA:\n{pcba}",
]
for key in global_keys:
    for inp in formatted_inputs:
        data = inp.encode('ascii')
        result = hmac.new(key, data, hashlib.sha256).digest()
        result_hex = result.hex().upper()
        if result_hex == target:
            print(f"FOUND! key={key}, input={repr(inp)}")
            found = True

# Test 5: maybe PCBA is not included for global key (oem get_unlock_code)
print("=== Testing without PCBA ===")
for key in global_keys:
    for sep in separators:
        for order in itertools.permutations([serial, imei]):
            data = sep.join(order).encode('ascii')
            result = hmac.new(key, data, hashlib.sha256).digest()
            result_hex = result.hex().upper()
            if result_hex == target:
                print(f"FOUND! key={key}, sep={repr(sep)}, order={order}")
                found = True

if not found:
    print("\nNot found. Showing closest attempts:")
    # Show first 4 bytes of each attempt
    for key in global_keys:
        for sep in ['', ',']:
            for order in [[serial, imei, pcba], [serial, imei], [imei, serial, pcba]]:
                data = sep.join(order).encode('ascii')
                result = hmac.new(key, data, hashlib.sha256).hexdigest().upper()
                print(f"  HMAC-SHA256(key={key[:8]}..., {repr(sep.join(order)[:30])}) = {result[:16]}...")
