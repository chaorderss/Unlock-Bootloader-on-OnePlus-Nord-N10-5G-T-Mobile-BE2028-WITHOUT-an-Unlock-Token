import sys

def check_strings(filepath):
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
            
        print(f"File: {filepath}")
        print(f"Size: {len(data)} bytes")
        
        target_strings = [
            b"Please flash unlock token first",
            b"unlock_token",
            b"token",
            b"signature",
            b"flashing unlock"
        ]
        
        found = False
        for s in target_strings:
            idx = data.find(s)
            if idx != -1:
                print(f"  [+] Found '{s.decode('ascii', errors='ignore')}' at offset 0x{idx:X}")
                found = True
                
        if not found:
            print("  [-] No token-related strings found.")
            
    except Exception as e:
        print(f"Error: {e}")

check_strings("global_abl_decompressed.bin")
