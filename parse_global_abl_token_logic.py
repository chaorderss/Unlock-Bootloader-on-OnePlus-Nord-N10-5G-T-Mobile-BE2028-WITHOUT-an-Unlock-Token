import sys

def analyze_token_logic(filepath):
    try:
        with open(filepath, 'rb') as f:
            data = f.read()

        target_string = b"Please flash unlock token first"
        str_offset = data.find(target_string)
        if str_offset == -1:
            print("String not found.")
            return

        print(f"String found at file offset: 0x{str_offset:X}")
        # Assuming VA base is around what we found before, usually string offset minus 0xB8 or similar
        # For typical OP Nord N10 ABL, VA base might be 0x0
        # Let's search for the VA of the string.
        # Guessing VA = offset - something. Wait, in previous scripts we had code to find the string xref.
        
    except Exception as e:
        print(f"Error: {e}")

analyze_token_logic("global_abl_decompressed.bin")
