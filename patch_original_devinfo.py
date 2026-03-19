import sys
with open('edl_backup/devinfo.bin.original', 'rb') as f:
    data = bytearray(f.read())
data[0x10] = 0x01
data[0x15] = 0x01
with open('edl_backup/devinfo_patched.bin', 'wb') as f:
    f.write(data)
print("Saved patched original to edl_backup/devinfo_patched.bin")
