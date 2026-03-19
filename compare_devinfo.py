import sys
with open('edl_backup/devinfo.bin.original', 'rb') as f:
    orig = f.read()
with open('edl_backup/devinfo_final.bin', 'rb') as f:
    mod = f.read()
for i in range(len(orig)):
    if orig[i] != mod[i]:
        print(f"Diff at 0x{i:X}: orig={orig[i]:02X} mod={mod[i]:02X}")
