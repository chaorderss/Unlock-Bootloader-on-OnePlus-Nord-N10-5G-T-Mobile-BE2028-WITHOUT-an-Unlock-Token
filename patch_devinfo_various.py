import sys

def patch_devinfo(infile, outfile, patch_type):
    with open(infile, 'rb') as f:
        data = bytearray(f.read())
    
    # Reset some padding to zero just in case
    # data[0x0D:0x10] = b'\x00\x00\x00'

    if patch_type == 'unlock_only':
        data[0x10] = 0x01
    elif patch_type == 'all_ones':
        data[0x10] = 0x01 # is_unlocked
        data[0x11] = 0x01 # is_unlock_critical
        data[0x15] = 0x01 # oem_unlock_allowed
    elif patch_type == 'magic_with_ff':
        data[0x10] = 0xFF
    else:
        pass
        
    with open(outfile, 'wb') as f:
        f.write(data)
    print(f"Generated {outfile} ({patch_type})")

patch_devinfo('edl_backup/devinfo.bin.original', 'edl_backup/devinfo_all1.bin', 'all_ones')
patch_devinfo('edl_backup/devinfo.bin.original', 'edl_backup/devinfo_unlock1.bin', 'unlock_only')
